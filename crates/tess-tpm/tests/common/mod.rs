//! Shared swtpm harness for the `sim`-gated integration tests: reserve a consecutive
//! command/control port pair, spawn an isolated foreground swtpm with a private 0700 state dir, wait
//! for both ports, and reap the process + wipe state on drop (even on panic) so no swtpm leaks.

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tess_tpm::TctiConfig;

/// Reserve a free command port `p` such that the control port `p + 1` is also free, returning
/// `(command, control)`. The swtpm TCTI hard-wires the control channel to the command port + 1, so
/// the two must be consecutive. The retry here only covers a port being unavailable at *reservation*
/// time; the small residual window between dropping the listeners and swtpm binding the ports is not
/// retried — a lost race surfaces as a clear startup assertion, not a hang.
fn reserve_consecutive_ports() -> (u16, u16) {
    for _ in 0..50 {
        let Ok(cmd) = TcpListener::bind("127.0.0.1:0") else {
            continue;
        };
        let cmd_port = cmd.local_addr().expect("local addr").port();
        if cmd_port == u16::MAX {
            continue;
        }
        let ctrl_port = cmd_port + 1;
        if TcpListener::bind(("127.0.0.1", ctrl_port)).is_ok() {
            return (cmd_port, ctrl_port);
        }
    }
    panic!("could not reserve a consecutive command/control port pair for swtpm");
}

/// RAII guard around a foreground swtpm child: SIGTERM (then SIGKILL on lingering) and reap on drop,
/// then wipe the state dir — even if an assertion panics, so no swtpm survives the test.
pub struct Swtpm {
    child: Child,
    state_dir: PathBuf,
}

impl Swtpm {
    /// Start an isolated swtpm, returning the guard and its matching transport config, or `None`
    /// when swtpm is not installed (so the feature build still passes on hardware-free hosts).
    pub fn start() -> Option<(Self, TctiConfig)> {
        match Command::new("swtpm").arg("--version").output() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping sim test: swtpm not found on PATH");
                return None;
            }
            Err(e) => panic!("failed to execute swtpm: {e}"),
            Ok(out) if !out.status.success() => panic!(
                "swtpm --version failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ),
            Ok(_) => {}
        }

        let (cmd_port, ctrl_port) = reserve_consecutive_ports();
        let state_dir =
            std::env::temp_dir().join(format!("tess-sim-{}-{}", std::process::id(), cmd_port));
        // 0700 so the emulator state (TPM material) isn't readable by other local users.
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&state_dir)
            .expect("create swtpm state dir");

        // Foreground (no --daemon): the spawned Child is swtpm itself, giving a reliable handle to
        // reap. swtpm exits when its client disconnects, so the guard mainly matters on a panic.
        let child = Command::new("swtpm")
            .arg("socket")
            .arg("--tpm2")
            .arg("--server")
            .arg(format!("type=tcp,bindaddr=127.0.0.1,port={cmd_port}"))
            .arg("--ctrl")
            .arg(format!("type=tcp,bindaddr=127.0.0.1,port={ctrl_port}"))
            .arg("--tpmstate")
            .arg(format!("dir={}", state_dir.display()))
            .arg("--flags")
            .arg("startup-clear")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn swtpm");

        let mut guard = Self { child, state_dir };

        // The swtpm TCTI connects to both the command port and the control port (command + 1), so
        // wait for both before opening a context, otherwise open_context() can flap.
        let cmd_addr: std::net::SocketAddr = format!("127.0.0.1:{cmd_port}").parse().unwrap();
        let ctrl_addr: std::net::SocketAddr = format!("127.0.0.1:{ctrl_port}").parse().unwrap();
        wait_for_port(cmd_addr, &mut guard.child).expect("swtpm command port");
        wait_for_port(ctrl_addr, &mut guard.child).expect("swtpm control port");

        let cfg = TctiConfig::Swtpm {
            host: "127.0.0.1".to_string(),
            port: cmd_port,
        };
        Some((guard, cfg))
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        if let Ok(Some(_)) = self.child.try_wait() {
            // Already exited (the happy path: swtpm quit when the client disconnected).
            let _ = std::fs::remove_dir_all(&self.state_dir);
            return;
        }
        // Graceful SIGTERM first, escalate to SIGKILL if it lingers. `kill` avoids unsafe libc.
        let pid = self.child.id().to_string();
        let sigterm_sent = Command::new("kill")
            .arg(&pid)
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        // Only pay the grace wait if SIGTERM was actually delivered; otherwise go straight to SIGKILL.
        if sigterm_sent {
            for _ in 0..50 {
                if let Ok(Some(_)) = self.child.try_wait() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

fn wait_for_port(addr: std::net::SocketAddr, child: &mut Child) -> Result<(), String> {
    for _ in 0..50 {
        // Fail fast if swtpm exited early (bad args / missing runtime deps) instead of waiting
        // out the full timeout.
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "swtpm exited early ({status}) while waiting for {addr}"
            ));
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!("timed out waiting for {addr}"))
}
