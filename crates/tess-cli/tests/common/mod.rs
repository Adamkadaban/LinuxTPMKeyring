//! Shared harnesses for the `sim` + `daemon-tests` enrollment suite: an isolated swtpm (TPM
//! seal/unseal) and a throwaway `gnome-keyring-daemon` on a private session bus (Secret Service
//! rekey). Both reap every spawned process and wipe their state on drop — even on panic — so no
//! swtpm, dbus-daemon, or gnome-keyring-daemon leaks.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;
use tess_tpm::TctiConfig;

// ---------------------------------------------------------------------------------------------
// swtpm
// ---------------------------------------------------------------------------------------------

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

/// RAII guard around a foreground swtpm child.
pub struct Swtpm {
    child: Child,
    state_dir: PathBuf,
}

impl Swtpm {
    /// Start an isolated swtpm, returning the guard and its transport config, or `None` when swtpm
    /// is not installed (so the suite skips cleanly on hardware-free hosts).
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
            std::env::temp_dir().join(format!("tess-cli-sim-{}-{}", std::process::id(), cmd_port));
        create_private_dir(&state_dir);

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
        reap(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

fn wait_for_port(addr: std::net::SocketAddr, child: &mut Child) -> Result<(), String> {
    for _ in 0..50 {
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

// ---------------------------------------------------------------------------------------------
// gnome-keyring on a private bus
// ---------------------------------------------------------------------------------------------

/// An isolated session bus with a `gnome-keyring-daemon` whose login keyring was created and
/// unlocked with the password fed on stdin. Everything lives under a throwaway home dir.
pub struct GnomeKeyring {
    _home: TempDir,
    dbus: Child,
    keyring: Child,
    address: String,
}

impl GnomeKeyring {
    /// Start the private bus and keyring, creating + unlocking the login keyring with `password`.
    /// Returns `None` when the daemons are absent so the suite skips cleanly.
    pub fn start(password: &[u8]) -> Option<Self> {
        if !binary_available("dbus-daemon") || !binary_available("gnome-keyring-daemon") {
            eprintln!("skipping daemon test: dbus-daemon or gnome-keyring-daemon not on PATH");
            return None;
        }

        let home = tempfile::tempdir().expect("create throwaway home");
        let data = home.path().join("data");
        let config = home.path().join("config");
        let runtime = home.path().join("run");
        for dir in [&data, &config, &runtime] {
            create_private_dir(dir);
        }

        let mut dbus = Command::new("dbus-daemon")
            .arg("--session")
            .arg("--nofork")
            .arg("--print-address")
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dbus-daemon");

        let address = {
            let stdout = dbus.stdout.take().expect("dbus-daemon stdout");
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .expect("read dbus-daemon address");
            line.trim().to_string()
        };
        assert!(
            !address.is_empty(),
            "dbus-daemon did not print a bus address"
        );

        let mut keyring = Command::new("gnome-keyring-daemon")
            .arg("--foreground")
            .arg("--components=secrets")
            .arg("--unlock")
            .env("HOME", home.path())
            .env("XDG_DATA_HOME", &data)
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gnome-keyring-daemon");

        {
            let mut stdin = keyring.stdin.take().expect("keyring stdin");
            stdin.write_all(password).expect("write keyring password");
        }

        let mut guard = Self {
            _home: home,
            dbus,
            keyring,
            address,
        };

        if let Err(reason) = wait_for_secrets(&guard.address, &mut guard.keyring) {
            panic!("gnome-keyring secrets service did not come up: {reason}");
        }
        Some(guard)
    }

    /// The private session-bus address.
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Drop for GnomeKeyring {
    fn drop(&mut self) {
        reap(&mut self.keyring);
        reap(&mut self.dbus);
    }
}

fn wait_for_secrets(address: &str, keyring: &mut Child) -> Result<(), String> {
    let connection = zbus::blocking::connection::Builder::address(address)
        .map_err(|e| format!("parse private bus address: {e}"))?
        .build()
        .map_err(|e| format!("connect to private bus: {e}"))?;
    let dbus = zbus::blocking::fdo::DBusProxy::new(&connection)
        .map_err(|e| format!("open org.freedesktop.DBus proxy: {e}"))?;
    let name = zbus::names::BusName::try_from("org.freedesktop.secrets")
        .map_err(|e| format!("bus name: {e}"))?;

    for _ in 0..150 {
        if let Ok(Some(status)) = keyring.try_wait() {
            return Err(format!("gnome-keyring-daemon exited early ({status})"));
        }
        if dbus.name_has_owner(name.clone()).unwrap_or(false) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("timed out waiting for org.freedesktop.secrets".to_string())
}

// ---------------------------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------------------------

fn binary_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .expect("create private dir");
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) {
    std::fs::create_dir_all(dir).expect("create private dir");
}

/// Graceful SIGTERM, escalate to SIGKILL if it lingers, reaping the child exactly once.
fn reap(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    if send_sigterm(child) {
        for _ in 0..50 {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(_) => return,
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn send_sigterm(child: &Child) -> bool {
    Command::new("kill")
        .arg(child.id().to_string())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn send_sigterm(_child: &Child) -> bool {
    false
}
