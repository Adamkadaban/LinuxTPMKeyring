//! Shared harnesses for the `sim` + `daemon-tests` enrollment suite: an isolated swtpm (TPM
//! seal/unseal) and a throwaway `gnome-keyring-daemon` on a private session bus (Secret Service
//! rekey). Both reap every spawned process and wipe their state on drop — even on panic — so no
//! swtpm, dbus-daemon, or gnome-keyring-daemon leaks.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
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
    ///
    /// Reserved ports are released before swtpm binds them, so another process can win the race in
    /// that window. Rather than fail sporadically, retry the whole spawn with fresh ports a few
    /// times: a lost race makes swtpm exit early, which `wait_for_port` reports, and we re-roll.
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

        const ATTEMPTS: u32 = 5;
        let mut last_err = String::new();
        for _ in 0..ATTEMPTS {
            match Self::start_once() {
                Ok(pair) => return Some(pair),
                Err(e) => last_err = e,
            }
        }
        panic!("swtpm did not start after {ATTEMPTS} attempts (last error: {last_err})");
    }

    /// One spawn attempt: reserve a fresh consecutive port pair, launch swtpm, and wait for both
    /// ports. On early exit (a lost port race) the guard is dropped — reaping swtpm and wiping its
    /// state — and the error is returned so the caller can retry with new ports.
    fn start_once() -> Result<(Self, TctiConfig), String> {
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
        // On early exit (a lost port race) `guard` drops here — reaping swtpm and wiping its state —
        // and the error propagates so the caller retries with fresh ports.
        wait_for_port(cmd_addr, &mut guard.child)
            .and_then(|()| wait_for_port(ctrl_addr, &mut guard.child))?;

        let cfg = TctiConfig::Swtpm {
            host: "127.0.0.1".to_string(),
            port: cmd_port,
        };
        Ok((guard, cfg))
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
// fprintd mock (python-dbusmock on its own private bus)
// ---------------------------------------------------------------------------------------------

const FPRINT_ADDRESS_TIMEOUT: Duration = Duration::from_secs(15);

fn fprintd_mock_script() -> String {
    format!(
        "{}/../../testing/fprint-mock/fprintd_mock.py",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// True when the fprintd mock tooling (`dbus-run-session` plus the Python modules the harness
/// imports) is usable, so the fingerprint tests skip cleanly when it is absent.
pub fn fprint_harness_available() -> bool {
    let dbus_run = binary_available("dbus-run-session");
    let python_imports = Command::new("python3")
        .args([
            "-c",
            "import dbus, dbusmock; from gi.repository import GLib",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    dbus_run && python_imports
}

/// A scripted `net.reactivated.Fprint` mock on its own private session bus, separate from the
/// keyring's bus. Dropping it reaps the whole process group (the `dbus-run-session`, its
/// `dbus-daemon`, and the `dbusmock` server), so nothing leaks.
pub struct FprintMock {
    child: Child,
    address: String,
}

impl FprintMock {
    /// Start the mock for `scenario` (`match` / `no-match` / `stall`) and return it once the harness
    /// has announced its private bus address.
    pub fn start(scenario: &str) -> Self {
        let mut child = Command::new("dbus-run-session")
            .arg("--")
            .args(["python3", &fprintd_mock_script(), scenario])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn dbus-run-session fprintd mock");

        let stdout = child.stdout.take().expect("fprintd mock stdout piped");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            if BufReader::new(stdout).read_line(&mut line).is_ok() {
                let _ = tx.send(line.trim().to_owned());
            }
        });

        let address = match rx.recv_timeout(FPRINT_ADDRESS_TIMEOUT) {
            Ok(addr) if !addr.is_empty() => addr,
            _ => {
                // A bare `Child` does not reap on drop, so kill and wait the whole process group
                // before failing — otherwise a timeout leaks the `dbus-daemon`/`dbusmock` group.
                let pgid = Pid::from_raw(child.id() as i32);
                let _ = killpg(pgid, Signal::SIGKILL);
                let _ = child.wait();
                panic!(
                    "fprintd mock did not announce a bus address within {FPRINT_ADDRESS_TIMEOUT:?}"
                );
            }
        };
        Self { child, address }
    }

    /// The private bus address the mock fprintd listens on.
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Drop for FprintMock {
    fn drop(&mut self) {
        let pgid = Pid::from_raw(self.child.id() as i32);
        let _ = killpg(pgid, Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && matches!(self.child.try_wait(), Ok(None)) {
            thread::sleep(Duration::from_millis(20));
        }
        // Unconditionally SIGKILL the whole group: children (`dbus-daemon`, the `dbusmock` server)
        // can outlive the `dbus-run-session` leader. SIGKILL to an already-dead group is a harmless
        // ESRCH.
        let _ = killpg(pgid, Signal::SIGKILL);
        let _ = self.child.wait();
    }
}

/// Run `tess-pam-helper` with the fingerprint front gate enabled (`--fingerprint`), pointing its
/// fprintd verify at `fprint_bus` (the [`FprintMock`]) with a bounded `fprint_timeout`. Otherwise
/// identical to [`run_pam_helper`]: the PIN is fed on stdin, the wait is bounded, and the child is
/// reaped under a hard deadline. Returns the exit success flag and the captured (secret-free)
/// stderr, on which the caller asserts the fingerprint verdict line.
pub fn run_pam_helper_fprint(
    tcti: &TctiConfig,
    bus_address: &str,
    data_home: &Path,
    pin: &[u8],
    fprint_bus: &str,
    fprint_timeout: Duration,
) -> (bool, String) {
    run_helper_inner(
        tcti,
        bus_address,
        data_home,
        pin,
        Some(FprintEnv {
            bus_address: fprint_bus.to_string(),
            timeout_ms: fprint_timeout.as_millis() as u64,
        }),
    )
}

struct FprintEnv {
    bus_address: String,
    timeout_ms: u64,
}

// ---------------------------------------------------------------------------------------------
// tess-pam-helper
// ---------------------------------------------------------------------------------------------

/// Run the `tess-pam-helper` binary the way the PAM module does: `pin` on stdin, a bounded wait, and
/// a best-effort reap under a hard deadline. Returns the exit success flag and the captured
/// (secret-free) stderr. On a clean exit the child is fully reaped; if it overruns the deadline the
/// function sends SIGKILL, polls briefly for the corpse, then panics (failing the test) — so a stuck
/// helper can never hang the suite indefinitely. A child that even outlasts that bounded post-kill
/// poll is left as a zombie that the OS reaps when the test process exits. The helper resolves its
/// enrollment metadata from `$XDG_DATA_HOME/tess` and selects the swtpm transport from
/// `TESS_SWTPM_HOST`/`TESS_SWTPM_PORT`, both derived from `tcti`.
///
/// The PAM module hands the PIN to the helper over a `memfd`, not a pipe; this test feeds stdin via
/// a pipe, since the SIGPIPE hazard the memfd avoids only applies inside the login process.
pub fn run_pam_helper(
    tcti: &TctiConfig,
    bus_address: &str,
    data_home: &Path,
    pin: &[u8],
) -> (bool, String) {
    run_helper_inner(tcti, bus_address, data_home, pin, None)
}

fn run_helper_inner(
    tcti: &TctiConfig,
    bus_address: &str,
    data_home: &Path,
    pin: &[u8],
    fprint: Option<FprintEnv>,
) -> (bool, String) {
    let (host, port) = match tcti {
        TctiConfig::Swtpm { host, port } => (host.clone(), port.to_string()),
        TctiConfig::DeviceManager { .. } => panic!("sim test must use swtpm"),
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_tess-pam-helper"));
    command
        .env("DBUS_SESSION_BUS_ADDRESS", bus_address)
        .env("XDG_DATA_HOME", data_home)
        .env("TESS_SWTPM_HOST", host)
        .env("TESS_SWTPM_PORT", port)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(fprint) = fprint {
        command
            .arg("--fingerprint")
            .env("TESS_FPRINT_BUS_ADDRESS", fprint.bus_address)
            .env("TESS_FPRINT_TIMEOUT_MS", fprint.timeout_ms.to_string());
    }
    let mut child = command.spawn().expect("spawn tess-pam-helper");

    child
        .stdin
        .take()
        .expect("helper stdin")
        .write_all(pin)
        .expect("write PIN to helper stdin");

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait helper") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            // Bounded reap after the kill — never an unbounded `wait()` that could itself hang CI if
            // the helper were stuck in uninterruptible I/O.
            for _ in 0..40 {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!("tess-pam-helper did not finish within the deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    (status.success(), stderr)
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
