//! Private-session-bus harness for the `daemon-tests` integration suite: spin up an isolated
//! `dbus-daemon` plus a `gnome-keyring-daemon` (secrets component) against a throwaway
//! `XDG_DATA_HOME`, then reap both — even on panic — so no daemons or temp state leak.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;

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
    /// Returns `None` when `dbus-daemon` or `gnome-keyring-daemon` is absent, so a host without the
    /// daemons skips cleanly instead of failing.
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
            // The daemon reads the login password from stdin until EOF (newlines are part of the
            // password), so write the raw bytes and close the pipe — never append a newline.
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

fn binary_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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

/// Graceful SIGTERM (via `kill`, avoiding an `unsafe` libc call), escalate to SIGKILL if it
/// lingers, reaping the child exactly once.
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
    // Still running (or no portable SIGTERM): force-kill and reap once.
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
