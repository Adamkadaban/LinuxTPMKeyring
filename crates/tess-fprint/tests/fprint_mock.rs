//! Headless, deterministic integration tests for [`tess_fprint::FprintClient`] driven by the
//! `python-dbusmock` harness in `testing/fprint-mock/`.
//!
//! Each test spawns its own private session bus (`dbus-run-session`) hosting a scripted
//! `net.reactivated.Fprint` mock, so they run in parallel without touching a real reader, real
//! fprintd, or the developer's session bus. When the harness tooling (python3, dbus-run-session,
//! python3-dbusmock) is absent the tests skip cleanly so the default `cargo test --workspace` stays
//! green on any machine; CI installs the tooling and runs them for real.

use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tess_core::{AuthGate, Error};
use tess_fprint::FprintClient;

const ADDRESS_READ_TIMEOUT: Duration = Duration::from_secs(15);

fn harness_script() -> String {
    format!(
        "{}/../../testing/fprint-mock/fprintd_mock.py",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// True when `dbus-run-session` and every Python module the harness imports (`dbus`, `dbusmock`,
/// `gi.repository.GLib`) are usable. Checking all of them keeps the "skip cleanly" promise: if any is
/// missing the tests skip instead of spawning a harness that would panic at the address-read timeout.
fn harness_available() -> bool {
    let dbus_run = Command::new("dbus-run-session")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
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

/// A scripted fprintd mock on a private bus. Dropping it reaps the whole process group (the
/// `dbus-run-session`, its `dbus-daemon`, and the `dbusmock` server), so nothing leaks.
struct MockHarness {
    child: Child,
}

impl MockHarness {
    /// Start the mock for `scenario` (`match` / `no-match` / `stall`) and return it with the private
    /// bus address once the harness has announced it.
    fn start(scenario: &str) -> (Self, String) {
        let mut child = Command::new("dbus-run-session")
            .arg("--")
            .args(["python3", &harness_script(), scenario])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("spawn dbus-run-session harness");

        let stdout = child.stdout.take().expect("harness stdout piped");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            if BufReader::new(stdout).read_line(&mut line).is_ok() {
                let _ = tx.send(line.trim().to_owned());
            }
        });

        let harness = Self { child };
        match rx.recv_timeout(ADDRESS_READ_TIMEOUT) {
            Ok(addr) if !addr.is_empty() => (harness, addr),
            _ => panic!("harness did not announce a bus address within {ADDRESS_READ_TIMEOUT:?}"),
        }
    }
}

impl Drop for MockHarness {
    fn drop(&mut self) {
        let pgid = Pid::from_raw(self.child.id() as i32);
        let _ = killpg(pgid, Signal::SIGTERM);
        // Give the group a moment to exit gracefully on SIGTERM.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && matches!(self.child.try_wait(), Ok(None)) {
            thread::sleep(Duration::from_millis(20));
        }
        // Unconditionally SIGKILL the whole group, even if the leader already exited: children
        // (`dbus-daemon`, the `dbusmock` server) can outlive the `dbus-run-session` leader, and a
        // member that ignored SIGTERM must still be reaped. SIGKILL to an already-dead group is a
        // harmless ESRCH.
        let _ = killpg(pgid, Signal::SIGKILL);
        let _ = self.child.wait();
    }
}

#[test]
fn verify_match_returns_ok() {
    if !harness_available() {
        eprintln!("skipping: python3-dbusmock / dbus-run-session not available");
        return;
    }
    let (_harness, addr) = MockHarness::start("match");
    let client = FprintClient::connect_address(&addr, "").expect("connect to mock bus");
    client.verify(5_000).expect("verify-match should authorize");
}

#[test]
fn verify_no_match_returns_auth_error() {
    if !harness_available() {
        eprintln!("skipping: python3-dbusmock / dbus-run-session not available");
        return;
    }
    let (_harness, addr) = MockHarness::start("no-match");
    let client = FprintClient::connect_address(&addr, "").expect("connect to mock bus");
    match client.verify(5_000) {
        Err(Error::Auth(msg)) => assert!(
            msg.contains("did not match"),
            "expected a no-match auth error, got: {msg}"
        ),
        other => panic!("expected Error::Auth, got {other:?}"),
    }
}

#[test]
fn verify_stall_times_out_bounded() {
    if !harness_available() {
        eprintln!("skipping: python3-dbusmock / dbus-run-session not available");
        return;
    }
    let (_harness, addr) = MockHarness::start("stall");
    let client = FprintClient::connect_address(&addr, "").expect("connect to mock bus");

    let deadline_ms = 500;
    let start = Instant::now();
    let result = client.verify(deadline_ms);
    let elapsed = start.elapsed();

    match result {
        Err(Error::Timeout(reported)) => assert_eq!(reported, deadline_ms),
        other => panic!("expected Error::Timeout, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(5),
        "verify must be bounded; took {elapsed:?}"
    );
}

#[test]
fn auth_gate_match_authorizes() {
    if !harness_available() {
        eprintln!("skipping: python3-dbusmock / dbus-run-session not available");
        return;
    }
    let (_harness, addr) = MockHarness::start("match");
    let client = FprintClient::connect_address(&addr, "").expect("connect to mock bus");
    let gate: &dyn AuthGate = &client;
    gate.authorize(5_000)
        .expect("AuthGate match should authorize");
}
