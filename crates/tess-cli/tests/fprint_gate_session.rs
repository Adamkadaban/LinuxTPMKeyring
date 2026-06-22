//! `sim` + `daemon-tests` end-to-end proof of the fingerprint front gate in the PAM session path.
//!
//! Enroll against an isolated swtpm and a throwaway `gnome-keyring-daemon`, then drive the real
//! `tess-pam-helper` binary with `--fingerprint` and a scripted `net.reactivated.Fprint` mock (the
//! `#21` python-dbusmock harness) on its own private bus. Three scenarios prove the precedence
//! **fingerprint (convenience) -> PIN (the real gate) -> password fallthrough**:
//!
//! * `match`    — fprintd matches; the PIN-backed unseal then unlocks the keyring.
//! * `no-match` — fprintd reports no match; the helper falls back to the PIN and still unlocks.
//! * `stall`    — fprintd never answers; the bounded verify times out and the helper falls back to
//!   the PIN within the deadline (proving the front gate never freezes login).
//!
//! In every case the PIN is what unseals the key — the fingerprint never substitutes for it.
//! Throwaway keyrings only; every spawned process (swtpm, dbus, keyring, fprintd mock, helper) is
//! reaped on drop or at the end of the test.
#![cfg(all(feature = "sim", feature = "daemon-tests"))]

mod common;

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use common::{fprint_harness_available, run_pam_helper_fprint, FprintMock, GnomeKeyring, Swtpm};
use secret_service::blocking::SecretService;
use secret_service::EncryptionType;
use tess_core::{KeyringBackend, SecretBytes};
use tess_keyring::SecretServiceBackend;

use tess_cli::enroll::sealer::TpmSealer;
use tess_cli::enroll::{enroll, Paths};

const OLD_PASSWORD: &[u8] = b"old-keyring-password";
const PIN: &[u8] = b"1234";
const ITEMS: [(&str, &[u8]); 3] = [
    ("alpha", b"secret-one"),
    ("beta", b"secret-two"),
    ("gamma", b"secret-three"),
];

// `secret-service`'s client reads the bus address from `DBUS_SESSION_BUS_ADDRESS`, a process-global.
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

fn login_collection_path(service: &SecretService<'_>) -> String {
    service
        .get_all_collections()
        .expect("list collections")
        .into_iter()
        .find(|c| c.collection_path.as_str().ends_with("/login"))
        .expect("login collection present")
        .collection_path
        .to_string()
}

fn seed_items(service: &SecretService<'_>, collection_path: &str) {
    let collection = service
        .get_all_collections()
        .expect("list collections")
        .into_iter()
        .find(|c| c.collection_path.as_str() == collection_path)
        .expect("login collection");
    for (label, secret) in ITEMS {
        let attributes = HashMap::from([("tess-test", label)]);
        collection
            .create_item(label, attributes, secret, true, "text/plain")
            .expect("store item");
    }
}

fn assert_items_intact(service: &SecretService<'_>, step: &str) {
    for (label, expected) in ITEMS {
        let attributes = HashMap::from([("tess-test", label)]);
        let found = service.search_items(attributes).expect("search items");
        let item = found
            .unlocked
            .first()
            .unwrap_or_else(|| panic!("[{step}] item {label} present and unlocked"));
        assert_eq!(
            item.get_secret().expect("decrypt item"),
            expected,
            "[{step}] item {label} must survive the session unlock"
        );
    }
}

fn lock_login(service: &SecretService<'_>, collection_path: &str) {
    let collection = service
        .get_all_collections()
        .expect("list collections")
        .into_iter()
        .find(|c| c.collection_path.as_str() == collection_path)
        .expect("login collection");
    collection.lock().expect("lock collection");
}

/// The enrolled, ready-to-unlock fixture shared by the three fingerprint scenarios.
struct Fixture<'a> {
    tcti: &'a tess_tpm::TctiConfig,
    backend: &'a SecretServiceBackend,
    service: &'a SecretService<'a>,
    collection_path: &'a str,
    data_home: &'a std::path::Path,
    bus_address: &'a str,
}

impl Fixture<'_> {
    /// Drive one fprintd scenario through the fingerprint front gate, asserting the keyring unlocks
    /// via the PIN regardless of the fingerprint result, that the helper logs the expected verdict,
    /// and that the run is bounded.
    fn run_scenario(&self, scenario: &str, expected_log: &str, fprint_timeout: Duration) {
        lock_login(self.service, self.collection_path);
        assert!(
            self.backend.is_locked().unwrap(),
            "[{scenario}] keyring locked before session"
        );

        let mock = FprintMock::start(scenario);
        let started = Instant::now();
        let (ok, stderr) = run_pam_helper_fprint(
            self.tcti,
            self.bus_address,
            self.data_home,
            PIN,
            mock.address(),
            fprint_timeout,
        );
        let elapsed = started.elapsed();
        drop(mock);

        assert!(
            ok,
            "[{scenario}] helper must unlock via the PIN; stderr: {stderr}"
        );
        assert!(
            stderr.contains(expected_log),
            "[{scenario}] expected log {expected_log:?}, got: {stderr}"
        );
        assert!(
            !self.backend.is_locked().unwrap(),
            "[{scenario}] the PIN-backed session must unlock the keyring"
        );
        assert_items_intact(self.service, scenario);
        // The whole run — bounded fingerprint verify plus the unseal/unlock — must finish well
        // within the helper's own hard kill deadline, proving the front gate never freezes login.
        assert!(
            elapsed < Duration::from_secs(15),
            "[{scenario}] session must be bounded; took {elapsed:?}"
        );
    }
}

#[test]
fn fingerprint_front_gate_precedence_match_nomatch_stall() {
    if !fprint_harness_available() {
        eprintln!("skipping: python3-dbusmock / dbus-run-session not available");
        return;
    }
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some((swtpm, tcti)) = Swtpm::start() else {
        return;
    };
    let Some(keyring) = GnomeKeyring::start(OLD_PASSWORD) else {
        return;
    };
    let _env = EnvGuard::set("DBUS_SESSION_BUS_ADDRESS", keyring.address());

    let service = SecretService::connect(EncryptionType::Dh).expect("connect Secret Service");
    let collection_path = login_collection_path(&service);
    seed_items(&service, &collection_path);

    let data_home = tempfile::tempdir().expect("temp data home");
    let tess_dir = data_home.path().join("tess");
    let paths = Paths {
        metadata: tess_dir.join("metadata.json"),
        recovery: tess_dir.join("recovery.json"),
    };

    let backend =
        SecretServiceBackend::connect_to(keyring.address(), &collection_path).expect("backend");
    let old = SecretBytes::new(OLD_PASSWORD.to_vec());
    let pin = SecretBytes::new(PIN.to_vec());
    let verify_item = || Ok(());

    {
        // Scope the sealer so its TPM context is closed before the helper opens its own against the
        // single-client swtpm.
        let mut sealer = TpmSealer::open(&tcti).expect("open swtpm sealer");
        enroll(&mut sealer, &backend, &paths, &old, &pin, &verify_item).expect("enroll");
    }
    assert!(
        !backend.is_locked().unwrap(),
        "keyring unlocked after enroll"
    );
    assert_items_intact(&service, "enroll");

    let fixture = Fixture {
        tcti: &tcti,
        backend: &backend,
        service: &service,
        collection_path: &collection_path,
        data_home: data_home.path(),
        bus_address: keyring.address(),
    };

    // A fingerprint match is convenience: the PIN still unseals.
    fixture.run_scenario("match", "fingerprint verified", Duration::from_secs(5));

    // No match falls back to the PIN and still unlocks.
    fixture.run_scenario("no-match", "did not match", Duration::from_secs(5));

    // A stalled reader times out under the bounded deadline and falls back to the PIN.
    fixture.run_scenario("stall", "timed out", Duration::from_millis(500));

    // Keep swtpm alive until the last helper has finished using it.
    drop(swtpm);
}
