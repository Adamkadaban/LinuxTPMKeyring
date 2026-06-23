//! `sim` + `daemon-tests` lifecycle suite: the `unlock`, `recover`, `unenroll`, and `status` flows
//! against an isolated swtpm and a throwaway `gnome-keyring-daemon`. Proves a manual unlock
//! round-trips, recovery restores access after a simulated TPM clear (and re-seal restores the PIN
//! path), unenroll returns the keyring to a password with every pre-existing item intact, and status
//! reports the real enrollment / keyring / TPM state. Throwaway keyrings only; every process is
//! reaped on drop.
#![cfg(all(feature = "sim", feature = "daemon-tests"))]

mod common;

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Mutex;

use common::{GnomeKeyring, Swtpm};
use secret_service::blocking::SecretService;
use secret_service::EncryptionType;
use tess_core::{KeyringBackend, SecretBytes};
use tess_keyring::SecretServiceBackend;
use tess_tpm::TctiConfig;

use tess_cli::enroll::sealer::{KeySealer, TpmSealer};
use tess_cli::enroll::{enroll, Paths};
use tess_cli::lifecycle::{gather_status, recover, reseal, unenroll, unlock};

const OLD_PASSWORD: &[u8] = b"old-keyring-password";
const NEW_PASSWORD: &[u8] = b"restored-keyring-password";
const PIN: &[u8] = b"1234";
const NEW_PIN: &[u8] = b"5678";
const ITEMS: [(&str, &[u8]); 3] = [
    ("alpha", b"secret-one"),
    ("beta", b"secret-two"),
    ("gamma", b"secret-three"),
];

// `secret-service`'s client reads the bus address from `DBUS_SESSION_BUS_ADDRESS`, a process-global.
// Serialize the suite so each test owns the env for its whole body.
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

fn assert_items_intact(service: &SecretService<'_>) {
    for (label, expected) in ITEMS {
        let attributes = HashMap::from([("tess-test", label)]);
        let found = service.search_items(attributes).expect("search items");
        let item = found
            .unlocked
            .first()
            .unwrap_or_else(|| panic!("item {label} present and unlocked"));
        assert_eq!(
            item.get_secret().expect("decrypt item"),
            expected,
            "item {label} must survive intact"
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

/// Hold the env lock, bring up swtpm + a throwaway keyring seeded with [`ITEMS`], and run `body`.
/// Skips cleanly (no panic) when swtpm or the keyring daemons are unavailable.
fn with_fixture(body: impl FnOnce(&SecretService<'_>, &str, &str, &TctiConfig)) {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some((_swtpm, tcti)) = Swtpm::start() else {
        return;
    };
    let Some(keyring) = GnomeKeyring::start(OLD_PASSWORD) else {
        return;
    };
    let _env = EnvGuard::set("DBUS_SESSION_BUS_ADDRESS", keyring.address());
    let service = SecretService::connect(EncryptionType::Dh).expect("connect Secret Service");
    let collection_path = login_collection_path(&service);
    seed_items(&service, &collection_path);
    body(&service, keyring.address(), &collection_path, &tcti);
}

fn paths_in(dir: &std::path::Path) -> Paths {
    Paths {
        metadata: dir.join("metadata.json"),
        recovery: dir.join("recovery.json"),
        lockout_owned: dir.join("lockout-owned"),
    }
}

/// Enroll once and return the recovery secret display string. Leaves the keyring sealed to `PIN`.
fn enroll_fixture(
    tcti: &TctiConfig,
    address: &str,
    collection_path: &str,
    paths: &Paths,
) -> String {
    let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
    let backend = SecretServiceBackend::connect_to(address, collection_path).expect("backend");
    let old = SecretBytes::new(OLD_PASSWORD.to_vec());
    let pin = SecretBytes::new(PIN.to_vec());
    let verify_item = || Ok(());
    enroll(&mut sealer, &backend, paths, &old, &pin, &verify_item)
        .expect("enrollment succeeds")
        .recovery_secret_display
}

#[test]
fn unlock_round_trips_with_the_pin() {
    with_fixture(|service, address, collection_path, tcti| {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        enroll_fixture(tcti, address, collection_path, &paths);

        let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        lock_login(service, collection_path);
        assert!(backend.is_locked().unwrap());

        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        let pin = SecretBytes::new(PIN.to_vec());
        unlock(&mut sealer, &backend, &paths, &pin).expect("unlock round-trips");

        assert!(
            !backend.is_locked().unwrap(),
            "keyring unlocked after unlock"
        );
        assert_items_intact(service);
    });
}

#[test]
fn recover_restores_access_after_simulated_tpm_clear() {
    with_fixture(|service, address, collection_path, tcti| {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let recovery_display = enroll_fixture(tcti, address, collection_path, &paths);
        let recovery_secret =
            tess_cli::enroll::recovery::decode(&recovery_display).expect("decode recovery secret");

        // Simulate a TPM clear: the sealed metadata is now useless, so drop it. The keyring
        // credential is still the random key, recoverable only via the recovery secret.
        std::fs::remove_file(&paths.metadata).expect("drop sealed metadata");
        assert!(paths.recovery.exists(), "recovery blob survives the clear");

        let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        lock_login(service, collection_path);
        assert!(backend.is_locked().unwrap());

        recover(&backend, &paths, &recovery_secret).expect("recover restores access");
        assert!(
            !backend.is_locked().unwrap(),
            "keyring unlocked after recover"
        );
        assert_items_intact(service);

        // Re-seal under a new PIN against the (fresh) TPM, then prove the normal PIN path works.
        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        let new_pin = SecretBytes::new(NEW_PIN.to_vec());
        reseal(&mut sealer, &paths, &recovery_secret, &new_pin).expect("re-seal under new PIN");
        assert!(paths.metadata.exists(), "metadata rewritten by re-seal");

        lock_login(service, collection_path);
        assert!(backend.is_locked().unwrap());
        unlock(&mut sealer, &backend, &paths, &new_pin).expect("unlock with the re-sealed PIN");
        assert!(!backend.is_locked().unwrap());
        assert_items_intact(service);
    });
}

#[test]
fn unenroll_restores_password_keyring_with_items_intact() {
    with_fixture(|service, address, collection_path, tcti| {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let recovery_display = enroll_fixture(tcti, address, collection_path, &paths);
        let recovery_secret =
            tess_cli::enroll::recovery::decode(&recovery_display).expect("decode recovery secret");

        let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        let pin = SecretBytes::new(PIN.to_vec());
        let new_password = SecretBytes::new(NEW_PASSWORD.to_vec());

        // Enroll bound the TPM lockout hierarchy to the recovery secret.
        assert!(
            sealer
                .lockout_auth_is_set()
                .expect("read lockout-auth state"),
            "enroll must set a non-empty lockout authValue"
        );

        unenroll(
            &mut sealer,
            &backend,
            &paths,
            &pin,
            &new_password,
            Some(&recovery_secret),
        )
        .expect("unenroll succeeds");

        assert!(!paths.metadata.exists(), "sealed metadata removed");
        assert!(!paths.recovery.exists(), "recovery blob removed");
        assert!(
            !sealer
                .lockout_auth_is_set()
                .expect("read lockout-auth state"),
            "unenroll must restore the lockout authValue to empty"
        );

        // The keyring is back on the user password, every item still decrypts.
        let restored = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        lock_login(service, collection_path);
        restored
            .unlock(&new_password)
            .expect("restored password unlocks the keyring");
        assert!(!restored.is_locked().unwrap());
        assert_items_intact(service);

        // The old TPM-sealed key is no longer the credential.
        lock_login(service, collection_path);
        assert!(
            restored
                .unlock(&SecretBytes::new(OLD_PASSWORD.to_vec()))
                .is_err()
                || restored.is_locked().unwrap(),
            "the pre-enroll password is not the restored credential"
        );
    });
}

#[test]
fn status_reports_enrollment_keyring_and_tpm() {
    with_fixture(|service, address, collection_path, tcti| {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());

        // Before enrollment: not enrolled, no recovery blob, TPM reachable via swtpm.
        let before = gather_status(&paths, Some(Ok(false)), tcti);
        assert!(!before.metadata_present, "not enrolled before enroll");
        assert!(!before.recovery_present);
        assert!(before.tpm.is_ok(), "swtpm reachable: {:?}", before.tpm);

        enroll_fixture(tcti, address, collection_path, &paths);

        let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        let locked = Some(backend.is_locked().map_err(|e| e.to_string()));
        let after = gather_status(&paths, locked, tcti);
        assert!(after.metadata_present, "enrolled after enroll");
        assert!(after.recovery_present, "recovery blob present after enroll");
        assert_eq!(
            after.keyring_locked,
            Some(Ok(false)),
            "keyring unlocked right after enroll"
        );
        let tpm = after.tpm.expect("swtpm reachable");
        assert!(!tpm.lockout.is_locked_out(), "swtpm not locked out");
        assert_items_intact(service);

        lock_login(service, collection_path);
        let locked = Some(backend.is_locked().map_err(|e| e.to_string()));
        let when_locked = gather_status(&paths, locked, tcti);
        assert_eq!(when_locked.keyring_locked, Some(Ok(true)), "reports locked");
    });
}
