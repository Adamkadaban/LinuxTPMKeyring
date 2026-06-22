//! `sim` + `daemon-tests` enrollment suite: the real transaction against an isolated swtpm and a
//! throwaway `gnome-keyring-daemon`. Proves the happy path seals + rekeys + verifies, both unlock
//! paths (TPM-unseal and TPM-independent recovery) recover the same key, and — the load-bearing
//! safety assertion — a failure injected at each destructive step rolls back with all pre-existing
//! items intact and no sealed/recovery blobs left behind. Throwaway keyrings only; every process is
//! reaped on drop.
#![cfg(all(feature = "sim", feature = "daemon-tests"))]

mod common;

use std::cell::Cell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{anyhow, ensure};
use common::{GnomeKeyring, Swtpm};
use secret_service::blocking::SecretService;
use secret_service::EncryptionType;
use tess_core::{Error as CoreError, KeyringBackend, Result as CoreResult, SecretBytes};
use tess_keyring::SecretServiceBackend;
use tess_tpm::TctiConfig;

use tess_cli::enroll::sealer::{KeySealer, TpmSealer};
use tess_cli::enroll::{enroll, recovery, Paths};

const OLD_PASSWORD: &[u8] = b"old-keyring-password";
const PIN: &[u8] = b"1234";
const ITEMS: [(&str, &[u8]); 3] = [
    ("alpha", b"secret-one"),
    ("beta", b"secret-two"),
    ("gamma", b"secret-three"),
];

// `secret-service`'s client reads the bus address from `DBUS_SESSION_BUS_ADDRESS`, a process-global.
// Serialize the suite so each test owns the env for its whole body.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// A keyring backend wrapper that (a) records whether the recovery blob already existed the first
/// time a rekey is attempted — to prove ordering — and (b) can inject a rekey failure.
struct ObservingBackend {
    inner: SecretServiceBackend,
    rekey_fails: bool,
    recovery_path: PathBuf,
    recovery_present_at_first_rekey: Cell<Option<bool>>,
}

impl ObservingBackend {
    fn new(inner: SecretServiceBackend, recovery_path: PathBuf, rekey_fails: bool) -> Self {
        Self {
            inner,
            rekey_fails,
            recovery_path,
            recovery_present_at_first_rekey: Cell::new(None),
        }
    }
}

impl KeyringBackend for ObservingBackend {
    fn rekey(&self, old: &SecretBytes, new: &SecretBytes) -> CoreResult<()> {
        if self.recovery_present_at_first_rekey.get().is_none() {
            self.recovery_present_at_first_rekey
                .set(Some(self.recovery_path.exists()));
        }
        if self.rekey_fails {
            return Err(CoreError::Keyring("injected rekey failure".into()));
        }
        self.inner.rekey(old, new)
    }
    fn unlock(&self, secret: &SecretBytes) -> CoreResult<()> {
        self.inner.unlock(secret)
    }
    fn is_locked(&self) -> CoreResult<bool> {
        self.inner.is_locked()
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
    std::env::set_var("DBUS_SESSION_BUS_ADDRESS", keyring.address());
    let service = SecretService::connect(EncryptionType::Dh).expect("connect Secret Service");
    let collection_path = login_collection_path(&service);
    seed_items(&service, &collection_path);
    body(&service, keyring.address(), &collection_path, &tcti);
}

fn paths_in(dir: &std::path::Path) -> Paths {
    Paths {
        metadata: dir.join("metadata.json"),
        recovery: dir.join("recovery.json"),
    }
}

#[test]
fn happy_path_seals_rekeys_and_both_unlock_paths_recover_the_key() {
    with_fixture(|service, address, collection_path, tcti| {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        let backend = ObservingBackend::new(
            SecretServiceBackend::connect_to(address, collection_path).expect("backend"),
            paths.recovery.clone(),
            false,
        );
        let old = SecretBytes::new(OLD_PASSWORD.to_vec());
        let pin = SecretBytes::new(PIN.to_vec());

        let verify_item = || -> anyhow::Result<()> {
            let found = service
                .search_items(HashMap::from([("tess-test", "alpha")]))
                .map_err(|e| anyhow!("search alpha: {e}"))?;
            let item = found
                .unlocked
                .first()
                .ok_or_else(|| anyhow!("alpha missing"))?;
            ensure!(item.get_secret().map_err(|e| anyhow!("{e}"))? == b"secret-one");
            Ok(())
        };

        let outcome = enroll(&mut sealer, &backend, &paths, &old, &pin, &verify_item)
            .expect("enrollment succeeds");
        assert!(!outcome.recovery_secret_display.is_empty());
        assert!(paths.metadata.exists(), "sealed metadata persisted");
        assert!(paths.recovery.exists(), "recovery blob persisted");
        assert!(
            !backend.is_locked().unwrap(),
            "keyring unlocked after enroll"
        );
        assert_items_intact(service);

        // Unlock path 1: reload + TPM-unseal with the PIN recovers the key.
        let metadata = tess_tpm::persist::load(&paths.metadata).expect("load metadata");
        let sealed = tess_tpm::persist::from_metadata(&metadata).expect("from_metadata");
        let from_tpm = sealer.unseal(&sealed, &pin).expect("unseal with PIN");

        lock_login(service, collection_path);
        assert!(backend.is_locked().unwrap());
        backend.unlock(&from_tpm).expect("unlock with unsealed key");
        assert!(!backend.is_locked().unwrap());
        assert_items_intact(service);

        // Unlock path 2: the TPM-independent recovery secret recovers the SAME key.
        let secret = recovery::decode(&outcome.recovery_secret_display).expect("decode recovery");
        let blob = recovery::load_blob(&paths.recovery).expect("load recovery blob");
        let from_recovery = recovery::unwrap_key(&blob, &secret).expect("unwrap recovery");
        assert_eq!(
            from_recovery.as_slice(),
            from_tpm.as_slice(),
            "TPM and recovery paths must recover the same key"
        );

        lock_login(service, collection_path);
        backend
            .unlock(&from_recovery)
            .expect("unlock with recovery key");
        assert!(!backend.is_locked().unwrap());
        assert_items_intact(service);
    });
}

#[test]
fn rollback_on_rekey_failure_preserves_items_and_recovery_was_first() {
    with_fixture(|service, address, collection_path, tcti| {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        let backend = ObservingBackend::new(
            SecretServiceBackend::connect_to(address, collection_path).expect("backend"),
            paths.recovery.clone(),
            true, // inject a rekey failure
        );
        let old = SecretBytes::new(OLD_PASSWORD.to_vec());
        let pin = SecretBytes::new(PIN.to_vec());
        let verify_item = || Ok(());

        let err = enroll(&mut sealer, &backend, &paths, &old, &pin, &verify_item)
            .expect_err("rekey failure must fail enrollment");
        assert!(
            format!("{err:#}").contains("rekey"),
            "error mentions the rekey: {err:#}"
        );

        // Ordering: the recovery blob existed before the (failed) rekey was attempted.
        assert_eq!(
            backend.recovery_present_at_first_rekey.get(),
            Some(true),
            "recovery backup must be created and verified before the destructive rekey"
        );
        // No leftovers, original keyring intact.
        assert!(!paths.metadata.exists(), "no sealed metadata left behind");
        assert!(!paths.recovery.exists(), "no recovery blob left behind");
        assert!(
            !backend.is_locked().unwrap(),
            "original keyring still unlocked"
        );
        assert_items_intact(service);
    });
}

#[test]
fn rollback_on_verify_failure_restores_original_keyring() {
    with_fixture(|service, address, collection_path, tcti| {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths_in(dir.path());
        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        let backend = ObservingBackend::new(
            SecretServiceBackend::connect_to(address, collection_path).expect("backend"),
            paths.recovery.clone(),
            false,
        );
        let old = SecretBytes::new(OLD_PASSWORD.to_vec());
        let pin = SecretBytes::new(PIN.to_vec());
        // The rekey succeeds, then item verification fails — rollback must rekey back to old.
        let verify_item = || Err(anyhow!("injected item-verification failure"));

        let err = enroll(&mut sealer, &backend, &paths, &old, &pin, &verify_item)
            .expect_err("verify failure must fail enrollment");
        assert!(format!("{err:#}").contains("rolled back"), "{err:#}");

        assert!(
            !paths.metadata.exists(),
            "sealed metadata removed on rollback"
        );
        assert!(
            !paths.recovery.exists(),
            "recovery blob removed on rollback"
        );
        // The keyring is back on the ORIGINAL password and the items still decrypt.
        let backend_old = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        lock_login(service, collection_path);
        backend_old
            .unlock(&old)
            .expect("original password unlocks the restored keyring");
        assert!(!backend_old.is_locked().unwrap());
        assert_items_intact(service);
    });
}

#[test]
fn rollback_on_persist_failure_never_touches_the_keyring() {
    with_fixture(|service, address, collection_path, tcti| {
        let dir = tempfile::tempdir().unwrap();
        // Make the metadata path unwritable: its parent is a regular file, so persist::save fails.
        let block = dir.path().join("block");
        std::fs::write(&block, b"x").unwrap();
        let paths = Paths {
            metadata: block.join("metadata.json"),
            recovery: dir.path().join("recovery.json"),
        };
        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        let backend = ObservingBackend::new(
            SecretServiceBackend::connect_to(address, collection_path).expect("backend"),
            paths.recovery.clone(),
            false,
        );
        let old = SecretBytes::new(OLD_PASSWORD.to_vec());
        let pin = SecretBytes::new(PIN.to_vec());
        let verify_item = || Ok(());

        let err = enroll(&mut sealer, &backend, &paths, &old, &pin, &verify_item)
            .expect_err("persist failure must fail enrollment");
        assert!(format!("{err:#}").contains("metadata"), "{err:#}");

        // The destructive rekey was never reached, so the keyring is untouched and the recovery blob
        // written in the prior step is rolled back.
        assert_eq!(
            backend.recovery_present_at_first_rekey.get(),
            None,
            "rekey must never be attempted when persistence fails first"
        );
        assert!(
            !paths.recovery.exists(),
            "recovery blob removed on rollback"
        );
        assert!(!paths.metadata.exists(), "no sealed metadata");
        assert!(!backend.is_locked().unwrap(), "original keyring untouched");
        assert_items_intact(service);
    });
}
