//! `sim` + `daemon-tests` Phase 3 exit gate: ONE cross-cutting end-to-end run of the whole
//! enrollment lifecycle on a single throwaway keyring seeded with N pre-existing secrets. It chains
//! every Phase 3 surface in order on the same keyring —
//!
//! 1. `enroll` (seal under the PIN + in-place rekey) → the keyring is unlocked by the TPM-sealed key;
//! 2. a simulated fresh login session driving the real `tess-pam-helper` binary (PIN on stdin, the
//!    same contract the PAM module uses) → the keyring unlocks with no password;
//! 3. `recover` after a simulated TPM clear (the sealed metadata is dropped) via the saved recovery
//!    secret, then `reseal` under a new PIN re-establishing the session path;
//! 4. `unenroll` back to a user password → stock password-based keyring restored —
//!
//! asserting the project's #1 safety property (all N pre-existing secrets survive, intact and
//! decryptable) at every transition. swtpm + a private-bus `gnome-keyring-daemon` come from
//! `tests/common`; every spawned process (swtpm, dbus-daemon, keyring, helper) is reaped on drop or
//! at the end of the test, under bounded waits. Throwaway keyrings only — never the host keyring.
#![cfg(all(feature = "sim", feature = "daemon-tests"))]

mod common;

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Mutex;

use common::{run_pam_helper, GnomeKeyring, Swtpm};
use secret_service::blocking::SecretService;
use secret_service::EncryptionType;
use tess_core::{KeyringBackend, SecretBytes};
use tess_keyring::SecretServiceBackend;

use tess_cli::enroll::sealer::TpmSealer;
use tess_cli::enroll::{enroll, recovery, Paths};
use tess_cli::lifecycle::{recover, reseal, unenroll};

const OLD_PASSWORD: &[u8] = b"old-keyring-password";
const RESTORED_PASSWORD: &[u8] = b"restored-keyring-password";
const PIN: &[u8] = b"1234";
const NEW_PIN: &[u8] = b"5678";

/// Common Secret Service attribute grouping every seeded item, used to count the whole set so the
/// invariant catches a *lost or duplicated* item, not just a changed one.
const GROUP_ATTR: (&str, &str) = ("application", "tess-phase3-e2e");

/// N ≥ 3 pre-existing secrets. Five exercises the preservation invariant well past the minimum.
const ITEMS: [(&str, &[u8]); 5] = [
    ("alpha", b"secret-one"),
    ("beta", b"secret-two"),
    ("gamma", b"secret-three"),
    ("delta", b"secret-four"),
    ("epsilon", b"secret-five"),
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

fn item_attributes(label: &str) -> HashMap<&str, &str> {
    HashMap::from([GROUP_ATTR, ("label", label)])
}

fn seed_items(service: &SecretService<'_>, collection_path: &str) {
    let collection = service
        .get_all_collections()
        .expect("list collections")
        .into_iter()
        .find(|c| c.collection_path.as_str() == collection_path)
        .expect("login collection");
    for (label, secret) in ITEMS {
        collection
            .create_item(label, item_attributes(label), secret, true, "text/plain")
            .expect("store item");
    }
}

/// Assert every one of the N seeded secrets is present, unlocked, and decrypts to its original value,
/// and that the group holds exactly N items — so neither loss nor duplication slips past. Run only
/// when the keyring is unlocked (locked items are not returned in `unlocked`). `step` names the
/// lifecycle transition just completed, for a legible failure message.
fn assert_items_intact(service: &SecretService<'_>, step: &str) {
    for (label, expected) in ITEMS {
        let found = service
            .search_items(item_attributes(label))
            .expect("search items");
        let item = found
            .unlocked
            .first()
            .unwrap_or_else(|| panic!("[{step}] item {label} present and unlocked"));
        assert_eq!(
            item.get_secret().expect("decrypt item"),
            expected,
            "[{step}] item {label} must survive intact"
        );
    }
    let group = service
        .search_items(HashMap::from([GROUP_ATTR]))
        .expect("search group");
    assert_eq!(
        group.unlocked.len(),
        ITEMS.len(),
        "[{step}] exactly {} pre-existing secrets must survive, none lost or duplicated",
        ITEMS.len()
    );
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

/// The whole Phase 3 lifecycle, end to end, on one keyring seeded with N pre-existing secrets:
/// enroll → simulated session (real helper) → recover (after a simulated TPM clear) → reseal →
/// unenroll, asserting all N secrets survive at every step. Skips cleanly when swtpm or the keyring
/// daemons are unavailable.
#[test]
fn full_phase3_cycle_preserves_all_items() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some((swtpm, tcti)) = Swtpm::start() else {
        return;
    };
    let Some(keyring) = GnomeKeyring::start(OLD_PASSWORD) else {
        return;
    };
    let address = keyring.address().to_string();
    let _env = EnvGuard::set("DBUS_SESSION_BUS_ADDRESS", &address);

    let service = SecretService::connect(EncryptionType::Dh).expect("connect Secret Service");
    let collection_path = login_collection_path(&service);
    seed_items(&service, &collection_path);

    // The helper resolves its enrollment metadata from `$XDG_DATA_HOME/tess`; enroll into the same
    // place so the simulated-login child finds it.
    let data_home = tempfile::tempdir().expect("temp data home");
    let tess_dir = data_home.path().join("tess");
    let paths = Paths {
        metadata: tess_dir.join("metadata.json"),
        recovery: tess_dir.join("recovery.json"),
    };

    let backend =
        SecretServiceBackend::connect_to(&address, &collection_path).expect("connect backend");
    let old = SecretBytes::new(OLD_PASSWORD.to_vec());
    let pin = SecretBytes::new(PIN.to_vec());
    let new_pin = SecretBytes::new(NEW_PIN.to_vec());
    let restored_password = SecretBytes::new(RESTORED_PASSWORD.to_vec());

    // -- Step 1: enroll (seal + in-place rekey). ------------------------------------------------
    let recovery_display = {
        // Scope the sealer so its TPM context is closed before the helper opens its own against the
        // single-client swtpm.
        let mut sealer = TpmSealer::open(&tcti).expect("open swtpm sealer");
        let verify_item = || Ok(());
        enroll(&mut sealer, &backend, &paths, &old, &pin, &verify_item)
            .expect("enrollment succeeds")
            .recovery_secret_display
    };
    let recovery_secret = recovery::decode(&recovery_display).expect("decode recovery secret");
    assert!(paths.metadata.exists(), "sealed metadata persisted");
    assert!(paths.recovery.exists(), "recovery blob persisted");
    assert!(
        !backend.is_locked().expect("read lock state"),
        "keyring unlocked by the TPM-sealed key after enroll"
    );
    assert_items_intact(&service, "enroll");

    // The pre-enroll password is no longer the credential: the keyring is sealed to the TPM key.
    // Attempt the unlock and assert it did NOT open — the security invariant is "still locked",
    // which catches a broken `unlock` that returns `Ok` while actually opening with the wrong key.
    // (gnome-keyring returns `Ok` from `unlock_with_master_password` even for a wrong password,
    // leaving the collection locked, so requiring an `Err` here would be incorrect for this backend.)
    lock_login(&service, &collection_path);
    let _ = backend.unlock(&old);
    assert!(
        backend.is_locked().expect("read lock state"),
        "the pre-enroll password must not unlock the enrolled keyring"
    );

    // -- Step 2: simulated fresh login session via the real tess-pam-helper. ---------------------
    assert!(
        backend.is_locked().expect("read lock state"),
        "keyring locked before the session unlock"
    );
    let (ok, stderr) = run_pam_helper(&tcti, &address, data_home.path(), PIN);
    assert!(
        ok,
        "session helper must unseal and unlock; stderr: {stderr}"
    );
    assert!(
        !backend.is_locked().expect("read lock state"),
        "the session helper unlocks the keyring with the PIN-derived TPM key, no password"
    );
    assert_items_intact(&service, "session");

    // -- Step 3: recover after a simulated TPM clear, then reseal under a new PIN. ----------------
    // Simulate a TPM clear by dropping the sealed metadata: the keyring credential is still the
    // random key, recoverable only via the TPM-independent recovery secret.
    std::fs::remove_file(&paths.metadata).expect("drop sealed metadata to simulate TPM clear");
    assert!(
        paths.recovery.exists(),
        "recovery blob survives the simulated clear"
    );
    lock_login(&service, &collection_path);
    assert!(backend.is_locked().expect("read lock state"));

    recover(&backend, &paths, &recovery_secret).expect("recover restores access");
    assert!(
        !backend.is_locked().expect("read lock state"),
        "keyring unlocked via the recovery secret after the simulated clear"
    );
    assert_items_intact(&service, "recover");

    // Re-establish the session path: seal the recovered key under a new PIN against the fresh TPM,
    // then prove the real helper unlocks with that new PIN (no password).
    {
        let mut sealer = TpmSealer::open(&tcti).expect("reopen swtpm sealer");
        reseal(&mut sealer, &paths, &recovery_secret, &new_pin).expect("reseal under the new PIN");
    }
    assert!(paths.metadata.exists(), "metadata rewritten by reseal");
    lock_login(&service, &collection_path);
    assert!(backend.is_locked().expect("read lock state"));
    let (ok, stderr) = run_pam_helper(&tcti, &address, data_home.path(), NEW_PIN);
    assert!(
        ok,
        "session helper must unlock with the re-sealed PIN; stderr: {stderr}"
    );
    assert!(
        !backend.is_locked().expect("read lock state"),
        "the re-sealed PIN drives the session unlock after recovery"
    );
    assert_items_intact(&service, "reseal-session");

    // -- Step 4: unenroll back to a stock password keyring. --------------------------------------
    {
        let mut sealer = TpmSealer::open(&tcti).expect("reopen swtpm sealer");
        unenroll(&mut sealer, &backend, &paths, &new_pin, &restored_password)
            .expect("unenroll succeeds");
    }
    assert!(
        !paths.metadata.exists(),
        "sealed metadata removed by unenroll"
    );
    assert!(
        !paths.recovery.exists(),
        "recovery blob removed by unenroll"
    );

    // The keyring is back on the user-supplied password, every item still decrypts.
    let restored =
        SecretServiceBackend::connect_to(&address, &collection_path).expect("reconnect backend");
    lock_login(&service, &collection_path);
    restored
        .unlock(&restored_password)
        .expect("restored password unlocks the keyring");
    assert!(
        !restored.is_locked().expect("read lock state"),
        "keyring back to a password credential after unenroll"
    );
    assert_items_intact(&service, "unenroll");

    // The old TPM-sealed key path is gone: the pre-enroll password cannot re-establish access (the
    // recovery blob is removed, so there is nothing to unseal). Assert the keyring stays locked after
    // the attempt rather than only that it errored — the same still-locked invariant as above.
    lock_login(&service, &collection_path);
    let _ = restored.unlock(&old);
    assert!(
        restored.is_locked().expect("read lock state"),
        "the pre-enroll password is not the restored credential"
    );

    // Keep swtpm alive until every TPM consumer above has finished using it.
    drop(swtpm);
}
