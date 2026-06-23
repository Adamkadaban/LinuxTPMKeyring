//! `sim` + `daemon-tests` end-to-end proof of the PAM session path: enroll against an isolated swtpm
//! and a throwaway `gnome-keyring-daemon`, lock the keyring, then run the real `tess-pam-helper`
//! binary with the PIN on its stdin — the same contract the PAM module relies on (the module uses a
//! `memfd`-backed stdin transfer; this test feeds stdin via a pipe, since the SIGPIPE hazard the
//! memfd avoids only applies inside the login process) — and assert it unseals the key and flips the
//! keyring to unlocked with every pre-existing item intact. Throwaway keyrings only; every spawned
//! process (swtpm, dbus, keyring, helper) is reaped on drop or at the end of the test.
#![cfg(all(feature = "sim", feature = "daemon-tests"))]

mod common;

use std::collections::HashMap;

use common::{GnomeKeyring, Swtpm, run_pam_helper};
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use tess_core::{KeyringBackend, SecretBytes};
use tess_keyring::SecretServiceBackend;

use tess_cli::enroll::sealer::TpmSealer;
use tess_cli::enroll::{Paths, enroll};
use tess_testenv::EnvGuard;

const OLD_PASSWORD: &[u8] = b"old-keyring-password";
const PIN: &[u8] = b"1234";
const ITEMS: [(&str, &[u8]); 3] = [
    ("alpha", b"secret-one"),
    ("beta", b"secret-two"),
    ("gamma", b"secret-three"),
];

// `secret-service`'s client reads the bus address from `DBUS_SESSION_BUS_ADDRESS`, a process-global.

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
            "item {label} must survive the session unlock"
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

#[test]
fn simulated_session_helper_unseals_and_unlocks_the_keyring() {
    let _lock = tess_testenv::env_lock();

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

    // The helper resolves its enrollment metadata from $XDG_DATA_HOME/tess; enroll into the same
    // place so the child finds it.
    let data_home = tempfile::tempdir().expect("temp data home");
    let tess_dir = data_home.path().join("tess");
    let paths = Paths {
        metadata: tess_dir.join("metadata.json"),
        recovery: tess_dir.join("recovery.json"),
        lockout_owned: tess_dir.join("lockout-owned"),
        metadata_face: tess_dir.join("metadata-face.json"),
        face_key: tess_dir.join("face-unlock.key"),
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
        enroll(
            &mut sealer,
            &backend,
            &paths,
            &old,
            &pin,
            &verify_item,
            None,
        )
        .expect("enroll");
    }
    assert!(
        !backend.is_locked().unwrap(),
        "keyring unlocked after enroll"
    );
    assert_items_intact(&service);

    // Lock the keyring so the helper's unlock is observable.
    lock_login(&service, &collection_path);
    assert!(
        backend.is_locked().unwrap(),
        "keyring locked before session"
    );

    let (ok, stderr) = run_pam_helper(&tcti, keyring.address(), data_home.path(), PIN);
    assert!(ok, "helper must succeed; stderr: {stderr}");

    assert!(
        !backend.is_locked().unwrap(),
        "the session helper must unlock the keyring"
    );
    assert_items_intact(&service);

    // Keep swtpm alive until the helper has finished using it.
    drop(swtpm);
}
