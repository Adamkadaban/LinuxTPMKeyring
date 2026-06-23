//! End-to-end `daemon-tests` suite against a real `gnome-keyring-daemon` on a private session bus.
//! The keyring-preservation invariant — rekey must keep every existing item decryptable — is the
//! load-bearing assertion. Throwaway keyrings only; the harness reaps every spawned process.

#![cfg(feature = "daemon-tests")]

mod common;

use std::collections::HashMap;

use common::GnomeKeyring;
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use tess_core::{KeyringBackend, SecretBytes};
use tess_keyring::SecretServiceBackend;
use tess_testenv::EnvGuard;

// `secret-service`'s client reads the bus address from `DBUS_SESSION_BUS_ADDRESS`, a process-global.
// Serialize the daemon tests so each owns the env for its whole body and they never see each other's
// private bus.

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

fn deterministic_new_key() -> SecretBytes {
    SecretBytes::new(
        (0u8..32)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect(),
    )
}

#[test]
fn rekey_preserves_items_and_lock_transitions() {
    let _env = tess_testenv::env_lock();

    let old = SecretBytes::new(b"old-keyring-password".to_vec());
    let Some(keyring) = GnomeKeyring::start(old.as_slice()) else {
        return;
    };
    let _bus = EnvGuard::set("DBUS_SESSION_BUS_ADDRESS", keyring.address());

    let service = SecretService::connect(EncryptionType::Dh).expect("connect Secret Service");
    let collection_path = login_collection_path(&service);
    let collection = service
        .get_all_collections()
        .expect("list collections")
        .into_iter()
        .find(|c| c.collection_path.as_str() == collection_path)
        .expect("login collection");

    let items = [
        ("alpha", b"secret-one".as_slice()),
        ("beta", b"secret-two".as_slice()),
        ("gamma", b"secret-three".as_slice()),
    ];
    for (label, secret) in items {
        let attributes = HashMap::from([("tess-test", label)]);
        collection
            .create_item(label, attributes, secret, true, "text/plain")
            .expect("store item");
    }

    let backend =
        SecretServiceBackend::connect_to(keyring.address(), &collection_path).expect("backend");

    assert!(
        !backend.is_locked().expect("is_locked after unlock"),
        "login keyring should start unlocked"
    );

    let new = deterministic_new_key();
    backend.rekey(&old, &new).expect("rekey old -> new");

    collection.lock().expect("lock collection");
    assert!(
        backend.is_locked().expect("is_locked after lock"),
        "keyring should be locked after Lock"
    );

    backend.unlock(&new).expect("unlock with new key");
    assert!(
        !backend.is_locked().expect("is_locked after unlock"),
        "keyring should be unlocked after unlock(new)"
    );

    for (label, expected) in items {
        let attributes = HashMap::from([("tess-test", label)]);
        let found = service.search_items(attributes).expect("search items");
        let item = found
            .unlocked
            .first()
            .unwrap_or_else(|| panic!("item {label} present and unlocked after rekey"));
        assert_eq!(
            item.get_secret().expect("decrypt item"),
            expected,
            "item {label} must survive the rekey intact"
        );
    }
}

#[test]
fn unlock_with_wrong_secret_fails() {
    let _env = tess_testenv::env_lock();

    let correct = SecretBytes::new(b"correct-keyring-password".to_vec());
    let Some(keyring) = GnomeKeyring::start(correct.as_slice()) else {
        return;
    };
    let _bus = EnvGuard::set("DBUS_SESSION_BUS_ADDRESS", keyring.address());

    let service = SecretService::connect(EncryptionType::Dh).expect("connect Secret Service");
    let collection_path = login_collection_path(&service);
    let collection = service
        .get_all_collections()
        .expect("list collections")
        .into_iter()
        .find(|c| c.collection_path.as_str() == collection_path)
        .expect("login collection");

    let backend =
        SecretServiceBackend::connect_to(keyring.address(), &collection_path).expect("backend");

    collection.lock().expect("lock collection");
    assert!(backend.is_locked().expect("is_locked after lock"));

    let wrong = SecretBytes::new(b"not-the-password".to_vec());
    // A wrong secret may be rejected (`Err`) or no-op, but it must never unlock — so the binding
    // assertion is that the collection is still locked, with `is_locked()` errors surfaced as test
    // failures rather than silently treated as "still locked".
    let _ = backend.unlock(&wrong);
    assert!(
        backend
            .is_locked()
            .expect("is_locked after wrong unlock attempt"),
        "a wrong secret must never unlock the keyring"
    );
}
