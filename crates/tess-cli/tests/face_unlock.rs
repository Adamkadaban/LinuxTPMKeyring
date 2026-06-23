//! `sim` + `daemon-tests` face-unlock suite: the model-B face-or-PIN flow against an isolated swtpm,
//! a throwaway `gnome-keyring-daemon`, and the mug virtual IR substrate + model-free mock matcher.
//! Proves a `--face` enrollment seals the same key under an independent on-disk authValue and that a
//! liveness-gated face match releases the key with no PIN typed; that a failed face falls back to the
//! PIN; that `A_face` is independent of the PIN and recovery secret; that unenroll clears every face
//! artifact; and that pre-existing keyring items survive throughout. Throwaway keyrings only; every
//! process is reaped on drop.
#![cfg(all(feature = "sim", feature = "daemon-tests"))]

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use common::{GnomeKeyring, Swtpm};
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use tess_core::{KeyringBackend, SecretBytes};
use tess_keyring::SecretServiceBackend;
use tess_tpm::TctiConfig;

use mug::camera::VirtualIrDevice;
use mug::liveness::synth;
use tess_cli::enroll::sealer::{KeySealer, TpmSealer};
use tess_cli::enroll::{FaceEnroll, Paths, enroll, recovery};
use tess_cli::lifecycle::{unenroll, unlock, unlock_with_face};
use tess_testenv::EnvGuard;

const OLD_PASSWORD: &[u8] = b"old-keyring-password";
const NEW_PASSWORD: &[u8] = b"restored-keyring-password";
const PIN: &[u8] = b"1234";
const FACE_USER: &str = "tess-face-test";
const ITEMS: [(&str, &[u8]); 3] = [
    ("alpha", b"secret-one"),
    ("beta", b"secret-two"),
    ("gamma", b"secret-three"),
];

// `secret-service`, the mug store dir, the virtual IR dir, and `$USER` are all process-global, so
// serialize the suite and let each test own them for its whole body.
static ENV_LOCK: Mutex<()> = Mutex::new(());

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

/// Write a synthetic frame pair as the `ir_off.grey`/`ir_on.grey` the virtual device serves.
fn write_frames(dir: &Path, pair: &mug::FramePair) {
    std::fs::write(
        dir.join(VirtualIrDevice::OFF_FRAME),
        pair.emitter_off.as_bytes(),
    )
    .unwrap();
    std::fs::write(
        dir.join(VirtualIrDevice::ON_FRAME),
        pair.emitter_on.as_bytes(),
    )
    .unwrap();
}

/// Bring up swtpm + a throwaway keyring seeded with [`ITEMS`], set the mug substrate env (virtual IR
/// dir holding a live face, a throwaway store dir, and a fixed `$USER`), and run `body`. Skips
/// cleanly when swtpm or the keyring daemons are unavailable. The returned IR dir is the live-face
/// capture; tests repoint `MUG_VIRTUAL_IR_DIR` to inject a spoof.
fn with_face_fixture(
    body: impl FnOnce(&SecretService<'_>, &str, &str, &TctiConfig, &Paths, &Path),
) {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some((_swtpm, tcti)) = Swtpm::start() else {
        return;
    };
    let Some(keyring) = GnomeKeyring::start(OLD_PASSWORD) else {
        return;
    };
    let _env = EnvGuard::set("DBUS_SESSION_BUS_ADDRESS", keyring.address());

    let data = tempfile::tempdir().unwrap();
    let paths = paths_in(data.path());
    let ir_dir = tempfile::tempdir().unwrap();
    write_frames(ir_dir.path(), &synth::live_pair(340, 340));
    let store_dir = tempfile::tempdir().unwrap();

    let _ir = EnvGuard::set_path(VirtualIrDevice::ENV_DIR, ir_dir.path());
    let _store = EnvGuard::set_path("MUG_STORE_DIR", store_dir.path());
    let _user = EnvGuard::set("USER", FACE_USER);

    let service = SecretService::connect(EncryptionType::Dh).expect("connect Secret Service");
    let collection_path = login_collection_path(&service);
    seed_items(&service, &collection_path);
    body(
        &service,
        keyring.address(),
        &collection_path,
        &tcti,
        &paths,
        ir_dir.path(),
    );
}

fn paths_in(dir: &Path) -> Paths {
    Paths {
        metadata: dir.join("metadata.json"),
        recovery: dir.join("recovery.json"),
        lockout_owned: dir.join("lockout-owned"),
        metadata_face: dir.join("metadata-face.json"),
        face_key: dir.join("face-unlock.key"),
    }
}

/// Enroll with `--face` into the env-configured store, returning the recovery-secret display string.
fn enroll_with_face(
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

    let store = tess_cli::face::enroll_store().expect("store");
    let username = tess_cli::face::current_username().expect("username");
    let mut template = tess_cli::face::template_source_from_env().expect("template source");
    let face = FaceEnroll {
        username: &username,
        store: &store,
        template: template.as_mut(),
    };
    enroll(
        &mut sealer,
        &backend,
        paths,
        &old,
        &pin,
        &verify_item,
        Some(face),
    )
    .expect("enroll --face succeeds")
    .recovery_secret_display
}

#[test]
fn enroll_face_then_face_unlock_releases_key_without_pin() {
    with_face_fixture(|service, address, collection_path, tcti, paths, _ir| {
        enroll_with_face(tcti, address, collection_path, paths);
        assert!(paths.metadata_face.exists(), "face metadata persisted");
        assert!(paths.face_key.exists(), "face authValue persisted");
        assert_items_intact(service);

        // Face unlock: load the enrollment, run the bounded liveness-gated match, then unseal K via
        // the on-disk face authValue and unlock — no PIN involved.
        let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        lock_login(service, collection_path);
        assert!(backend.is_locked().unwrap());

        let enrollment = tess_cli::face::load_enrollment()
            .expect("load enrollment")
            .expect("face enrollment present");
        tess_cli::face::verify_from_env(&enrollment).expect("live face matches the enrollment");

        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        unlock_with_face(&mut sealer, &backend, paths).expect("face unlock releases the key");
        assert!(!backend.is_locked().unwrap(), "keyring unlocked via face");
        assert_items_intact(service);
    });
}

#[test]
fn failed_face_falls_back_to_the_pin() {
    with_face_fixture(|service, address, collection_path, tcti, paths, ir| {
        enroll_with_face(tcti, address, collection_path, paths);

        // Inject a self-emitting-screen spoof at the capture dir: liveness rejects it, so the face
        // gate fails and the caller must fall back to the PIN.
        write_frames(ir, &synth::screen_pair(340, 340));

        let enrollment = tess_cli::face::load_enrollment()
            .expect("load enrollment")
            .expect("face enrollment present");
        let face_result = tess_cli::face::verify_from_env(&enrollment);
        assert!(
            face_result.is_err(),
            "a screen spoof must fail the face gate, got {face_result:?}"
        );

        // Fallback: the PIN path still unlocks the keyring.
        let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        lock_login(service, collection_path);
        assert!(backend.is_locked().unwrap());
        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        let pin = SecretBytes::new(PIN.to_vec());
        unlock(&mut sealer, &backend, paths, &pin).expect("PIN fallback unlocks");
        assert!(
            !backend.is_locked().unwrap(),
            "keyring unlocked via PIN fallback"
        );
        assert_items_intact(service);
    });
}

#[test]
fn a_face_is_independent_of_pin_and_recovery_secret() {
    with_face_fixture(|_service, address, collection_path, tcti, paths, _ir| {
        let recovery_display = enroll_with_face(tcti, address, collection_path, paths);
        let recovery_secret = recovery::decode(&recovery_display).expect("decode recovery");

        let a_face = std::fs::read(&paths.face_key).expect("read face authValue");
        assert_ne!(a_face.as_slice(), PIN, "A_face must not equal the PIN");
        assert_ne!(
            a_face.as_slice(),
            recovery_secret.as_slice(),
            "A_face must not equal the recovery secret"
        );

        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");

        // The face-sealed object must NOT unseal with the PIN — only with A_face.
        let face_md = tess_tpm::persist::load(&paths.metadata_face).expect("load face metadata");
        let face_sealed = tess_tpm::persist::from_metadata(&face_md).expect("face from_metadata");
        assert!(
            sealer
                .unseal(&face_sealed, &SecretBytes::new(PIN.to_vec()))
                .is_err(),
            "the PIN must not unseal the face-sealed object"
        );
        let k_face = sealer
            .unseal(&face_sealed, &SecretBytes::new(a_face.clone()))
            .expect("A_face unseals the face object");

        // A_face recovers the SAME key the PIN object holds.
        let pin_md = tess_tpm::persist::load(&paths.metadata).expect("load PIN metadata");
        let pin_sealed = tess_tpm::persist::from_metadata(&pin_md).expect("pin from_metadata");
        let k_pin = sealer
            .unseal(&pin_sealed, &SecretBytes::new(PIN.to_vec()))
            .expect("PIN unseals the PIN object");
        assert_eq!(
            k_face.as_slice(),
            k_pin.as_slice(),
            "both sealed copies must recover the same keyring key"
        );
    });
}

#[test]
fn unenroll_clears_every_face_artifact_with_items_intact() {
    with_face_fixture(|service, address, collection_path, tcti, paths, _ir| {
        let recovery_display = enroll_with_face(tcti, address, collection_path, paths);
        let recovery_secret = recovery::decode(&recovery_display).expect("decode recovery");

        let store = tess_cli::face::enroll_store().expect("store");
        let username = tess_cli::face::current_username().expect("username");
        assert!(
            store.load(&username).unwrap().is_some(),
            "face enrolled in the mug store"
        );

        let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
        let pin = SecretBytes::new(PIN.to_vec());
        let new_password = SecretBytes::new(NEW_PASSWORD.to_vec());

        unenroll(
            &mut sealer,
            &backend,
            paths,
            &pin,
            &new_password,
            Some(&recovery_secret),
            Some((&username, &store)),
        )
        .expect("unenroll succeeds");

        assert!(!paths.metadata.exists(), "sealed metadata removed");
        assert!(!paths.recovery.exists(), "recovery blob removed");
        assert!(!paths.metadata_face.exists(), "face metadata removed");
        assert!(!paths.face_key.exists(), "face authValue removed");
        assert!(
            store.load(&username).unwrap().is_none(),
            "mug store entry removed"
        );

        // The keyring is back on the user password with every item intact.
        let restored = SecretServiceBackend::connect_to(address, collection_path).unwrap();
        lock_login(service, collection_path);
        restored
            .unlock(&new_password)
            .expect("restored password unlocks");
        assert!(!restored.is_locked().unwrap());
        assert_items_intact(service);
    });
}
