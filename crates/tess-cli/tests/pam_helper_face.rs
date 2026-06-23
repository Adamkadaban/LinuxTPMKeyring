//! `sim` + `daemon-tests` end-to-end proof of the face release path in the PAM session helper.
//!
//! Enroll with `--face` against an isolated swtpm, a throwaway `gnome-keyring-daemon`, and the mug
//! virtual IR substrate + model-free mock matcher, then drive the real `tess-pam-helper` binary with
//! `--face` exactly as the PAM module does. Three scenarios prove the precedence **face (model-B,
//! releases the key with no password) → PIN (the real gate) → password fallthrough**:
//!
//! * a live, matching face unlocks the keyring with an **empty** stdin (no password typed);
//! * a screen-spoof face fails liveness, so the helper falls back to the PIN on stdin and still
//!   unlocks;
//! * `--face` with no face enrollment is unchanged PIN-only behaviour.
//!
//! In every case the keyring ends unlocked with every pre-existing item intact. Throwaway keyrings
//! only; every spawned process (swtpm, dbus, keyring, helper) is reaped on drop or at end of test.
#![cfg(all(feature = "sim", feature = "daemon-tests"))]

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use common::{GnomeKeyring, Swtpm, run_pam_helper_face};
use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use tess_core::{KeyringBackend, SecretBytes};
use tess_keyring::SecretServiceBackend;
use tess_tpm::TctiConfig;

use mug::camera::VirtualIrDevice;
use mug::liveness::synth;
use tess_cli::enroll::sealer::TpmSealer;
use tess_cli::enroll::{FaceEnroll, Paths, enroll};
use tess_testenv::EnvGuard;

const OLD_PASSWORD: &[u8] = b"old-keyring-password";
const PIN: &[u8] = b"1234";
const FACE_USER: &str = "tess-face-test";
const ITEMS: [(&str, &[u8]); 3] = [
    ("alpha", b"secret-one"),
    ("beta", b"secret-two"),
    ("gamma", b"secret-three"),
];

// `secret-service`, the mug store dir, the virtual IR dir, and `$USER` are all process-global, and
// the spawned helper inherits them — so serialize the suite and let each test own them.
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

/// Paths under `$XDG_DATA_HOME/tess`, matching what the helper's `Paths::for_user()` resolves from
/// the `XDG_DATA_HOME` the harness sets for the child.
fn paths_in(data_home: &Path) -> Paths {
    let dir = data_home.join("tess");
    Paths {
        metadata: dir.join("metadata.json"),
        recovery: dir.join("recovery.json"),
        lockout_owned: dir.join("lockout-owned"),
        metadata_face: dir.join("metadata-face.json"),
        face_key: dir.join("face-unlock.key"),
    }
}

/// The shared fixture: swtpm + a throwaway keyring seeded with [`ITEMS`], the mug substrate env (a
/// live-face virtual IR dir, a throwaway store dir, and a fixed `$USER`), and `XDG_DATA_HOME` for the
/// helper. The closure receives the bus address, the data-home path (the helper reads
/// `$XDG_DATA_HOME/tess`), the swtpm transport, the enrollment paths, and the live IR dir (tests
/// repoint it to inject a spoof). Skips cleanly when swtpm or the daemons are unavailable.
fn with_face_fixture(
    body: impl FnOnce(&SecretService<'_>, &str, &str, &Path, &TctiConfig, &Paths, &Path),
) {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some((swtpm, tcti)) = Swtpm::start() else {
        return;
    };
    let Some(keyring) = GnomeKeyring::start(OLD_PASSWORD) else {
        return;
    };
    let _env = EnvGuard::set("DBUS_SESSION_BUS_ADDRESS", keyring.address());

    let data_home = tempfile::tempdir().unwrap();
    let paths = paths_in(data_home.path());
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
        data_home.path(),
        &tcti,
        &paths,
        ir_dir.path(),
    );

    // Keep swtpm alive until the helper has finished using it.
    drop(swtpm);
}

/// Enroll the PIN factor, optionally with `--face`, into the env-configured store/paths. The sealer's
/// TPM context is dropped before returning so the single-client swtpm is free for the helper.
fn do_enroll(
    tcti: &TctiConfig,
    address: &str,
    collection_path: &str,
    paths: &Paths,
    with_face: bool,
) {
    let mut sealer = TpmSealer::open(tcti).expect("open swtpm sealer");
    let backend = SecretServiceBackend::connect_to(address, collection_path).expect("backend");
    let old = SecretBytes::new(OLD_PASSWORD.to_vec());
    let pin = SecretBytes::new(PIN.to_vec());
    let verify_item = || Ok(());

    if with_face {
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
        .expect("enroll --face succeeds");
    } else {
        enroll(&mut sealer, &backend, paths, &old, &pin, &verify_item, None)
            .expect("enroll succeeds");
    }
}

#[test]
fn face_match_unlocks_the_keyring_with_no_password_typed() {
    with_face_fixture(
        |service, address, collection_path, data_home, tcti, paths, _ir| {
            do_enroll(tcti, address, collection_path, paths, true);
            assert!(paths.metadata_face.exists(), "face metadata persisted");
            assert!(paths.face_key.exists(), "face authValue persisted");
            assert_items_intact(service);

            let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
            lock_login(service, collection_path);
            assert!(
                backend.is_locked().unwrap(),
                "keyring locked before session"
            );

            // Empty stdin: no password is typed. Only the face release path can unlock here — the PIN
            // path would read an empty PIN and fail — so a success proves the keyring opened via the
            // face authValue.
            let (ok, stderr) = run_pam_helper_face(tcti, address, data_home, b"");
            assert!(ok, "face must unlock with no password; stderr: {stderr}");
            assert!(
                stderr.contains("keyring unlocked via the face authValue"),
                "expected a face-unlock log line, got: {stderr}"
            );
            assert!(
                !backend.is_locked().unwrap(),
                "the face release path must unlock the keyring"
            );
            assert_items_intact(service);
        },
    );
}

#[test]
fn spoofed_face_falls_back_to_the_pin_and_still_unlocks() {
    with_face_fixture(
        |service, address, collection_path, data_home, tcti, paths, ir| {
            do_enroll(tcti, address, collection_path, paths, true);

            // Inject a self-emitting-screen spoof: liveness rejects it, so the face gate fails and the
            // helper must fall back to the PIN supplied on stdin.
            write_frames(ir, &synth::screen_pair(340, 340));

            let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
            lock_login(service, collection_path);
            assert!(
                backend.is_locked().unwrap(),
                "keyring locked before session"
            );

            let (ok, stderr) = run_pam_helper_face(tcti, address, data_home, PIN);
            assert!(
                ok,
                "PIN fallback must unlock after a spoof; stderr: {stderr}"
            );
            assert!(
                stderr.contains("face unavailable"),
                "expected a face-fallback log line, got: {stderr}"
            );
            assert!(
                !backend.is_locked().unwrap(),
                "the PIN fallback must unlock the keyring"
            );
            assert_items_intact(service);
        },
    );
}

#[test]
fn face_flag_without_enrollment_is_pin_only() {
    with_face_fixture(
        |service, address, collection_path, data_home, tcti, paths, _ir| {
            // Enroll the PIN factor only — no face artifacts on disk.
            do_enroll(tcti, address, collection_path, paths, false);
            assert!(!paths.metadata_face.exists(), "no face metadata");
            assert!(!paths.face_key.exists(), "no face authValue");

            let backend = SecretServiceBackend::connect_to(address, collection_path).unwrap();
            lock_login(service, collection_path);
            assert!(
                backend.is_locked().unwrap(),
                "keyring locked before session"
            );

            // `--face` is set but nothing is enrolled: the helper reports the fallback and unlocks via
            // the PIN, unchanged from PIN-only behaviour.
            let (ok, stderr) = run_pam_helper_face(tcti, address, data_home, PIN);
            assert!(
                ok,
                "PIN path must unlock when face is not enrolled; stderr: {stderr}"
            );
            assert!(
                stderr.contains("face not enrolled"),
                "expected a not-enrolled log line, got: {stderr}"
            );
            assert!(
                !backend.is_locked().unwrap(),
                "the PIN path must unlock the keyring"
            );
            assert_items_intact(service);
        },
    );
}
