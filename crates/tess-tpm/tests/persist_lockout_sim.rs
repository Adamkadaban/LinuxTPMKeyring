//! `sim`-gated integration tests for Phase 1 persistence and DA-lockout handling: persist a sealed
//! object to disk and reload it back into a freshly re-derived primary to unseal the original key;
//! observe the dictionary-attack counter climb on wrong PINs; and confirm a hard lockout surfaces a
//! distinct error. Off by default; run with `cargo test -p tess-tpm --features sim`.
#![cfg(feature = "sim")]

mod common;

use common::Swtpm;
use tess_core::SecretBytes;
use tess_tpm::{
    create_primary, from_metadata, generate_sealing_key, load, read_lockout_state, reset_lockout,
    save, seal, to_metadata, unseal, Error,
};

/// A unique temp directory for one test's metadata file, removed when the returned guard drops.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tess-persist-sim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn persist_reload_unseal_round_trips_key() {
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    let mut context = cfg.open_context().expect("open ESAPI context");
    let primary = create_primary(&mut context).expect("create primary");

    let key = generate_sealing_key(&mut context).expect("generate sealing key");
    let pin = SecretBytes::new(b"1234".to_vec());
    let sealed = seal(&mut context, primary.key_handle, &pin, &key).expect("seal");

    // Persist to disk as versioned metadata, then read it back.
    let metadata = to_metadata(&sealed).expect("to_metadata");
    let tmp = TempDir::new("roundtrip");
    let path = tmp.path("metadata.json");
    save(&metadata, &path).expect("save");
    let loaded = load(&path).expect("load");
    let reloaded = from_metadata(&loaded).expect("from_metadata");

    // Simulate a reboot: drop the original primary handle and re-derive the deterministic primary,
    // proving the persisted blob is not bound to a transient handle, only to this TPM + PIN.
    context
        .flush_context(primary.key_handle.into())
        .expect("flush original primary");
    let primary = create_primary(&mut context).expect("re-derive primary");

    let recovered =
        unseal(&mut context, primary.key_handle, &reloaded, &pin).expect("unseal reloaded object");
    assert_eq!(
        recovered.as_slice(),
        key.as_slice(),
        "reloaded sealed object must unseal to the original key"
    );

    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}

#[test]
fn wrong_pin_increments_counter_and_pin_holder_recovers() {
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    let mut context = cfg.open_context().expect("open ESAPI context");
    let primary = create_primary(&mut context).expect("create primary");

    let key = generate_sealing_key(&mut context).expect("generate sealing key");
    let pin = SecretBytes::new(b"1234".to_vec());
    let wrong = SecretBytes::new(b"0000".to_vec());
    let sealed = seal(&mut context, primary.key_handle, &pin, &key).expect("seal");

    let before = read_lockout_state(&mut context).expect("read lockout state");

    // A single wrong PIN must register as a wrong PIN and tick the DA counter up.
    let err = unseal(&mut context, primary.key_handle, &sealed, &wrong)
        .expect_err("wrong PIN must not unseal");
    assert!(
        matches!(err, Error::WrongPin),
        "wrong PIN must map to Error::WrongPin, got {err:?}"
    );

    if before.max_auth_fail == 0 {
        eprintln!("DA lockout disabled on this TPM (max_auth_fail=0); skipping counter assertion");
    } else {
        let after = read_lockout_state(&mut context).expect("read lockout state");
        assert_eq!(
            after.counter,
            before.counter + 1,
            "a wrong PIN must increment the DA lockout counter"
        );
        assert!(
            !after.is_locked_out(),
            "one wrong PIN must not hard-lock a TPM whose max_auth_fail > 1"
        );
    }

    // Below hard lockout the legitimate PIN holder still authorizes (and the object still yields the
    // original key on a normal unseal).
    reset_lockout(&mut context, primary.key_handle, &sealed, &pin)
        .expect("PIN holder authorizes below hard lockout");
    let recovered =
        unseal(&mut context, primary.key_handle, &sealed, &pin).expect("correct PIN still unseals");
    assert_eq!(recovered.as_slice(), key.as_slice());

    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}

#[test]
fn hard_lockout_surfaces_distinct_error() {
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    let mut context = cfg.open_context().expect("open ESAPI context");
    let primary = create_primary(&mut context).expect("create primary");

    let key = generate_sealing_key(&mut context).expect("generate sealing key");
    let pin = SecretBytes::new(b"1234".to_vec());
    let wrong = SecretBytes::new(b"0000".to_vec());
    let sealed = seal(&mut context, primary.key_handle, &pin, &key).expect("seal");

    let initial = read_lockout_state(&mut context).expect("read lockout state");
    if initial.max_auth_fail == 0 {
        eprintln!("DA lockout disabled on this TPM (max_auth_fail=0); skipping hard-lockout test");
        context
            .flush_context(primary.key_handle.into())
            .expect("flush primary");
        return;
    }

    // Hammer wrong PINs until the TPM stops reporting "wrong PIN" and instead reports lockout. The
    // cap is defensive so a misbehaving TPM can't spin this loop forever.
    let cap = initial.max_auth_fail + 5;
    let mut saw_wrong_pin = false;
    let mut saw_lockout = false;
    for _ in 0..cap {
        match unseal(&mut context, primary.key_handle, &sealed, &wrong) {
            Err(Error::WrongPin) => saw_wrong_pin = true,
            Err(Error::Lockout) => {
                saw_lockout = true;
                break;
            }
            other => panic!("unexpected result while hammering wrong PINs: {other:?}"),
        }
    }
    assert!(
        saw_wrong_pin,
        "early wrong PINs must map to Error::WrongPin"
    );
    assert!(
        saw_lockout,
        "after max_auth_fail wrong PINs the TPM must surface a distinct Error::Lockout"
    );

    let locked = read_lockout_state(&mut context).expect("read lockout state");
    assert!(
        locked.is_locked_out(),
        "lockout state must report locked out, got {locked:?}"
    );

    // A hard lockout is not PIN-recoverable: even the correct PIN is refused with Error::Lockout
    // (the privileged TPM2_DictionaryAttackLockReset path is tracked as tech-debt).
    let reset = reset_lockout(&mut context, primary.key_handle, &sealed, &pin);
    assert!(
        matches!(reset, Err(Error::Lockout)),
        "hard lockout must not be cleared by the PIN, got {reset:?}"
    );

    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}
