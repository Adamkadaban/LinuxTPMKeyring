//! `sim`-gated integration test: bring up an isolated swtpm, open a real ESAPI context over the
//! swtpm TCTI, create the ECC storage primary, and start the salted HMAC + parameter-encryption
//! session. Proves the Phase 1 plumbing works end-to-end against a software TPM. Off by default so
//! `cargo test --workspace` stays hardware-free; run with `cargo test -p tess-tpm --features sim`.
#![cfg(feature = "sim")]

mod common;

use common::Swtpm;
use tess_core::SecretBytes;
use tess_tpm::{
    create_primary, generate_sealing_key, seal, start_salted_hmac_session, unseal, Error,
};

#[test]
fn opens_context_creates_primary_and_starts_salted_session() {
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return; // swtpm absent: skip cleanly so the feature build still passes.
    };

    let mut context = cfg
        .open_context()
        .expect("open ESAPI context against swtpm");

    let primary = create_primary(&mut context).expect("create ECC storage primary");

    let session = start_salted_hmac_session(&mut context, primary.key_handle)
        .expect("start salted HMAC + parameter-encryption session");

    // The session is a real, started HMAC handle, not the password pseudo-session.
    use tss_esapi::handles::SessionHandle;
    use tss_esapi::interface_types::session_handles::AuthSession;
    assert!(
        !matches!(session, AuthSession::Password),
        "expected a started HMAC session, not the password session"
    );

    // Flush the session before the primary so neither leaks a TPM handle.
    context
        .flush_context(SessionHandle::from(session).into())
        .expect("flush session");
    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}

#[test]
fn seal_unseal_round_trips_the_same_key() {
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    let mut context = cfg.open_context().expect("open ESAPI context");
    let primary = create_primary(&mut context).expect("create primary");

    let key = generate_sealing_key(&mut context).expect("generate sealing key");
    assert_eq!(key.len(), 32);
    let pin = SecretBytes::new(b"1234".to_vec());

    let sealed = seal(&mut context, primary.key_handle, &pin, &key).expect("seal");
    let recovered = unseal(&mut context, primary.key_handle, &sealed, &pin).expect("unseal");

    assert_eq!(
        recovered.as_slice(),
        key.as_slice(),
        "unseal must return the exact sealed key"
    );

    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}

#[test]
fn unseal_with_wrong_pin_fails_cleanly() {
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    let mut context = cfg.open_context().expect("open ESAPI context");
    let primary = create_primary(&mut context).expect("create primary");

    let key = generate_sealing_key(&mut context).expect("generate sealing key");
    let pin = SecretBytes::new(b"1234".to_vec());
    let wrong = SecretBytes::new(b"4321".to_vec());

    let sealed = seal(&mut context, primary.key_handle, &pin, &key).expect("seal");
    let err = unseal(&mut context, primary.key_handle, &sealed, &wrong)
        .expect_err("wrong PIN must not unseal");
    assert!(
        matches!(err, Error::WrongPin),
        "wrong PIN must map to Error::WrongPin, got {err:?}"
    );

    // The correct PIN still unseals afterwards (the object is intact, not consumed by the failure).
    let recovered = unseal(&mut context, primary.key_handle, &sealed, &pin)
        .expect("correct PIN unseals after a wrong attempt");
    assert_eq!(recovered.as_slice(), key.as_slice());

    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}

#[test]
fn sealing_key_is_32_bytes_and_varies_across_calls() {
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    let mut context = cfg.open_context().expect("open ESAPI context");

    let a = generate_sealing_key(&mut context).expect("first key");
    let b = generate_sealing_key(&mut context).expect("second key");
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 32);
    assert_ne!(a.as_slice(), b.as_slice(), "two generated keys must differ");
}
