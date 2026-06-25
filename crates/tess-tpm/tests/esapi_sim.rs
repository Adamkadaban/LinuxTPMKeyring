//! `sim`-gated integration test: bring up an isolated swtpm, open a real ESAPI context over the
//! swtpm TCTI, create the ECC storage primary, and start the salted HMAC + parameter-encryption
//! session. Proves the Phase 1 plumbing works end-to-end against a software TPM. Off by default so
//! `cargo test --workspace` stays hardware-free; run with `cargo test -p tess-tpm --features sim`.
#![cfg(feature = "sim")]

mod common;

use common::Swtpm;
use tess_core::SecretBytes;
use tess_tpm::{
    Error, create_primary, generate_sealing_key, primary_name, seal, start_salted_hmac_session,
    unseal,
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

#[test]
fn primary_name_is_stable_across_rederivation() {
    // The storage primary is regenerated from the owner seed each boot via the deterministic
    // template, so its Name must be identical across re-derivations — otherwise pinning would lock
    // out the legitimate user on every unlock.
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    let mut context = cfg.open_context().expect("open ESAPI context");

    let p1 = create_primary(&mut context).expect("create primary");
    let n1 = primary_name(&mut context, p1.key_handle).expect("read primary name");
    context
        .flush_context(p1.key_handle.into())
        .expect("flush first primary");

    let p2 = create_primary(&mut context).expect("re-derive primary");
    let n2 = primary_name(&mut context, p2.key_handle).expect("read re-derived primary name");
    context
        .flush_context(p2.key_handle.into())
        .expect("flush second primary");

    assert!(!n1.is_empty(), "a primary Name must be non-empty");
    assert_eq!(
        n1, n2,
        "the deterministic template must yield a stable Name across re-derivation"
    );
}

#[test]
fn unseal_refuses_a_substituted_primary_name() {
    // Security invariant (interposer detection): an object whose pinned primary Name differs from
    // the live primary — exactly what a substituted salt key produces — must refuse to unseal,
    // while the genuine object still unseals.
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    let mut context = cfg.open_context().expect("open ESAPI context");
    let primary = create_primary(&mut context).expect("create primary");

    let key = generate_sealing_key(&mut context).expect("generate sealing key");
    let pin = SecretBytes::new(b"1234".to_vec());
    let sealed = seal(&mut context, primary.key_handle, &pin, &key).expect("seal");

    // Round-trip through persistence, then forge the pinned Name to a different valid value.
    let mut metadata = tess_tpm::persist::to_metadata(&sealed).expect("to_metadata");
    metadata.primary_name = swap_first_base64_char(&metadata.primary_name);
    let tampered = tess_tpm::persist::from_metadata(&metadata).expect("from_metadata");

    let err = unseal(&mut context, primary.key_handle, &tampered, &pin)
        .expect_err("a substituted primary Name must refuse to unseal");
    assert!(
        matches!(err, Error::PrimaryNameMismatch),
        "expected PrimaryNameMismatch, got {err:?}"
    );

    // The genuine object (correct pinned Name) still unseals: the check is precise, not a blanket
    // block on the loaded object.
    let recovered =
        unseal(&mut context, primary.key_handle, &sealed, &pin).expect("genuine object unseals");
    assert_eq!(recovered.as_slice(), key.as_slice());

    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}

/// Flip the first base64 character to a different valid one: changes the decoded Name bytes while
/// staying valid base64 so `from_metadata` still decodes it.
fn swap_first_base64_char(s: &str) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    if let Some(c) = chars.first_mut() {
        *c = if *c == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}
