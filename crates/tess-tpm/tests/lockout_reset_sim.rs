//! `sim`-gated integration tests for the privileged dictionary-attack lockout reset (#16): bind the
//! lockout-hierarchy authValue, drive the TPM to a hard lockout, then clear it via the privileged
//! `reset_lockout` (a `tpm2_dictionarylockout` subprocess) and confirm a normal unseal works again —
//! and that a wrong authValue is refused, so anti-hammering is preserved. Off by default; run with
//! `cargo test -p tess-tpm --features sim` (needs swtpm + tpm2-tools).
#![cfg(feature = "sim")]

mod common;

use std::process::Command;

use common::Swtpm;
use tess_core::SecretBytes;
use tess_tpm::{
    Error, SealedObject, create_primary, generate_sealing_key, lockout_auth_is_set,
    read_lockout_state, reset_lockout, seal, set_lockout_auth, unseal,
};
use tss_esapi::Context;

/// A distinct 32-byte authValue, standing in for a recovery-derived lockout authValue (the HKDF
/// derivation itself is unit-tested in `tess-cli`).
fn lockout_auth(seed: u8) -> SecretBytes {
    SecretBytes::new(
        (0u8..32)
            .map(|i| i.wrapping_mul(7).wrapping_add(seed))
            .collect(),
    )
}

fn empty_auth() -> SecretBytes {
    SecretBytes::new(Vec::new())
}

/// Whether tpm2-tools' `tpm2_dictionarylockout` is invokable. The subprocess-backed tests skip
/// cleanly when it is absent so the `sim` build still passes locally; CI installs tpm2-tools so they
/// actually run.
fn tpm2_tools_available() -> bool {
    match Command::new("tpm2_dictionarylockout")
        .arg("--version")
        .output()
    {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Drive the sealed object to a hard lockout by hammering wrong PINs, returning whether the harness'
/// TPM is suitable (a tiny `max_auth_fail`, like swtpm's default of 3). Leaves the TPM hard-locked.
fn hammer_to_lockout(
    context: &mut Context,
    primary: tss_esapi::handles::KeyHandle,
    sealed: &SealedObject,
) -> bool {
    let initial = read_lockout_state(context).expect("read lockout state");
    if initial.max_auth_fail == 0 || initial.max_auth_fail > 32 {
        eprintln!(
            "skipping: max_auth_fail={} is unsuitable for a bounded lockout loop",
            initial.max_auth_fail
        );
        return false;
    }
    let wrong = SecretBytes::new(b"0000".to_vec());
    let cap = initial.max_auth_fail.saturating_add(5);
    for _ in 0..cap {
        match unseal(context, primary, sealed, &wrong) {
            Err(Error::WrongPin) => {}
            Err(Error::Lockout) => return true,
            other => panic!("unexpected result while hammering wrong PINs: {other:?}"),
        }
    }
    panic!("TPM did not enter hard lockout within {cap} wrong PINs");
}

#[test]
fn set_then_clear_lockout_auth_toggles_state() {
    // No tpm2-tools needed: exercises both directions of the safe `set_lockout_auth` (empty ->
    // derived at enroll, derived -> empty at unenroll) and the read-only `lockout_auth_is_set` probe.
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    let mut context = cfg.open_context().expect("open ESAPI context");
    let primary = create_primary(&mut context).expect("create primary");

    assert!(
        !lockout_auth_is_set(&mut context).expect("read lockout-auth state"),
        "a fresh swtpm has no lockout authValue"
    );

    let auth = lockout_auth(1);
    set_lockout_auth(&mut context, primary.key_handle, &empty_auth(), &auth)
        .expect("bind lockout authValue empty -> derived");
    assert!(
        lockout_auth_is_set(&mut context).expect("read lockout-auth state"),
        "lockoutAuthSet must be reported after binding"
    );

    set_lockout_auth(&mut context, primary.key_handle, &auth, &empty_auth())
        .expect("restore lockout authValue derived -> empty");
    assert!(
        !lockout_auth_is_set(&mut context).expect("read lockout-auth state"),
        "lockoutAuthSet must be clear after restoring to empty"
    );

    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}

#[test]
fn privileged_reset_clears_hard_lockout_with_correct_auth() {
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    if !tpm2_tools_available() {
        eprintln!("skipping privileged reset test: tpm2_dictionarylockout not found");
        return;
    }

    let auth = lockout_auth(2);
    let pin = SecretBytes::new(b"1234".to_vec());

    // Phase A: bind the lockout authValue, seal a key, hammer to a hard lockout. The ESAPI context
    // is dropped at the end of this block so its connection is released — swtpm is single-client, so
    // tpm2-tools (Phase B) could not connect while it is held open.
    let (sealed, key, reached_lockout) = {
        let mut context = cfg.open_context().expect("open ESAPI context");
        let primary = create_primary(&mut context).expect("create primary");
        set_lockout_auth(&mut context, primary.key_handle, &empty_auth(), &auth)
            .expect("bind lockout authValue");

        let key = generate_sealing_key(&mut context).expect("generate sealing key");
        let sealed = seal(&mut context, primary.key_handle, &pin, &key).expect("seal");

        let reached = hammer_to_lockout(&mut context, primary.key_handle, &sealed);
        if reached {
            assert!(
                read_lockout_state(&mut context)
                    .expect("read lockout state")
                    .is_locked_out(),
                "TPM must report locked out before the reset"
            );
        }
        context
            .flush_context(primary.key_handle.into())
            .expect("flush primary");
        (sealed, key, reached)
    };
    if !reached_lockout {
        return;
    }

    // Phase B: privileged reset via tpm2_dictionarylockout, authorized by the correct authValue.
    reset_lockout(&cfg, &auth).expect("privileged reset succeeds with the correct authValue");

    // Phase C: reopen, confirm the counter is cleared and the correct PIN unseals the key again.
    let mut context = cfg.open_context().expect("reopen ESAPI context");
    let primary = create_primary(&mut context).expect("re-derive primary");
    let state = read_lockout_state(&mut context).expect("read lockout state");
    assert_eq!(state.counter, 0, "reset must zero the DA lockout counter");
    assert!(!state.is_locked_out(), "TPM must no longer be locked out");

    let recovered = unseal(&mut context, primary.key_handle, &sealed, &pin)
        .expect("the correct PIN unseals again after the reset");
    assert_eq!(
        recovered.as_slice(),
        key.as_slice(),
        "unseal must return the original key"
    );
    context
        .flush_context(primary.key_handle.into())
        .expect("flush primary");
}

#[test]
fn privileged_reset_with_wrong_auth_is_refused() {
    let Some((_swtpm, cfg)) = Swtpm::start() else {
        return;
    };
    if !tpm2_tools_available() {
        eprintln!("skipping privileged reset test: tpm2_dictionarylockout not found");
        return;
    }

    let correct = lockout_auth(3);
    let wrong = lockout_auth(9);

    {
        let mut context = cfg.open_context().expect("open ESAPI context");
        let primary = create_primary(&mut context).expect("create primary");
        set_lockout_auth(&mut context, primary.key_handle, &empty_auth(), &correct)
            .expect("bind lockout authValue");
        context
            .flush_context(primary.key_handle.into())
            .expect("flush primary");
    }

    // Anti-hammering: a wrong authValue cannot clear the lockout counter.
    let err = reset_lockout(&cfg, &wrong)
        .expect_err("a wrong lockout authValue must not be able to reset the counter");
    assert!(
        matches!(err, Error::LockoutReset(_)),
        "wrong-auth reset must surface Error::LockoutReset, got {err:?}"
    );
}
