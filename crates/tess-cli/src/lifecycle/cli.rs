//! Wiring for the lifecycle subcommands: gather PINs / passwords / the recovery secret (without
//! echo), build the real TPM and Secret Service collaborators, and run the core flows in [`super`].

use anyhow::{ensure, Context, Result};
use tess_core::{KeyringBackend, SecretBytes};
use tess_keyring::SecretServiceBackend;
use zeroize::Zeroizing;

use crate::enroll::recovery;
use crate::enroll::sealer::TpmSealer;
use crate::enroll::Paths;
use crate::tcti;

use super::{
    dry_run, gather_status, recover, render_dry_run, render_status, reseal, unenroll, unlock,
};

/// Take a PIN from `--pin` or prompt for it without echo. The plaintext is held only in a
/// `Zeroizing` buffer until it reaches the zeroizing [`SecretBytes`]; an empty PIN is rejected early.
fn pin_or_prompt(pin: Option<String>, prompt: &str) -> Result<SecretBytes> {
    let entered = Zeroizing::new(match pin {
        Some(p) => p,
        None => rpassword::prompt_password(prompt).context("read PIN")?,
    });
    ensure!(!entered.is_empty(), "PIN must not be empty");
    Ok(SecretBytes::new(entered.as_bytes().to_vec()))
}

/// Best-effort keyring lock state for the read-only `status`/`test` reports: connect to the Secret
/// Service and read the login collection's `Locked` property, folding any failure into a reason
/// string rather than aborting the command.
fn keyring_lock_state() -> Option<std::result::Result<bool, String>> {
    Some(match SecretServiceBackend::connect() {
        Ok(backend) => backend.is_locked().map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    })
}

/// `tess unlock`.
pub fn run_unlock(pin: Option<String>) -> Result<()> {
    let paths = Paths::for_user().context("resolve tess data directory")?;
    super::ensure_enrolled(&paths)?;
    let pin = pin_or_prompt(pin, "PIN to unseal the keyring key: ")?;
    let mut sealer = TpmSealer::open(&tcti::from_env()).context("open the TPM")?;
    let keyring = SecretServiceBackend::connect().context("connect to the Secret Service")?;
    unlock(&mut sealer, &keyring, &paths, &pin)?;
    println!("Keyring unlocked.");
    Ok(())
}

/// `tess recover` — restore access via the recovery secret, optionally re-sealing under a new PIN.
pub fn run_recover(reseal_flag: bool, pin: Option<String>) -> Result<()> {
    let paths = Paths::for_user().context("resolve tess data directory")?;
    super::ensure_recoverable(&paths)?;
    let recovery_secret = {
        let entered = Zeroizing::new(
            rpassword::prompt_password("Recovery secret: ").context("read recovery secret")?,
        );
        recovery::decode(&entered).context("parse the recovery secret")?
    };

    // If the TPM is hard-locked, clear it with the recovery secret first so the PIN-unseal path (and
    // any `--reseal` below) works again. A failure here is surfaced but does not block keyring
    // recovery, which is TPM-independent.
    let tcti = tcti::from_env();
    match super::reset_hard_lockout(&tcti, &recovery_secret) {
        Ok(true) => println!(
            "TPM was hard-locked; reset the dictionary-attack lockout with the recovery secret."
        ),
        Ok(false) => {}
        Err(e) => eprintln!(
            "warning: could not check or reset the TPM lockout ({e:#}); continuing with recovery"
        ),
    }

    let keyring = SecretServiceBackend::connect().context("connect to the Secret Service")?;
    recover(&keyring, &paths, &recovery_secret)?;
    println!("Keyring access restored via the recovery secret.");

    if reseal_flag {
        let new_pin = pin_or_prompt(pin, "New PIN to re-seal the keyring key under: ")?;
        let mut sealer = TpmSealer::open(&tcti).context("open the TPM")?;
        reseal(&mut sealer, &paths, &recovery_secret, &new_pin)?;
        println!(
            "Re-sealed the keyring key under the new PIN; the normal PIN-unlock path is restored."
        );
    }
    Ok(())
}

/// `tess unenroll`.
pub fn run_unenroll(pin: Option<String>) -> Result<()> {
    let paths = Paths::for_user().context("resolve tess data directory")?;
    super::ensure_enrolled(&paths)?;
    let pin = pin_or_prompt(pin, "PIN to unseal the keyring key: ")?;
    let recovery_secret = prompt_optional_recovery_secret()?;
    let new_password = prompt_new_password()?;
    let mut sealer = TpmSealer::open(&tcti::from_env()).context("open the TPM")?;
    let keyring = SecretServiceBackend::connect().context("connect to the Secret Service")?;
    unenroll(
        &mut sealer,
        &keyring,
        &paths,
        &pin,
        &new_password,
        recovery_secret.as_ref(),
    )?;
    println!(
        "Unenrolled. The login keyring is back on a password and the sealed blobs were removed."
    );
    Ok(())
}

/// Prompt (without echo) for the recovery secret used to release the TPM lockout hierarchy at
/// unenroll. Optional: an empty entry skips the release (the lockout authValue stays bound, with a
/// warning), so a user who lost the secret can still unenroll the keyring.
fn prompt_optional_recovery_secret() -> Result<Option<SecretBytes>> {
    let entered = Zeroizing::new(
        rpassword::prompt_password(
            "Recovery secret (to release the TPM lockout hierarchy; press Enter to skip): ",
        )
        .context("read recovery secret")?,
    );
    if entered.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(
        recovery::decode(&entered).context("parse the recovery secret")?,
    ))
}

/// Prompt for the new keyring password twice (without echo) and confirm the two entries match.
fn prompt_new_password() -> Result<SecretBytes> {
    let first = Zeroizing::new(
        rpassword::prompt_password("New keyring password: ")
            .context("read new keyring password")?,
    );
    ensure!(
        !first.is_empty(),
        "the new keyring password must not be empty"
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("Confirm new keyring password: ")
            .context("confirm new keyring password")?,
    );
    ensure!(*first == *second, "the new keyring passwords did not match");
    Ok(SecretBytes::new(first.as_bytes().to_vec()))
}

/// `tess status`.
pub fn run_status() -> Result<()> {
    let paths = Paths::for_user().context("resolve tess data directory")?;
    let report = gather_status(&paths, keyring_lock_state(), &tcti::from_env());
    print!("{}", render_status(&report));
    Ok(())
}

/// `tess test`.
pub fn run_test() -> Result<()> {
    let paths = Paths::for_user().context("resolve tess data directory")?;
    let report = dry_run(&paths, keyring_lock_state(), &tcti::from_env());
    print!("{}", render_dry_run(&report));
    Ok(())
}
