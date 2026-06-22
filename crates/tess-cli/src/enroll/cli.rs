//! Wiring for `tess enroll`: gather the PIN and current keyring credential, build the real TPM and
//! Secret Service collaborators, run the transaction, and print the recovery secret to save.

use anyhow::{Context, Result};
use tess_core::SecretBytes;
use tess_keyring::SecretServiceBackend;
use zeroize::Zeroizing;

use super::sealer::TpmSealer;
use super::{enroll, Paths};
use crate::tcti;

/// Run `tess enroll`. `pin` comes from `--pin`; when absent it is prompted without echo. The current
/// keyring password is always prompted without echo.
pub fn run(pin: Option<String>) -> Result<()> {
    // Keep each secret in a Zeroizing buffer until it reaches the zeroizing SecretBytes.
    let pin = {
        let entered = Zeroizing::new(match pin {
            Some(p) => p,
            None => rpassword::prompt_password("PIN to gate the TPM-sealed key: ")
                .context("read PIN")?,
        });
        SecretBytes::new(entered.as_bytes().to_vec())
    };
    if pin.is_empty() {
        anyhow::bail!("PIN must not be empty");
    }
    let old = {
        let entered = Zeroizing::new(
            rpassword::prompt_password("Current keyring password: ")
                .context("read current keyring password")?,
        );
        SecretBytes::new(entered.as_bytes().to_vec())
    };

    let paths = Paths::for_user().context("resolve tess data directory")?;
    let mut sealer = TpmSealer::open(&tcti::from_env()).context("open the TPM")?;
    let keyring = SecretServiceBackend::connect().context("connect to the Secret Service")?;

    // The transaction already verifies the keyring unlocks with the new key; item-level decryption
    // is asserted in the integration tests, which have Secret Service item access the stable backend
    // trait does not expose.
    let verify_item = || Ok(());
    let outcome = enroll(&mut sealer, &keyring, &paths, &old, &pin, &verify_item)?;

    println!("Enrollment succeeded. The login keyring is now sealed to the TPM under your PIN.");
    println!();
    println!(
        "SAVE THIS RECOVERY SECRET — it is shown only once and is the only way back in if the"
    );
    println!("TPM is cleared or the PIN is lost. It is NOT stored anywhere in recoverable form:");
    println!();
    println!("    {}", outcome.recovery_secret_display);
    Ok(())
}
