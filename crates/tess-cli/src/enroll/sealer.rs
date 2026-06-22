//! The key-sealing capability the enrollment transaction depends on, and its real TPM-backed
//! implementation.
//!
//! Factoring seal/unseal behind a trait keeps the transaction in [`super`] testable with a mock that
//! needs no TPM, while [`TpmSealer`] is the production path: it owns an ESAPI context and the ECC
//! storage primary and forwards to `tess_tpm`. The `tss_esapi` types stay confined to this module.

use anyhow::{Context as _, Result};
use tess_core::SecretBytes;
use tess_tpm::{create_primary, generate_sealing_key, seal, unseal, SealedObject, TctiConfig};
use tss_esapi::handles::KeyHandle;
use tss_esapi::Context;

/// Seal/unseal of the keyring's random key under a PIN. The transaction generates the key, seals it,
/// and verifies it unseals before doing anything destructive to the keyring.
pub trait KeySealer {
    /// Generate a fresh random sealing key (OS CSPRNG mixed with the TPM RNG in the real impl).
    fn generate_key(&mut self) -> Result<SecretBytes>;
    /// Seal `key` under `pin` as a TPM keyedhash object.
    fn seal(&mut self, pin: &SecretBytes, key: &SecretBytes) -> Result<SealedObject>;
    /// Unseal a previously sealed object with `pin`, recovering the key.
    fn unseal(&mut self, sealed: &SealedObject, pin: &SecretBytes) -> Result<SecretBytes>;
}

/// Production [`KeySealer`] over a live TPM (swtpm in tests, `/dev/tpmrm0` otherwise).
pub struct TpmSealer {
    context: Context,
    primary: KeyHandle,
}

impl TpmSealer {
    /// Open an ESAPI context against `tcti` and create the ECC storage primary the sealed objects
    /// live under.
    pub fn open(tcti: &TctiConfig) -> Result<Self> {
        let mut context = tcti.open_context().context("open TPM context")?;
        let primary = create_primary(&mut context).context("create ECC storage primary")?;
        Ok(Self {
            context,
            primary: primary.key_handle,
        })
    }
}

impl Drop for TpmSealer {
    fn drop(&mut self) {
        // Best-effort: free the transient primary handle so a long-lived process doesn't leak TPM
        // object slots. A failure here is not actionable (the context is closing anyway).
        let _ = self.context.flush_context(self.primary.into());
    }
}

impl KeySealer for TpmSealer {
    fn generate_key(&mut self) -> Result<SecretBytes> {
        generate_sealing_key(&mut self.context).context("generate sealing key")
    }

    fn seal(&mut self, pin: &SecretBytes, key: &SecretBytes) -> Result<SealedObject> {
        seal(&mut self.context, self.primary, pin, key).context("seal key under PIN")
    }

    fn unseal(&mut self, sealed: &SealedObject, pin: &SecretBytes) -> Result<SecretBytes> {
        unseal(&mut self.context, self.primary, sealed, pin).context("unseal key with PIN")
    }
}
