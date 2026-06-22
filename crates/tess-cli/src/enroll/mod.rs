//! The atomic, recoverable enrollment transaction — tess's #1 safety-critical path.
//!
//! Enrollment rekeys the login keyring from its password-derived wrapping key to a fresh random key
//! sealed in the TPM. That rekey is destructive: a crash or error mid-flight must never leave a
//! half-rekeyed keyring the user can no longer open. The transaction enforces a strict order so the
//! keyring is always either fully-old or fully-enrolled, and rolls back on any failure:
//!
//! 1. refuse to clobber an existing enrollment, and prove the supplied old credential opens the
//!    keyring — both *before* writing anything to disk;
//! 2. generate the random key `K`;
//! 3. **back up a recovery secret first** — wrap `K` under a user-saved recovery secret and verify
//!    the wrap round-trips before persisting it (so a TPM-independent way back in exists *before*
//!    anything destructive);
//! 4. seal `K` under the PIN, verify it unseals, and persist the sealed blobs + metadata;
//! 5. rekey the keyring in place old → `K`;
//! 6. verify the keyring unlocks with `K` and a pre-existing item still decrypts;
//! 7. commit.
//!
//! On any failure after a blob is written the keyring credential is restored and the just-written
//! blobs are removed, leaving the system exactly as before. The one path that deliberately preserves
//! the blobs is a failure to restore the keyring credential during rollback: then the sealed/recovery
//! blobs are the only way back in, so they are kept and the recovery secret is printed for
//! `tess recover`.

pub mod cli;
pub mod recovery;
pub mod sealer;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use tess_core::{KeyringBackend, SecretBytes};

use sealer::KeySealer;

/// On-disk locations the transaction writes (and removes on rollback).
#[derive(Debug, Clone)]
pub struct Paths {
    /// TPM sealed-object metadata (`tess_tpm::persist` schema).
    pub metadata: PathBuf,
    /// Recovery blob (`recovery::RecoveryBlob`).
    pub recovery: PathBuf,
}

impl Paths {
    /// Per-user data locations under `$XDG_DATA_HOME/tess` (falling back to `$HOME/.local/share`).
    pub fn for_user() -> Result<Self> {
        let base = if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            PathBuf::from(xdg)
        } else {
            let home = std::env::var_os("HOME")
                .ok_or_else(|| anyhow!("neither XDG_DATA_HOME nor HOME is set"))?;
            PathBuf::from(home).join(".local/share")
        };
        let dir = base.join("tess");
        Ok(Self {
            metadata: dir.join("metadata.json"),
            recovery: dir.join("recovery.json"),
        })
    }
}

/// What enrollment hands back to the caller. Carries the recovery secret to display **once**; never
/// the keyring key or any sealed material.
pub struct EnrollOutcome {
    /// The recovery secret to show the user to save offline (grouped-hex form).
    pub recovery_secret_display: String,
}

impl std::fmt::Debug for EnrollOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the recovery secret through Debug — it is shown to the user exactly once.
        f.debug_struct("EnrollOutcome")
            .field("recovery_secret_display", &"<redacted>")
            .finish()
    }
}

/// Tracks the destructive steps performed so a failure can undo exactly what happened, in reverse.
#[derive(Default)]
struct Tx {
    recovery_written: bool,
    metadata_written: bool,
    /// `Some` once the keyring credential has actually been changed to this key; rollback rekeys it
    /// back to the original credential. `None` means the keyring was never touched.
    new_key: Option<SecretBytes>,
}

impl Tx {
    /// Undo, in reverse order, whatever was committed. Restores the keyring credential first; only
    /// once it is safely back on `old` are the on-disk blobs removed. If the credential cannot be
    /// restored, the blobs are deliberately **kept** (they are the only way back in) and the error
    /// says so.
    fn rollback(
        &self,
        keyring: &dyn KeyringBackend,
        paths: &Paths,
        old: &SecretBytes,
    ) -> Result<()> {
        if let Some(new_key) = &self.new_key {
            keyring.rekey(new_key, old).context(
                "CRITICAL: could not restore the original keyring credential after a failed \
                 enrollment; the sealed and recovery blobs were left in place — run `tess recover` \
                 with the saved recovery secret",
            )?;
        }
        if self.metadata_written {
            remove_file(&paths.metadata).context("remove sealed metadata during rollback")?;
        }
        if self.recovery_written {
            remove_file(&paths.recovery).context("remove recovery blob during rollback")?;
        }
        Ok(())
    }
}

/// Run the enrollment transaction. `old` is the current keyring credential, `pin` the PIN that will
/// gate the TPM-sealed key, and `verify_item` an additional check that a known pre-existing keyring
/// item still decrypts after the rekey (the CLI passes a no-op; tests assert real items survive).
pub fn enroll<S: KeySealer>(
    sealer: &mut S,
    keyring: &dyn KeyringBackend,
    paths: &Paths,
    old: &SecretBytes,
    pin: &SecretBytes,
    verify_item: &dyn Fn() -> Result<()>,
) -> Result<EnrollOutcome> {
    ensure!(!pin.is_empty(), "PIN must not be empty");

    // Refuse to clobber an existing enrollment: its blobs are the only way to unseal/recover the
    // current keyring key, and overwriting them here (then deleting them on rollback) could strand
    // the user. Re-keying an existing enrollment is `tess unenroll` + enroll, or `tess recover`.
    ensure!(
        !paths.metadata.exists() && !paths.recovery.exists(),
        "already enrolled (found {} or {}); run `tess unenroll` or `tess recover` first",
        paths.metadata.display(),
        paths.recovery.display()
    );

    // Prove the supplied credential opens the keyring *before* writing anything to disk, so a wrong
    // credential fails with no on-disk side effects and nothing to roll back.
    keyring
        .unlock(old)
        .context("verify the current keyring credential before enrolling")?;

    let key = sealer
        .generate_key()
        .context("generate the random keyring key")?;
    let recovery_secret =
        recovery::generate_recovery_secret().context("generate the recovery secret")?;
    let display = recovery::encode(&recovery_secret);

    let mut tx = Tx::default();
    match commit(
        &mut tx,
        sealer,
        keyring,
        paths,
        old,
        pin,
        &key,
        &recovery_secret,
        verify_item,
    ) {
        Ok(()) => Ok(EnrollOutcome {
            recovery_secret_display: display,
        }),
        Err(err) => match tx.rollback(keyring, paths, old) {
            Ok(()) => {
                Err(err.context("enrollment failed and was rolled back to the original keyring"))
            }
            Err(rollback_err) => {
                // Catastrophe: the keyring is left on the new key and could not be restored, so the
                // sealed + recovery blobs were kept. The user needs the recovery secret to get back
                // in — print it directly to the terminal (one-time, like the success path) rather
                // than embedding it in the error chain, which could be logged/telemetried repeatedly.
                eprintln!(
                    "CRITICAL: enrollment failed and the original keyring credential could not be \
                     restored. Save this recovery secret and run `tess recover`:\n\n    {display}\n"
                );
                Err(err.context(format!(
                    "enrollment failed and rollback could not fully restore the keyring \
                     ({rollback_err:#}); the recovery secret was printed to stderr — run \
                     `tess recover`"
                )))
            }
        },
    }
}

/// The ordered, destructive body of [`enroll`], split out so the caller can roll back on any error.
/// Each step records its progress in `tx` so rollback knows precisely what to undo.
#[allow(clippy::too_many_arguments)]
fn commit<S: KeySealer>(
    tx: &mut Tx,
    sealer: &mut S,
    keyring: &dyn KeyringBackend,
    paths: &Paths,
    old: &SecretBytes,
    pin: &SecretBytes,
    key: &SecretBytes,
    recovery_secret: &SecretBytes,
    verify_item: &dyn Fn() -> Result<()>,
) -> Result<()> {
    // Step 3: recovery backup FIRST, created and verified before anything destructive.
    let blob =
        recovery::wrap_key(key, recovery_secret).context("wrap the keyring key for recovery")?;
    let round_trip = recovery::unwrap_key(&blob, recovery_secret)
        .context("verify the recovery blob decrypts")?;
    ensure!(
        round_trip.as_slice() == key.as_slice(),
        "recovery blob did not round-trip the keyring key"
    );
    recovery::save_blob(&blob, &paths.recovery).context("persist the recovery blob")?;
    tx.recovery_written = true;

    // Step 4: seal under the PIN, prove it unseals, then persist. Verifying the unseal before the
    // destructive rekey means a broken TPM path can never strand the keyring on a key we can't
    // recover via the PIN.
    let sealed = sealer
        .seal(pin, key)
        .context("seal the keyring key under the PIN")?;
    let unsealed = sealer
        .unseal(&sealed, pin)
        .context("verify the sealed key unseals with the PIN before rekeying")?;
    ensure!(
        unsealed.as_slice() == key.as_slice(),
        "sealed key did not unseal to the generated key"
    );
    let metadata = tess_tpm::persist::to_metadata(&sealed).context("encode the sealed metadata")?;
    tess_tpm::persist::save(&metadata, &paths.metadata).context("persist the sealed metadata")?;
    tx.metadata_written = true;

    // Step 5: rekey in place (destructive). The old credential was already proven to open the
    // keyring in `enroll` before any blob was written.
    keyring
        .rekey(old, key)
        .context("rekey the login keyring to the TPM-sealed key")?;
    tx.new_key = Some(key.clone());

    // Step 6: verify the keyring opens with the new key and a known item still decrypts.
    keyring
        .unlock(key)
        .context("verify the keyring unlocks with the new TPM-sealed key")?;
    ensure!(
        !keyring
            .is_locked()
            .context("re-read keyring lock state after unlocking")?,
        "keyring is still locked after unlocking with the new key"
    );
    verify_item().context("verify a pre-existing keyring item still decrypts after the rekey")?;

    Ok(())
}

/// Remove a file, treating an already-absent file as success so rollback is idempotent.
fn remove_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tess_core::{Error, Result as CoreResult};

    /// A minimal in-memory keyring for unit-testing the rollback state machine without a daemon.
    struct MockKeyring {
        credential: RefCell<Vec<u8>>,
        rekey_back_fails: bool,
        rekeys: RefCell<Vec<(Vec<u8>, Vec<u8>)>>,
    }

    impl MockKeyring {
        fn new(initial: &[u8]) -> Self {
            Self {
                credential: RefCell::new(initial.to_vec()),
                rekey_back_fails: false,
                rekeys: RefCell::new(Vec::new()),
            }
        }
    }

    impl KeyringBackend for MockKeyring {
        fn rekey(&self, old: &SecretBytes, new: &SecretBytes) -> CoreResult<()> {
            if self.rekey_back_fails {
                return Err(Error::Keyring("injected rekey-back failure".into()));
            }
            self.rekeys
                .borrow_mut()
                .push((old.as_slice().to_vec(), new.as_slice().to_vec()));
            *self.credential.borrow_mut() = new.as_slice().to_vec();
            Ok(())
        }
        fn unlock(&self, _secret: &SecretBytes) -> CoreResult<()> {
            Ok(())
        }
        fn is_locked(&self) -> CoreResult<bool> {
            Ok(false)
        }
    }

    fn write(path: &Path) {
        std::fs::write(path, b"x").unwrap();
    }

    fn paths(dir: &Path) -> Paths {
        Paths {
            metadata: dir.join("metadata.json"),
            recovery: dir.join("recovery.json"),
        }
    }

    #[test]
    fn rollback_without_rekey_removes_blobs_and_leaves_credential() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write(&p.metadata);
        write(&p.recovery);
        let keyring = MockKeyring::new(b"old");

        let tx = Tx {
            recovery_written: true,
            metadata_written: true,
            new_key: None,
        };
        tx.rollback(&keyring, &p, &SecretBytes::new(b"old".to_vec()))
            .unwrap();

        assert!(!p.metadata.exists(), "metadata must be removed");
        assert!(!p.recovery.exists(), "recovery blob must be removed");
        assert_eq!(*keyring.credential.borrow(), b"old", "credential untouched");
        assert!(
            keyring.rekeys.borrow().is_empty(),
            "no rekey when never rekeyed"
        );
    }

    #[test]
    fn rollback_after_rekey_restores_credential_then_removes_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write(&p.metadata);
        write(&p.recovery);
        let keyring = MockKeyring::new(b"new"); // already rekeyed to the new key

        let tx = Tx {
            recovery_written: true,
            metadata_written: true,
            new_key: Some(SecretBytes::new(b"new".to_vec())),
        };
        tx.rollback(&keyring, &p, &SecretBytes::new(b"old".to_vec()))
            .unwrap();

        assert_eq!(
            *keyring.credential.borrow(),
            b"old",
            "credential restored to old"
        );
        assert_eq!(
            keyring.rekeys.borrow().as_slice(),
            &[(b"new".to_vec(), b"old".to_vec())],
            "rollback rekeys new -> old"
        );
        assert!(!p.metadata.exists());
        assert!(!p.recovery.exists());
    }

    #[test]
    fn rollback_keeps_blobs_when_credential_cannot_be_restored() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        write(&p.metadata);
        write(&p.recovery);
        let mut keyring = MockKeyring::new(b"new");
        keyring.rekey_back_fails = true;

        let tx = Tx {
            recovery_written: true,
            metadata_written: true,
            new_key: Some(SecretBytes::new(b"new".to_vec())),
        };
        let err = tx
            .rollback(&keyring, &p, &SecretBytes::new(b"old".to_vec()))
            .expect_err("must surface the restore failure");

        assert!(format!("{err:#}").contains("tess recover"));
        assert!(p.metadata.exists(), "blobs kept as the only way back in");
        assert!(
            p.recovery.exists(),
            "recovery blob kept as the only way back in"
        );
    }
}
