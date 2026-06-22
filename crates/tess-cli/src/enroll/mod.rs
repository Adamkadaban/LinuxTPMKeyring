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

/// The outcome of a rollback, distinguishing the two failure modes so the caller reacts correctly.
enum Rollback {
    /// The keyring is back on the original credential (or was never changed) and the blobs are gone.
    Restored,
    /// The keyring is back on the original credential but removing the now-orphaned blobs failed.
    /// The keyring is safe and the recovery secret is **not** needed — only stale files remain.
    CleanupFailed(anyhow::Error),
    /// The original credential could **not** be restored: the keyring is stranded on the new key and
    /// the blobs were deliberately kept as the only way back in. The recovery secret is needed.
    RestoreFailed(anyhow::Error),
}

impl Tx {
    /// Undo, in reverse order, whatever was committed. Restores the keyring credential first; only
    /// once it is safely back on `old` are the on-disk blobs removed. The three outcomes
    /// ([`Rollback`]) let the caller tell a true lockout risk ([`Rollback::RestoreFailed`]) apart
    /// from a benign leftover-file error ([`Rollback::CleanupFailed`]).
    fn rollback(&self, keyring: &dyn KeyringBackend, paths: &Paths, old: &SecretBytes) -> Rollback {
        if let Some(new_key) = &self.new_key {
            if let Err(e) = keyring.rekey(new_key, old) {
                return Rollback::RestoreFailed(anyhow::Error::new(e).context(
                    "could not restore the original keyring credential after a failed enrollment",
                ));
            }
        }
        // The keyring is safe (on `old`, or never changed). Removing the orphaned blobs is
        // best-effort cleanup; a failure here leaves only stale files, never a lockout.
        let mut cleanup: Result<()> = Ok(());
        if self.metadata_written {
            if let Err(e) = remove_file(&paths.metadata) {
                cleanup = Err(anyhow::Error::new(e).context(format!(
                    "remove sealed metadata {} during rollback",
                    paths.metadata.display()
                )));
            }
        }
        if self.recovery_written {
            if let Err(e) = remove_file(&paths.recovery) {
                let err = anyhow::Error::new(e).context(format!(
                    "remove recovery blob {} during rollback",
                    paths.recovery.display()
                ));
                cleanup = Err(match cleanup {
                    Ok(()) => err,
                    Err(prev) => prev.context(err.to_string()),
                });
            }
        }
        match cleanup {
            Ok(()) => Rollback::Restored,
            Err(e) => Rollback::CleanupFailed(e),
        }
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
            Rollback::Restored => {
                Err(err.context("enrollment failed and was rolled back to the original keyring"))
            }
            // The keyring is safe (restored to the original credential); only orphaned blobs remain.
            // Do not print or expose the recovery secret — it isn't needed.
            Rollback::CleanupFailed(cleanup_err) => Err(err.context(format!(
                "enrollment failed and was rolled back to the original keyring, but removing the \
                 orphaned enrollment blobs failed ({cleanup_err:#}); delete them manually"
            ))),
            // Genuine lockout risk: the keyring is stranded on the new key and the blobs were kept.
            // The user needs the recovery secret — print it once to the terminal (like the success
            // path) rather than embedding it in the error chain, which could be logged repeatedly.
            Rollback::RestoreFailed(restore_err) => {
                eprintln!(
                    "CRITICAL: enrollment failed and the original keyring credential could not be \
                     restored. Save this recovery secret and run `tess recover`:\n\n    {display}\n"
                );
                Err(err.context(format!(
                    "enrollment failed and the original keyring credential could not be restored \
                     ({restore_err:#}); the recovery secret was printed to stderr — run \
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
        assert!(matches!(
            tx.rollback(&keyring, &p, &SecretBytes::new(b"old".to_vec())),
            Rollback::Restored
        ));

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
        assert!(matches!(
            tx.rollback(&keyring, &p, &SecretBytes::new(b"old".to_vec())),
            Rollback::Restored
        ));

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
        let outcome = tx.rollback(&keyring, &p, &SecretBytes::new(b"old".to_vec()));

        let Rollback::RestoreFailed(err) = outcome else {
            panic!("expected RestoreFailed");
        };
        assert!(format!("{err:#}").contains("restore the original keyring credential"));
        assert!(p.metadata.exists(), "blobs kept as the only way back in");
        assert!(
            p.recovery.exists(),
            "recovery blob kept as the only way back in"
        );
    }

    #[test]
    fn rollback_after_restore_reports_cleanup_failure_without_keeping_lockout_risk() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        // A directory at the metadata path makes `remove_file` fail, simulating a cleanup IO error
        // *after* the credential was restored — the keyring is safe, only a stale entry remains.
        std::fs::create_dir(&p.metadata).unwrap();
        write(&p.recovery);
        let keyring = MockKeyring::new(b"new");

        let tx = Tx {
            recovery_written: true,
            metadata_written: true,
            new_key: Some(SecretBytes::new(b"new".to_vec())),
        };
        let outcome = tx.rollback(&keyring, &p, &SecretBytes::new(b"old".to_vec()));

        let Rollback::CleanupFailed(err) = outcome else {
            panic!("expected CleanupFailed");
        };
        assert!(format!("{err:#}").contains("metadata"));
        assert_eq!(
            *keyring.credential.borrow(),
            b"old",
            "credential was restored despite the cleanup failure"
        );
        assert!(
            !p.recovery.exists(),
            "the removable blob was still cleaned up"
        );
    }
}
