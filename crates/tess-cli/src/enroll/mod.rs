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

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use mug::{EnrollStore, FaceEnrollment};
use tess_core::{KeyringBackend, SecretBytes};

use sealer::KeySealer;

/// On-disk locations the transaction writes (and removes on rollback).
#[derive(Debug, Clone)]
pub struct Paths {
    /// TPM sealed-object metadata (`tess_tpm::persist` schema).
    pub metadata: PathBuf,
    /// Recovery blob (`recovery::RecoveryBlob`).
    pub recovery: PathBuf,
    /// Marker (empty file): present iff tess bound the TPM lockout-hierarchy authValue at enroll, so
    /// unenroll knows it owns the auth and may safely release it. Absent on a machine where enroll
    /// skipped binding (a foreign lockout owner) — so unenroll never authorizes a wrong reset there.
    pub lockout_owned: PathBuf,
    /// TPM sealed-object metadata for the face-unlock credential: the same keyring key sealed a
    /// second time under the independent face authValue. Present only when `--face` was enrolled.
    pub metadata_face: PathBuf,
    /// The face-unlock authValue (`A_face`) on disk, mode 0600. Lets the TPM unseal the key after a
    /// liveness-gated face match, with no PIN typed. Present only when `--face` was enrolled.
    pub face_key: PathBuf,
}

impl Paths {
    /// Per-user data locations under `$XDG_DATA_HOME/tess` (falling back to `$HOME/.local/share`).
    pub fn for_user() -> Result<Self> {
        let base = Self::resolve_base(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))?;
        let dir = base.join("tess");
        Ok(Self {
            metadata: dir.join("metadata.json"),
            recovery: dir.join("recovery.json"),
            lockout_owned: dir.join("lockout-owned"),
            metadata_face: dir.join("metadata-face.json"),
            face_key: dir.join("face-unlock.key"),
        })
    }

    /// Pure env-resolution logic, separated from the process-global `std::env` read so it is
    /// deterministically testable. Per the XDG spec a relative (including empty) `XDG_DATA_HOME` is
    /// ignored, so blobs never land in an unexpected relative/CWD location; an empty `HOME` is
    /// likewise treated as unset.
    fn resolve_base(xdg: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
        if let Some(dir) = xdg.map(PathBuf::from).filter(|p| p.is_absolute()) {
            return Ok(dir);
        }
        let home = home
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| anyhow!("neither XDG_DATA_HOME nor HOME is set to a usable path"))?;
        Ok(home.join(".local/share"))
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

/// Captures a face-enrollment template (the IR embedding + liveness calibration) from a live or
/// virtual capture. The transaction calls this once, before any face artifact is written, so a
/// camera/liveness failure aborts the face enrollment before it touches disk. A CI impl drives the
/// virtual IR source + mock matcher; the hardware impl drives the Brio + ONNX matcher.
pub trait FaceTemplateSource {
    fn capture_template(&mut self) -> Result<FaceEnrollment>;
}

/// The optional face leg of an enrollment: where to store the face template and how to capture it.
/// When passed to [`enroll`], the same keyring key is additionally sealed under a fresh independent
/// authValue and the captured template is saved to `store` under `username` — all inside the
/// transaction, rolled back on any failure.
pub struct FaceEnroll<'a> {
    pub username: &'a str,
    pub store: &'a EnrollStore,
    pub template: &'a mut dyn FaceTemplateSource,
}

/// Tracks the destructive steps performed so a failure can undo exactly what happened, in reverse.
#[derive(Default)]
struct Tx {
    recovery_written: bool,
    metadata_written: bool,
    /// Face-unlock artifacts (additive, fully transactional): the second sealed metadata, the
    /// on-disk authValue, and the mug-store template. Removed on rollback in reverse.
    face_metadata_written: bool,
    face_key_written: bool,
    face_store_enrolled: bool,
    /// `Some(derived_auth)` once enrollment changed the TPM lockout authValue from empty to the
    /// recovery-derived value; rollback restores it to empty using that same value.
    lockout_auth: Option<SecretBytes>,
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
    fn rollback<S: KeySealer>(
        &self,
        sealer: &mut S,
        keyring: &dyn KeyringBackend,
        paths: &Paths,
        old: &SecretBytes,
        face: Option<(&str, &EnrollStore)>,
    ) -> Rollback {
        if let Some(new_key) = &self.new_key {
            if let Err(e) = keyring.rekey(new_key, old) {
                return Rollback::RestoreFailed(anyhow::Error::new(e).context(
                    "could not restore the original keyring credential after a failed enrollment",
                ));
            }
        }
        // Restore the TPM lockout authValue to empty (the stock state for a TPM tess just bound).
        // Authorized by the recovery-derived value we set, so it cannot strand anyone; a failure
        // here leaves only a tess-owned lockout authValue, recoverable with the recovery secret, so
        // it is logged rather than escalated to a keyring-lockout outcome.
        if let Some(derived) = &self.lockout_auth {
            if let Err(e) = sealer.set_lockout_auth(derived, &SecretBytes::new(Vec::new())) {
                eprintln!(
                    "warning: could not restore the TPM lockout authValue to empty during rollback \
                     ({e:#}); it remains bound to the recovery secret"
                );
            } else if let Err(e) = remove_file(&paths.lockout_owned) {
                // Auth is back to empty, so the ownership marker must not linger.
                eprintln!(
                    "warning: could not remove the lockout-ownership marker during rollback ({e:#})"
                );
            }
        }
        // The keyring is safe (on `old`, or never changed). Removing the orphaned blobs is
        // best-effort cleanup; a failure here leaves only stale files, never a lockout.
        let mut cleanup: Result<()> = Ok(());
        if self.face_store_enrolled {
            if let Some((username, store)) = face {
                if let Err(e) = store.remove(username) {
                    cleanup = Err(anyhow!(
                        "remove face enrollment for {username} during rollback: {e}"
                    ));
                }
            }
        }
        if self.face_key_written {
            if let Err(e) = remove_file(&paths.face_key) {
                let err = anyhow::Error::new(e).context(format!(
                    "remove face-unlock key {} during rollback",
                    paths.face_key.display()
                ));
                cleanup = fold_cleanup(cleanup, err);
            }
        }
        if self.face_metadata_written {
            if let Err(e) = remove_file(&paths.metadata_face) {
                let err = anyhow::Error::new(e).context(format!(
                    "remove face sealed metadata {} during rollback",
                    paths.metadata_face.display()
                ));
                cleanup = fold_cleanup(cleanup, err);
            }
        }
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
                cleanup = fold_cleanup(cleanup, err);
            }
        }
        match cleanup {
            Ok(()) => Rollback::Restored,
            Err(e) => Rollback::CleanupFailed(e),
        }
    }
}

/// Chain a later cleanup error onto whatever the cleanup result already holds, preserving the first.
fn fold_cleanup(cleanup: Result<()>, err: anyhow::Error) -> Result<()> {
    match cleanup {
        Ok(()) => Err(err),
        Err(prev) => Err(prev.context(err.to_string())),
    }
}

/// Run the enrollment transaction. `old` is the current keyring credential, `pin` the PIN that will
/// gate the TPM-sealed key, and `verify_item` an additional check that a known pre-existing keyring
/// item still decrypts after the rekey (the CLI passes a no-op; tests assert real items survive).
/// `face`, when supplied, additionally seals the same key under an independent face authValue and
/// enrolls the face template — fully inside the transaction (rolled back on any failure).
pub fn enroll<S: KeySealer>(
    sealer: &mut S,
    keyring: &dyn KeyringBackend,
    paths: &Paths,
    old: &SecretBytes,
    pin: &SecretBytes,
    verify_item: &dyn Fn() -> Result<()>,
    mut face: Option<FaceEnroll>,
) -> Result<EnrollOutcome> {
    ensure!(!pin.is_empty(), "PIN must not be empty");

    // Refuse to clobber an existing enrollment: its blobs are the only way to unseal/recover the
    // current keyring key, and overwriting them here (then deleting them on rollback) could strand
    // the user. The face-unlock artifacts are included so a stale `metadata-face.json`/`face-unlock.key`
    // (e.g. from a prior failed `--face` attempt) can't silently persist a face credential. Run
    // `tess unenroll` to clear a prior enrollment, or remove the named stale blob(s) to re-enroll.
    ensure!(
        !paths.metadata.exists()
            && !paths.recovery.exists()
            && !paths.metadata_face.exists()
            && !paths.face_key.exists(),
        "already enrolled: one of {}, {}, {}, {} already exists. Run `tess unenroll`, or remove the \
         stale blob(s) to re-enroll from scratch.",
        paths.metadata.display(),
        paths.recovery.display(),
        paths.metadata_face.display(),
        paths.face_key.display()
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
    let result = commit(
        &mut tx,
        sealer,
        keyring,
        paths,
        old,
        pin,
        &key,
        &recovery_secret,
        verify_item,
        face.as_mut(),
    );
    match result {
        Ok(()) => Ok(EnrollOutcome {
            recovery_secret_display: display,
        }),
        Err(err) => {
            let face_cleanup = face.as_ref().map(|f| (f.username, f.store));
            match tx.rollback(sealer, keyring, paths, old, face_cleanup) {
                Rollback::Restored => {
                    Err(err
                        .context("enrollment failed and was rolled back to the original keyring"))
                }
                // The keyring is safe (restored to the original credential); only orphaned blobs
                // remain. Do not print or expose the recovery secret — it isn't needed.
                Rollback::CleanupFailed(cleanup_err) => Err(err.context(format!(
                    "enrollment failed and was rolled back to the original keyring, but removing \
                     the orphaned enrollment blobs failed ({cleanup_err:#}); delete them manually"
                ))),
                // Genuine lockout risk: the keyring is stranded on the new key and the blobs were
                // kept. The user needs the recovery secret — print it once to the terminal (like the
                // success path) rather than embedding it in the error chain, which could be logged
                // repeatedly.
                Rollback::RestoreFailed(restore_err) => {
                    eprintln!(
                        "CRITICAL: enrollment failed and the original keyring credential could not \
                         be restored. Save this recovery secret and run `tess recover`:\n\n    \
                         {display}\n"
                    );
                    Err(err.context(format!(
                        "enrollment failed and the original keyring credential could not be \
                         restored ({restore_err:#}); the recovery secret was printed to stderr — \
                         run `tess recover`"
                    )))
                }
            }
        }
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
    face: Option<&mut FaceEnroll>,
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

    // Step 4.5 (optional): the additive face-unlock credential. The same key is sealed a SECOND time
    // under a fresh, independent authValue (`A_face`, not derived from the PIN or recovery secret),
    // that authValue is stored 0600, and the face template is enrolled. Done before the destructive
    // rekey, so any failure here rolls back with the keyring never touched — face is additive and a
    // failure never strands the keyring.
    if let Some(face) = face {
        commit_face(tx, sealer, paths, key, face).context("enroll the face-unlock credential")?;
    }

    // Step 4.6: bind the TPM lockout hierarchy to the recovery secret so a future hard lockout is
    // resettable by the recovery-secret holder (the privileged DA reset). Skipped — with a warning,
    // not an error — when the lockout hierarchy already carries an authValue tess did not set, so a
    // managed machine still enrolls (only the privileged reset is unavailable there).
    if sealer
        .lockout_auth_is_set()
        .context("read the TPM lockout-auth state before binding it")?
    {
        eprintln!(
            "warning: the TPM lockout hierarchy already has an authValue tess did not set; not \
             binding it. Privileged dictionary-attack reset via the recovery secret is unavailable \
             on this machine."
        );
    } else {
        let lockout_auth = recovery::derive_lockout_auth(recovery_secret)
            .context("derive the lockout authValue from the recovery secret")?;
        sealer
            .set_lockout_auth(&SecretBytes::new(Vec::new()), &lockout_auth)
            .context("bind the TPM lockout hierarchy to the recovery secret")?;
        tx.lockout_auth = Some(lockout_auth);
        // Record that tess (not a foreign owner) bound the lockout auth, so unenroll knows it may
        // safely release it. Durable (fsync) so a crash after enroll can't lose the marker while the
        // TPM authValue stays set. Written after the bind so the marker never claims absent ownership.
        recovery::write_durable_marker(&paths.lockout_owned)
            .context("write the lockout-ownership marker")?;
    }

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

/// The additive face-unlock steps, ordered so disk writes only happen after the (failable) capture.
/// Each completed step is recorded in `tx` so rollback removes exactly the face artifacts created.
fn commit_face<S: KeySealer>(
    tx: &mut Tx,
    sealer: &mut S,
    paths: &Paths,
    key: &SecretBytes,
    face: &mut FaceEnroll,
) -> Result<()> {
    // Capture FIRST: a camera/liveness failure aborts before any face artifact reaches disk.
    let template = face
        .template
        .capture_template()
        .context("capture the face enrollment template")?;

    // A fresh independent authValue, drawn from the same getrandom+TPM-RNG mix as the keyring key.
    // It is NOT derived from the PIN or the recovery secret — a distinct on-disk credential.
    let a_face = sealer
        .generate_key()
        .context("generate the independent face authValue")?;

    // Seal the SAME keyring key under `A_face`, and prove it unseals before persisting so a broken
    // face object can never be left behind.
    let sealed = sealer
        .seal(&a_face, key)
        .context("seal the keyring key under the face authValue")?;
    let check = sealer
        .unseal(&sealed, &a_face)
        .context("verify the face-sealed key unseals before persisting")?;
    ensure!(
        check.as_slice() == key.as_slice(),
        "face-sealed key did not unseal to the keyring key"
    );
    let metadata =
        tess_tpm::persist::to_metadata(&sealed).context("encode the face-sealed metadata")?;
    tess_tpm::persist::save(&metadata, &paths.metadata_face)
        .context("persist the face-sealed metadata")?;
    tx.face_metadata_written = true;

    // Store `A_face` durably, 0600.
    recovery::write_secret_file(&paths.face_key, &a_face)
        .context("store the face-unlock authValue")?;
    tx.face_key_written = true;

    // Enroll the face template into the per-user mug store.
    face.store
        .save(face.username, &template)
        .map_err(|e| anyhow!("save the face enrollment for {}: {e}", face.username))?;
    tx.face_store_enrolled = true;
    Ok(())
}

/// Remove a file, treating an already-absent file as success so rollback is idempotent.
pub(crate) fn remove_file(path: &Path) -> std::io::Result<()> {
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

    /// A `KeySealer` that performs no TPM work, for the rollback-state-machine unit tests (which
    /// never exercise sealing). `set_lockout_auth` is a no-op so a rollback that restores the
    /// lockout authValue stays exercisable without a TPM.
    struct NoopSealer;

    impl sealer::KeySealer for NoopSealer {
        fn generate_key(&mut self) -> Result<SecretBytes> {
            unreachable!("rollback tests never generate a key")
        }
        fn seal(
            &mut self,
            _pin: &SecretBytes,
            _key: &SecretBytes,
        ) -> Result<tess_tpm::SealedObject> {
            unreachable!("rollback tests never seal")
        }
        fn unseal(
            &mut self,
            _sealed: &tess_tpm::SealedObject,
            _pin: &SecretBytes,
        ) -> Result<SecretBytes> {
            unreachable!("rollback tests never unseal")
        }
        fn lockout_auth_is_set(&mut self) -> Result<bool> {
            Ok(false)
        }
        fn set_lockout_auth(&mut self, _current: &SecretBytes, _new: &SecretBytes) -> Result<()> {
            Ok(())
        }
    }

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
            lockout_owned: dir.join("lockout-owned"),
            metadata_face: dir.join("metadata-face.json"),
            face_key: dir.join("face-unlock.key"),
        }
    }

    #[test]
    fn resolve_base_prefers_absolute_xdg() {
        let base = Paths::resolve_base(
            Some(OsString::from("/data/xdg")),
            Some(OsString::from("/home/u")),
        )
        .unwrap();
        assert_eq!(base, PathBuf::from("/data/xdg"));
    }

    #[test]
    fn resolve_base_ignores_empty_or_relative_xdg() {
        let from_empty =
            Paths::resolve_base(Some(OsString::from("")), Some(OsString::from("/home/u"))).unwrap();
        assert_eq!(from_empty, PathBuf::from("/home/u/.local/share"));

        let from_relative = Paths::resolve_base(
            Some(OsString::from("relative/dir")),
            Some(OsString::from("/home/u")),
        )
        .unwrap();
        assert_eq!(from_relative, PathBuf::from("/home/u/.local/share"));
    }

    #[test]
    fn resolve_base_rejects_missing_and_empty_home() {
        assert!(Paths::resolve_base(None, None).is_err());
        assert!(Paths::resolve_base(Some(OsString::from("")), Some(OsString::from(""))).is_err());
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
            ..Tx::default()
        };
        assert!(matches!(
            tx.rollback(
                &mut NoopSealer,
                &keyring,
                &p,
                &SecretBytes::new(b"old".to_vec()),
                None,
            ),
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
            ..Tx::default()
        };
        assert!(matches!(
            tx.rollback(
                &mut NoopSealer,
                &keyring,
                &p,
                &SecretBytes::new(b"old".to_vec()),
                None,
            ),
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
            ..Tx::default()
        };
        let outcome = tx.rollback(
            &mut NoopSealer,
            &keyring,
            &p,
            &SecretBytes::new(b"old".to_vec()),
            None,
        );

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
            ..Tx::default()
        };
        let outcome = tx.rollback(
            &mut NoopSealer,
            &keyring,
            &p,
            &SecretBytes::new(b"old".to_vec()),
            None,
        );

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
