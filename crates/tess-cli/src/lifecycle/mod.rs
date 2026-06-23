//! The post-enrollment lifecycle subcommands — `recover`, `unenroll`, `status`, `unlock`, `test` —
//! built on the same seal/unseal, recovery, and in-place rekey building blocks the enrollment
//! transaction uses. No cryptography is reimplemented here: this module composes
//! [`crate::enroll::recovery`], [`crate::enroll::sealer`], and `tess_tpm::persist`/`unseal` into the
//! remaining user-facing flows, reusing the credential-first rollback discipline for the one other
//! destructive path (`unenroll`).

pub mod cli;

use anyhow::{ensure, Context, Result};
use mug::EnrollStore;
use tess_core::{KeyringBackend, SecretBytes};
use tess_tpm::{persist, LockoutState, TctiConfig};

use crate::doctor::{lockout_summary, read_caps};
use crate::enroll::sealer::KeySealer;
use crate::enroll::{recovery, Paths};

/// Fail fast when there is no sealed enrollment to act on. Called by the CLI *before* prompting for
/// a PIN or opening the TPM so a not-enrolled user gets the right message with no wasted prompt.
pub fn ensure_enrolled(paths: &Paths) -> Result<()> {
    ensure!(
        paths.metadata.exists(),
        "not enrolled: {} does not exist (run `tess enroll` first)",
        paths.metadata.display()
    );
    Ok(())
}

/// Fail fast when there is no recovery blob to recover from. Called by the CLI *before* prompting for
/// the recovery secret.
pub fn ensure_recoverable(paths: &Paths) -> Result<()> {
    ensure!(
        paths.recovery.exists(),
        "no recovery blob at {} (nothing to recover)",
        paths.recovery.display()
    );
    Ok(())
}

/// Reconstruct the sealed object from `paths.metadata` and unseal it with `pin`, recovering the
/// keyring key. Errors if the enrollment metadata is absent or unreadable, so the caller never
/// proceeds against a missing enrollment.
fn unseal_with_pin<S: KeySealer>(
    sealer: &mut S,
    paths: &Paths,
    pin: &SecretBytes,
) -> Result<SecretBytes> {
    ensure_enrolled(paths)?;
    let metadata = persist::load(&paths.metadata)
        .with_context(|| format!("load sealed metadata {}", paths.metadata.display()))?;
    let sealed =
        persist::from_metadata(&metadata).context("reconstruct the sealed object from metadata")?;
    sealer
        .unseal(&sealed, pin)
        .context("unseal the keyring key with the PIN")
}

/// Recover the keyring key from the TPM-independent recovery blob (`paths.recovery`) using
/// `recovery_secret`. Works with no TPM at all — the whole point of the recovery path.
fn recovered_key(paths: &Paths, recovery_secret: &SecretBytes) -> Result<SecretBytes> {
    ensure_recoverable(paths)?;
    let blob = recovery::load_blob(&paths.recovery).context("load the recovery blob")?;
    recovery::unwrap_key(&blob, recovery_secret)
        .context("unwrap the keyring key with the recovery secret")
}

/// Unlock the keyring with `secret` and confirm it actually opened.
fn unlock_and_verify(keyring: &dyn KeyringBackend, secret: &SecretBytes, what: &str) -> Result<()> {
    keyring
        .unlock(secret)
        .with_context(|| format!("unlock the login keyring with the {what}"))?;
    ensure!(
        !keyring
            .is_locked()
            .context("re-read keyring lock state after unlocking")?,
        "keyring still locked after unlocking with the {what}"
    );
    Ok(())
}

/// `tess unlock` — one-shot manual unlock: unseal the keyring key with the PIN, then unlock the
/// login keyring with it. Changes only the keyring's lock state; no blob is written or removed.
pub fn unlock<S: KeySealer>(
    sealer: &mut S,
    keyring: &dyn KeyringBackend,
    paths: &Paths,
    pin: &SecretBytes,
) -> Result<()> {
    let key = unseal_with_pin(sealer, paths, pin)?;
    unlock_and_verify(keyring, &key, "unsealed key")
}

/// Whether the face-unlock credential is enrolled (both the face-sealed metadata and the on-disk
/// face authValue are present).
pub fn face_enrolled(paths: &Paths) -> bool {
    paths.metadata_face.exists() && paths.face_key.exists()
}

/// `tess unlock --face` (post-gate half): unseal the keyring key via the on-disk face authValue and
/// unlock the keyring with it. Assumes the liveness-gated face match already passed; the caller runs
/// the match first and falls back to the PIN path on any failure here.
pub fn unlock_with_face<S: KeySealer>(
    sealer: &mut S,
    keyring: &dyn KeyringBackend,
    paths: &Paths,
) -> Result<()> {
    ensure!(
        face_enrolled(paths),
        "face-unlock is not enrolled ({} or {} is missing)",
        paths.metadata_face.display(),
        paths.face_key.display()
    );
    let key = crate::face::unseal_with_face(sealer, paths)?;
    unlock_and_verify(keyring, &key, "face-unsealed key")
}

/// `tess recover` — re-establish keyring access using the recovery secret when the TPM path is
/// unavailable (cleared TPM, lost PIN, changed PCRs). Unwraps the keyring key from the recovery blob
/// and unlocks the keyring with it. Non-destructive: it neither rekeys nor removes any blob.
pub fn recover(
    keyring: &dyn KeyringBackend,
    paths: &Paths,
    recovery_secret: &SecretBytes,
) -> Result<()> {
    let key = recovered_key(paths, recovery_secret)?;
    unlock_and_verify(keyring, &key, "recovered key")
}

/// Reset a *hard* TPM dictionary-attack lockout using the recovery secret, so the normal PIN-unseal
/// path works again. Reads the lockout state first; when the TPM is hard-locked it derives the
/// lockout-hierarchy authValue from `recovery_secret` and runs the privileged
/// `TPM2_DictionaryAttackLockReset` (via `tess_tpm::reset_lockout`). Returns whether a reset was
/// performed (`false` when the TPM was not locked out, so the caller can stay quiet). The TPM read
/// and the subprocess run sequentially — no ESAPI context is held open while tpm2-tools talks to the
/// same (single-client) TPM.
pub fn reset_hard_lockout(tcti: &TctiConfig, recovery_secret: &SecretBytes) -> Result<bool> {
    let (_, lockout) =
        read_caps(tcti).map_err(|e| anyhow::anyhow!("read TPM lockout state before reset: {e}"))?;
    if !lockout.is_locked_out() {
        return Ok(false);
    }
    let lockout_auth = recovery::derive_lockout_auth(recovery_secret)
        .context("derive the lockout authValue from the recovery secret")?;
    tess_tpm::reset_lockout(tcti, &lockout_auth)
        .context("run the privileged TPM dictionary-attack lockout reset")?;
    Ok(true)
}

/// Re-seal the recovered keyring key under `new_pin` against the current TPM and rewrite the sealed
/// metadata, re-establishing the normal PIN-unseal path after a TPM clear. The keyring credential is
/// unchanged (it remains the recovered key), so this only seals + atomically overwrites
/// `paths.metadata`; the recovery blob still wraps the same key and is left untouched.
pub fn reseal<S: KeySealer>(
    sealer: &mut S,
    paths: &Paths,
    recovery_secret: &SecretBytes,
    new_pin: &SecretBytes,
) -> Result<()> {
    ensure!(!new_pin.is_empty(), "PIN must not be empty");
    let key = recovered_key(paths, recovery_secret)?;
    let sealed = sealer
        .seal(new_pin, &key)
        .context("seal the recovered key under the new PIN")?;
    let check = sealer
        .unseal(&sealed, new_pin)
        .context("verify the re-sealed key unseals with the new PIN before persisting")?;
    ensure!(
        check.as_slice() == key.as_slice(),
        "re-sealed key did not unseal to the recovered key"
    );
    let metadata = persist::to_metadata(&sealed).context("encode the re-sealed metadata")?;
    persist::save(&metadata, &paths.metadata).context("persist the re-sealed metadata")?;
    Ok(())
}

/// `tess unenroll` — transactionally rekey the login keyring from the TPM-sealed key back to a
/// user-supplied password and remove the sealed + recovery blobs, restoring stock password-based
/// behaviour with every item intact. Reuses enrollment's credential-first rollback discipline: the
/// destructive rekey is verified before any blob is removed, and a failed verification rekeys back to
/// the TPM-sealed key (keeping the blobs, which still gate that key) rather than stranding the user.
///
/// When `recovery_secret` is supplied, the TPM lockout-hierarchy authValue tess bound at enroll is
/// also reset to empty (authorized by the recovery-derived value), leaving the lockout hierarchy as
/// tess found it. Releasing the lockout hierarchy is best-effort: it runs only after the keyring is
/// safely back on the password, and a failure is surfaced as a warning rather than failing the
/// unenroll (the keyring — the load-bearing guarantee — is already restored).
pub fn unenroll<S: KeySealer>(
    sealer: &mut S,
    keyring: &dyn KeyringBackend,
    paths: &Paths,
    pin: &SecretBytes,
    new_password: &SecretBytes,
    recovery_secret: Option<&SecretBytes>,
    face: Option<(&str, &EnrollStore)>,
) -> Result<()> {
    ensure!(
        !new_password.is_empty(),
        "the new keyring password must not be empty"
    );

    // Prove the PIN and recover the current keyring credential (the TPM-sealed key) before touching
    // anything, and confirm it actually opens (and unlocks) the keyring.
    let key = unseal_with_pin(sealer, paths, pin)?;
    unlock_and_verify(keyring, &key, "TPM-sealed key before unenrolling")?;

    // Destructive: rekey in place to the user password. `rekey` is a single atomic Secret Service
    // call, so a failure here leaves the keyring on the TPM-sealed key with the blobs intact.
    keyring
        .rekey(&key, new_password)
        .context("rekey the login keyring back to the password")?;

    if let Err(err) = unlock_and_verify(keyring, new_password, "restored password") {
        // The rekey landed but the keyring would not open with the password: rekey back to the
        // TPM-sealed key (still gated by the kept blobs) so the user is never locked out.
        keyring.rekey(new_password, &key).context(
            "restore the keyring to the TPM-sealed key after a failed unenroll verification",
        )?;
        return Err(err
            .context("unenroll failed after rekey and was rolled back to the TPM-sealed keyring"));
    }

    // The keyring is safely on the user password. Release the TPM lockout hierarchy back to empty so
    // uninstalling tess leaves the TPM as it was found. Best-effort: a failure here is not a keyring
    // lockout, so warn and continue to blob removal rather than failing the whole unenroll.
    if let Some(recovery_secret) = recovery_secret {
        if let Err(err) = release_lockout_auth(sealer, paths, recovery_secret) {
            eprintln!(
                "warning: could not reset the TPM lockout-hierarchy authValue to empty ({err:#}); \
                 it remains bound to the recovery secret"
            );
        }
    }

    // The sealed/recovery blobs are now stale. Removing them is the final, non-destructive cleanup —
    // a failure here leaves only orphaned files.
    remove_blobs(paths, face)
        .context("remove the sealed metadata and recovery blob after a successful unenroll")
}

/// Reset the TPM lockout-hierarchy authValue from the recovery-derived value back to empty. A no-op
/// (with no error) when tess does not own the lockout hierarchy — gated on the `lockout_owned`
/// marker written at enroll, NOT on the TPM's `lockoutAuthSet` bit (which is also set by a foreign
/// owner). On a managed machine where enroll skipped binding, the marker is absent, so unenroll
/// never authorizes a wrong reset that would self-lock the lockout hierarchy.
fn release_lockout_auth<S: KeySealer>(
    sealer: &mut S,
    paths: &Paths,
    recovery_secret: &SecretBytes,
) -> Result<()> {
    if !paths.lockout_owned.exists() {
        return Ok(());
    }
    let lockout_auth = recovery::derive_lockout_auth(recovery_secret)
        .context("derive the lockout authValue from the recovery secret")?;
    sealer
        .set_lockout_auth(&lockout_auth, &SecretBytes::new(Vec::new()))
        .context("reset the TPM lockout-hierarchy authValue to empty")?;
    crate::enroll::remove_file(&paths.lockout_owned)
        .with_context(|| format!("remove {}", paths.lockout_owned.display()))
}

/// Remove the sealed metadata, recovery blob, and any face-unlock artifacts, idempotently (an
/// already-absent file is success). The `lockout-owned` marker is intentionally NOT removed here: it
/// tracks whether tess still owns the TPM lockout authValue, which `release_lockout_auth` clears
/// (and the marker with it) only when the auth is actually released. Deleting it unconditionally
/// would orphan a still-bound auth — a later re-enroll would see `lockoutAuthSet` and wrongly treat
/// tess's own auth as a foreign owner. The mug store entry is removed when `face` is supplied.
fn remove_blobs(paths: &Paths, face: Option<(&str, &EnrollStore)>) -> Result<()> {
    crate::enroll::remove_file(&paths.metadata)
        .with_context(|| format!("remove {}", paths.metadata.display()))?;
    crate::enroll::remove_file(&paths.recovery)
        .with_context(|| format!("remove {}", paths.recovery.display()))?;
    crate::enroll::remove_file(&paths.metadata_face)
        .with_context(|| format!("remove {}", paths.metadata_face.display()))?;
    crate::enroll::remove_file(&paths.face_key)
        .with_context(|| format!("remove {}", paths.face_key.display()))?;
    if let Some((username, store)) = face {
        store
            .remove(username)
            .map_err(|e| anyhow::anyhow!("remove the face enrollment for {username}: {e}"))?;
    }
    Ok(())
}

/// The TPM facts `status`/`test` surface: version string and DA-lockout snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmInfo {
    pub version: String,
    pub lockout: LockoutState,
}

/// Read-only snapshot of enrollment, keyring, and TPM state for `tess status`. Every field is
/// best-effort; an unreadable component carries its reason rather than failing the command.
#[derive(Debug, Clone)]
pub struct StatusReport {
    pub metadata_present: bool,
    pub recovery_present: bool,
    /// Whether the face-unlock credential (face metadata + on-disk authValue) is enrolled.
    pub face_present: bool,
    /// `None` when the lock state was not probed; `Some(Err)` carries why it could not be read.
    pub keyring_locked: Option<std::result::Result<bool, String>>,
    pub tpm: std::result::Result<TpmInfo, String>,
}

/// Gather [`StatusReport`]. `keyring_locked` is supplied by the caller (so the I/O and its error
/// surface are testable in isolation); the TPM read goes through the shared read-only cap probe.
pub fn gather_status(
    paths: &Paths,
    keyring_locked: Option<std::result::Result<bool, String>>,
    tcti: &TctiConfig,
) -> StatusReport {
    StatusReport {
        metadata_present: paths.metadata.exists(),
        recovery_present: paths.recovery.exists(),
        face_present: face_enrolled(paths),
        keyring_locked,
        tpm: read_caps(tcti).map(|(version, lockout)| TpmInfo {
            version: version.to_string(),
            lockout,
        }),
    }
}

/// Render a [`StatusReport`] as a short aligned report.
pub fn render_status(report: &StatusReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "tess status");
    let _ = writeln!(
        out,
        "  enrollment:    {}",
        if report.metadata_present {
            "enrolled (sealed metadata present)"
        } else {
            "not enrolled"
        }
    );
    let _ = writeln!(
        out,
        "  recovery blob: {}",
        if report.recovery_present {
            "present"
        } else {
            "absent"
        }
    );
    let _ = writeln!(
        out,
        "  face-unlock:   {}",
        if report.face_present {
            "enrolled"
        } else {
            "not enrolled"
        }
    );
    let _ = writeln!(
        out,
        "  keyring:       {}",
        keyring_phrase(&report.keyring_locked)
    );
    let _ = writeln!(out, "  TPM:           {}", tpm_phrase(&report.tpm));
    out
}

/// Read-only "would the session unlock path work right now?" verdict for `tess test`. Performs no
/// unseal and no unlock, so it consumes no DA attempt and changes nothing.
#[derive(Debug, Clone)]
pub struct DryRun {
    pub metadata_present: bool,
    /// `Ok` when the metadata loads and reconstructs into a sealed object; `Err` carries the reason.
    pub metadata_loadable: std::result::Result<(), String>,
    /// DA-lockout snapshot, or why the TPM could not be reached.
    pub tpm: std::result::Result<LockoutState, String>,
    pub keyring_locked: Option<std::result::Result<bool, String>>,
}

impl DryRun {
    /// Whether the session unlock path would succeed: enrolled, metadata loadable, TPM reachable and
    /// not locked out, and the keyring reachable (already-unlocked counts as success).
    pub fn would_succeed(&self) -> bool {
        self.blocking_reasons().is_empty()
    }

    /// Human-readable reasons the session unlock path would fail, empty when it would succeed.
    pub fn blocking_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if !self.metadata_present {
            reasons.push("not enrolled (no sealed metadata)".to_string());
        } else if let Err(e) = &self.metadata_loadable {
            reasons.push(format!("sealed metadata is not loadable ({e})"));
        }
        match &self.tpm {
            Ok(lockout) if lockout.is_locked_out() => {
                reasons.push("TPM is in dictionary-attack lockout".to_string())
            }
            Ok(_) => {}
            Err(e) => reasons.push(format!("TPM unavailable ({e})")),
        }
        match &self.keyring_locked {
            Some(Ok(_)) => {}
            Some(Err(e)) => reasons.push(format!("keyring unavailable ({e})")),
            None => reasons.push("keyring state was not probed".to_string()),
        }
        reasons
    }
}

/// Gather a [`DryRun`] without unsealing or unlocking anything.
pub fn dry_run(
    paths: &Paths,
    keyring_locked: Option<std::result::Result<bool, String>>,
    tcti: &TctiConfig,
) -> DryRun {
    let metadata_present = paths.metadata.exists();
    let metadata_loadable = if metadata_present {
        persist::load(&paths.metadata)
            .map_err(|e| e.to_string())
            .and_then(|m| {
                persist::from_metadata(&m)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
    } else {
        Err("no sealed metadata".to_string())
    };
    DryRun {
        metadata_present,
        metadata_loadable,
        tpm: read_caps(tcti).map(|(_, lockout)| lockout),
        keyring_locked,
    }
}

/// Render a [`DryRun`] as a short report ending in a one-line verdict.
pub fn render_dry_run(report: &DryRun) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "tess test — session unlock dry-run (no changes made)");
    let _ = writeln!(
        out,
        "  enrollment:    {}",
        match (&report.metadata_present, &report.metadata_loadable) {
            (true, Ok(())) => "present and loadable".to_string(),
            (true, Err(e)) => format!("present but not loadable ({e})"),
            (false, _) => "absent".to_string(),
        }
    );
    let _ = writeln!(
        out,
        "  TPM:           {}",
        match &report.tpm {
            Ok(lockout) => lockout_summary(lockout),
            Err(e) => format!("unavailable ({e})"),
        }
    );
    let _ = writeln!(
        out,
        "  keyring:       {}",
        keyring_phrase(&report.keyring_locked)
    );
    let reasons = report.blocking_reasons();
    if reasons.is_empty() {
        let _ = writeln!(out, "  verdict:       session unlock WOULD SUCCEED");
    } else {
        let _ = writeln!(
            out,
            "  verdict:       session unlock WOULD FAIL — {}",
            reasons.join("; ")
        );
    }
    out
}

fn keyring_phrase(locked: &Option<std::result::Result<bool, String>>) -> String {
    match locked {
        None => "unknown".to_string(),
        Some(Ok(true)) => "locked".to_string(),
        Some(Ok(false)) => "unlocked".to_string(),
        Some(Err(e)) => format!("unavailable ({e})"),
    }
}

fn tpm_phrase(tpm: &std::result::Result<TpmInfo, String>) -> String {
    match tpm {
        Ok(info) => format!("{}; {}", info.version, lockout_summary(&info.lockout)),
        Err(e) => format!("unavailable ({e})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lockout(counter: u32, max: u32) -> LockoutState {
        LockoutState {
            counter,
            max_auth_fail: max,
            interval: 100,
        }
    }

    #[test]
    fn status_renders_enrolled_unlocked_and_tpm() {
        let report = StatusReport {
            metadata_present: true,
            recovery_present: true,
            face_present: true,
            keyring_locked: Some(Ok(false)),
            tpm: Ok(TpmInfo {
                version: "TPM 2.0 (spec rev 138)".to_string(),
                lockout: lockout(0, 3),
            }),
        };
        let out = render_status(&report);
        assert!(out.contains("enrolled (sealed metadata present)"));
        assert!(out.contains("recovery blob: present"));
        assert!(out.contains("face-unlock:   enrolled"));
        assert!(out.contains("keyring:       unlocked"));
        assert!(out.contains("TPM 2.0 (spec rev 138); DA lockout 0/3"));
    }

    #[test]
    fn status_renders_not_enrolled_and_unavailable_components() {
        let report = StatusReport {
            metadata_present: false,
            recovery_present: false,
            face_present: false,
            keyring_locked: Some(Err("connect: no bus".to_string())),
            tpm: Err("no TCTI library".to_string()),
        };
        let out = render_status(&report);
        assert!(out.contains("not enrolled"));
        assert!(out.contains("recovery blob: absent"));
        assert!(out.contains("face-unlock:   not enrolled"));
        assert!(out.contains("keyring:       unavailable (connect: no bus)"));
        assert!(out.contains("TPM:           unavailable (no TCTI library)"));
    }

    #[test]
    fn status_keyring_unknown_when_not_probed() {
        let report = StatusReport {
            metadata_present: true,
            recovery_present: false,
            face_present: false,
            keyring_locked: None,
            tpm: Err("busy".to_string()),
        };
        assert!(render_status(&report).contains("keyring:       unknown"));
    }

    #[test]
    fn dry_run_succeeds_when_all_ready() {
        let report = DryRun {
            metadata_present: true,
            metadata_loadable: Ok(()),
            tpm: Ok(lockout(0, 3)),
            keyring_locked: Some(Ok(true)),
        };
        assert!(report.would_succeed());
        assert!(report.blocking_reasons().is_empty());
        assert!(render_dry_run(&report).contains("WOULD SUCCEED"));
    }

    #[test]
    fn dry_run_fails_and_lists_every_blocker() {
        let report = DryRun {
            metadata_present: false,
            metadata_loadable: Err("no sealed metadata".to_string()),
            tpm: Err("no TPM".to_string()),
            keyring_locked: Some(Err("no bus".to_string())),
        };
        assert!(!report.would_succeed());
        let reasons = report.blocking_reasons();
        assert!(reasons.iter().any(|r| r.contains("not enrolled")));
        assert!(reasons.iter().any(|r| r.contains("TPM unavailable")));
        assert!(reasons.iter().any(|r| r.contains("keyring unavailable")));
        assert!(render_dry_run(&report).contains("WOULD FAIL"));
    }

    #[test]
    fn dry_run_flags_lockout_as_blocking() {
        let report = DryRun {
            metadata_present: true,
            metadata_loadable: Ok(()),
            tpm: Ok(lockout(3, 3)),
            keyring_locked: Some(Ok(true)),
        };
        assert!(!report.would_succeed());
        assert!(report
            .blocking_reasons()
            .iter()
            .any(|r| r.contains("lockout")));
    }

    #[test]
    fn dry_run_unloadable_metadata_is_blocking() {
        let report = DryRun {
            metadata_present: true,
            metadata_loadable: Err("bad base64".to_string()),
            tpm: Ok(lockout(0, 3)),
            keyring_locked: Some(Ok(true)),
        };
        assert!(!report.would_succeed());
        assert!(report
            .blocking_reasons()
            .iter()
            .any(|r| r.contains("not loadable")));
    }
}
