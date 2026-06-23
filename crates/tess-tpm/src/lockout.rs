//! Read the TPM's dictionary-attack (DA) lockout state and let the legitimate PIN holder recover
//! before hard lockout.
//!
//! The sealed object is DA-protected, so each wrong PIN counts toward the TPM's global
//! `lockoutCounter`. Once it reaches `maxAuthFail` the TPM refuses further DA-protected
//! authorizations until the lockout is reset or self-heals over the lockout interval. Reading the
//! counter lets callers warn before lockout; mapping the TPM's lockout response code to a distinct
//! error lets callers tell "locked out" apart from "wrong PIN".

use std::io::{Read as _, Write as _};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tess_core::SecretBytes;
use tss_esapi::constants::{CapabilityType, PropertyTag};
use tss_esapi::handles::{AuthHandle, KeyHandle, ObjectHandle, SessionHandle};
use tss_esapi::structures::{Auth, CapabilityData};
use tss_esapi::Context;

use crate::esapi::{start_salted_hmac_session, Error, Result};
use crate::seal::{flush, unseal, SealedObject};
use crate::TctiConfig;

/// `TPMA_PERMANENT.lockoutAuthSet` (bit 2): set once the lockout-hierarchy authValue is non-empty.
/// Read via `TPM2_GetCapability` on `TPM2_PT_PERMANENT` — a read-only probe that, unlike trying a
/// wrong auth, does not touch the lockout DA counter. (TCG TPM2 spec, Part 2, TPMA_PERMANENT.)
const TPMA_PERMANENT_LOCKOUT_AUTH_SET: u32 = 0x0000_0004;

/// Largest authValue tess sets on the lockout hierarchy: the SHA-256 digest size, the cap for an
/// authValue on a TPM whose lockout name algorithm is SHA-256.
const MAX_LOCKOUT_AUTH_LEN: usize = 32;

/// A snapshot of the TPM's dictionary-attack lockout parameters and current failure count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutState {
    /// `TPM2_PT_LOCKOUT_COUNTER`: failed DA-protected authorizations since the last reset.
    pub counter: u32,
    /// `TPM2_PT_MAX_AUTH_FAIL`: the count at which the TPM enters lockout. `0` means DA lockout is
    /// disabled (the TPM never locks out on auth failures).
    pub max_auth_fail: u32,
    /// `TPM2_PT_LOCKOUT_INTERVAL`: seconds before the counter self-decrements by one.
    pub interval: u32,
}

impl LockoutState {
    /// Whether the TPM is currently in (or past) DA lockout: the counter has reached the configured
    /// maximum. Always `false` when DA lockout is disabled (`max_auth_fail == 0`).
    pub fn is_locked_out(&self) -> bool {
        self.max_auth_fail != 0 && self.counter >= self.max_auth_fail
    }

    /// Remaining wrong attempts before lockout, or `None` when DA lockout is disabled.
    pub fn remaining_attempts(&self) -> Option<u32> {
        if self.max_auth_fail == 0 {
            None
        } else {
            Some(self.max_auth_fail.saturating_sub(self.counter))
        }
    }
}

/// Read the current DA-lockout state via `TPM2_GetCapability` on the relevant TPM properties. A
/// read-only operation needing no authorization or session.
pub fn read_lockout_state(context: &mut Context) -> Result<LockoutState> {
    Ok(LockoutState {
        counter: read_property(context, PropertyTag::LockoutCounter)?,
        max_auth_fail: read_property(context, PropertyTag::MaxAuthFail)?,
        interval: read_property(context, PropertyTag::LockoutInterval)?,
    })
}

/// Read a single TPM property as a `u32`. `get_capability` returns the requested property (or the
/// next defined one at/after it); the lockout properties are defined on every TPM2, so request
/// exactly one and confirm the tag matches rather than trusting positional return.
pub(crate) fn read_property(context: &mut Context, tag: PropertyTag) -> Result<u32> {
    let (data, _more) = context
        .get_capability(CapabilityType::TpmProperties, u32::from(tag), 1)
        .map_err(|e| Error::Capability(e.to_string()))?;

    let CapabilityData::TpmProperties(properties) = data else {
        return Err(Error::Capability(
            "TPM returned a non-property capability for a property query".to_string(),
        ));
    };

    properties
        .iter()
        .find(|property| property.property() == tag)
        .map(|property| property.value())
        .ok_or_else(|| Error::Capability(format!("TPM did not report property {tag:?}")))
}

/// Recover from *accumulated* DA failures, before hard lockout, by proving the PIN with one
/// successful unseal. This is the safe, PIN-holder-driven path: the legitimate user demonstrating
/// the PIN confirms they can still authorize, and the recovered secret is dropped immediately — the
/// call exists only to exercise the authorization, not to hand back the key.
///
/// This is **not** the privileged DA-counter reset: once the TPM is in *hard* lockout
/// (`counter >= max_auth_fail`) it refuses the authorization with [`Error::Lockout`], which this
/// function surfaces rather than clears. Escaping a hard lockout needs the lockout hierarchy's
/// `TPM2_DictionaryAttackLockReset` ([`reset_lockout`], gated by the recovery secret) or waiting out
/// the lockout interval.
pub fn pin_holder_recover(
    context: &mut Context,
    primary: KeyHandle,
    sealed: &SealedObject,
    pin: &tess_core::SecretBytes,
) -> Result<()> {
    if read_lockout_state(context)?.is_locked_out() {
        return Err(Error::Lockout);
    }
    let _secret = unseal(context, primary, sealed, pin)?;
    Ok(())
}

/// Whether the TPM lockout hierarchy already carries a non-empty authValue (`lockoutAuthSet`). A
/// read-only `TPM2_GetCapability` probe — it never tries an authorization, so it consumes no DA
/// attempt. Enrollment reads this first and refuses to clobber a lockout hierarchy it did not set.
pub fn lockout_auth_is_set(context: &mut Context) -> Result<bool> {
    let permanent = read_property(context, PropertyTag::Permanent)?;
    Ok(permanent & TPMA_PERMANENT_LOCKOUT_AUTH_SET != 0)
}

/// Change the TPM lockout-hierarchy authValue from `current` to `new`, under the mandatory salted
/// HMAC + parameter-encryption session (so the new authValue is encrypted on the bus). An empty
/// `SecretBytes` denotes the empty authValue: enrollment sets `empty -> derived`, unenroll restores
/// `derived -> empty`. `current` is bound to the permanent lockout handle so the session can
/// authorize the change with whatever the hierarchy's authValue currently is.
pub fn set_lockout_auth(
    context: &mut Context,
    primary: KeyHandle,
    current: &SecretBytes,
    new: &SecretBytes,
) -> Result<()> {
    let current_auth = lockout_auth_value(current)?;
    let new_auth = lockout_auth_value(new)?;

    context
        .tr_set_auth(ObjectHandle::Lockout, current_auth)
        .map_err(|e| Error::LockoutAuth(e.to_string()))?;

    let session = start_salted_hmac_session(context, primary)?;
    let changed = context.execute_with_session(Some(session), |ctx| {
        ctx.hierarchy_change_auth(AuthHandle::Lockout, new_auth)
    });
    let session_flushed = flush(context, SessionHandle::from(session).into());

    changed.map_err(|e| Error::LockoutAuth(e.to_string()))?;
    session_flushed?;
    Ok(())
}

/// Convert a recovery-derived secret into the TPM lockout `Auth`, rejecting anything longer than the
/// SHA-256 authValue cap. An empty secret yields the empty authValue (the stock lockout state).
fn lockout_auth_value(secret: &SecretBytes) -> Result<Auth> {
    if secret.len() > MAX_LOCKOUT_AUTH_LEN {
        return Err(Error::LockoutAuth(format!(
            "lockout authValue is {} bytes, exceeds the {MAX_LOCKOUT_AUTH_LEN}-byte limit",
            secret.len()
        )));
    }
    Auth::try_from(secret.as_slice()).map_err(|e| Error::LockoutAuth(e.to_string()))
}

/// Wall-clock cap on the `tpm2_dictionarylockout` subprocess so a hung TPM/TCTI can't hang recovery.
const RESET_TIMEOUT: Duration = Duration::from_secs(30);
const RESET_POLL: Duration = Duration::from_millis(50);

/// Kills and reaps the wrapped child on drop unless [`Self::disarm`]ed, so no early return (a failed
/// stdin write, a timeout) can leak a live `tpm2_dictionarylockout` process.
struct ReapOnDrop(Option<Child>);

impl ReapOnDrop {
    fn child(&mut self) -> &mut Child {
        self.0.as_mut().expect("child present until dropped")
    }
}

impl Drop for ReapOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Privileged dictionary-attack reset: run `TPM2_DictionaryAttackLockReset` so the global
/// `lockoutCounter` returns to zero even from a *hard* lockout, authorized by the lockout-hierarchy
/// authValue. The pinned `tss-esapi` 7.7 exposes no safe wrapper for this command, so it runs via
/// the tpm2-tools `tpm2_dictionarylockout` subprocess (keeping `tess-tpm` free of `unsafe`).
///
/// `lockout_auth` is the raw authValue (recovery-derived, set by [`set_lockout_auth`]). It is fed on
/// the subprocess **stdin** (`--auth file:-`), never argv, so it does not leak via `/proc`.
/// `TPM2TOOLS_TCTI` is set to the same transport tess uses so tpm2-tools targets the same TPM. The
/// child is bounded by [`RESET_TIMEOUT`] and reaped on every exit path (failure, timeout, success).
/// A wrong authValue (or a still-locked lockout hierarchy) makes tpm2-tools exit non-zero, surfaced
/// as [`Error::LockoutReset`].
pub fn reset_lockout(tcti: &TctiConfig, lockout_auth: &SecretBytes) -> Result<()> {
    let child = Command::new("tpm2_dictionarylockout")
        .arg("--clear-lockout")
        .arg("--auth")
        .arg("file:-")
        .env("TPM2TOOLS_TCTI", tcti.tpm2_tools_tcti())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::LockoutReset(
                "tpm2_dictionarylockout not found; install tpm2-tools for hard-lockout recovery"
                    .to_string(),
            ),
            _ => Error::LockoutReset(format!("spawn tpm2_dictionarylockout: {e}")),
        })?;
    // From here every early return drops `guard`, which kills + reaps the child.
    let mut guard = ReapOnDrop(Some(child));

    {
        let mut stdin = guard.child().stdin.take().ok_or_else(|| {
            Error::LockoutReset("tpm2_dictionarylockout stdin unavailable".to_string())
        })?;
        stdin
            .write_all(lockout_auth.as_slice())
            .map_err(|e| Error::LockoutReset(format!("write authValue to stdin: {e}")))?;
        // stdin dropped here → EOF so tpm2-tools stops reading the authValue.
    }

    let deadline = Instant::now() + RESET_TIMEOUT;
    loop {
        let status = guard
            .child()
            .try_wait()
            .map_err(|e| Error::LockoutReset(format!("wait for tpm2_dictionarylockout: {e}")))?;
        match status {
            Some(status) => {
                let mut stderr = String::new();
                if let Some(mut handle) = guard.child().stderr.take() {
                    let _ = handle.read_to_string(&mut stderr);
                }
                // `try_wait` already reaped the exited child; `guard` drops harmlessly here.
                if !status.success() {
                    return Err(Error::LockoutReset(format!(
                        "tpm2_dictionarylockout exited with {}: {}",
                        status,
                        stderr.trim()
                    )));
                }
                return Ok(());
            }
            None => {
                if Instant::now() >= deadline {
                    return Err(Error::LockoutReset(format!(
                        "tpm2_dictionarylockout timed out after {}s",
                        RESET_TIMEOUT.as_secs()
                    )));
                }
                std::thread::sleep(RESET_POLL);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_out_when_counter_reaches_max() {
        let state = LockoutState {
            counter: 3,
            max_auth_fail: 3,
            interval: 100,
        };
        assert!(state.is_locked_out());
        assert_eq!(state.remaining_attempts(), Some(0));
    }

    #[test]
    fn not_locked_out_below_max() {
        let state = LockoutState {
            counter: 1,
            max_auth_fail: 3,
            interval: 100,
        };
        assert!(!state.is_locked_out());
        assert_eq!(state.remaining_attempts(), Some(2));
    }

    #[test]
    fn disabled_lockout_never_locks() {
        let state = LockoutState {
            counter: 9999,
            max_auth_fail: 0,
            interval: 0,
        };
        assert!(!state.is_locked_out());
        assert_eq!(state.remaining_attempts(), None);
    }

    #[test]
    fn lockout_auth_value_accepts_empty_and_max() {
        assert!(lockout_auth_value(&SecretBytes::new(Vec::new())).is_ok());
        assert!(lockout_auth_value(&SecretBytes::new(vec![0u8; MAX_LOCKOUT_AUTH_LEN])).is_ok());
    }

    #[test]
    fn lockout_auth_value_rejects_oversized() {
        let too_long = SecretBytes::new(vec![0u8; MAX_LOCKOUT_AUTH_LEN + 1]);
        assert!(matches!(
            lockout_auth_value(&too_long),
            Err(Error::LockoutAuth(_))
        ));
    }
}
