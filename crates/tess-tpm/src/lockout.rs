//! Read the TPM's dictionary-attack (DA) lockout state and clear an accumulated failure count.
//!
//! The sealed object is DA-protected, so each wrong PIN counts toward the TPM's global
//! `lockoutCounter`. Once it reaches `maxAuthFail` the TPM refuses further DA-protected
//! authorizations until the lockout is reset or self-heals over `lockoutInterval`. Reading the
//! counter lets callers warn before lockout; mapping the TPM's lockout response code to a distinct
//! error lets callers tell "locked out" apart from "wrong PIN".

use tss_esapi::constants::{CapabilityType, PropertyTag};
use tss_esapi::handles::KeyHandle;
use tss_esapi::structures::CapabilityData;
use tss_esapi::Context;

use crate::esapi::{Error, Result};
use crate::seal::{unseal, SealedObject};

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
fn read_property(context: &mut Context, tag: PropertyTag) -> Result<u32> {
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
/// Once the TPM is in *hard* lockout (`counter >= max_auth_fail`) it refuses the authorization with
/// [`Error::Lockout`]; escaping that needs the lockout hierarchy's `TPM2_DictionaryAttackLockReset`
/// or waiting out `lockout_interval`. The lockout-hierarchy reset is not yet wired (the pinned
/// `tss-esapi` exposes no safe wrapper for it and `unsafe` FFI is disallowed in this crate), so a
/// hard lockout is surfaced for the caller to handle via recovery rather than cleared here.
pub fn reset_lockout(
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
}
