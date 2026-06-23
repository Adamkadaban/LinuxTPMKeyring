//! `pam_tess.so` — the tess PAM module.
//!
//! Hard rule: this module must never freeze login. Heavy, fallible work (TPM unseal, D-Bus keyring
//! unlock) runs in a watchdog'd helper process under a hard wall-clock deadline. The auth phase
//! falls through to the password factor (`PAM_AUTHINFO_UNAVAIL`/`PAM_IGNORE`); the session phase
//! obtains the PIN through the PAM conversation, runs the helper to unseal the key and unlock the
//! login keyring, and returns `PAM_SUCCESS` regardless of the outcome — on timeout or failure the
//! keyring simply stays locked, login proceeds.
//!
//! `unsafe` is confined to the [`ffi`] module — every other line is safe Rust.
#![deny(unsafe_code)]

#[allow(unsafe_code)]
pub mod ffi;
pub mod gate;
pub mod helper;

pub use gate::{classify, decide, should_abort, GateEnv, GatePhase, GateResult, HelperSpec};
pub use helper::Watchdog;

/// PAM return codes used by this module (subset).
pub mod ret {
    pub const PAM_SUCCESS: i32 = 0;
    pub const PAM_AUTHINFO_UNAVAIL: i32 = 9;
    pub const PAM_IGNORE: i32 = 25;
}

/// Decide whether the gate can run and, if so, classify the helper outcome — independent of PAM
/// phase. Returns `None` when there is no gesture to run (remote session or no TPM); otherwise
/// `Some(result)`: `Unavailable` when `pin` is `None` (no input handle, so no helper is spawned),
/// else the classified outcome of running the watchdog'd helper with `pin` — which may be an empty
/// slice — on its standard input. When `helper_spec.fingerprint` is set, the helper additionally
/// runs a bounded fprintd verify as a front gate before the PIN unseal — host-trusted convenience
/// that never replaces the PIN. When `helper_spec.face` is set, the helper first attempts a bounded
/// liveness-gated face match that can release the key with no PIN typed; the session gate therefore
/// hands an empty stdin (`Some(&[])`, not `None`) when face is enabled but no password was supplied,
/// so the helper still runs. Bounded by `watchdog.deadline + 2 * watchdog.term_grace`; never blocks
/// login.
pub fn evaluate(
    env: &GateEnv,
    helper_spec: &HelperSpec,
    watchdog: &Watchdog,
    pin: Option<&[u8]>,
) -> Option<GateResult> {
    if env.aborts() {
        return None;
    }
    match pin {
        // No PIN (no conversation, or the user supplied nothing): nothing to unseal with. Fail open
        // rather than spawn a helper that cannot succeed.
        None => Some(GateResult::Unavailable),
        Some(pin) => {
            let mut command = helper_spec.command();
            Some(classify(&helper::run_with_input(
                &mut command,
                watchdog,
                pin,
            )))
        }
    }
}

/// Run the gate for `phase` and map its outcome to a PAM return code. Aborts cleanly if no gesture
/// is available (remote session / no TPM): auth returns `PAM_IGNORE` (decline, fall through to
/// password) while a session open returns `PAM_SUCCESS` so it never disturbs login under any control
/// flag. Otherwise the helper runs under the watchdog with `pin` on its standard input and the
/// result maps per [`decide`]. Bounded by `watchdog.deadline + 2 * watchdog.term_grace`.
pub fn run_gate(
    phase: GatePhase,
    env: &GateEnv,
    helper_spec: &HelperSpec,
    watchdog: &Watchdog,
    pin: Option<&[u8]>,
) -> i32 {
    match evaluate(env, helper_spec, watchdog, pin) {
        None => match phase {
            GatePhase::Auth => ret::PAM_IGNORE,
            GatePhase::Session => ret::PAM_SUCCESS,
        },
        Some(result) => decide(phase, result),
    }
}
