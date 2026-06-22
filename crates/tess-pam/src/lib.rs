//! `pam_tess.so` — the tess PAM module.
//!
//! Hard rule: this module must never freeze login. Heavy, fallible work (TPM unseal, D-Bus) runs in
//! a watchdog'd helper process under a hard wall-clock deadline; on timeout or helper failure the
//! auth phase returns `PAM_AUTHINFO_UNAVAIL`/`PAM_IGNORE` so the stack falls through to the password
//! factor, and the session phase returns success regardless of the unseal outcome. The real
//! unseal/unlock helper is wired in a later phase; this is the non-blocking skeleton.
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

/// Run the gate for `phase`: abort cleanly if no gesture is available (remote session / no TPM),
/// otherwise run the helper under the watchdog and map its outcome to a PAM return code. When
/// aborting, auth returns `PAM_IGNORE` (decline, fall through to password) while a session open
/// returns `PAM_SUCCESS` so it never disturbs login under any control flag. Bounded by
/// `watchdog.deadline + 2 * watchdog.term_grace`; never blocks login.
pub fn run_gate(
    phase: GatePhase,
    env: &GateEnv,
    helper_spec: &HelperSpec,
    watchdog: &Watchdog,
) -> i32 {
    if env.aborts() {
        return match phase {
            GatePhase::Auth => ret::PAM_IGNORE,
            GatePhase::Session => ret::PAM_SUCCESS,
        };
    }
    let mut command = helper_spec.command();
    let result = helper::run(&mut command, watchdog);
    decide(phase, classify(&result))
}
