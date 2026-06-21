//! `pam_tess.so` — the tess PAM module.
//!
//! Hard rule (`AGENTS.md`): this module must never freeze login. The heavy, fallible work (TPM
//! unseal, D-Bus) runs in a watchdog'd helper process under a hard wall-clock deadline; on timeout
//! the module returns `PAM_AUTHINFO_UNAVAIL`/`PAM_IGNORE` and the stack falls through to the
//! password factor. The session-phase unseal returns success regardless.
//!
//! `unsafe` is confined to the [`ffi`] module — every other line is safe Rust.
//! Skeleton — implemented in Phases 2–4 (see `PLAN.md` §5).
#![deny(unsafe_code)]

/// Minimal hand-rolled PAM FFI over `libc` (the C ABI surface is tiny and frozen). This is the only
/// place `unsafe` is permitted in the entire workspace. Populated in Phase 2 — `pam_get_item`,
/// `pam_set_data`/`get_data`, `pam_get_authtok`, and the conversation struct.
#[allow(unsafe_code)]
pub mod ffi {}

/// PAM return codes we use (subset). Real bindings land with the `ffi` module in Phase 2.
pub mod ret {
    pub const PAM_SUCCESS: i32 = 0;
    pub const PAM_IGNORE: i32 = 25;
    pub const PAM_AUTHINFO_UNAVAIL: i32 = 9;
}

/// Whether tess should abort cleanly (no gesture available) — e.g. in an SSH/remote session.
pub fn should_abort_remote_session(is_remote: bool, tpm_present: bool) -> i32 {
    if is_remote || !tpm_present {
        ret::PAM_IGNORE
    } else {
        ret::PAM_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aborts_in_remote_session_and_without_tpm() {
        assert_eq!(should_abort_remote_session(true, true), ret::PAM_IGNORE);
        assert_eq!(should_abort_remote_session(false, false), ret::PAM_IGNORE);
        assert_eq!(should_abort_remote_session(false, true), ret::PAM_SUCCESS);
    }
}
