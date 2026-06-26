//! Process-level hardening applied at secret-touching entry points.

use nix::sys::resource::{Resource, setrlimit};

/// Forbid core dumps for this process (best-effort).
///
/// A crash while a secret (the unsealed key, the recovery secret, a PIN) is live in RAM could
/// otherwise write that memory to a core file on disk — an at-rest leak that `mlock` does **not**
/// prevent (`mlock` stops swap only). Lowering the `RLIMIT_CORE` hard limit to 0 never requires
/// privilege and cannot be raised again by this process, so it is safe to call unconditionally at
/// startup. Failure is non-fatal: it is logged once and the process continues (core dumps are a
/// defense-in-depth measure, never an auth gate).
///
/// This closes the core-dump vector only. Suspend-to-disk/hibernation still snapshots all of RAM
/// regardless and needs encrypted swap as a separate, operator-level mitigation.
pub fn disable_core_dumps() {
    if let Err(e) = setrlimit(Resource::RLIMIT_CORE, 0, 0) {
        // Warn once per process — a repeat call (e.g. another entry point or a test) shouldn't spam.
        use std::sync::Once;
        static WARNED: Once = Once::new();
        WARNED.call_once(|| {
            eprintln!(
                "tess: note: could not disable core dumps ({e}); a crash could leave secret material \
                 in a core file. Set `ulimit -c 0` or disable core dumps system-wide as a fallback."
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::resource::getrlimit;

    #[test]
    fn disable_core_dumps_zeroes_the_limit() {
        // Mutates this test process's RLIMIT_CORE (harmless — we don't want core files from tests).
        disable_core_dumps();
        let (soft, hard) = getrlimit(Resource::RLIMIT_CORE).expect("getrlimit RLIMIT_CORE");
        assert_eq!(
            soft, 0,
            "soft RLIMIT_CORE must be 0 after disable_core_dumps"
        );
        assert_eq!(
            hard, 0,
            "hard RLIMIT_CORE must be 0 after disable_core_dumps"
        );
    }
}
