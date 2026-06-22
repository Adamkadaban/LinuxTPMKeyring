//! Decision logic for the PAM entrypoints: where the work runs, when to abort, and how a helper
//! outcome maps to a PAM return code. All pure and safe — the FFI boundary lives in [`crate::ffi`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::helper::{RunOutcome, Termination};
use crate::ret;

/// Which PAM phase is running the gate. Auth may fail open to the password factor; a session open
/// must never fail login regardless of the unseal outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatePhase {
    Auth,
    Session,
}

/// The classified result of running the helper, independent of PAM phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateResult {
    /// Helper exited successfully — the factor was satisfied.
    Authorized,
    /// Helper ran to completion but declined (e.g. wrong PIN, no match).
    Declined,
    /// Helper timed out, was killed, could not be spawned, or otherwise produced no verdict.
    Unavailable,
}

/// Map a supervised helper run to a [`GateResult`]. A spawn/syscall error is treated as
/// `Unavailable` (fail open), never as authorization.
pub fn classify(result: &std::io::Result<RunOutcome>) -> GateResult {
    match result {
        Ok(reaped) => match reaped.termination {
            Termination::Exited(status) if status.success() => GateResult::Authorized,
            Termination::Exited(_) => GateResult::Declined,
            Termination::TimedOut { .. } => GateResult::Unavailable,
        },
        Err(_) => GateResult::Unavailable,
    }
}

/// Map a [`GateResult`] to a PAM return code for the given phase.
///
/// Auth: only an explicit `Authorized` returns `PAM_SUCCESS`; everything else returns
/// `PAM_AUTHINFO_UNAVAIL` so a `[success=done default=ignore]` stack falls through to the password
/// factor. Session: always `PAM_SUCCESS` — a slow or failed unseal degrades to "keyring stays
/// locked, login proceeds", never a frozen or failed login.
pub fn decide(phase: GatePhase, result: GateResult) -> i32 {
    match phase {
        GatePhase::Session => ret::PAM_SUCCESS,
        GatePhase::Auth => match result {
            GateResult::Authorized => ret::PAM_SUCCESS,
            GateResult::Declined | GateResult::Unavailable => ret::PAM_AUTHINFO_UNAVAIL,
        },
    }
}

/// Whether tess should abort cleanly with no gesture available — an SSH/remote session, or no TPM
/// device present. Returns `PAM_IGNORE` to abort, `PAM_SUCCESS` to proceed with the gate.
pub fn should_abort(is_remote: bool, tpm_present: bool) -> i32 {
    if is_remote || !tpm_present {
        ret::PAM_IGNORE
    } else {
        ret::PAM_SUCCESS
    }
}

/// Environment facts that decide whether the gate can run at all.
#[derive(Debug, Clone, Copy)]
pub struct GateEnv {
    pub is_remote: bool,
    pub tpm_present: bool,
}

impl GateEnv {
    /// Detect the environment. `pam_rhost` is PAM's `PAM_RHOST` item (the remote host, if any).
    pub fn detect(pam_rhost: Option<&str>) -> Self {
        Self {
            is_remote: is_remote_session(pam_rhost),
            tpm_present: tpm_present(),
        }
    }

    /// Whether the gate must abort (`PAM_IGNORE`) before doing any work.
    pub fn aborts(&self) -> bool {
        should_abort(self.is_remote, self.tpm_present) == ret::PAM_IGNORE
    }
}

/// A non-empty `PAM_RHOST` means a remote session. This relies only on the authoritative
/// PAM-provided item, not on environment variables, which are not a trustworthy signal in the
/// privileged PAM context.
pub fn is_remote_session(pam_rhost: Option<&str>) -> bool {
    pam_rhost.is_some_and(|host| !host.is_empty())
}

/// Whether a TPM resource-manager or raw device node is present.
pub fn tpm_present() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

const DEFAULT_HELPER_PATH: &str = "/usr/lib/tess/tess-pam-helper";
#[cfg(debug_assertions)]
const HELPER_PATH_ENV: &str = "TESS_PAM_HELPER";

/// The helper program the gate runs under the watchdog. The real unseal/unlock helper is wired in a
/// later phase; until it is installed, spawning a missing path fails open (auth → fall through,
/// session → success), which is the correct non-blocking behaviour.
#[derive(Debug, Clone)]
pub struct HelperSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

impl HelperSpec {
    pub fn new(program: impl Into<PathBuf>, args: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            args,
        }
    }

    /// Resolve the helper from the PAM module arguments (`helper=PATH`), the root-controlled channel
    /// configured in the PAM stack, falling back to the compiled install path. Debug/test builds
    /// additionally honour `TESS_PAM_HELPER` for the test harness; release builds ignore the
    /// environment entirely, so a caller's environment cannot substitute the helper executable in
    /// the privileged PAM context.
    pub fn resolve(pam_args: &[&str]) -> Self {
        if let Some(path) = helper_arg(pam_args) {
            return Self::new(path, Vec::new());
        }
        #[cfg(debug_assertions)]
        if let Some(path) = std::env::var_os(HELPER_PATH_ENV) {
            return Self::new(PathBuf::from(path), Vec::new());
        }
        Self::new(DEFAULT_HELPER_PATH, Vec::new())
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        command
    }
}

/// Extract an absolute `helper=PATH` PAM module argument, if present. A relative path is rejected so
/// the resolved executable never depends on the caller's working directory in the privileged PAM
/// context; resolution then falls back to the compiled install path.
fn helper_arg(pam_args: &[&str]) -> Option<PathBuf> {
    pam_args.iter().find_map(|arg| {
        arg.strip_prefix("helper=")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn reaped(termination: Termination) -> std::io::Result<RunOutcome> {
        Ok(RunOutcome {
            pid: 1,
            termination,
        })
    }

    #[test]
    fn auth_authorizes_only_on_clean_success() {
        let ok = reaped(Termination::Exited(ExitStatus::from_raw(0)));
        assert_eq!(decide(GatePhase::Auth, classify(&ok)), ret::PAM_SUCCESS);
    }

    #[test]
    fn auth_falls_through_on_decline_timeout_and_spawn_failure() {
        let declined = reaped(Termination::Exited(ExitStatus::from_raw(1 << 8)));
        let timed_out = reaped(Termination::TimedOut {
            escalated_to_sigkill: true,
        });
        let spawn_failed: std::io::Result<RunOutcome> =
            Err(std::io::Error::from_raw_os_error(libc::ENOENT));

        for outcome in [&declined, &timed_out, &spawn_failed] {
            assert_eq!(
                decide(GatePhase::Auth, classify(outcome)),
                ret::PAM_AUTHINFO_UNAVAIL
            );
        }
    }

    #[test]
    fn session_always_succeeds_regardless_of_outcome() {
        let timed_out = reaped(Termination::TimedOut {
            escalated_to_sigkill: false,
        });
        let declined = reaped(Termination::Exited(ExitStatus::from_raw(3 << 8)));
        let spawn_failed: std::io::Result<RunOutcome> =
            Err(std::io::Error::from_raw_os_error(libc::ENOENT));

        for outcome in [&timed_out, &declined, &spawn_failed] {
            assert_eq!(
                decide(GatePhase::Session, classify(outcome)),
                ret::PAM_SUCCESS
            );
        }
    }

    #[test]
    fn aborts_in_remote_session_and_without_tpm() {
        assert_eq!(should_abort(true, true), ret::PAM_IGNORE);
        assert_eq!(should_abort(false, false), ret::PAM_IGNORE);
        assert_eq!(should_abort(false, true), ret::PAM_SUCCESS);
    }

    #[test]
    fn gate_env_aborts_mirror_the_decision() {
        assert!(GateEnv {
            is_remote: true,
            tpm_present: true
        }
        .aborts());
        assert!(GateEnv {
            is_remote: false,
            tpm_present: false
        }
        .aborts());
        assert!(!GateEnv {
            is_remote: false,
            tpm_present: true
        }
        .aborts());
    }

    #[test]
    fn pam_rhost_marks_a_remote_session() {
        assert!(is_remote_session(Some("10.0.0.5")));
        assert!(!is_remote_session(Some("")));
        assert!(!is_remote_session(None));
    }

    #[test]
    fn helper_spec_new_uses_explicit_program() {
        let spec = HelperSpec::new("/tmp/custom-helper", vec![OsString::from("--check")]);
        assert_eq!(spec.command().get_program(), "/tmp/custom-helper");
    }

    #[test]
    fn helper_spec_resolve_prefers_absolute_pam_arg() {
        // An absolute PAM argument short-circuits before any env/default lookup, so this holds in
        // every build mode.
        assert_eq!(
            HelperSpec::resolve(&["debug", "helper=/etc/tess/helper"]).program,
            PathBuf::from("/etc/tess/helper")
        );
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn helper_spec_release_ignores_env_override() {
        // In release builds resolution never consults the environment. (HELPER_PATH_ENV only exists
        // under debug_assertions, so reference the variable name by literal here.)
        let prev = std::env::var_os("TESS_PAM_HELPER");
        std::env::set_var("TESS_PAM_HELPER", "/env/should/be/ignored");
        assert_eq!(
            HelperSpec::resolve(&[]).program,
            PathBuf::from(DEFAULT_HELPER_PATH)
        );
        assert_eq!(
            HelperSpec::resolve(&["helper=relative/helper"]).program,
            PathBuf::from(DEFAULT_HELPER_PATH)
        );
        match prev {
            Some(value) => std::env::set_var("TESS_PAM_HELPER", value),
            None => std::env::remove_var("TESS_PAM_HELPER"),
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn helper_spec_resolution_precedence() {
        // Restore any pre-existing value on the way out, even if an assertion panics, so this test
        // neither leaks global state into others nor breaks when CI pre-sets the variable. This is
        // the only test that touches HELPER_PATH_ENV, so no concurrent reader observes the mutation.
        struct EnvGuard {
            prev: Option<OsString>,
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.prev {
                    Some(value) => std::env::set_var(HELPER_PATH_ENV, value),
                    None => std::env::remove_var(HELPER_PATH_ENV),
                }
            }
        }
        let _guard = EnvGuard {
            prev: std::env::var_os(HELPER_PATH_ENV),
        };

        // A root-controlled PAM argument wins over the environment and the default.
        std::env::set_var(HELPER_PATH_ENV, "/env/helper");
        assert_eq!(
            HelperSpec::resolve(&["helper=/etc/tess/helper", "debug"]).program,
            PathBuf::from("/etc/tess/helper")
        );

        // No PAM argument: the debug/test-only env override applies.
        assert_eq!(
            HelperSpec::resolve(&[]).program,
            PathBuf::from("/env/helper")
        );

        // No PAM argument, no env: the compiled install path.
        std::env::remove_var(HELPER_PATH_ENV);
        assert_eq!(
            HelperSpec::resolve(&[]).program,
            PathBuf::from(DEFAULT_HELPER_PATH)
        );

        // A relative (or empty) helper path is rejected; resolution falls back to the default.
        assert_eq!(
            HelperSpec::resolve(&["helper=relative/helper"]).program,
            PathBuf::from(DEFAULT_HELPER_PATH)
        );
        assert_eq!(
            HelperSpec::resolve(&["helper="]).program,
            PathBuf::from(DEFAULT_HELPER_PATH)
        );
    }
}
