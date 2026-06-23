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

/// The flag the gate appends to the helper command line to enable the fingerprint front gate.
const FINGERPRINT_FLAG: &str = "--fingerprint";
/// The flag the gate appends to the helper command line to enable the face release path.
const FACE_FLAG: &str = "--face";
/// The environment variable carrying the login user to the helper, so its fprintd verify claims the
/// device for the right user. Not a secret; the username only selects whose enrolled finger fprintd
/// matches against.
const FPRINT_USER_ENV: &str = "TESS_FPRINT_USER";

/// The helper program the gate runs under the watchdog, plus whether the fingerprint front gate is
/// enabled. A missing helper path fails open (auth → fall through, session → success), the correct
/// non-blocking behaviour.
#[derive(Debug, Clone)]
pub struct HelperSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// When true, the helper attempts a bounded fprintd verify before the PIN unseal. The
    /// fingerprint match is host-trusted convenience that never replaces the PIN: the key is sealed
    /// under the PIN authValue, so the PIN remains required to unseal regardless of the verify
    /// result. Defaults off (PIN-only), the safe default.
    pub fingerprint: bool,
    /// The login user passed to the helper for the fprintd claim (`None` until the session phase
    /// resolves `PAM_USER`). Only meaningful when `fingerprint` is true.
    pub fingerprint_user: Option<String>,
    /// When true, the helper attempts a bounded, liveness-gated face match *before* the PIN unseal
    /// and, on success, releases the keyring key via the independent on-disk `A_face` authValue with
    /// no PIN typed (model-B unlock). Face is host-trusted convenience that never replaces the PIN:
    /// the PIN authValue is the real TPM gate, and any face decline/timeout/not-enrolled degrades
    /// cleanly to the PIN — face never blocks login. Defaults off (PIN-only), the safe default.
    pub face: bool,
}

impl HelperSpec {
    pub fn new(program: impl Into<PathBuf>, args: Vec<OsString>) -> Self {
        Self {
            program: program.into(),
            args,
            fingerprint: false,
            fingerprint_user: None,
            face: false,
        }
    }

    /// Resolve the helper from the PAM module arguments (`helper=PATH`), the root-controlled channel
    /// configured in the PAM stack, falling back to the compiled install path. Debug/test builds
    /// additionally honour `TESS_PAM_HELPER` for the test harness; release builds ignore the
    /// environment entirely, so a caller's environment cannot substitute the helper executable in
    /// the privileged PAM context. The `fingerprint=yes` module argument enables the fingerprint
    /// front gate and `face=yes` enables the face release path; either may be set independently or
    /// together, and anything else (including their absence) leaves both off.
    pub fn resolve(pam_args: &[&str]) -> Self {
        let fingerprint = fingerprint_enabled(pam_args);
        let face = face_enabled(pam_args);
        let mut spec = if let Some(path) = helper_arg(pam_args) {
            Self::new(path, Vec::new())
        } else {
            #[cfg(debug_assertions)]
            {
                if let Some(path) = std::env::var_os(HELPER_PATH_ENV) {
                    Self::new(PathBuf::from(path), Vec::new())
                } else {
                    Self::new(DEFAULT_HELPER_PATH, Vec::new())
                }
            }
            #[cfg(not(debug_assertions))]
            {
                Self::new(DEFAULT_HELPER_PATH, Vec::new())
            }
        };
        spec.fingerprint = fingerprint;
        spec.face = face;
        spec
    }

    /// Set the login user used for the fprintd claim. No-op effect unless `fingerprint` is enabled.
    pub fn with_fingerprint_user(mut self, user: Option<String>) -> Self {
        self.fingerprint_user = user;
        self
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if self.fingerprint {
            command.arg(FINGERPRINT_FLAG);
            match &self.fingerprint_user {
                Some(user) => {
                    command.env(FPRINT_USER_ENV, user);
                }
                // The environment is not a trusted channel in the privileged PAM context: clear any
                // inherited value so the helper can only ever use the PAM-resolved user (or the
                // empty-string default), never one an attacker planted in the parent environment.
                None => {
                    command.env_remove(FPRINT_USER_ENV);
                }
            }
        }
        if self.face {
            command.arg(FACE_FLAG);
        }
        command
    }
}

/// Whether a `fingerprint=yes` module argument is present. Only an explicit `yes` enables the front
/// gate; `no`, any other value, or the argument's absence keeps the PIN-only default.
fn fingerprint_enabled(pam_args: &[&str]) -> bool {
    pam_args
        .iter()
        .filter_map(|arg| arg.strip_prefix("fingerprint="))
        .next_back()
        .map(|value| value.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
}

/// Whether a `face=yes` module argument is present. Only an explicit `yes` enables the face release
/// path; `no`, any other value, or the argument's absence keeps the PIN-only default.
fn face_enabled(pam_args: &[&str]) -> bool {
    pam_args
        .iter()
        .filter_map(|arg| arg.strip_prefix("face="))
        .next_back()
        .map(|value| value.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
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
    fn fingerprint_defaults_off_and_adds_no_flag() {
        let spec = HelperSpec::new("/tmp/helper", Vec::new());
        assert!(!spec.fingerprint);
        let args: Vec<_> = spec.command().get_args().map(|a| a.to_owned()).collect();
        assert!(
            !args.iter().any(|a| a == "--fingerprint"),
            "PIN-only helper must not get --fingerprint"
        );
    }

    #[test]
    fn fingerprint_yes_arg_enables_flag_and_passes_user() {
        let spec = HelperSpec::resolve(&["helper=/etc/tess/helper", "fingerprint=yes"])
            .with_fingerprint_user(Some("alice".to_string()));
        assert!(spec.fingerprint);
        let command = spec.command();
        let args: Vec<_> = command.get_args().map(|a| a.to_owned()).collect();
        assert!(
            args.iter().any(|a| a == "--fingerprint"),
            "fingerprint=yes must append --fingerprint"
        );
        let user_env = command
            .get_envs()
            .find(|(k, _)| *k == "TESS_FPRINT_USER")
            .and_then(|(_, v)| v)
            .map(|v| v.to_owned());
        assert_eq!(user_env, Some(OsString::from("alice")));
    }

    #[test]
    fn fingerprint_without_user_clears_inherited_env() {
        // With the front gate on but no PAM-resolved user, the command must explicitly *remove*
        // TESS_FPRINT_USER so an attacker-planted parent-environment value can't reach the helper.
        let spec = HelperSpec::resolve(&["fingerprint=yes"]);
        assert!(spec.fingerprint_user.is_none());
        let command = spec.command();
        let removed = command
            .get_envs()
            .any(|(k, v)| k == "TESS_FPRINT_USER" && v.is_none());
        assert!(removed, "TESS_FPRINT_USER must be explicitly cleared");
    }

    #[test]
    fn fingerprint_only_yes_enables_it() {
        assert!(!HelperSpec::resolve(&["fingerprint=no"]).fingerprint);
        assert!(!HelperSpec::resolve(&["fingerprint=maybe"]).fingerprint);
        assert!(!HelperSpec::resolve(&[]).fingerprint);
        assert!(HelperSpec::resolve(&["fingerprint=yes"]).fingerprint);
        // Case-insensitive, and a later occurrence wins.
        assert!(HelperSpec::resolve(&["fingerprint=no", "fingerprint=YES"]).fingerprint);
    }

    #[test]
    fn face_defaults_off_and_adds_no_flag() {
        let spec = HelperSpec::new("/tmp/helper", Vec::new());
        assert!(!spec.face);
        let args: Vec<_> = spec.command().get_args().map(|a| a.to_owned()).collect();
        assert!(
            !args.iter().any(|a| a == "--face"),
            "PIN-only helper must not get --face"
        );
    }

    #[test]
    fn face_yes_arg_enables_flag() {
        let spec = HelperSpec::resolve(&["helper=/etc/tess/helper", "face=yes"]);
        assert!(spec.face);
        let command = spec.command();
        let args: Vec<_> = command.get_args().map(|a| a.to_owned()).collect();
        assert!(
            args.iter().any(|a| a == "--face"),
            "face=yes must append --face"
        );
    }

    #[test]
    fn face_only_yes_enables_it() {
        assert!(!HelperSpec::resolve(&["face=no"]).face);
        assert!(!HelperSpec::resolve(&["face=maybe"]).face);
        assert!(!HelperSpec::resolve(&[]).face);
        assert!(HelperSpec::resolve(&["face=yes"]).face);
        // Case-insensitive, and a later occurrence wins.
        assert!(HelperSpec::resolve(&["face=no", "face=YES"]).face);
    }

    #[test]
    fn fingerprint_and_face_combine_and_each_append_their_flag() {
        let spec = HelperSpec::resolve(&["fingerprint=yes", "face=yes"])
            .with_fingerprint_user(Some("alice".to_string()));
        assert!(spec.fingerprint);
        assert!(spec.face);
        let command = spec.command();
        let args: Vec<_> = command.get_args().map(|a| a.to_owned()).collect();
        assert!(args.iter().any(|a| a == "--fingerprint"));
        assert!(args.iter().any(|a| a == "--face"));
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
        // RAII restore so a panicking assertion can't leak the mutation into other tests.
        // (HELPER_PATH_ENV only exists under debug_assertions, so the var name is a literal here.)
        struct EnvGuard {
            prev: Option<OsString>,
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.prev {
                    Some(value) => std::env::set_var("TESS_PAM_HELPER", value),
                    None => std::env::remove_var("TESS_PAM_HELPER"),
                }
            }
        }
        let _guard = EnvGuard {
            prev: std::env::var_os("TESS_PAM_HELPER"),
        };
        std::env::set_var("TESS_PAM_HELPER", "/env/should/be/ignored");

        // In release builds resolution never consults the environment.
        assert_eq!(
            HelperSpec::resolve(&[]).program,
            PathBuf::from(DEFAULT_HELPER_PATH)
        );
        assert_eq!(
            HelperSpec::resolve(&["helper=relative/helper"]).program,
            PathBuf::from(DEFAULT_HELPER_PATH)
        );
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
