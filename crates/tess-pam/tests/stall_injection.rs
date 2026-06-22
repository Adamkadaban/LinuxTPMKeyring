//! "Login never freezes" proof. Each case spawns a real child and asserts the watchdog completes
//! within a hard bound, maps to the correct PAM return code, and leaves no live/zombie child.

use std::process::Command;
use std::time::{Duration, Instant};

use pam_tess::gate::{classify, decide, GatePhase};
use pam_tess::helper::{process_alive, run, Termination, Watchdog};
use pam_tess::ret;

fn slow_but_ok() -> Command {
    let mut cmd = Command::new("sleep");
    cmd.arg("0.1");
    cmd
}

fn clean_failure() -> Command {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "exit 3"]);
    cmd
}

/// Ignores SIGTERM and busy-loops, forcing the watchdog to escalate to SIGKILL. No child process of
/// its own, so nothing can be orphaned.
fn hang_forever() -> Command {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", "trap '' TERM; while :; do :; done"]);
    cmd
}

#[test]
fn slow_but_eventually_ok_authorizes_and_is_reaped() {
    let mut cmd = slow_but_ok();
    let reaped = run(&mut cmd, &Watchdog::new(Duration::from_secs(2))).expect("spawn");

    assert!(matches!(reaped.termination, Termination::Exited(s) if s.success()));
    assert_eq!(
        decide(GatePhase::Auth, classify(&Ok(reaped.clone()))),
        ret::PAM_SUCCESS
    );
    assert!(!process_alive(reaped.pid), "child must be reaped");
}

#[test]
fn clean_failure_falls_through_and_is_reaped() {
    let mut cmd = clean_failure();
    let reaped = run(&mut cmd, &Watchdog::new(Duration::from_secs(2))).expect("spawn");

    assert!(matches!(reaped.termination, Termination::Exited(s) if !s.success()));
    assert_eq!(
        decide(GatePhase::Auth, classify(&Ok(reaped.clone()))),
        ret::PAM_AUTHINFO_UNAVAIL
    );
    assert!(!process_alive(reaped.pid), "child must be reaped");
}

#[test]
fn hang_forever_times_out_bounded_and_is_reaped() {
    let watchdog = Watchdog::new(Duration::from_millis(300)).with_grace(Duration::from_millis(150));
    let mut cmd = hang_forever();

    let started = Instant::now();
    let reaped = run(&mut cmd, &watchdog).expect("spawn");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "watchdog must be bounded, took {elapsed:?}"
    );
    assert!(matches!(
        reaped.termination,
        Termination::TimedOut {
            escalated_to_sigkill: true
        }
    ));
    assert!(
        !process_alive(reaped.pid),
        "hung child must be killed and reaped"
    );

    // Auth falls through to password; a session open still succeeds despite the timeout.
    let auth = decide(GatePhase::Auth, classify(&Ok(reaped.clone())));
    let session = decide(GatePhase::Session, classify(&Ok(reaped)));
    assert_eq!(auth, ret::PAM_AUTHINFO_UNAVAIL);
    assert_eq!(session, ret::PAM_SUCCESS);
}

#[test]
fn hang_forever_with_pin_input_times_out_bounded_and_is_reaped() {
    // The real session path hands the PIN to the helper on stdin; prove that wiring still bounds and
    // reaps a hung helper exactly like the no-input path.
    use pam_tess::helper::run_with_input;

    let watchdog = Watchdog::new(Duration::from_millis(300)).with_grace(Duration::from_millis(150));
    let mut cmd = hang_forever();

    let started = Instant::now();
    let reaped = run_with_input(&mut cmd, &watchdog, b"1234").expect("spawn");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "watchdog must be bounded with stdin input, took {elapsed:?}"
    );
    assert!(matches!(
        reaped.termination,
        Termination::TimedOut {
            escalated_to_sigkill: true
        }
    ));
    assert!(
        !process_alive(reaped.pid),
        "hung child must be killed and reaped"
    );
}

#[test]
fn end_to_end_gate_runs_helper_when_not_aborting() {
    use pam_tess::{run_gate, GateEnv, HelperSpec};

    let env = GateEnv {
        is_remote: false,
        tpm_present: true,
    };
    // `sleep` ignores the PIN we feed it on stdin and exits cleanly, so the gate authorizes.
    let spec = HelperSpec::new("sleep", vec!["0.05".into()]);
    let rc = run_gate(
        GatePhase::Auth,
        &env,
        &spec,
        &Watchdog::new(Duration::from_secs(2)),
        Some(b"1234"),
    );
    assert_eq!(rc, ret::PAM_SUCCESS);
}

#[test]
fn gate_without_pin_falls_through_for_auth() {
    use pam_tess::{run_gate, GateEnv, HelperSpec};

    // No PIN available and not aborting: auth must fall through to the password factor without
    // spawning a helper that could not succeed.
    let env = GateEnv {
        is_remote: false,
        tpm_present: true,
    };
    let spec = HelperSpec::new("/nonexistent/helper", Vec::new());
    let rc = run_gate(
        GatePhase::Auth,
        &env,
        &spec,
        &Watchdog::new(Duration::from_secs(1)),
        None,
    );
    assert_eq!(rc, ret::PAM_AUTHINFO_UNAVAIL);
}

#[test]
fn gate_aborts_without_running_helper_when_no_tpm() {
    use pam_tess::{run_gate, GateEnv, HelperSpec};

    let env = GateEnv {
        is_remote: false,
        tpm_present: false,
    };
    // A missing helper would fail open; the abort must short-circuit before any spawn.
    let spec = HelperSpec::new("/nonexistent/helper", Vec::new());
    let rc = run_gate(
        GatePhase::Auth,
        &env,
        &spec,
        &Watchdog::new(Duration::from_secs(2)),
        Some(b"1234"),
    );
    assert_eq!(rc, ret::PAM_IGNORE);
}

#[test]
fn session_abort_succeeds_rather_than_ignoring() {
    use pam_tess::{run_gate, GateEnv, HelperSpec};

    // A remote session has no gesture available, but a session open must never disturb login.
    let env = GateEnv {
        is_remote: true,
        tpm_present: true,
    };
    let spec = HelperSpec::new("/nonexistent/helper", Vec::new());
    let rc = run_gate(
        GatePhase::Session,
        &env,
        &spec,
        &Watchdog::new(Duration::from_secs(1)),
        None,
    );
    assert_eq!(rc, ret::PAM_SUCCESS);
}

#[test]
fn session_gate_unlocks_when_helper_succeeds() {
    use pam_tess::{evaluate, GateEnv, GateResult, HelperSpec};

    // The session path classifies a clean helper exit as Authorized (keyring unlocked). `true`
    // ignores the PIN on stdin and exits 0.
    let env = GateEnv {
        is_remote: false,
        tpm_present: true,
    };
    let spec = HelperSpec::new("true", Vec::new());
    let outcome = evaluate(
        &env,
        &spec,
        &Watchdog::new(Duration::from_secs(2)),
        Some(b"1234"),
    );
    assert_eq!(outcome, Some(GateResult::Authorized));
}
