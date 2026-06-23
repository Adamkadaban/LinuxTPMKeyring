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
fn hung_face_capture_is_bounded_reaped_and_falls_through_to_the_pin() {
    // Stall injection for the face release path. The session gate hands the helper an *empty* stdin
    // when face is enabled but no password was typed (face can unlock on its own), so model a hung
    // face capture as a helper that never exits and is fed that empty stdin. The watchdog must still
    // (a) return within a hard wall-clock bound, (b) SIGKILL and reap the child, and (c) classify the
    // timeout so auth falls through to the password and a session open still succeeds.
    use pam_tess::helper::run_with_input;

    let watchdog = Watchdog::new(Duration::from_millis(300)).with_grace(Duration::from_millis(150));
    let mut cmd = hang_forever();

    let started = Instant::now();
    let reaped = run_with_input(&mut cmd, &watchdog, b"").expect("spawn");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "a hung face capture must be bounded, took {elapsed:?}"
    );
    assert!(matches!(
        reaped.termination,
        Termination::TimedOut {
            escalated_to_sigkill: true
        }
    ));
    assert!(
        !process_alive(reaped.pid),
        "the hung face helper PID must be reaped, not leaked"
    );

    let auth = decide(GatePhase::Auth, classify(&Ok(reaped.clone())));
    let session = decide(GatePhase::Session, classify(&Ok(reaped)));
    assert_eq!(
        auth,
        ret::PAM_AUTHINFO_UNAVAIL,
        "a stalled face must fall through to the password factor"
    );
    assert_eq!(
        session,
        ret::PAM_SUCCESS,
        "a stalled face must never freeze a session open"
    );
}

#[test]
fn face_helper_runs_without_a_pin_and_can_authorize() {
    // Model B: face can release the key with no password typed, so the session gate runs the helper
    // even when no PIN is available (it passes an empty stdin). `true` ignores stdin and exits 0, so
    // the gate authorizes — proving the face leg is not short-circuited to Unavailable like the
    // PIN-only no-password case.
    use pam_tess::{evaluate, GateEnv, GateResult, HelperSpec};

    let env = GateEnv {
        is_remote: false,
        tpm_present: true,
    };
    let mut spec = HelperSpec::new("true", Vec::new());
    spec.face = true;
    let outcome = evaluate(
        &env,
        &spec,
        &Watchdog::new(Duration::from_secs(2)),
        Some(b""),
    );
    assert_eq!(outcome, Some(GateResult::Authorized));
}

#[test]
fn run_gate_with_pin_authorizes_when_helper_succeeds() {
    // This exercises run_gate directly with a PIN supplied. Note the real PAM auth entrypoint
    // (run_auth_gate) intentionally passes None so auth always falls through to the password
    // factor — this test is about run_gate's success path, not auth-phase policy.
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
