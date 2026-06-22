//! Bounded, killable, reaped execution of a short-lived child process.
//!
//! The PAM thread must never block on TPM / D-Bus / camera I/O, so all heavy or fallible work runs
//! in a child process supervised here under a hard wall-clock deadline. On deadline the child is
//! sent `SIGTERM`, given a short grace period, then `SIGKILL`ed and reaped — no zombies, no leaks.

use std::io;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// Timing parameters for the watchdog. `deadline` is the hard wall-clock budget for the child;
/// `term_grace` is how long it may take to honour `SIGTERM` before escalation to `SIGKILL`.
#[derive(Debug, Clone, Copy)]
pub struct Watchdog {
    pub deadline: Duration,
    pub term_grace: Duration,
    pub poll: Duration,
}

impl Watchdog {
    pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(3);
    pub const DEFAULT_TERM_GRACE: Duration = Duration::from_millis(250);
    pub const DEFAULT_POLL: Duration = Duration::from_millis(5);

    pub fn new(deadline: Duration) -> Self {
        Self {
            deadline,
            term_grace: Self::DEFAULT_TERM_GRACE,
            poll: Self::DEFAULT_POLL,
        }
    }

    pub fn with_grace(mut self, term_grace: Duration) -> Self {
        self.term_grace = term_grace;
        self
    }
}

impl Default for Watchdog {
    fn default() -> Self {
        Self::new(Self::DEFAULT_DEADLINE)
    }
}

/// How the supervised child ended.
#[derive(Debug, Clone)]
pub enum Termination {
    /// The child exited on its own within the deadline.
    Exited(ExitStatus),
    /// The child exceeded the deadline and was terminated by the watchdog. `escalated_to_sigkill`
    /// is true when `SIGTERM` was not honoured within the grace period and `SIGKILL` was needed.
    TimedOut { escalated_to_sigkill: bool },
}

/// The outcome of one supervised run. The child has been waited on, so `pid` is no longer a live
/// process by the time this is returned.
#[derive(Debug, Clone)]
pub struct Reaped {
    pub pid: u32,
    pub termination: Termination,
}

/// Spawn `command`, supervise it under `watchdog`, and reap it. Returns an error only if the child
/// could not be spawned or a syscall failed — never blocks past `deadline + term_grace`.
pub fn run(command: &mut Command, watchdog: &Watchdog) -> io::Result<Reaped> {
    let mut child = command.spawn()?;
    let pid = child.id();
    let started = Instant::now();

    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Reaped {
                pid,
                termination: Termination::Exited(status),
            });
        }
        if started.elapsed() >= watchdog.deadline {
            break;
        }
        std::thread::sleep(watchdog.poll);
    }

    let escalated = terminate_and_reap(&mut child, pid, watchdog)?;
    Ok(Reaped {
        pid,
        termination: Termination::TimedOut {
            escalated_to_sigkill: escalated,
        },
    })
}

fn terminate_and_reap(child: &mut Child, pid: u32, watchdog: &Watchdog) -> io::Result<bool> {
    send_signal(pid, Signal::SIGTERM)?;

    let grace_started = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(false);
        }
        if grace_started.elapsed() >= watchdog.term_grace {
            break;
        }
        std::thread::sleep(watchdog.poll);
    }

    send_signal(pid, Signal::SIGKILL)?;
    // SIGKILL cannot be caught or ignored, so this reaps promptly and leaves no zombie.
    child.wait()?;
    Ok(true)
}

fn send_signal(pid: u32, signal: Signal) -> io::Result<()> {
    match kill(Pid::from_raw(pid as i32), signal) {
        Ok(()) => Ok(()),
        // The child has already exited (we have not yet reaped it, so its PID is still ours and
        // cannot have been recycled); there is nothing to signal.
        Err(Errno::ESRCH) => Ok(()),
        Err(err) => Err(io::Error::from_raw_os_error(err as i32)),
    }
}

/// Whether `pid` currently refers to a live (or zombie-but-unreaped) process. Used by tests to prove
/// the watchdog left nothing behind. Only `ESRCH` means definitely gone; `EPERM` (exists but not
/// signalable) still counts as alive.
pub fn process_alive(pid: u32) -> bool {
    !matches!(kill(Pid::from_raw(pid as i32), None), Err(Errno::ESRCH))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_watchdog_is_bounded() {
        let wd = Watchdog::default();
        assert_eq!(wd.deadline, Watchdog::DEFAULT_DEADLINE);
        assert!(wd.term_grace < wd.deadline);
        assert!(wd.poll < wd.term_grace);
    }

    #[test]
    fn spawn_failure_is_an_error_not_a_hang() {
        let mut cmd = Command::new("/nonexistent/tess/helper/definitely-not-here");
        let result = run(&mut cmd, &Watchdog::new(Duration::from_millis(200)));
        assert!(result.is_err());
    }
}
