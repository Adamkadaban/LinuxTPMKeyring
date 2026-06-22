# 0010 — Pass the PIN to the PAM helper over a memfd, not a pipe

- Status: Accepted
- Date: 2026-06-22

## Context

The tess PAM session module (#29) must hand the user's PIN to a short-lived helper process that does
the TPM unseal and keyring unlock off the PAM thread. The PIN must not be visible to other users
(ruling out argv and the environment, which `ps`/`/proc` expose) and must not be persisted to disk
(the project never writes a secret or a secret-hash). The standard remaining channel is the child's
standard input.

The obvious implementation — a pipe to the child's stdin — has a fatal hazard in this context.
`pam_tess.so` is a `cdylib` loaded into the **login process** (login/gdm/sshd/su). Rust's runtime,
which installs `SIGPIPE → SIG_IGN`, only runs for Rust *binaries* via `lang_start`; a cdylib inherits
the host C process's `SIGPIPE` disposition, typically `SIG_DFL` (terminate). Writing the PIN to a pipe
whose read end the child has already closed (e.g. the helper crashed during startup) would deliver
`SIGPIPE` and **kill the login process** — the exact "must never freeze/break login" violation the
module exists to avoid.

The pipe could be made safe by blocking `SIGPIPE` on the writing thread, writing, then draining any
pending `SIGPIPE` before restoring the mask. But a bounded, non-blocking drain needs `sigtimedwait`,
which `nix` 0.29 does not wrap; doing it by hand needs `unsafe` `libc`, which is forbidden outside
`tess-pam`'s `ffi` module. An unbounded `sigwait` drain risks hanging the PAM thread — strictly worse
than the problem it solves.

## Decision

Pass the PIN through an **anonymous in-memory file** (`memfd`):

- `helper::run_with_input` creates a `memfd` via `nix::sys::memfd::memfd_create` (a safe wrapper,
  under the `fs` feature already enabled), writes the PIN with a single bounded `write_all`, rewinds,
  and hands it to the child as stdin via `std::process::Stdio::from(File)`.
- The child reads its stdin to EOF and gets exactly the PIN.

A regular-file descriptor never raises `SIGPIPE` on write, so the hazard is structurally eliminated
with no signal masking. A `memfd` lives only in RAM (tmpfs) and is freed when the last descriptor
closes, so nothing is persisted. The write is a single `write_all` of at most a few KB into a fresh
fd, so it cannot block the caller.

## Consequences

- No `SIGPIPE` can reach the login process from the PIN transfer, in any helper state, with no
  `pthread_sigmask`/`sigwait` machinery and no `unsafe` outside `ffi`.
- The PIN never touches argv, the environment, or disk.
- Linux/`memfd_create`-specific (`linux_android`/FreeBSD in `nix`). tess targets Debian 13, so this
  is acceptable; a non-Linux port would need a different safe transport.

## Alternatives

- **Pipe to stdin** — rejected: `SIGPIPE` can kill the host login process; the safe variant needs an
  unbounded `sigwait` drain or `unsafe` `sigtimedwait`.
- **argv / environment variable** — rejected: visible to any user via `ps`/`/proc/<pid>`.
- **Temp file on disk** — rejected: persists the PIN, even briefly, violating the no-secret-on-disk
  rule.
- **Inherited fd via `pre_exec` `dup2` or `from_raw_fd`** — rejected: both ends need `unsafe`, which is
  forbidden outside `ffi`; `memfd` + `Stdio::from(File)` achieves the same with safe code only.
