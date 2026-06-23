# 0013 — Confine test-only `std::env` mutation to a `tess-testenv` crate

## Status

Accepted

## Context

Rust edition 2024 made `std::env::set_var` and `std::env::remove_var` `unsafe`: mutating the process
environment is a data race against any concurrent reader (including libc internals) on other threads.

The workspace sets `[workspace.lints.rust] unsafe_code = "forbid"` as the default for every crate,
and the only place tess mutates the environment is **test setup** — an `EnvGuard` RAII helper that
overrides a variable for a test and restores it on drop. Before edition 2024 this was safe code; the
helper was also duplicated verbatim across ~8 integration-test files plus the `#[cfg(test)]` modules
of `tess-pam` and `mug`.

After the edition bump, those `set_var`/`remove_var` calls require `unsafe`, which `forbid` rejects.
`forbid` cannot be locally overridden, so we cannot wrap the calls in `unsafe {}` in place.

## Decision

Add a small test-support crate `crates/tess-testenv` (`publish = false`) that is
`#![deny(unsafe_code)]` with a single `#[allow(unsafe_code)]` module, `env`, holding the one
`EnvGuard` RAII type and the only `set_var`/`remove_var` call sites in the workspace
(`crates/tess-testenv/src/env.rs:1`). Every test crate depends on it as a dev-dependency and uses
`tess_testenv::EnvGuard` instead of a local copy.

The guard documents its soundness invariant: callers hold the suite's `ENV_LOCK` mutex (or otherwise
run single-threaded) for the guard's lifetime, so no other thread reads the environment concurrently.

This mirrors how the workspace already confines its other two unavoidable `unsafe` sites — the PAM C
ABI in `tess-pam::ffi` (ADR-0010) and the raw V4L2/UVC ioctls in `mug::sys` (ADR-0012): one named,
audited module per crate, with the rest of the workspace staying `forbid`/`deny(unsafe_code)`.

## Consequences

- The new `unsafe` is confined to one audited, test-only module and never ships in a binary.
- The duplicated `EnvGuard` is removed from every test file (DRY).
- The shipping crates keep `unsafe_code = "forbid"`; the sanctioned-`unsafe` list in `AGENTS.md` now
  has three entries (`tess-pam::ffi`, `mug::sys`, `tess-testenv::env`).

## Alternatives considered

- **Sprinkle `#[allow(unsafe_code)]` (and `unsafe {}`) across every test crate.** Rejected: spreads
  unsafe across the codebase, defeats the "one audited module" invariant, and `forbid` would have to
  be downgraded to `deny` workspace-wide to allow it.
- **Adopt the `temp-env` crate** (a maintained crate that wraps env mutation behind a safe
  closure API). Rejected: its scoped-closure API (`with_var(key, val, || …)`) does not match the
  pervasive RAII-guard-held-across-a-test-body pattern the suite already uses, so adopting it would
  mean rewriting every test's control flow; a 60-line confined RAII helper fit the existing code with
  near-zero churn and adds no third-party dependency.
