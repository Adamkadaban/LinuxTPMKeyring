//! Test-only environment-variable RAII guard for the tess workspace.
//!
//! Edition 2024 made [`std::env::set_var`] and [`std::env::remove_var`] `unsafe`, because mutating
//! the process environment is a data race against any concurrent reader (including libc internals)
//! on other threads. The workspace defaults to `unsafe_code = "forbid"`, and the only env mutation
//! anywhere in tess is test setup. This crate exists to confine that single unavoidable `unsafe`
//! site to one audited module so every shipping crate stays `forbid`/`deny(unsafe_code)` — the same
//! pattern `tess-pam::ffi` (PAM C ABI) and `mug::sys` (raw V4L2 ioctls) use for their FFI.
//!
//! [`EnvGuard`] captures a variable's prior value, overwrites it, and on `Drop` restores the prior
//! value (or removes it if it was unset) — even on panic — so a mutation never leaks into another
//! test in the same process.

#![deny(unsafe_code)]

mod env;

pub use env::{EnvGuard, env_lock};
