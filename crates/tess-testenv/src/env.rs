//! The single audited home of process-environment mutation in the workspace.
//!
//! Every `std::env::set_var`/`remove_var` call lives here, behind [`EnvGuard`]. This is the only
//! `#[allow(unsafe_code)]` module in the crate.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// Process-wide guard serializing environment access within a test binary. Each test binary links
/// its own instance; all env-touching tests in that binary must hold it (via [`env_lock`]) so a
/// mutation never races a concurrent read/write under the parallel test harness.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Acquire the binary-wide environment lock. Hold the returned guard for the entire lifetime of any
/// [`EnvGuard`] created under it; poisoning is ignored (a panicking test still leaves the env
/// consistent because `EnvGuard` restores on drop).
pub fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Saves a process-global env var and restores its prior value (or unsets it) on `Drop`, including
/// on panic, so the override never leaks into another test in the same process.
///
/// Mutating the environment races every other thread that reads it, so callers must hold the test
/// suite's `ENV_LOCK` mutex (or otherwise run single-threaded) for the guard's whole lifetime. That
/// invariant is what makes the `unsafe` blocks below sound.
pub struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    /// Set `key` to `value`, capturing the prior value for restoration on drop.
    pub fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        // SAFETY: the caller holds the suite's ENV_LOCK, so no other thread reads the environment
        // for the guard's lifetime.
        unsafe { std::env::set_var(key, value) };
        Self { key, prev }
    }

    /// Set `key` to a filesystem path, capturing the prior value for restoration on drop.
    pub fn set_path(key: &'static str, value: &Path) -> Self {
        let prev = std::env::var_os(key);
        // SAFETY: see `set`.
        unsafe { std::env::set_var(key, value) };
        Self { key, prev }
    }

    /// Remove `key`, capturing the prior value for restoration on drop.
    pub fn remove(key: &'static str) -> Self {
        let prev = std::env::var_os(key);
        // SAFETY: see `set`.
        unsafe { std::env::remove_var(key) };
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            // SAFETY: see `set` — still under the caller's ENV_LOCK.
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            // SAFETY: see `set`.
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}
