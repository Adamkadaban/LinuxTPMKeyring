# 0019 — `mlock` secret buffers via the safe `region` crate

## Status

Accepted

## Context

`tess-core::SecretBytes` holds every long-lived secret (the unsealed keyring key, the recovery
secret, the PIN). It was `zeroize`-on-drop but its pages were **pageable**: the kernel could write
the cleartext key to swap or a hibernation image, where it persists at rest — the exact attack class
(memory disclosure via swap/cold-boot) the threat-model lists and the project's **at-rest** guarantee
cares about. `mlock(2)` pins the pages in RAM so they are never swapped. This was tracked as #87 and
previously over-claimed as done in the Phase-0 PLAN deliverable.

`mlock`/`munlock` are `unsafe` `libc` FFI. AGENTS.md restricts `unsafe` to exactly three audited
modules (`tess-pam::ffi`, `mug::sys`, `tess-testenv::env`); `tess-core` is `#![forbid(unsafe_code)]`.
So the lock cannot be a raw `libc::mlock` call in `tess-core`.

## Decision

Lock secret pages with the **`region`** crate's `region::lock(ptr, len) -> Result<LockGuard>`, which
is a **safe** function (no caller-side `unsafe`) returning an RAII `LockGuard` that `munlock`s on
drop. `tess-core` stays `#![forbid(unsafe_code)]`.

`SecretBytes` now carries `{ _lock: Option<region::LockGuard>, data: Vec<u8> }`:

- `new` locks the buffer's pages **best-effort**: on failure (e.g. a low `RLIMIT_MEMLOCK`) it logs a
  one-line note and proceeds with `_lock = None`. Locking **never** fails construction or blocks an
  auth path — a pageable secret is still `zeroize`-on-drop.
- Field **declaration order** (`_lock` before `data`) plus a manual `Drop` that `zeroize`s `data`
  gives the correct teardown sequence: **wipe → unlock → free** (the guard `munlock`s the pages while
  `data`'s buffer is still allocated, before the `Vec` frees it).
- `Clone` re-locks: each clone owns a distinct allocation and locks it independently.
- A `/proc/self/status` `VmLck`-delta test asserts the lock takes effect when permitted and the empty
  / lock-denied paths degrade gracefully.

`region` adds four lockfile crates — `region`, `bitflags 1.x`, and the never-compiled-on-Linux
`mach2` (macOS) and `windows-sys 0.52` (Windows) — all exempted in `cargo-vet` and cleared by
`cargo-deny`. A small, justified supply-chain cost for a core security feature.

## Consequences

- Secrets are pinned in RAM (no swap/hibernation leak) wherever `RLIMIT_MEMLOCK` permits, strengthening
  the at-rest guarantee; `tess-core` remains unsafe-free.
- A very low `RLIMIT_MEMLOCK` silently degrades to "pageable but zeroized" with a logged note (the
  documented best-effort contract). Operators who want a hard guarantee raise the limit.
- `SecretBytes` is no longer a `derive`d `Zeroize`/`ZeroizeOnDrop` tuple struct; it has hand-written
  `Zeroize`, `ZeroizeOnDrop`, `Clone`, and `Drop` impls. The public API (`new`/`as_slice`/`len`/
  `is_empty`/`Debug`) is unchanged.

## Alternatives considered

- **Raw `libc::mlock` / `nix::sys::mman::mlock` in `tess-core`.** Both are `unsafe`; using them would
  break `tess-core`'s `#![forbid(unsafe_code)]`. Rejected.
- **Add a fourth allowed-`unsafe` module in `tess-core`.** Expands the audited `unsafe` surface in the
  most security-sensitive crate and needs an AGENTS.md change. Rejected in favor of a safe wrapper.
- **`secrecy`'s mlock.** `secrecy` (already a dependency) dropped its `mlock`/`SecretVec` page-locking
  support; current versions only `zeroize`. Rejected — would not actually lock.
- **`memsec`.** Provides allocation-based secure boxes but is a heavier model (custom allocator) than
  pinning an existing `Vec`'s pages. Rejected as more invasive than needed.
- **Do nothing (keep secrets pageable).** Rejected: leaves a swap/hibernation leak against the
  project's own at-rest guarantee, which the threat-model already commits to closing.
