# 0012 — Mug IR camera/UVC raw ioctls: a second confined `unsafe` location

- Status: Accepted
- Date: 2026-06-22

## Context

The Phase 5 face factor (`mug`) needs three kernel interactions the safe Rust ecosystem does not
cover for our target hardware (Logitech Brio, `046d:085e`):

1. Selecting the Brio IR node by the `GREY` pixelformat (`VIDIOC_ENUM_FMT`).
2. Forcing that node to `GREY` at its native 340×340 (`VIDIOC_S_FMT`) and reading frames.
3. **Enabling the IR emitter**, which on the Brio is a *vendor UVC extension-unit* control reachable
   only via `UVCIOC_CTRL_QUERY` (`UVC_SET_CUR`) — the same mechanism `linux-enable-ir-emitter` uses.
   There is no safe wrapper for an arbitrary vendor XU control in the `v4l`/`uvc` crates.

Until now `tess-pam`'s `ffi` module was the workspace's only `unsafe`; every other crate is
`#![forbid(unsafe_code)]`. The `v4l` crate would wrap V4L2 safely but still cannot drive the UVC XU
emitter control, and it adds a `-sys`/`libv4l` link plus a registry-dep tree that would churn the
`cargo deny` / `cargo vet --locked` gates for code that cannot be exercised in headless CI anyway.

## Decision

- Add a **single confined `unsafe` module, `mug::sys`**, holding the raw V4L2/UVC kernel-ABI structs
  and the `nix`-generated ioctl wrappers. The crate root is `#![deny(unsafe_code)]`; only
  `mod sys` is `#[allow(unsafe_code)]` — mirroring `tess-pam`'s `ffi` confinement. This makes
  **two** allowed-`unsafe` locations in the workspace (`tess-pam::ffi`, `mug::sys`).
- Do **not** depend on the `v4l`/`ort`/`image`/`ndarray` crates in wave 1. The real capture/emitter
  path uses only already-vendored workspace deps (`libc`, `nix` with the `ioctl` feature), so the
  dependency graph, `cargo deny`, and `cargo vet --locked` are unchanged (Cargo.lock gains only the
  `mug` entry).
- The Brio emitter unit/selector/payload are treated as **device data supplied by configuration**,
  not magic baked into logic. Wrong values fail safe: the emitter stays off, the liveness
  differential cannot pass, and the face factor degrades to the PIN.
- All security-critical logic (liveness statistics, matcher cosine distance, enroll store) stays in
  safe, `unsafe`-free, fully-unit-tested modules. The `sys` module is pure kernel plumbing.

## Consequences

- `AGENTS.md`'s "`unsafe` is allowed only in `tess-pam`'s `ffi` module" invariant must be amended to
  also permit `mug::sys`. This ADR is that record; the `AGENTS.md` line is updated alongside.
- The `sys` module is **not exercised in CI** (no camera); it is linted (clippy builds it, it is not
  feature-gated) and the orchestrator validates it against the physical Brio. Headless tests drive a
  synthetic file-backed source + a mock matcher instead.
- If a future safe crate exposes arbitrary UVC XU `SET_CUR` and V4L2 capture without a heavy `-sys`
  tree, `mug::sys` can be retired and the crate returned to `forbid(unsafe_code)`.

## Alternatives

- **Depend on `v4l` (safe V4L2 wrapper)** — rejected for wave 1: it still cannot drive the UVC XU
  emitter (the security-relevant part), adds a `libv4l`/`-sys` link and a registry-dep subtree that
  churns the supply-chain gates, and buys nothing for headless CI. Reconsider if the emitter ever
  moves to a standard control.
- **Shell out to the `linux-enable-ir-emitter` binary at runtime** — rejected: a runtime dependency
  on an external binary, no error propagation, and a larger trust surface than one confined ioctl.
- **Keep `forbid(unsafe_code)` and skip the real hardware path** — rejected: the deliverable requires
  the Brio enum/emitter/capture path to exist for the orchestrator's real-camera validation.
