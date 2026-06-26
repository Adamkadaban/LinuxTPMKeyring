# 0006 — Hand-rolled minimal PAM FFI; pinned dependency set

- Status: Accepted
- Date: 2026-06-21

## Context

We need to author a PAM module (`.so`) and drive a PAM conversation, in security-critical code we want
to keep small and auditable. The Rust PAM ecosystem is uneven: `pam`/`pam-sys` (1wilkens) are ~2.5
years cold with `pam-sys` frozen at `1.0.0-alpha`; `pamsm` is ~2 years stale **and GPL-3.0** (a
copyleft hazard for a system-wide `.so`); `pam-bindings` (lvkv, formerly tozny) is alive but
module-authoring-only. The existing `Mug` project already hand-rolls a minimal PAM FFI over `libc`.

## Decision

- **Hand-roll a minimal PAM FFI** over `libc` in `tess-pam`'s `ffi` module — the only `unsafe` in the
  workspace; every other crate is `#![forbid(unsafe_code)]`. The PAM C ABI surface we need
  (`pam_get_item`, `pam_set_data`/`get_data`, `pam_get_authtok`, the conversation struct) is tiny and
  frozen.
- **Pin the security-critical deps:** `tss-esapi ≥ 7.1.0` (closes GHSA-w3vw-ccc5-qr8v, an FFI
  use-after-free in `start_auth_session`). Prefer `getrandom` for key bytes, `zeroize`/`secrecy` for
  hygiene, `zbus` + `secret-service` for D-Bus, `nix` for `keyctl`/syscalls.
- **Gate every PR with `cargo audit` + `cargo deny`** (advisories/bans/licenses/sources). License
  allowlist: MIT/Apache-2.0/BSD/ISC. Avoid GPL/LGPL crates linked into our binaries (`pamsm`,
  `libbpf-rs`).

## Consequences

- No `bindgen`/`clang-sys` dependency for PAM; no stale-alpha or GPL trap.
- Both the module and client/conversation sides live under one roof with minimal supply-chain risk.
- Fuzzing of our own untrusted-input parsers (metadata, TPM blob, D-Bus reply) is scheduled for the
  dedicated fuzzing phase.

## Alternatives

- **`pam-sys`/`pam` (1wilkens)** — rejected: ~2.5 yr cold, perpetual alpha.
- **`pamsm`** — rejected: stale and GPL-3.0.
- **`pam-bindings` (lvkv)** — usable as a reference for the module trait shape, but doesn't cover the
  client side; not adopted as a dependency.
