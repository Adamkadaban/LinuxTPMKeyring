# 0008 — Defer the privileged DA-lockout reset; ship persistence + lockout detection now

- Status: Superseded by [0011](./0011-privileged-da-lockout-reset.md)
- Date: 2026-06-21

> **Superseded by [0011](./0011-privileged-da-lockout-reset.md).** The privileged
> `TPM2_DictionaryAttackLockReset` deferred here is now implemented: the lockout-hierarchy authValue
> is bound to the recovery secret at enroll and reset via a `tpm2_dictionarylockout` subprocess
> (still no `unsafe` in `tess-tpm`). This document is retained unchanged below as the original
> reasoning for the deferral.

## Context

Issue #10 asks for durable persistence of the sealed object plus dictionary-attack (DA) lockout
handling, including an owner/lockout-hierarchy-guarded `reset_lockout`. The TPM2 primitive for a
prompt, non-destructive reset of the global failure counter (`failedTries`) is
`TPM2_DictionaryAttackLockReset`, authorized by the lockout hierarchy.

The pinned `tss-esapi` is 7.7.0 (the latest 7.x; the next published release is 8.0.0-alpha). Its
`Context` exposes **no safe wrapper** for that command — `dictionary_attack_functions.rs` is
`// Missing function: DictionaryAttackLockReset`. The command exists only as raw
`tss-esapi-sys::Esys_DictionaryAttackLockReset`, whose use requires `unsafe`. The workspace sets
`unsafe_code = "forbid"`, and `unsafe` is permitted only in `tess-pam`'s `ffi` module.

Empirically against swtpm/libtpms (default `maxTries = 3`, `lockoutInterval = 1000s`): each wrong PIN
increments `lockoutCounter`; at `counter == maxTries` the TPM enters hard lockout and refuses even the
correct PIN (the failure surfaces at `TPM2_Load`, with the lockout response code); a *successful*
authorization does **not** reset the counter; self-heal is one decrement per `lockoutInterval`.

## Decision

- Ship now, entirely in safe Rust: sealed-object persistence (`to_metadata`/`from_metadata`/`save`/
  `load`, base64 TPM2B blobs in the versioned `Metadata`), a read-only `read_lockout_state`
  (`get_capability` on the lockout properties), and distinct error mapping — a TPM lockout response
  code becomes `tess_tpm::Error::Lockout` → `tess_core::Error::Lockout`, separable from `WrongPin`.
- `reset_lockout` implements only the **PIN-holder recovery** path: refuse when already hard-locked
  (`Error::Lockout`), otherwise prove the PIN with one successful unseal. The privileged
  `TPM2_DictionaryAttackLockReset` is **deferred** (tracked as #16), to be wired when `tss-esapi` 8.x
  provides the safe wrapper or a vetted FFI boundary exists.
- Do **not** use `TPM2_Clear` as a reset: it would wipe the whole storage hierarchy and the user's
  sealed key.
- Do **not** bump to `tss-esapi` 8.0.0-alpha mid-phase: an alpha dependency for auth-critical code,
  with API churn risk against the merged #8/#9 seal/unseal code, is a foundational change that does
  not meet the bar here.

## Consequences

- Persistence reload + lockout detection + wrong-PIN/lockout discrimination are complete and tested
  on swtpm. The hard-lockout recovery story is partial: a user who exhausts `maxTries` must wait out
  the recovery interval or (once #16 lands) use the privileged reset / recovery secret.
- The error taxonomy already distinguishes "locked out" from "wrong PIN", so the Phase 3 enrollment
  and recovery layers can branch on it without rework when #16 is implemented.

## Alternatives

- **Raw `unsafe` FFI to `Esys_DictionaryAttackLockReset` in `tess-tpm`** — rejected: violates the
  workspace `forbid(unsafe_code)` and the `AGENTS.md` rule scoping `unsafe` to `tess-pam`.
- **`TPM2_Clear` on the lockout hierarchy** — rejected: destroys the storage hierarchy and every TPM
  object; catastrophic for a keyring-unlock product.
- **Bump to `tss-esapi` 8.0.0-alpha for the safe wrapper** — rejected for now: alpha dependency,
  cross-cutting API-churn risk against merged seal/unseal code; revisit at 8.x stable (#16).
- **Treat a successful unseal as the counter reset** — rejected: empirically libtpms does not reset
  `failedTries` on success, so it would over-claim.
