# 0011 — Privileged DA-lockout reset, bound to the recovery secret, via `tpm2_dictionarylockout`

- Status: Accepted
- Date: 2026-06-22
- Supersedes: [0008](./0008-defer-privileged-da-lockout-reset.md)

## Context

[0008](./0008-defer-privileged-da-lockout-reset.md) deferred the privileged
`TPM2_DictionaryAttackLockReset` (the prompt, non-destructive reset of the global DA failure
counter, authorized by the lockout hierarchy) because the pinned `tss-esapi` 7.7 exposes **no safe
wrapper** for that command — it lives only as the raw `Esys_DictionaryAttackLockReset`, whose use
requires `unsafe`, which the workspace forbids outside `tess-pam`'s `ffi` module. Without it, a user
who exhausts `maxAuthFail` wrong PINs is stuck until the lockout interval self-heals (1000 s on the
swtpm default), with the recovery secret as the only other way back into the keyring.

The decision now is to ship the privileged reset rather than wait for `tss-esapi` 8.x to stabilise.
Two sub-problems: (a) how to *authorize* the reset without weakening anti-hammering, and (b) how to
*issue* the command without `unsafe`.

## Decision

**Authorization — bind the lockout hierarchy to the recovery secret.** At enroll, tess sets the TPM
lockout-hierarchy authValue to a key derived from the user's recovery secret:
`HKDF-SHA256(ikm = recovery_secret, salt = "", info = "tess-lockout-auth-v1")`, truncated to 32
bytes. A distinct `info` label domain-separates it from the recovery key-encryption key
(`info = "tess recovery key-encryption key v1"`), so the lockout authValue is never equal to the
keyring-wrapping key. The derivation is salt-less and therefore deterministic from the recovery
secret alone, so a reset needs no stored material beyond what the user already saved offline. The
auth change runs under the project's mandatory salted-HMAC + parameter-encryption session, so the new
authValue is encrypted on the TPM bus.

Only the recovery-secret holder can reproduce the lockout authValue, so only they can reset the
counter — anti-hammering is preserved: a PIN-guessing attacker who trips the lockout cannot clear it.

**Issuing the command — shell out to `tpm2_dictionarylockout`.** The reset itself runs
`tpm2_dictionarylockout --clear-lockout --auth file:-` (tpm2-tools) as a subprocess, with the raw
32-byte authValue fed on **stdin** (never argv, so it does not leak via `/proc/<pid>/cmdline`), and
`TPM2TOOLS_TCTI` set to the same transport tess uses (`swtpm:host=…,port=…` in tests,
`device:/dev/tpmrm0` in prod) so tpm2-tools talks to the same TPM. tpm2-tools becomes a **runtime
dependency** for the hard-lockout-recovery path only.

**Lifecycle.** `tess enroll` sets the lockout authValue (transactionally; rollback restores it to
empty). `tess unenroll` clears it back to empty using the recovery-derived auth, so uninstalling
tess leaves the lockout hierarchy as it was found. `tess recover` detects a hard lockout and runs the
privileged reset before restoring keyring access. If the lockout hierarchy already has an authValue
tess did not set (another owner), tess refuses to clobber it: it skips the binding with a logged
warning and the privileged reset is simply unavailable on that machine.

## Consequences

- A hard-locked user with their recovery secret recovers immediately via `tess recover`, instead of
  waiting out the lockout interval.
- tess now owns the TPM lockout hierarchy on a machine where it was previously unowned. `unenroll`
  releases it; a machine whose lockout hierarchy is owned by something else gets keyring enrollment
  but no privileged reset (documented edge).
- tpm2-tools must be installed for hard-lockout recovery (added to CI system deps; documented in the
  README as a runtime dependency).
- The subprocess boundary keeps `tess-tpm` `#![forbid(unsafe_code)]`. The cost is a process spawn and
  a dependency on tpm2-tools' CLI contract for one command.

## Alternatives

- **Raw `unsafe` FFI to `Esys_DictionaryAttackLockReset`** — rejected: violates `forbid(unsafe_code)`
  and the `AGENTS.md` rule scoping `unsafe` to `tess-pam`. The subprocess achieves the same effect in
  safe Rust.
- **Bump to `tss-esapi` 8.0.0-alpha for the safe wrapper** — rejected (as in 0008): an alpha
  dependency for auth-critical code with API-churn risk against the merged seal/unseal code; revisit
  at 8.x stable.
- **Bind the lockout auth to the keyring-wrapping key `K` instead of the recovery secret** — rejected:
  the explicit project rule is to derive a distinct sub-key and never reuse `K`; binding to `K` would
  also let any PIN holder (not just the recovery-secret holder) reset the counter when not locked out.
- **Passing the authValue in argv (`hex:…`/`str:…`)** — rejected where avoidable: argv is world-
  readable via `/proc`. stdin (`file:-`) keeps the secret off the process table. tpm2-tools' `file:-`
  reads the raw bytes, which match the raw `TPM2B_AUTH` set via `hierarchy_change_auth`.
- **Persisting a flag/secret to know tess owns the lockout hierarchy** — rejected: the recovery secret
  reproduces the authValue deterministically, so no extra persisted state is needed, and persisting a
  secret-derived value would widen the attack surface.
