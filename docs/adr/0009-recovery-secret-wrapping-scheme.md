# 0009 — Recovery-secret wrapping: HKDF-SHA256 + XChaCha20-Poly1305, separate from TPM metadata

- Status: Accepted
- Date: 2026-06-22

## Context

Enrollment (#26) rekeys the login keyring to a random key `K` sealed in the TPM under a PIN. That
single unlock path dies if the TPM is cleared, the motherboard is replaced, or the PIN is forgotten —
which would lock the user out of every keyring item permanently. The keyring-preservation invariant
(`PLAN.md` §2) and Anticipated Risk "enrollment is destructive / lockout" require a recovery path that
works **without the TPM**, established and verified *before* the destructive rekey, while never
persisting the keyring secret (or a hash of it) in plaintext.

`tess-core::Metadata` already carries the TPM sealed blobs and is reloaded by `tess-tpm::persist`. We
needed to decide (a) how to wrap `K` for recovery and (b) where to store the wrapped form.

## Decision

- **Back `K` up under a high-entropy recovery secret `R`**, not the password and not a PCR. `R` is 256
  bits from the OS CSPRNG, shown to the user once as transcription-friendly grouped hex, saved offline.
- **Derive a key-encryption key `KEK = HKDF-SHA256(salt, R, info)`** with a fresh per-enrollment random
  salt. Because `R` is already full-entropy, an extract/expand KDF is cryptographically sufficient and
  keeps recovery instant — a deliberately *fast* KDF, unlike a password hash.
- **AEAD-seal `K` under `KEK` with XChaCha20-Poly1305** and a fresh random 192-bit nonce. The extended
  nonce makes random-nonce generation safe without nonce-reuse bookkeeping.
- **Persist only `{version, salt, nonce, ciphertext}`** in a dedicated `recovery.json`, base64-encoded,
  written atomically (temp sibling + rename, mode `0600`). Never `K`, `R`, or any hash of either.
- **Keep the recovery blob in a separate file from the TPM metadata**, owned by the `tess-cli` enroll
  module, not folded into `tess-core::Metadata`. The transaction writes both and removes both on
  rollback.
- **Delegate all primitives to audited RustCrypto crates** (`chacha20poly1305`, `hkdf`, `sha2`) — no
  hand-rolled crypto. All three are MIT/Apache-2.0 and `cargo deny`/`cargo audit` clean; `hkdf`/`sha2`
  were already transitive deps, so only `chacha20poly1305` is genuinely new.

## Consequences

- A cleared TPM or lost PIN is survivable: `tess recover` (wave 2) re-derives `KEK` from the
  user-entered `R`, decrypts the blob back to `K`, and re-unlocks / re-seals. The recovery test proves
  `R` recovers the *same* `K` the TPM unseals.
- The blob is inert without `R`: ciphertext is indistinguishable from random and the Poly1305 tag
  rejects a wrong secret or tampering (unit-tested). `R` is at least as strong as the PIN, so the
  at-rest guarantee is not weakened.
- The recovery blob is a new on-disk format with its own `version`; it can evolve independently of the
  TPM `Metadata` schema.
- One more workspace dependency (`chacha20poly1305`) in the supply-chain surface.

## Alternatives

- **Store a recovery-wrapped copy inside `tess-core::Metadata`** — rejected: couples a `tess-cli`
  concern to the shared TPM schema, forces a `Metadata` version bump, and entangles two independently
  evolving formats. A separate file keeps the boundary clean and the rollback symmetric.
- **Derive `KEK` from `R` with Argon2 / a slow password hash** — rejected: `R` is full-entropy, so a
  memory-hard KDF buys nothing against brute force and only slows legitimate recovery; it also adds a
  heavier dependency.
- **Use the password-derived keyring key as the only backup (no separate `R`)** — rejected: that is
  exactly the reference repo's mistake; it ties recovery to a low-entropy, reused secret and provides
  no TPM-independent escape if the password is also rotated.
- **Seal a second TPM object as the "recovery" copy** — rejected: still inside the TPM, so it does not
  survive a TPM clear — the primary failure mode recovery must cover.
- **AES-256-GCM instead of XChaCha20-Poly1305** — rejected (marginal): GCM's 96-bit nonce needs
  reuse-avoidance care; XChaCha20-Poly1305's 192-bit nonce is safe with random nonces and the crate is
  the same RustCrypto-audited lineage. Either would be acceptable; the extended-nonce variant is the
  lower-footgun choice.
