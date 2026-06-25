# 0021 — Pin the storage primary's Name to detect an active TPM-bus interposer

## Status

Accepted. Extends [ADR-0001](0001-tpm-seal-random-key-pin-authvalue-hmac-sessions.md) (mandatory
salted HMAC + parameter-encryption sessions); does not supersede it.

## Context

Every seal/unseal already runs under a salted HMAC + AES-128-CFB parameter-encryption session
(ADR-0001), which defeats a **passive** TPM-bus sniffer (the Dolos/BitLocker LPC-sniff class): the PIN
authValue and the unsealed key never cross the bus in cleartext.

A salted session does **not**, on its own, defeat an **active** interposer (NCC Group *TPM Genie*).
The session salt is encrypted to the storage primary's public key. ESAPI obtains that public area from
the `CreatePrimary` response — over the bus. An active interposer can substitute its **own** public key
in that response; the host then derives the session key against a key the attacker controls, and the
parameter encryption is defeated. The code and docs claimed to "defeat an interposer" without doing the
one thing that actually backs that claim against substitution: **verifying the primary's identity.**

The TCG-standard defence is to verify the salt key's **Name** (the SHA-256 fingerprint of its public
area) against a value the host trusts (`tpm2_startauthsession -n` documents this as the MITM defence).
We did not pin or verify the Name. Tracked as #93.

## Decision

**Pin the storage primary's Name at enrollment and re-verify it on every unseal.**

- `tess_tpm::primary_name(context, primary)` returns the primary's Name via `Esys_TR_GetName`.
- `seal()` records the Name in the returned `SealedObject` (`expected_primary_name`).
- `unseal()` re-reads the live primary's Name and **refuses with `Error::PrimaryNameMismatch`** before
  loading anything if it differs from the pinned value — fail closed, so the caller falls back to the
  password rather than releasing the key under a substituted (attacker-controlled) primary.
- The Name is persisted in the versioned metadata as a new required field `Metadata.primary_name`
  (base64). `METADATA_VERSION` bumps **1 → 2**; v1 metadata has no pinned Name and is rejected
  (re-enroll required). The Name is public material — never a secret — and is compared with plain
  equality (no constant-time requirement), with an empty pinned Name treated as a mismatch (fail
  closed).

This is a **trust-on-first-use (TOFU)** model: the Name trusted at enrollment is whatever the TPM
returns then. The deterministic ECC-P256 storage template makes the Name stable across boots, so a
legitimate re-derivation always matches.

## Consequences

- An interposer **introduced after enrollment** (the realistic evil-maid: enroll on a clean machine,
  attacker later splices in a device) is detected — the substituted primary yields a different Name and
  the unseal fails closed. This makes the "defeats an interposer" claim true for the post-enrollment
  case and lets the threat-model/architecture/ADR-0001 prose stop over-claiming.
- **Residual (documented, not closed):** an interposer active **during enrollment** can pin its own
  key's Name and pass at unseal. This is the inherent TOFU limit; enrollment is the trusted-setup
  ceremony, and a live-machine adversary at that moment is already out of scope (ADR-0002). The
  security argument continues to rest on the PIN authValue + TPM anti-hammering as the real gate.
- Schema change forces re-enrollment of any pre-v2 metadata. Acceptable pre-release (no shipped users;
  enroll is the documented setup step).
- Verification is local to ESAPI metadata (`TR_GetName` does not round-trip the bus), so it adds no
  measurable latency and no new failure mode beyond the intended mismatch rejection.

## Alternatives considered

- **Soften the comment only** (document active-interposer resistance as out of scope, no code). Cheaper
  and defensible under the stated threat model, but for auth code "make the claim true" beats "walk the
  claim back" when the fix is small. Rejected in favour of implementing the check (the #93 decision).
- **Persist the full primary public area instead of the Name.** Equivalent security (the Name is a hash
  of it) but larger and less canonical than the TPM's own fingerprint. Rejected.
- **Make a persistent SRK at a fixed handle and verify by handle.** A handle is not an identity; an
  interposer controls what a handle resolves to. The Name is the identity. Rejected.
- **Constant-time Name comparison.** Unnecessary — the Name is public, not secret. Rejected as
  cargo-culting; the comparison is plain equality with an explicit empty-fails-closed rule.
