# 0001 — Seal a random key under a PIN authValue with mandatory HMAC sessions (not PCR-only, not the password)

- Status: Accepted
- Date: 2026-06-21

## Context

The reference repo `Tunahanyrd/tpm-keyring-unlock` seals the *actual keyring password* into the TPM
gated by **PCR-7 only** — no PIN, no authValue, no anti-hammering — so the object unseals for *any*
caller who can boot the machine, and it additionally writes an unsalted SHA-256 of the password to
disk. Documented TPM attacks reinforce the failure modes: bus-sniffing lifts PCR-only-sealed keys off
the SPI bus (Dolos/BitLocker, TPM Genie); ROCA showed TPM-generated RSA keys can be weak; TPM-FAIL
showed secret-dependent timing side channels.

## Decision

- Seal a **freshly generated random 256-bit key** (mix `getrandom(2)` with TPM `GetRandom`), **never**
  the password and **never** a TPM-born RSA key.
- Bind the sealed object with a **`PolicyAuthValue` (PIN)** policy session; the TPM's
  **dictionary-attack lockout** is the anti-hammering root.
- Use an **ECC (P-256)** primary under the owner hierarchy.
- **Mandatory: a salted TPM2 HMAC + parameter-encryption session on every seal/unseal**, so the PIN
  authValue and the unsealed blob are encrypted and integrity-protected in transit.
- **Never** seal on PCRs alone; PCR binding is a deferred, optional add-on (ADR to follow if adopted).
- Handle the PIN in constant time; rely on DA-lockout rather than comparison-timing secrecy.
- **Never** persist any secret or secret-hash to disk.

## Consequences

- Anti-hammering and at-rest protection come from the TPM, not from our code or from boot state.
- An interposer on the TPM bus cannot read the authValue or the unsealed key.
- A wrong PIN fails closed and counts toward DA-lockout; recovery requires the recovery secret.
- We accept that PCR-free policy means no boot-state binding in the MVP (Azure vTPM PCRs differ from
  bare metal anyway, so PCR binding would be brittle).

## Alternatives

- **PCR-only sealing (the reference repo)** — rejected: unseals for any local caller, no
  anti-hammering, defeated by bus sniffing.
- **Seal the keyring password directly** — rejected: couples the durable secret to a guessable value
  and to password changes.
- **PolicyOR(PIN ∨ biometric) now** — deferred to Phase 5; MVP is PIN-only for a clean core.
