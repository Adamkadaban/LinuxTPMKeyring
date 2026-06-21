# Threat Model

> Stub — finalized in Phase 4. Source of truth for what tess does and does not protect. The README
> carries the short version; this is the long form.

## One-line summary

tess is **system authentication** that unlocks your own keyring at rest. It is **not** a
proof-of-presence or attestation mechanism, and it does **not** defend a live machine already owned by
a root/kernel attacker.

## What we protect

- **The GNOME login keyring at rest.** The keyring's wrapping key is a random blob sealed in *your*
  TPM under *your* PIN authValue; it is not derivable from anything on disk.
- **Against offline attack.** A stolen disk, a stolen sealed blob, or a powered-off laptop yields
  nothing without the PIN on the original TPM.
- **Against PIN brute force.** The TPM's dictionary-attack lockout rate-limits guesses in hardware.

## Explicitly out of scope

- **A root/kernel adversary on a live, running machine.** Root can keylog the PIN or read the released
  key from process memory. This is acceptable because such an attacker already has system access —
  there is nothing left to protect from them here — and no Linux system defends this without VBS-class
  isolation, which does not exist on commodity hardware (see `docs/adr/0002`).
- **Proof of presence / attestation.** The biometric leg is host-trusted; tess cannot prove to a third
  party that a specific human was present.

## Attack-class → control

| Attack class (cited prior art) | Control in tess |
|---|---|
| Bus sniff / interposer (Dolos BitLocker, TPM Genie) | No PCR-only sealing; PIN authValue + mandatory HMAC/parameter-encryption sessions |
| Weak keygen / RNG (ROCA) | Self-generated random blob (not a TPM RSA key); ECC P-256; `getrandom` mixed with TPM RNG |
| Timing side channel (TPM-FAIL, Hertzbleed) | Constant-time PIN handling; rely on DA-lockout, not comparison secrecy |
| Biometric spoof (Windows Hello IR replay, CVE-2021-34466) | Biometric host-trusted, never the sole gate; PIN authValue is the real gate; IR liveness in Mug |
| TOCTOU / confused deputy in PAM | Unseal inside PAM auth, gated by TPM policy; session-bound single-use match |
| Memory disclosure (cold boot, swap, ptrace, core dump) | `mlock` + `zeroize` ASAP; disable core dumps; minimize key lifetime |
| Dependency FFI UAF (RUSTSEC-2023-0044) | Pin `tss-esapi ≥ 7.1.0`; `cargo audit`/`deny`/`vet` |
