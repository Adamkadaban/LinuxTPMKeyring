# 0003 — Userspace tss-esapi sealing, not kernel trusted-keys

- Status: Accepted
- Date: 2026-06-21

## Context

The Linux kernel can seal/unseal TPM objects itself via the `trusted` key type (trust source `tpm2`),
which keeps plaintext key material inside the kernel. That would be attractive for a key we don't want
in userspace memory.

Two findings rule it out for this project:
1. **`CONFIG_TRUSTED_KEYS` is not compiled into Debian 13** (confirmed on stock 6.12: `is not set`).
   On Azure Debian 13 you cannot use kernel trusted keys without a custom/recompiled kernel — which
   contradicts the "stock kernel, easy deploy" goal.
2. **The keyring unlock API needs cleartext anyway.** GNOME's `UnlockWithMasterPassword` (and the
   `gnome-keyring-daemon --unlock` stdin path) take a plaintext secret, so the key must materialize in
   userspace to be handed over. Kernel trusted-keys' headline advantage ("plaintext never leaves the
   kernel") is largely defeated here.

## Decision

Use **userspace `tss-esapi` (ESAPI)** sealing against `/dev/tpmrm0`. Mitigate userspace exposure with
`mlock` + `zeroize` + minimal key lifetime (and, optionally, a `keyctl logon` stash later).

## Consequences

- Works on stock Debian 13 / Azure vTPM with no kernel changes.
- The unsealed key is briefly in process memory; we minimize and wipe it. Acceptable given root is
  already out of scope (ADR-0002).
- Pin `tss-esapi ≥ 7.1.0` (ADR-0006).

## Alternatives

- **Kernel trusted-keys (`trusted`/`encrypted` key types)** — rejected: not compiled into Debian 13;
  benefit defeated by the cleartext unlock API.
- **`tpm2-pkcs11`** — rejected for the core path: heavier integration surface than direct ESAPI sealing.
