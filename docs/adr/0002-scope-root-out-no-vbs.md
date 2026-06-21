# 0002 — Scope the root/runtime adversary out; deliver at-rest auth, not proof-of-presence

- Status: Accepted
- Date: 2026-06-21

## Context

Windows Hello's runtime isolation of derived secrets relies on **VBS / Credential Guard** (a Hyper-V
secure world, VTL1). The question arose whether we should build a VBS equivalent on Linux, or use a
commodity TEE, to protect the released keyring key from a root/kernel attacker on a live machine.

Research findings:
- **Building VBS on Linux** = a type-1 hypervisor + a from-scratch secure kernel + IOMMU/firmware
  contracts — a multi-year OS-team effort. The only existing attempt (Heki/LVBS) is an unmerged
  research PoC that protects kernel integrity, not user secrets.
- **Commodity TEEs don't fit:** Intel SGX was removed from client CPUs (and has a heavy side-channel
  record); Intel TDX / AMD SEV-SNP protect a *VM from the host* (wrong direction) and are server-only;
  ARM TrustZone is ARM-only and vendor-gated; ARM CCA is nascent. None give "protect a key from root"
  on a stock Debian 13 x86 laptop.
- **ChromeOS cryptohome** — the closest shipped FOSS analogue — explicitly concedes "once an attacker
  has root, any user who logs in is exposed until reboot," and relies on verified boot + TPM at-rest.

## Decision

**Scope the root/kernel adversary on a live machine explicitly OUT of the threat model**, and say so
in the README and `docs/threat-model.md`. tess delivers an **at-rest** guarantee (stolen/powered-off
laptop) plus TPM anti-hammering. It is **system authentication**, not a **proof-of-presence /
attestation** mechanism — it cannot prove to a third party that a human was present.

Consequently we do **not** build VBS, do **not** use any TEE, and do **not** modify fprintd/libfprint.
The biometric leg is host-trusted convenience; the PIN authValue carries the real hardware guarantee.

## Consequences

- The design stays small, auditable, 100% safe Rust, userspace-only.
- We must never overclaim runtime-root resistance in docs or marketing.
- A future, optional bar-raise toward the ChromeOS model (UEFI Secure Boot + measured boot +
  locked-down rootfs) is possible but raises the cost of *persistent* root, never isolating secrets
  from a live root. Recorded as an extension point, not built.

## Alternatives

- **Build a Linux VBS / KVM-based credential trustlet** — rejected: multi-year scope, no commodity
  hardware path, out of proportion to a keyring-unlock tool.
- **Use SGX/TrustZone/TDX/SEV** — rejected: unavailable on the target, or wrong trust direction.
- **Claim Windows-Hello-equivalent runtime security** — rejected: dishonest; no Linux system can.
