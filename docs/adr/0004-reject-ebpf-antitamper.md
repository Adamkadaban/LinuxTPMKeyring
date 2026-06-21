# 0004 — Reject eBPF / BPF-LSM anti-tamper

- Status: Accepted
- Date: 2026-06-21

## Context

An eBPF/BPF-LSM "tripwire" was proposed to restrict `ptrace`/`open` of the agent process, the sealed
blobs, and `/dev/tpmrm0` to a trusted binary, and to audit unseal events.

## Decision

**Do not use eBPF for the MVP, and absent a concrete new requirement, not at all.**

## Consequences

- Smaller trusted computing base; no `aya`/CO-RE/kernel-version compatibility burden; no `CAP_BPF`
  requirement; consistent with "small, auditable, 100% safe Rust."
- If tamper-*evidence* is ever wanted, add a few `auditd` rules in packaging — documented explicitly
  as audit/observability, **not** a security boundary.

## Rationale

As a security boundary against root it is theater: loading a BPF-LSM program requires `CAP_SYS_ADMIN`
/ `CAP_BPF` — i.e. root, the very adversary it nominally targets. Root can detach the program, load
an overriding one, or boot without the LSM. The "restrict ptrace/open" hooks don't bound a root
attacker who can read `/proc/<pid>/mem`, `/dev/mem`, `/proc/kcore`, replace the allowed binary, or
keylog the PIN and unseal legitimately. Root is already out of scope (ADR-0002), so the protection
guards an adversary we don't defend against while expanding attack surface.

## Alternatives

- **`aya` BPF-LSM tripwire** — rejected: not a boundary against root; adds TCB and a false sense of
  security.
- **`auditd` tamper-evidence** — acceptable later, as audit only, not a boundary.
