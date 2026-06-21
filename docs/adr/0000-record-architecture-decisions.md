# 0000 — Record architecture decisions

- Status: Accepted
- Date: 2026-06-21

## Context

This project is security-sensitive and experimentation-heavy. Decisions about TPM policy, the trust
boundary, dependencies, and protocol/schema shape are easy to silently reverse later by a contributor
(human or AI) who wasn't present for the original reasoning. We need a durable, greppable record so a
session months from now doesn't reintroduce a rejected library or weaken a deliberate security choice.

## Decision

Use [MADR](https://adr.github.io/madr/)-format Architecture Decision Records in `docs/adr/`, one
immutable file per non-trivial decision (`NNNN-title.md`), with sections Status, Context, Decision,
Consequences, Alternatives.

## Consequences

- **Read on entry (mandatory):** before contradicting a prior choice, `ls docs/adr/` and read the
  related ones.
- **Write on exit (mandatory)** when: choosing between named alternatives; rejecting a
  library/pattern future work might reintroduce; committing to a backend/protocol/schema hard to
  swap; or writing "we tried X, switched to Y because…" in `NOTES.md`.
- ADRs are immutable once accepted; a superseding decision gets a new ADR that links the old one.
- Operational lessons (gotchas, dead-ends) go in `NOTES.md`, not here. ADRs are decisions, not a log.

## Alternatives

- **No formal record** (rely on commit messages / PLAN.md) — rejected: not greppable by decision,
  bloats PLAN, gets lost.
