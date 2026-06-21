# 0007 — License: MIT

- Status: Accepted
- Date: 2026-06-21

## Context

We need a license. Every planned runtime dependency is permissive (`tss-esapi` Apache-2.0; `libc`,
`zbus`, `secret-service`, `getrandom`, `zeroize`, `secrecy`, `rand`, `nix`, `serde`, `anyhow`,
`thiserror`, `clap`, `ort`, `aya` all MIT or MIT/Apache-2.0). Both reference repos we learn plumbing
patterns from — `boltgolt/howdy` and `Tunahanyrd/tpm-keyring-unlock` — are MIT. We interact with
LGPL/GPL system components (`libfprint`/`fprintd`, `gnome-keyring`) only over D-Bus / `dlopen`, which
does not propagate copyleft. The Reddit framing that seeded the project signals intended openness.

## Decision

License the project **MIT**. Copyright line: `Copyright (c) 2026 Adam Hassan`.

## Consequences

- Maximum reuse and contribution freedom; the only inherited obligation (attribution from the MIT
  references) is satisfied.
- A PAM `.so` linked into GPL hosts (gdm/login) is fine — MIT is GPL-compatible.

## Alternatives

- **Apache-2.0** — viable, adds an explicit patent grant (reasonable for crypto/TPM code). Rejected in
  favor of MIT for simplicity and ecosystem norm; revisit if a patent grant becomes desirable.
- **Copyleft (GPL/LGPL/AGPL)** — rejected: no copyleft obligation is inherited, and copyleft would
  reduce reuse against the project's open intent.
