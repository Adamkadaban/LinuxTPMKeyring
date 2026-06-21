# 0005 — Keyring access via the freedesktop Secret Service API behind a `KeyringBackend` trait

- Status: Accepted
- Date: 2026-06-21

## Context

The MVP targets the GNOME login keyring, but the user wants compatibility with as many environments as
possible. gnome-keyring, KeePassXC, and (since KDE Frameworks 5.97.0, with `apiEnabled=true`) KWallet
all implement the freedesktop **Secret Service** D-Bus API (`org.freedesktop.secrets`). The unlock
flow we need — `Unlock`/`Lock`/`Prompt` on collections — is part of that spec.

## Decision

Define a **`KeyringBackend` trait** whose default implementation speaks the **Secret Service** API.
GNOME is the reference implementation. Any GNOME-specific or unstable private D-Bus calls (e.g.
`InternalUnsupportedGuiltRiddenInterface.UnlockWithMasterPassword`) are **isolated behind the trait**,
with a preference for the stable `gnome-keyring-daemon --unlock` path.

## Consequences

- Most of the design is desktop-agnostic; KWallet (via `apiEnabled`) and KeePassXC are reachable
  through the same trait.
- KWallet's native `pam_kwallet` path (keyed to the login password, not fingerprint-unlockable) is
  **out of scope** — we drive its Secret Service `Unlock` with our released key instead.
- Unstable private GNOME calls are contained, so churn there doesn't ripple through the codebase.

## Alternatives

- **Bind directly to gnome-keyring internals** — rejected: not portable; couples us to private APIs.
- **Target KWallet's native PAM path** — rejected: password-keyed, not fingerprint-unlockable.
