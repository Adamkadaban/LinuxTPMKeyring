<h1 align="center">tess</h1>

<p align="center">
  Windows-Hello-style unlocking for the Linux keyring — your secrets, sealed in the TPM, released by a PIN (and soon your fingerprint or face), not your password.
</p>

<p align="center">
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <img alt="platform: Debian 13" src="https://img.shields.io/badge/platform-Debian%2013-a80030">
  <img alt="status: pre-MVP" src="https://img.shields.io/badge/status-pre--MVP-orange">
  <img alt="made with vibes" src="https://img.shields.io/badge/made_with-vibes-ff69b4">
</p>

---

On Linux the GNOME login keyring is encrypted with a key **derived from your login password**, so
when you log in with a fingerprint (Howdy, `fprintd`) the keyring stays locked and you type your
password anyway. **tess** fixes this the way Windows, macOS, and Android do: a high-entropy **random**
key lives sealed in your **TPM 2.0**, and authentication merely *authorizes the TPM to release* it.
A PAM module unseals the key at login and unlocks your keyring — no password.

## Highlights

- **TPM-sealed, never password-derived** — the keyring key is random and sealed in your TPM, bound to a PIN, with hardware anti-hammering (TPM dictionary-attack lockout).
- **At-rest protection that actually holds** — a stolen or powered-off laptop's secrets can't be unsealed without your PIN on *your* TPM. No offline brute force.
- **Never freezes your login** — the PAM module runs auth in a watchdog'd helper with a hard timeout and fails open to your password. A stuck TPM or camera can't lock you out (Howdy's #1 flaw, fixed).
- **Keeps your existing secrets** — enrollment rekeys your keyring *in place*, preserving every item. Transactional, with a recovery secret and one-command rollback.
- **100% safe Rust, userspace-only** — no kernel module, no custom kernel, no eBPF. Talks to `fprintd` and `gnome-keyring` over their existing D-Bus APIs; modifies neither.
- **Honest about scope** — see below.

## What tess is (and isn't)

tess is **system authentication** — it unlocks *your own secrets* on a machine *you control* once
you pass the gate. It is **not a proof-of-presence or attestation** mechanism: it cannot prove to a
third party or a remote policy that a specific human was physically present. The biometric leg is
host-trusted convenience; the PIN authValue is the real hardware gate.

tess protects your keyring **at rest** (stolen/powered-off laptop) and rate-limits PIN guessing in
hardware. It deliberately does **not** defend against a **root/kernel attacker on a live machine** —
such an attacker already owns the system, and no Linux system defends that without VBS-class
isolation, which doesn't exist on commodity hardware. This is the same boundary ChromeOS ships.

## Install

> Pre-MVP — not yet installable. The flow below is the target for the first release.

```sh
# on Debian 13 with a TPM 2.0
curl -fsSL https://example/install.sh | sh   # placeholder until Phase 4
tess enroll        # set a PIN, seal a random key, rekey your keyring (transactional)
```

## Use

```sh
tess status        # enrollment + keyring + TPM state
tess enroll        # enroll (prints a recovery secret — keep it safe)
tess recover       # re-unlock using the recovery secret
tess unenroll      # restore the password-based keyring (items preserved)
tess doctor        # check TPM / keyring / fprintd readiness
```

## Status

Active bootstrap. Roadmap and phase checklist live in [`PLAN.md`](./PLAN.md); contributor and agent
rules in [`AGENTS.md`](./AGENTS.md); the security boundary in [`docs/threat-model.md`](./docs/threat-model.md).

## License

[MIT](./LICENSE) © 2026 Adam Hassan
