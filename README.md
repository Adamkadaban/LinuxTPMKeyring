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
tess install       # wire pam_tess.so into the session stack (idempotent, fail-open)
tess install --uninstall   # remove the wiring and module, restoring the original stack
```

### PAM wiring (`tess install`)

`tess install` (run as root) does two things, idempotently:

1. copies the built `pam_tess.so` into the system PAM module directory (auto-detected the way the CI
   smoke test finds it — via `pam_permit.so` under `/lib` and `/usr/lib`), and
2. adds one line to the session stack (`/etc/pam.d/common-session` by default) inside a re-runnable
   marked block:

   ```pam
   # >>> tess >>>
   session optional pam_tess.so
   # <<< tess <<<
   ```

The control flag is `optional`, so a tess failure (no TPM, a slow or declined unseal) is ignored and
login proceeds with the keyring simply left locked — **it can never lock you out**. Before editing,
`tess install` backs up the original file and validates the result is well-formed and fail-open,
aborting if not. `tess install --uninstall` removes the block (restoring the original stack
byte-for-byte), deletes the module, and removes the backup; it is safe to run when nothing is
installed. Flags: `--service`, `--module`, `--module-dir` override the auto-detected paths. The
snippet and exact placement are documented in [`deploy/pam/`](./deploy/pam/README.md).

> tess never wires PAM on the developer host — the real wiring happens on the Azure VM (Phase 4) or
> a user's machine. The install logic is exercised in tests against throwaway fixtures only.

## Status

Active bootstrap. Roadmap and phase checklist live in [`PLAN.md`](./PLAN.md); contributor and agent
rules in [`AGENTS.md`](./AGENTS.md); the security boundary in [`docs/threat-model.md`](./docs/threat-model.md).

## Azure dev VM (real vTPM)

CI exercises a software TPM (swtpm), but the only **real** TPM 2.0 acceptance gate is an Azure
**Gen2 Trusted-Launch** Debian 13 VM with a hardware-backed vTPM. The developer's own laptop is
never used to seal, unseal, enroll, or touch a TPM/keyring — that work happens on this VM or in CI.

> **This spends money.** A running VM bills by the second. Deallocate when idle and delete at
> wind-down. Budget and kill-by date live in [`NOTES.md`](./NOTES.md).

```sh
# Provision: Gen2 Trusted-Launch Debian 13 VM, vTPM + secure boot on, key-only SSH, all tagged
# project=LinuxTPMKeyring. Defaults are overridable via env vars (see the script header).
TESS_SSH_PUBKEY=~/.ssh/id_ed25519.pub deploy/azure/provision.sh

# Self-check readiness on the VM (prints the same table as below). NOTE: tess is pre-MVP and
# is NOT preinstalled on the VM — build it (`cargo build --release`) and copy the `tess` binary
# to the VM first; otherwise this fails with `tess: command not found`.
ssh tess@<public-ip> tess doctor

deploy/azure/deallocate.sh        # stop billing while idle (VM kept, disk persists)
deploy/azure/teardown.sh          # delete everything (lists resources, then asks to confirm)
```

By default `provision.sh` restricts the SSH firewall rule to your detected public IP (`/32` for IPv4,
`/128` for IPv6). Set `TESS_SSH_SOURCE` to override it (e.g. `TESS_SSH_SOURCE=203.0.113.4/32`, or `*`
for any source); if IP detection fails it falls back to `*` with a warning.

| Script | Purpose | Key env vars |
|---|---|---|
| `provision.sh` | create RG + Trusted-Launch vTPM VM via `main.bicep` | `TESS_RG`, `TESS_LOCATION`, `TESS_VM_NAME`, `TESS_VM_SIZE`, `TESS_ADMIN_USER`, `TESS_SSH_PUBKEY`, `TESS_SSH_SOURCE` |
| `deallocate.sh` | stop the VM to halt compute billing (no delete) | `TESS_RG`, `TESS_VM_NAME` |
| `teardown.sh` | delete the whole resource group (`--yes`/`TESS_CONFIRM=yes` to skip the prompt) | `TESS_RG` |

Default image: `Debian:debian-13:13-gen2:latest` (Gen2 is mandatory for Trusted Launch / vTPM).
Default size: `Standard_B4ms`. Azure vTPM PCR values differ from bare metal, so the MVP TPM policy
is PIN authValue only — no PCR binding.

## `tess doctor`

`tess doctor` runs **read-only** readiness probes (no D-Bus, no secret access, no unlock) and prints
a table plus a one-line verdict:

```text
COMPONENT                           STATUS   DETAIL
TPM resource manager (/dev/tpmrm0)  OK       present
TPM raw device (/dev/tpm0)          OK       present
Secret Service daemon               OK       gnome-keyring-daemon on PATH (not contacted)
fprintd                             MISSING  fprintd not on PATH

verdict: READY — TPM present; 1 optional component(s) missing.
```

Only the TPM resource manager is required for the core sealing guarantee; the keyring daemon and
fprintd are reported but never fail the verdict.

## License

[MIT](./LICENSE) © 2026 Adam Hassan
