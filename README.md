<h1 align="center">tess</h1>

<p align="center">
  Windows-Hello-style unlocking for the Linux keyring — your secrets, sealed in the TPM, released by a PIN (with an optional fingerprint front gate; face is post-MVP), not your password.
</p>

<p align="center">
  <a href="./LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <img alt="platform: Debian 13" src="https://img.shields.io/badge/platform-Debian%2013-a80030">
  <img alt="TPM 2.0" src="https://img.shields.io/badge/TPM-2.0-5b2d8f">
  <img alt="status: MVP" src="https://img.shields.io/badge/status-MVP%20·%20phase%204-2e7d32">
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
- **Optional fingerprint front gate** — an `fprintd` verify can run ahead of the PIN (opt-in; default PIN-only). It's host-trusted convenience layered *on* the PIN, never a replacement — the PIN authValue is the real gate, so a fingerprint match alone can't unseal.
- **Never freezes your login** — the PAM module runs auth in a watchdog'd helper with a hard timeout and fails open to your password. A stuck TPM or reader can't lock you out (Howdy's #1 flaw, fixed).
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

## Supported platforms

| Component | Supported | Notes |
|---|---|---|
| OS | **Debian 13** (trixie) | The reference target. Other systemd + PAM distros are likely workable but untested. |
| TPM | **TPM 2.0** — discrete/firmware, or an **Azure Gen2 Trusted-Launch vTPM** | Operations go through the kernel TPM **resource manager** `/dev/tpmrm0` (required by enroll/unlock and `tess doctor`'s verdict). Debian 13 exposes it by default for a TPM 2.0. The MVP policy binds the PIN authValue only (no PCR binding), so Azure's differing vTPM PCRs are fine. |
| Keyring | **GNOME** login keyring (freedesktop **Secret Service**, `org.freedesktop.secrets`) | Reference daemon. KWallet/KeePassXC expose the same API, so lock-state works, but headless rekey/unlock on non-GNOME daemons is future work. |
| Login stack | **PAM** session phase (`pam_tess.so`, fail-open `optional`) | Wired by `tess install`; never blocks or fails a login. |
| Fingerprint | **fprintd** (`net.reactivated.Fprint`), consumed unmodified | Optional front gate (opt-in); convenience only. |

> Automated tests never touch real hardware: CI exercises a software TPM (swtpm) + the libfprint
> virtual driver, and real-TPM acceptance runs on an Azure Gen2 Trusted-Launch vTPM.

## Install

> Pre-MVP. tess targets **Debian 13 (trixie)** on a machine with a TPM 2.0. The one-command path
> builds and installs a `.deb`, then wires the fail-open PAM module.

```sh
# on Debian 13 with a TPM 2.0, from a checkout of this repo
deploy/install.sh        # build + install the .deb (with runtime deps), then `tess install`
tess enroll              # set a PIN, seal a random key, rekey your keyring (transactional)
```

`deploy/install.sh` detects Debian 13, builds the `.deb` (installing `cargo-deb` if needed),
installs it with its runtime dependencies, then runs `tess install` to wire the fail-open PAM session
module. It is idempotent. Flags: `--deb PATH` installs a prebuilt package instead of building;
`--no-pam` skips the PAM wiring (run `sudo tess install` yourself later); `--yes` makes apt
non-interactive.

To build the package by hand:

```sh
cargo build --release --workspace          # builds tess, tess-pam-helper, and libpam_tess.so
cargo deb -p tess-cli --no-build           # -> target/debian/tess_<ver>_amd64.deb
```

The package installs `tess` to `/usr/bin/tess`, the PAM helper to `/usr/lib/tess/tess-pam-helper`
(the path the module resolves at runtime), and `pam_tess.so` to the Debian PAM module directory
(`/usr/lib/x86_64-linux-gnu/security/`). It **does not** edit `/etc/pam.d` — PAM wiring is always the
explicit, fail-open `tess install`, so installing the package can never lock you out. Runtime
dependencies (`gnome-keyring`, the tpm2-tss libraries) are pulled in automatically; `fprintd` is a
Recommends (the optional fingerprint front gate; tess runs PIN-only without it).

## Use

```sh
tess status        # enrollment + keyring + TPM state
tess enroll        # enroll (prints a recovery secret — keep it safe)
tess unlock        # one-shot manual unlock (unseal with PIN → unlock keyring)
tess test          # dry-run the session unlock path (no changes)
tess recover       # re-unlock using the recovery secret (add --reseal to re-seal under a new PIN)
tess unenroll      # restore the password-based keyring (items preserved)
tess doctor        # check TPM / keyring / fprintd readiness
tess install       # wire pam_tess.so into the session stack (idempotent, fail-open)
tess install --uninstall   # remove the tess block + module (best-effort), un-wiring the stack
```

### PAM wiring (`tess install`)

`tess install` (run as root) does two things, idempotently:

1. copies the built `pam_tess.so` into the system PAM module directory (auto-detected by locating a
   stock module, `pam_permit.so`, under the common library roots `/lib`, `/usr/lib`, `/lib64`, and
   `/usr/lib64` — the same locate-`pam_permit.so` trick the CI smoke test uses, which itself only
   needs to search `/lib` and `/usr/lib`), and
2. adds one line to the session stack (`/etc/pam.d/common-session` by default) inside a re-runnable
   marked block:

   ```pam
   # >>> tess >>>
   # Managed by `tess install` — remove with `tess install --uninstall`. `optional` means a tess
   # failure is ignored and login proceeds with the keyring left locked; it can never lock you out.
   session optional pam_tess.so
   # <<< tess <<<
   ```

The control flag is `optional`, so a tess failure (no TPM, a slow or declined unseal) is ignored and
login proceeds with the keyring simply left locked — **it can never lock you out**. Before editing,
`tess install` backs up the original file and validates the result is well-formed and fail-open,
aborting if not. `tess install --uninstall` removes the managed block (restoring the stack to its
pre-tess state while preserving any admin edits made outside the block) and deletes the module on a
best-effort basis (if module-dir auto-detection fails it still un-wires the stack and warns rather
than aborting); it is safe to run when nothing is installed. Flags: `--service`, `--module`,
`--module-dir` override the auto-detected paths. The snippet and exact placement are documented in
[`deploy/pam/`](./deploy/pam/README.md).

#### Optional fingerprint front gate

The fingerprint front gate is **opt-in** and **off by default** (PIN-only). To enable it, add the
`fingerprint=yes` module argument to the tess PAM line:

```pam
session optional pam_tess.so fingerprint=yes
```

The module then runs one bounded `fprintd` verify ahead of the PIN unseal and falls through to the
PIN **regardless of the result** — a match never skips the PIN, and a no-match or stalled reader
never blocks login. Precedence: **fingerprint (convenience) → PIN (the real gate) → password
fallthrough**. There is no `tess`-CLI fingerprint flag in the MVP; the gate is configured at the PAM
line. Multi-factor enrollment UX (`--fingerprint`/`--face`) is post-MVP (Phase 5, the Mug face
daemon).

> The PAM install logic is exercised in tests against throwaway fixtures only — it never edits a real
> `/etc/pam.d` or module directory in CI.

## Status

MVP (Phase 4). The TPM core, keyring rekey/unlock, fprintd verify, the non-blocking PAM module, the
transactional enroll/recover/unenroll lifecycle, and the installer all ship and are green in CI on a
software TPM. Remaining Phase 4 work: the `.deb` package (#38) and the real Azure-vTPM end-to-end
acceptance. Roadmap and phase checklist live in [`PLAN.md`](./PLAN.md); contributor and agent rules
in [`AGENTS.md`](./AGENTS.md); the security boundary in [`docs/threat-model.md`](./docs/threat-model.md).

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

# Self-check readiness on the VM (prints the same table as below). NOTE: tess is NOT preinstalled
# on the VM — build it (`cargo build --release`) and copy the `tess` binary to the VM first;
# otherwise this fails with `tess: command not found`.
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
