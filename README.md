<h1 align="center">tess</h1>

<p align="center">
  Windows-Hello-style unlocking for the Linux keyring — your secrets, sealed in the TPM, released by a PIN (with an optional fingerprint front gate, or a face-or-PIN unlock via `--face`), not your password.
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
| TPM | **TPM 2.0** — discrete/firmware, or an **Azure Gen2 Trusted-Launch vTPM** | Operations go through the kernel TPM **resource manager** `/dev/tpmrm0` (required by enroll/unlock and `tess doctor`'s verdict). Debian 13 exposes it by default for a TPM 2.0; the active seat user gets access automatically (udev `uaccess`), with mode `0660` + group `tss` as a headless/SSH fallback (the installer arranges both — see [Install](#install)). The MVP policy binds the PIN authValue only (no PCR binding), so Azure's differing vTPM PCRs are fine. |
| Keyring | **GNOME** login keyring (freedesktop **Secret Service**, `org.freedesktop.secrets`) | Reference daemon. KWallet/KeePassXC expose the same API, so lock-state works, but headless rekey/unlock on non-GNOME daemons is future work. |
| Login stack | **PAM** session phase (`pam_tess.so`, fail-open `optional`) | Wired by `tess install`; never blocks or fails a login. |
| Fingerprint | **fprintd** (`net.reactivated.Fprint`), consumed unmodified | Optional front gate (opt-in); convenience only. |

> Automated tests never touch real hardware: CI exercises a software TPM (swtpm) + the libfprint
> virtual driver, and real-TPM acceptance runs on an Azure Gen2 Trusted-Launch vTPM.

## Install

> Pre-MVP. tess targets **Debian 13 (trixie) on amd64 (x86_64)** with a TPM 2.0. The packaged
> artifact (`tess_<ver>_amd64.deb`) and PAM module path (`/usr/lib/x86_64-linux-gnu/security/`) are
> amd64-specific; `deploy/install.sh` fails early on other architectures. The one-command path builds
> and installs the `.deb`, then wires the fail-open PAM module.

```sh
# on Debian 13 with a TPM 2.0, from a checkout of this repo
deploy/install.sh        # build + install the .deb (with runtime deps), then `tess install`
tess enroll              # set a PIN, seal a random key, rekey your keyring (transactional)
```

`deploy/install.sh` detects Debian 13, builds the `.deb` (installing `cargo-deb` if needed),
installs it with its runtime dependencies, then runs `tess install` to wire the fail-open PAM session
module. It is idempotent. Flags: `--deb PATH` installs a prebuilt package instead of building;
`--no-pam` skips the PAM wiring — wire it later with
`sudo tess install --module /usr/lib/x86_64-linux-gnu/security/pam_tess.so`; `--yes` runs apt
non-interactively (`-y` plus `DEBIAN_FRONTEND=noninteractive`).

### TPM device access (the `tss` group)

`tess enroll`/`unlock`/`status` run **as your login user** (they need your D-Bus session bus to reach
the keyring) and talk to the TPM resource manager at `/dev/tpmrm0`. On a normal graphical/console
login the **active seat user gets access automatically** (the packaged udev rule tags the device
`uaccess`), so there's nothing to do. Running the commands under `sudo` does *not* work — a session
bus authorizes only its owner UID, so root is refused.

The installer ships a udev rule (`/usr/lib/udev/rules.d/70-tess-tpm.rules`) that tags `/dev/tpm*` and
`/dev/tpmrm*` `uaccess` (seat user) and also sets mode `0660` with group `tss` as a fallback for
**headless/SSH or multi-user** setups; `deploy/install.sh` additionally adds the user who ran it to
the `tss` group. If you need the group fallback, note **group membership only applies to a new login
session** — log out and back in (or reboot). When you install the `.deb` directly on a headless box
(not via `deploy/install.sh`), add yourself to `tss` manually:

```sh
sudo usermod -aG tss "$USER"   # then log out and back in
```

To build the package by hand:

```sh
cargo build --release -p tess-cli -p tess-pam   # builds tess, tess-pam-helper, and libpam_tess.so
cargo deb -p tess-cli --no-build           # -> target/debian/tess_<ver>_amd64.deb
```

The package installs `tess` to `/usr/bin/tess`, the PAM helper to `/usr/lib/tess/tess-pam-helper`
(the path the module resolves at runtime), `pam_tess.so` to the Debian PAM module directory
(`/usr/lib/x86_64-linux-gnu/security/`), and the TPM-access udev rule to
`/usr/lib/udev/rules.d/70-tess-tpm.rules`. Its `postinst` creates the `tss` group if missing, reloads
udev, and prints the `usermod -aG tss <user>` step (a package can't know your seat user). It **does
not** edit `/etc/pam.d` — PAM wiring is always the
explicit, fail-open `tess install`, so installing the package can never lock you out. Because the
packaged `tess` lands in `/usr/bin` with no module beside it (`tess install` looks next to the
binary by default), point it at the installed module with
`--module /usr/lib/x86_64-linux-gnu/security/pam_tess.so` — which `deploy/install.sh` does for you. Runtime
dependencies (`gnome-keyring`, the tpm2-tss libraries) are pulled in automatically. `tpm2-tools`
(`tpm2_dictionarylockout`) is a runtime dependency of the hard-lockout recovery path only — `tess
recover` uses it to clear a tripped TPM dictionary-attack lockout with your recovery secret; install
it (`apt install tpm2-tools`) if you expect to recover from a hard lockout, otherwise the rest of tess
works without it. `fprintd` (the
optional fingerprint front gate; tess runs PIN-only without it) is a Recommends — apt installs it by
default, but it is removable and you can skip it with `deploy/install.sh --no-recommends` (or
`apt --no-install-recommends`).

### Recovering from a hard TPM lockout

Every wrong PIN counts toward the TPM's hardware dictionary-attack counter; after enough misses the
TPM enters a **hard lockout** and refuses even the correct PIN until the lockout interval elapses. To
recover immediately, run `tess recover` and enter your **recovery secret**: enrollment bound the TPM
lockout hierarchy to a key derived from that secret, so `tess recover` can run the privileged
`TPM2_DictionaryAttackLockReset` (via `tpm2_dictionarylockout`) to clear the counter, then restore
keyring access. Only the recovery-secret holder can do this — a PIN-guessing attacker who trips the
lockout cannot clear it, so anti-hammering is preserved. `tess recover` (with the recovery secret)
resets the DA counter and restores keyring access but keeps the authValue bound. Given the recovery
secret, `tess unenroll` releases the lockout hierarchy back to its stock (empty) state; if you skip
the recovery secret at unenroll, the authValue stays bound (a warning is printed) and a later
unenroll with the secret releases it.

## Use

```sh
tess status        # enrollment + keyring + TPM state (incl. whether face-unlock is enrolled)
tess enroll        # enroll (prints a recovery secret — keep it safe)
tess enroll --face # also enroll face-unlock: seal the key a 2nd time under a face-released authValue
tess unlock        # one-shot manual unlock (unseal with PIN → unlock keyring)
tess unlock --face # try a liveness-gated face match first (no PIN typed), fall back to the PIN
tess test          # dry-run the session unlock path (no changes)
tess recover       # re-unlock using the recovery secret; auto-resets a hard TPM lockout, and with --reseal re-seals under a new PIN
tess unenroll      # restore the password-based keyring (items preserved); also clears any face-unlock artifacts; releases the TPM lockout hierarchy when given the recovery secret
tess doctor        # check TPM / keyring / fprintd / enrollment readiness (non-zero exit when not ready)
tess doctor --post-install   # stricter check: also require a keyring provider binary on PATH + a completed enrollment
tess install       # wire pam_tess.so into the session stack (idempotent, fail-open)
tess install --uninstall   # remove the tess block + module (best-effort), un-wiring the stack
```

### Face-or-PIN unlock (`--face`)

`tess enroll --face` adds a Windows-Hello-style **face-or-PIN** unlock on top of the PIN, without ever
putting the keyring key on disk. The same random key `K` that the PIN seals is sealed a **second**
time under a fresh, independent random authValue `A_face`; that authValue is stored `0600` at
`face-unlock.key`, and your face is enrolled (an IR embedding + liveness calibration, never a raw
image). `tess unlock --face` captures an IR frame pair, runs the active-illumination **liveness**
check, matches your face, and — on success — reads `A_face` and unseals `K` with **no PIN typed**.
Any face failure, timeout, or missing enrollment falls back to the PIN. The PIN always works; face is
the convenience path.

**Capture backends.** The face pipeline picks an IR capture backend from `MUG_IR_BACKEND`
(`auto` — the default — `virtual`, or `hardware`):

- **virtual substrate** (`MUG_VIRTUAL_IR_DIR`, holding `ir_off.grey`/`ir_on.grey`) — the CI/default
  path and the way to try the flow without a camera; `auto` selects it whenever that dir is set.
- **real Logitech Brio** — opt-in with `MUG_IR_BACKEND=hardware` (or auto-selected when no virtual
  dir is set and a Brio GREY IR node is discoverable). It drives the by-id GREY IR node and the
  UVC extension-unit IR emitter. When no camera is present the factor reports unavailable and unlock
  degrades to the PIN. (Identity matching requires the real `tract` ONNX matcher (`face-model`
  feature + `MUG_MODEL_PATH`); without a model the face factor fails closed and unlock falls back to
  the PIN — see below.) The Brio emitter SET_CUR payloads default to a starting value and
  are overridable with `MUG_IR_EMITTER_ON_HEX` / `MUG_IR_EMITTER_OFF_HEX` (hex, e.g. `0x01`); a wrong
  value fails safe (the emitter stays off, liveness can't pass, the factor degrades to the PIN).

**No model ships — face *identity* matching needs a user-supplied model, and is required for face
unlock.** The model-free path is a deterministic **mock** with **no identity discrimination** — it
would accept essentially any live face — so it is **never** used for a real unlock: without a real
model, `enroll --face` and `unlock --face` **fail closed** (error / fall back to the PIN) rather than
silently accept any face. The mock exists only as a hermetic test substrate, gated behind the
explicit `TESS_ALLOW_MOCK_FACE=1` opt-in (CI sets it; never set it on a real machine). The
security-critical *liveness* gate is real on both backends regardless.

The real matcher uses the self-contained [`tract`](https://github.com/sonos/tract) ONNX engine — no
native ONNX Runtime at runtime (it builds some SIMD kernels via `cc`, so a C toolchain is needed at
build time). To enable face identity matching:

1. **Build with the feature** (it lives on `tess-cli`, so a bare `--features face-model` from the
   workspace root won't resolve):
   ```sh
   cargo build -p tess-cli --release --features face-model
   ```
2. **Download a model** and point `MUG_MODEL_PATH` at it. tess ships none (licensing/size); supply a
   fixed-shape **NCHW** ONNX face-embedding network. Known sources of compatible models:
   - **OpenCV Zoo SFace** (Apache-2.0): <https://github.com/opencv/opencv_zoo/tree/main/models/face_recognition_sface>
   - **InsightFace ArcFace** model zoo: <https://github.com/deepinsight/insightface/tree/master/model_zoo>

   **Input contract** (what tess feeds the model): a single fixed-shape `[1, C, H, W]` input; the
   GREY IR crop is resized to `H×W`, each pixel scaled, and the result replicated across `C` channels.
   The output is flattened and L2-normalized to the embedding; matching is cosine distance against the
   enrolled template. **Pixel scaling is configurable** via `MugConfig.pixel_scale` to match the
   model's training-time normalization:
   - `symmetric` (default) — `(p − 127.5) / 127.5` ≈ `[-1, 1]`, the common ArcFace/SFace convention;
   - `unit` — `p / 255` → `[0, 1]`;
   - `standardized` — `(p / 255 − mean) / std` for the given scalars.

   Most ArcFace/SFace networks use `symmetric`; pick the mode matching your model and verify it
   end-to-end with the enroll self-test before relying on it. Set a non-default mode (or any other
   `MugConfig` field) via a JSON config file pointed at by `MUG_CONFIG`:
   ```sh
   cat > mug.json <<'JSON'
   { "capture_deadline_ms": 2500, "match_threshold": 0.34,
     "liveness": { "min_mean_delta": 0, "min_delta_std": 0, "min_gradient_energy": 0,
       "max_baseline_for_live": 0, "emission_min_delta": 0, "max_saturated_fraction": 0,
       "score_threshold": 0 },
     "model_path": null,
     "pixel_scale": { "mode": "standardized", "mean": 0.5, "std": 0.5 } }
   JSON
   MUG_CONFIG=mug.json MUG_MODEL_PATH=/path/to/face.onnx tess enroll --face
   ```

(See [ADR-0015](docs/adr/0015-tract-onnx-face-matcher.md); `tract` was chosen over `ort`, whose only
releases are yanked or pre-release with a non-hermetic native download.)

#### Manual real-Brio smoke (maintainer, dedicated test machine — never CI)

The hardware path is validated by a manual smoke on a **dedicated test machine** with the Brio
attached (CI never touches a camera). Because `enroll --face` rekeys the login keyring, run this
against a **throwaway keyring/TPM** (a test VM with the Brio passed through, or a disposable login) —
**never the daily-driver keyring/TPM** (`enroll --face` rekeys it):

```sh
# 0. Use a face-model build with a real model (face unlock fails closed without one).
export MUG_MODEL_PATH=/path/to/face.onnx        # see the model contract above

# 1. Enroll against the real camera (look at the Brio; the IR emitter toggles during capture).
MUG_IR_BACKEND=hardware tess enroll --face
# (If the emitter does not light, tune MUG_IR_EMITTER_ON_HEX/OFF_HEX to the device's SET_CUR bytes.)

# 2. Liveness/photo-rejection check: a live face unlocks; a flat printed photo or a phone screen
#    held to the lens must be REJECTED (emitter-on/off IR differential), falling back to the PIN.
MUG_IR_BACKEND=hardware tess unlock --face            # live face → unlock, no PIN typed
MUG_IR_BACKEND=hardware tess unlock --face            # hold up a printed photo → rejected → PIN
# 3. Identity check: a *different* live person must be REJECTED (→ PIN), not unlocked.
MUG_IR_BACKEND=hardware tess unlock --face            # someone else's live face → rejected → PIN
```

A pass is: live face unlocks with no PIN typed; the photo/screen is rejected by liveness and the PIN
fallback engages; and a *different* live person is rejected (PIN fallback). Identity discrimination
requires a real model (`MUG_MODEL_PATH`, above); without one this smoke can't run at all (face fails
closed) unless you set `TESS_ALLOW_MOCK_FACE=1`, which disables identity matching and proves capture +
liveness only.)


**Honest at-rest trade-off — read before enrolling `--face`.** With a typed PIN, *nothing* that
unlocks the key is ever stored, so a powered-off stolen laptop yields nothing: **disk-only theft
stays fully protected either way** (unsealing always needs the TPM/laptop, and `K` is never on disk).
But `A_face` on disk lets the TPM unseal `K` after a userspace face match, so **whole-laptop
powered-off theft is softened** versus PIN-only — mitigated by **full-disk encryption** (use it).
There is no TEE/VBS on commodity Linux to anchor the face gate, so it is a userspace authentication
gate, not a cryptographic binding; a root adversary on a live machine is out of scope. Users who want
the strongest at-rest posture use PIN-only and leave face unenrolled.

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
line.

#### Optional face release path

The face release path is likewise **opt-in** and **off by default**. Enable it with the `face=yes`
module argument (and combine it with `fingerprint=yes` if you want both):

```pam
# Pick one (these are alternatives, not both — adding both runs the module twice per session):
session optional pam_tess.so face=yes                  # face-only
session optional pam_tess.so fingerprint=yes face=yes  # face + fingerprint front gate
```

With `face=yes` the session helper first attempts a **bounded, liveness-gated face match**. Unlike
the fingerprint gate, a successful face match **can release the keyring key without a PIN** — when
PAM supplies no password token (e.g. autologin, or a greeter that doesn't hand the password to the
session) the keyring unlocks on the face match alone; when a token *is* supplied it serves as the PIN
fallback. Mechanically:
the same key is sealed a second time in the TPM under an independent on-disk authValue (`A_face`,
mode 0600), and a live, matching face unseals it. Face is **host-trusted convenience, never the sole
gate** — the PIN authValue stays the real TPM gate, and **any** face outcome (no enrollment, no
capture backend, no match, liveness rejection, timeout, TPM/keyring fault) degrades cleanly to the
PIN. The face capture is bounded inside the helper and the whole helper is bounded by the PAM
module's watchdog, so a wedged camera can never freeze login. Enroll the factor with
`tess enroll --face`. Precedence with everything enabled: **face → fingerprint → PIN → password
fallthrough**.

The face/fingerprint/PIN keyring unlock runs in the **session** phase (where the keyring is opened),
so the `face=yes` / `fingerprint=yes` module arguments take effect there. The **auth**-phase module
is only an optional fail-open *gate*: it always declines and falls through to the password (it does
not itself perform the face/PIN unlock), so use a fail-open control flag and don't expect `face=yes`
to act as an auth factor:

```pam
session optional pam_tess.so face=yes
auth [success=done default=ignore] pam_tess.so
```

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
a table plus a one-line verdict. It exits **non-zero** when a required component is missing, so it
works as a scriptable readiness gate:

```text
COMPONENT                           STATUS   DETAIL
TPM resource manager (/dev/tpmrm0)  OK       present; TPM 2.0; DA lockout 0/3
TPM raw device (/dev/tpm0)          OK       present
Secret Service daemon               OK       gnome-keyring-daemon on PATH (not contacted)
fprintd                             MISSING  fprintd not on PATH
tess enrollment                     OK       enrolled; recovery blob present

verdict: READY — 1 optional component(s) missing.
```

By default only the TPM resource manager is required for the core sealing guarantee; the keyring
daemon, fprintd, and enrollment state are reported but never fail the verdict. The TPM check
requires the resource manager to be **openable** (not merely present) — a present-but-unopenable
node (missing TCTI library, permission denied) reports MISSING, since enroll/unlock would fail too;
the version/DA-lockout detail is read best-effort and never fails the verdict on its own. Run
`tess doctor --post-install` after installing and enrolling to additionally **require** a Secret
Service provider binary on PATH and a completed, parseable enrollment — this is the post-install
verification the Azure acceptance harness asserts. (The keyring check looks for a provider binary,
not a running daemon / active session bus — see the `not contacted` note in the table.) When a
required probe is missing the verdict appends a one-line remediation hint (e.g.
`→ tess enrollment: run \`tess enroll\``).

## License

[MIT](./LICENSE) © 2026 Adam Hassan
