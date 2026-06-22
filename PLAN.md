# PLAN.md — LinuxTPMKeyring (`tess` / `tessera`)

> **Name (confirmed): `tessera`** is the project/full name; **`tess`** is the short form and the CLI
> binary. PAM module `pam_tess.so`, crates `tess-*`. Repo stays `LinuxTPMKeyring`. The Phase 5 face
> daemon stays **Mug**. (A Roman *tessera* was a token used as a password / proof of identity to gain
> entry — fitting, with the deliberate caveat below that tess authenticates you *to your own system*,
> it is **not** a proof-of-presence/attestation token to any third party.)

## 1. Overview

LinuxTPMKeyring brings Windows-Hello-style unlocking to the Linux secret store. Today the GNOME
login keyring is encrypted with a key **derived from your login password**, so biometric logins
(Howdy, `fprintd`) leave the keyring locked — you still type your password after every reboot. We
fix this the way Windows/macOS/iOS/Android all do: a durable, high-entropy **random** key lives
sealed in the **TPM 2.0**, and authentication (**a PIN** for the MVP, **fingerprint/face** layered
on) *authorizes the TPM to release* that key (it is never derived from the PIN/biometric). A PAM
module unseals the key at session open and hands it to `gnome-keyring`, so the keyring unlocks with
no password. The MVP is **100% safe Rust, userspace-only** (no kernel module, no custom kernel, no
eBPF — all confirmed unnecessary), deployable on **Debian 13** or an **Azure Gen2 Trusted-Launch
VM** with one command.

**Security scope (honest, and load-bearing):** this protects your keyring **at rest** — a stolen or
powered-off laptop's secrets are sealed to *your* TPM and need *your* PIN, with hardware
anti-hammering (TPM dictionary-attack lockout). It is a real upgrade over today's
offline-brute-forceable password-derived key, and it matches the part of Windows Hello that protects
*your key*. It explicitly does **NOT** defend against a **root/kernel adversary on a live machine**
— root can keylog the PIN or read the released key from memory. That's an acceptable boundary
*because tess only authenticates a local user to their own system*: an attacker who is already
root/kernel on the live box has system access regardless, so there's nothing left to protect from
them here. No Linux system solves runtime-root without VBS-class isolation, which does not exist on
commodity hardware (see §10, Threat Model). We **scope root out and say so** — the same position
ChromeOS cryptohome ships. We do **not** build VBS, do **not** use any TEE, and do **not** modify
fprintd/libfprint.

**What tess is and isn't (the README must state this plainly):** tess is **system auth** — it
unlocks your own secrets on a machine you control once you pass the gate. It is **NOT a
proof-of-presence or attestation** mechanism: it cannot prove to a third party or a remote policy
that a specific human was physically present (the biometric leg is host-trusted, and the model
assumes the box isn't already root-compromised). Use it to log in and unlock your keyring; never as
evidence of presence to something that doesn't already trust the machine.

## 2. Architecture

A Cargo **workspace** of small crates with hard boundaries. Everything is `#![forbid(unsafe_code)]`
**except** the PAM FFI crate, which confines `unsafe` to one `ffi` module.

| Crate | Type | Responsibility | Key deps |
|---|---|---|---|
| `tess-core` | lib | Shared types, versioned `Metadata` schema, config, error types, secret hygiene (`zeroize`/`secrecy`/`mlock`), `SecretStash` trait | `serde`, `thiserror`, `zeroize`, `secrecy`, `nix`, `getrandom` |
| `tess-tpm` | lib | TPM2 seal/unseal of a random 256-bit key, bound to a **PolicyAuthValue (PIN)**; **mandatory HMAC + parameter-encryption sessions**; ECC primary; DA-lockout aware; swtpm (dev/CI) + real/vTPM | `tss-esapi ≥7.1.0`, `tess-core` |
| `tess-keyring` | lib | `KeyringBackend` trait over the freedesktop **Secret Service** API (`org.freedesktop.secrets`) — GNOME reference impl; KWallet supported via `apiEnabled`. Rekey (enroll) + unlock (runtime) | `zbus`, `secret-service`, `tess-core` |
| `tess-fprint` | lib | `fprintd` client over `net.reactivated.Fprint` (verify flow, **consumed unmodified**) + deterministic mock harness (libfprint virtual driver + `python-dbusmock`) | `zbus`, `tess-core` |
| `tess-pam` | cdylib + rlib | `pam_tess.so`: **non-blocking** gate → unseal → unlock. Hand-rolled minimal PAM FFI (the only `unsafe`). Heavy work runs in a **watchdog'd helper process** under a hard timeout; fails open to password | `libc`, the libs above |
| `tess-cli` | bin | `tess` binary (long form `tessera`): `enroll`, `unlock`, `status`, `doctor`, `test`, `install`, `recover`, `unenroll`. Atomic enrollment with a printed recovery secret | `clap`, the libs above |

**Non-blocking PAM (hard requirement — Howdy's #1 flaw fixed).** The PAM module never does blocking
TPM/D-Bus/camera I/O on the PAM thread. It forks a short-lived **helper process**, waits with a
hard wall-clock deadline, and on timeout SIGTERM→SIGKILLs the helper and returns
`PAM_AUTHINFO_UNAVAIL`/`PAM_IGNORE` so the stack **falls through to the password factor**
(`[success=done default=ignore]`). The *session*-phase unseal must return success regardless — a
failed/slow unseal degrades to "keyring stays locked, login proceeds," never a frozen login. A
deterministic test injects a stall (slow swtpm / blocking dbusmock) and asserts the stack completes
within N seconds and the helper PID is reaped.

**Security controls baked in from day one** (from the prior-vuln survey, §10):
- **No PCR-only sealing.** PIN `PolicyAuthValue` + TPM DA-lockout is the anti-bruteforce root.
- **Mandatory TPM2 HMAC + parameter-encryption sessions** on every seal/unseal, so the PIN and the
  unsealed blob are encrypted/integrity-protected in transit (defeats bus-sniffing / interposer).
- **ECC (P-256)** for TPM objects; the sealed secret is **self-generated** (`getrandom` mixed with
  TPM RNG), never a TPM-born RSA key (sidesteps ROCA-class keygen flaws).
- **Constant-time** PIN/secret handling; lean on DA-lockout, not comparison-timing secrecy.
- **`mlock` + `zeroize`** the released key, disable core dumps (`PR_SET_DUMPABLE=0`), minimize key
  lifetime to the unseal→handoff window.
- **Bind the unseal to the authenticated PAM session** (single-use, session-scoped) — no trusting a
  replayable out-of-band "verify-match" (defeats TOCTOU / confused-deputy).
- **`tss-esapi ≥ 7.1.0`** (closes RUSTSEC-2023-0044 FFI use-after-free).

**Prior art we study, not reinvent:** **ChromeOS cryptohome** (seal a *random* per-user key, never
the password; the unpadded-blob trick to throttle guesses without tripping TPM lockout) and
**systemd-homed** (signed multi-factor user-record schema shape).

**Keyring-preservation invariant (must never break a real user's keyring).** Enrollment **rekeys the
existing login keyring in place** — it changes the *wrapping key* (password-derived → random TPM
secret) while preserving **every existing item** (passwords, tokens, SSH keys, Wi-Fi secrets). It
must never create a fresh empty keyring that shadows the old one, and never drop items. The flow:
back up a recovery secret → verify the old keyring unlocks → re-wrap with the new secret → verify a
known pre-existing item still decrypts → only then commit. Any failure rolls back to the original
password-derived state. A test asserts "N pre-existing secrets are all still readable after enroll,
recover, and unenroll." (This is tested only against throwaway keyrings on the Azure VM — never the
user's real keyring.)

## 3. Repo Layout

```
LinuxTPMKeyring/
├── Cargo.toml                      # workspace
├── rust-toolchain.toml
├── deny.toml                       # cargo-deny: advisories/bans/licenses/sources
├── crates/
│   ├── tess-core/  tess-tpm/  tess-keyring/  tess-fprint/  tess-pam/  tess-cli/
│   └── */fuzz/                     # cargo-fuzz targets (Phase 6)
├── deploy/
│   ├── azure/                      # Gen2 Trusted-Launch Debian13 + vTPM + SSH (acceptance only)
│   ├── qemu/                       # local QEMU+swtpm vTPM (contributors only)
│   ├── debian/                     # cargo-deb packaging
│   ├── pam/                        # pam.d snippets
│   └── install.sh
├── testing/
│   ├── swtpm/                      # software-TPM harness
│   └── fprint-mock/                # python-dbusmock + virtual-driver helpers
├── docs/
│   ├── adr/
│   ├── architecture.md
│   └── threat-model.md             # the honest scope (root out, at-rest guarantee)
├── references/                     # gitignored
├── .github/workflows/test.yml
├── PLAN.md  AGENTS.md  README.md  CONTRIBUTING.md  NOTES.md  LICENSE
```

## 4. MVP

**Smallest end-to-end demo (real, not stubbed):** on an Azure Gen2 Trusted-Launch Debian 13 VM,
`tess enroll` sets a PIN, generates a random key, seals it in the **real vTPM** bound to the PIN
(HMAC sessions on), rekeys the login keyring to that key, and prints a recovery secret. A fresh
session whose auth is satisfied by the **fprintd virtual driver** (scripted match) has the PAM module
unseal the key and the GNOME login keyring is **unlocked with no password**. `tess status`
confirms keyring=unlocked, TPM-backed. Survives reboot. A stall-injection test proves login never
freezes. Teardown removes all Azure resources.

## 5. Phased Checklist

> **MVP = Phases 0–4.** Phase 5 = post-MVP face daemon (Mug). Phase 6 = fuzzing/hardening. Tick
> boxes as deliverables merge. **The developer's host (the user's personal laptop) is never used to
> run, test, enroll, seal, or touch any secret/keyring/TPM.** Automated tests run in **CI on
> GitHub-hosted runners** (swtpm + libfprint virtual driver — not the host, free). Real-vTPM exit
> tests and any interactive agent testing run on an **Azure Gen2 Trusted-Launch VM**. `deploy/qemu/`
> (local QEMU+swtpm) is an *optional convenience for external contributors only* — the agent does not
> use it on this user's machine.

---

### Phase 0 — Bootstrap skeleton, test substrate & supply-chain gates

**Goal:** Green workspace with six crate stubs, CI (incl. `cargo audit`/`cargo deny`), and
reproducible vTPM/fprint test substrates (local QEMU+swtpm + virtual fprint).

**Exit test:** `cargo build/clippy/test --workspace` green in CI with `cargo audit` + `cargo deny`
passing; in CI a swtpm-backed `/dev/tpmrm0` that `tess-tpm` connects to is present; on
a provisioned Azure VM `tess doctor` reports the vTPM present.

**Deliverables:**
- [ ] Workspace `Cargo.toml` + `rust-toolchain.toml` + six crate skeletons; `#![forbid(unsafe_code)]` everywhere except `tess-pam`
- [ ] `tess-core`: error enum, versioned `Metadata`, `SecretBytes` (zeroizing + mlock), `SecretStash`/`KeyringBackend`/`AuthGate` trait stubs
- [x] `.github/workflows/test.yml`: `pull_request` + `workflow_dispatch`, concurrency-cancel, installs swtpm/tpm2-tss, runs fmt/clippy/test + **`cargo audit` + `cargo deny`**
- [x] `deny.toml` (advisories deny, license allowlist MIT/Apache/BSD/ISC, sources crates.io-only); pin `tss-esapi ≥ 7.1.0`
- [x] `testing/swtpm/run.sh` + mssim/socket TCTI helper; `tess-tpm` connect smoke test
- [x] `deploy/qemu/up.sh`/`down.sh`: local Debian 13 KVM guest with `swtpm` vTPM, SSH key-only — optional, for external contributors (the agent uses CI + Azure, never this host)
- [x] `deploy/azure/provision.sh` (+ Bicep) Gen2 Trusted-Launch Debian13 B-series, vTPM, SSH pubkey, tagged `project=LinuxTPMKeyring`; `teardown.sh`
- [x] `tess doctor` skeleton: probes `/dev/tpmrm0` + `/dev/tpm0`, a Secret Service daemon binary on PATH, and fprintd on PATH
- [ ] `README.md` (pretty) + `docs/architecture.md` + `docs/threat-model.md` stubs

| Wave | Worktree slug | Depends on | Tasks |
|---|---|---|---|
| 1 (solo) | bootstrap-skeleton | — | workspace, crate stubs, `forbid(unsafe)`, `tess-core` types + trait stubs |
| 2 (parallel ×3) | ci-supplychain | wave 1 | `test.yml`, `deny.toml`, cargo audit/deny, fmt/clippy/test wiring |
| 2 (parallel ×3) | vm-substrate | wave 1 | `deploy/qemu/` local swtpm vTPM VM, `testing/swtpm/`, `tess-tpm` smoke test |
| 2 (parallel ×3) | azure-provisioning | wave 1 | `deploy/azure/` provision+teardown, `tess doctor` skeleton |

---

### Phase 1 — TPM seal/unseal core (`tess-tpm`) with hardened sessions

**Goal:** Random key sealed under a PIN policy with **HMAC/parameter-encryption sessions** and ECC,
unsealed back correctly — fixing every design error the reference repo made.

**Exit test:** on the **Azure vTPM**, `cargo test -p tess-tpm --features hw` round-trips a random
32-byte secret with PIN; wrong PIN fails; N wrong PINs trip DA lockout; sessions are encrypted
(verified by asserting the bus transcript carries no plaintext authValue). Same suite green on
swtpm in CI (`--features sim`).

**Deliverables:**
- [x] `TctiConfig` (swtpm TCTI vs `/dev/tpmrm0`) via feature/env
- [x] ECC `create_primary()` under the owner hierarchy; deterministic template
- [x] **Salted HMAC + parameter-encryption session** helper used by every seal/unseal
- [x] `seal(secret, pin)`: `PolicyAuthValue` policy, authValue = PIN, encrypted session
- [x] `unseal(pin)`: policy session → `unseal` → `SecretBytes` (mlock'd, zeroized)
- [x] Key-gen: `getrandom` mixed with TPM `GetRandom`; constant-time PIN handling
- [x] Versioned blob+metadata persistence; **no secret/secret-hash ever on disk**
- [x] DA-lockout error mapping + lockout-state read + PIN-holder recovery (privileged lockout-hierarchy reset deferred → #16 / ADR-0008)
- [x] Tests (swtpm/CI, `--features sim`): round-trip, wrong-PIN, lockout, persistence reload, **session-encryption assertion**; `hw`-feature suite + Azure exit-test harness + `doctor` TPM detail authored
- [x] Same suite green on the **Azure vTPM** (`cargo test -p tess-tpm --features hw`) — orchestrator's real-hardware exit run

| Wave | Worktree slug | Depends on | Tasks |
|---|---|---|---|
| 1 (solo) | tpm-sessions-primary | Phase 0 | `TctiConfig`, ECC primary, HMAC/param-encryption session helper, `sim`/`hw` flags |
| 2 (parallel ×2) | tpm-seal-unseal | tpm-sessions-primary | `seal`/`unseal`, `PolicyAuthValue`, key-gen mix, constant-time, mlock/zeroize |
| 2 (parallel ×2) | tpm-persistence-lockout | tpm-sessions-primary | versioned persistence, DA-lockout mapping + reset |
| 3 (solo) | tpm-hw-validation | wave 2 | vTPM exit-test harness, session-encryption assertion, `doctor` TPM detail |

---

### Phase 2 — Keyring, fprintd client, PAM FFI (three parallel tracks)

**Goal:** Land the three remaining blocks independently: Secret Service rekey/unlock, fprintd verify
(real mock), and a non-blocking PAM shell.

**Exit test:** (a) `cargo test -p tess-keyring` rekeys a throwaway keyring to a random secret and
re-unlocks it via Secret Service against a real `gnome-keyring-daemon`; (b) `cargo test -p
tess-fprint` drives enroll+verify(match/no-match) headless through the libfprint virtual driver +
`python-dbusmock`; (c) `pam_tess.so` loads in `pamtester`/`pam_wrapper`, runs a no-op session
returning `PAM_SUCCESS`, **and a stall-injection test proves it times out and falls through within N
seconds with the helper reaped**.

**Deliverables:**
- [x] `tess-keyring`: `KeyringBackend` trait over `org.freedesktop.secrets` (`Unlock`/`Lock`/`Prompt`)
- [x] `tess-keyring`: `rekey(old, new)` (enroll) + `unlock(secret)`; GNOME reference impl; unstable private calls isolated behind the trait with a stable fallback
- [x] `tess-keyring`: KWallet notes (`apiEnabled`), native-`pam_kwallet` path explicitly out of scope
- [x] `tess-keyring`: tests vs a real daemon on the session bus
- [x] `tess-fprint`: `FprintClient` (`Claim`/`VerifyStart`/`VerifyStatus`/`Release`), consumed unmodified
- [x] `tess-fprint`: `testing/fprint-mock/` virtual-driver socket scripting + `python-dbusmock` template
- [x] `tess-fprint`: deterministic verify(match/no-match) tests, headless
- [x] `tess-pam`: minimal `libc` FFI in isolated `ffi` module; session entrypoints
- [x] `tess-pam`: **watchdog'd helper process + hard timeout + fail-open**; SSH/remote + no-TPM abort
- [x] `tess-pam`: **stall-injection "login never freezes" test** (bounded, helper reaped)

| Wave | Worktree slug | Depends on | Tasks |
|---|---|---|---|
| 1 (parallel ×3) | keyring-secretservice | Phase 1 | `KeyringBackend` over Secret Service, `rekey`, `unlock`, daemon tests, KWallet notes |
| 1 (parallel ×3) | fprint-client-mock | Phase 1 | `FprintClient`, `fprint-mock/` harness, verify tests |
| 1 (parallel ×3) | pam-nonblocking-shell | Phase 1 | PAM FFI, helper-process + timeout + fail-open, SSH/no-TPM abort, stall test |

---

### Phase 3 — Enrollment CLI & PAM wiring (transactional, recoverable)

**Goal:** Compose the blocks into a usable `tess` CLI and a PAM module that unseals and unlocks,
with **atomic, recoverable** enrollment (the abandonment-risk killer).

**Exit test:** in **CI (GitHub runner with swtpm)** and on the **Azure VM**: `tess enroll --pin 1234`
prints a recovery secret; `tess status` shows `enrolled, keyring=locked`; running the session PAM
stack via `pamtester` unseals and flips to `keyring=unlocked`; `tess recover` re-unlocks via the
recovery secret; `tess unenroll` restores password-based keyring with all items intact. `cargo test
--workspace` green.

**Deliverables:**
- [x] `tess enroll`: gen key → seal (PIN) → **back up recovery secret first** → **rekey keyring in place, preserving all existing items** → write metadata; transactional with rollback
- [x] `tess recover`: re-unlock/re-enroll via recovery secret (covers TPM clear, PIN loss, PCR change)
- [x] `tess unenroll`: rekey keyring back to a password, remove blobs — restores stock behavior, items intact
- [x] `tess status`: enrollment/keyring/TPM/DA-lockout state
- [x] `tess unlock` (one-shot) + `tess test` (dry-run session path)
- [ ] `pam_tess.so` session flow: non-blocking gate (PIN via conv now) → `tess-tpm::unseal` → `tess-keyring::unlock`; bounded, errors never swallowed
- [x] `deploy/pam/` snippet + `tess install`/uninstall (idempotent `pam.d` edit)
- [ ] Integration test: enroll → simulated session → unlocked, + rollback/recovery coverage, + **"N pre-existing secrets survive enroll/recover/unenroll" preservation assertion**

| Wave | Worktree slug | Depends on | Tasks |
|---|---|---|---|
| 1 (solo) | enroll-transaction | Phase 2 | atomic `enroll`, recovery-secret backup, rollback, metadata |
| 2 (parallel ×3) | cli-lifecycle | enroll-transaction | `recover`, `unenroll`, `status`, `unlock`, `test` |
| 2 (parallel ×3) | pam-wire | enroll-transaction | `pam_tess.so` session unseal→unlock, conv PIN, bounded |
| 2 (parallel ×3) | installer-pam-config | enroll-transaction | `deploy/pam/`, `tess install`/uninstall, idempotent edit |
| 3 (solo) | phase3-integration | wave 2 | enroll→session→unlock integration + recovery coverage |

---

### Phase 4 — End-to-end on Azure vTPM + one-command deploy (MVP ships)

**Goal:** Prove the full chain on a real TPM with a virtual-fprint front-end; make it trivially
installable on Debian 13.

**Exit test (MVP demo):** fresh Azure Gen2 Trusted-Launch Debian 13 VM; one `tess install`;
`tess enroll` seals to the **real vTPM**; a session satisfied by the **fprintd virtual driver**
unlocks the GNOME login keyring with **no password** (verified by `secret-tool`/`tess status`);
survives reboot; stall-injection proves login never freezes; teardown removes all Azure resources.

**Deliverables:**
- [ ] Wire `tess-fprint` verify as the PAM gate (PIN kept as fallback), still non-blocking
- [ ] `deploy/install.sh`: detect Debian 13, install runtime deps, build/fetch binaries, `tess install`
- [ ] `deploy/debian/`: `cargo-deb` producing an installable `.deb`
- [ ] Azure E2E harness: provision → install → enroll → scripted virtual-fprint session → assert unlocked → teardown (one script)
- [ ] Reboot-persistence test
- [ ] `docs/threat-model.md` finalized (root out of scope, at-rest guarantee, biometric host-trusted, recovery/uninstall)
- [ ] README: real install/use/uninstall + supported-platform matrix
- [ ] `tess doctor` full readiness + post-install verification

| Wave | Worktree slug | Depends on | Tasks |
|---|---|---|---|
| 1 (solo) | pam-fprint-gate | Phase 3 | swap PIN-only gate for fprintd-verify (PIN fallback), still bounded/non-blocking |
| 2 (parallel ×3) | debian-packaging | pam-fprint-gate | `cargo-deb`, `.deb`, `install.sh`, dep detection |
| 2 (parallel ×3) | azure-e2e-harness | pam-fprint-gate | provision→install→enroll→virtual-fprint→assert→teardown |
| 2 (parallel ×3) | docs-threatmodel | pam-fprint-gate | finalize `threat-model.md`, README, platform matrix |
| 3 (solo) | mvp-acceptance | wave 2 | full Azure vTPM acceptance demo, reboot-persistence, sign-off |

---

### Phase 5 — Mug: async secure face daemon (post-MVP)

**Goal:** A Rust, async, IR-aware face factor that **never blocks login** — a *real* secure
replacement for Howdy, plugged in as another `AuthGate` behind the same bounded-timeout interface.
Howdy's flaws we explicitly fix: it's Python (slow, heavy to load in PAM), it blocks login on a
stuck camera, and it does **no real liveness/anti-spoofing** — it's dlib face *recognition* on the
RGB or IR stream with no defense against a photo/video. Mug targets genuine security: IR-reflectance
liveness, a modern matcher, async non-blocking. First hardware target: **Logitech Brio** (Windows-
Hello IR camera). *(The user's Brio is physically connected for one-time hardware/format discovery —
enumerate V4L2 nodes, probe the IR emitter control, list formats — but **no face-present testing**:
the user will never be in front of the camera. All matcher/liveness testing uses synthetic/virtual
V4L2 IR frames, never the user's real face.)*

**Exit test:** on a VM with a virtual V4L2 IR source, Mug authenticates a scripted IR frame within a
bounded async deadline without blocking the PAM stack; a printed-photo spoof is rejected by the IR
liveness check; enrollment is non-destructive.

**Deliverables:**
- [ ] Adopt the existing `~/Desktop/Mug` skeleton (PAM FFI, V4L2 capture, ONNX engine) into the workspace
- [ ] Brio IR: enumerate greyscale V4L2 nodes; one-time IR-emitter enable (wrap/learn from `linux-enable-ir-emitter`, also Rust); stable device-by-path
- [ ] Capture `Y8/Y16` IR frames; **IR-reflectance liveness** as the primary anti-spoof signal
- [ ] Face matcher in safe Rust via `ort` (ArcFace/SFace ONNX) — verify model licensing before shipping
- [ ] Async, timeout-bounded face verify as an `AuthGate`; never the sole factor (TPM PIN remains the gate)
- [ ] `tess enroll --pin --fingerprint --face` multi-factor UX
- [ ] (stretch) Slint-based pretty enroll/unlock UI (software renderer, greeter-friendly)

| Wave | Worktree slug | Depends on | Tasks |
|---|---|---|---|
| 1 (parallel ×2) | mug-capture-ir | Phase 4 | Mug import, Brio IR node enum, emitter enable, bounded V4L2 capture |
| 1 (parallel ×2) | mug-matcher-liveness | Phase 4 | `ort` ArcFace matcher, IR-reflectance liveness, enroll store |
| 2 (solo) | mug-authgate | wave 1 | async non-blocking `AuthGate`, multi-factor enroll wiring |
| 3 (solo) | mug-ui | wave 2 | Slint enroll/unlock UI (stretch) |

---

### Phase 6 — Fuzzing & supply-chain hardening (post-MVP)

**Goal:** Fuzz every place untrusted bytes reach a parser; formalize dependency hygiene.

**Exit test:** three `cargo-fuzz` targets run clean for a bounded duration in nightly CI; `cargo
audit`/`cargo deny`/`cargo vet` gate every PR; `cargo +nightly -Z minimal-versions check` passes.

**Deliverables:**
- [ ] `fuzz_metadata` — the on-disk `Metadata` deserializer + our post-deserialize validation
- [ ] `fuzz_tpm_blob` — the sealed pub/priv blob loader before it crosses into `tss-esapi` FFI
- [ ] `fuzz_dbus_reply` — our interpretation of Secret Service / fprintd replies
- [ ] Seeded corpora from real artifacts; short-in-PR / long-nightly CI
- [ ] `cargo vet` supply-chain audit set imported; `tess-tpm`/`secret-service` manually certified
- [ ] `cargo +nightly -Z minimal-versions` CI job (prove declared lower bounds build)
- [ ] `auditd` tamper-evidence config in packaging (documented as *audit*, not a security boundary)

| Wave | Worktree slug | Depends on | Tasks |
|---|---|---|---|
| 1 (parallel ×3) | fuzz-metadata | Phase 4 | `fuzz_metadata` target + corpus + nightly wiring |
| 1 (parallel ×3) | fuzz-tpm-blob | Phase 4 | `fuzz_tpm_blob` target + corpus |
| 1 (parallel ×3) | fuzz-dbus-reply | Phase 4 | `fuzz_dbus_reply` target + corpus |
| 2 (solo) | supplychain-vet | wave 1 | `cargo vet`, minimal-versions CI, auditd config |

## 6. Anticipated Risks

- **Login freeze (perf/safety, #1 UX risk).** Howdy hangs login on a stuck camera. *Mitigation:*
  PAM module never blocks on its own thread — watchdog'd helper process, hard timeout, fail-open to
  password; session unseal returns success regardless; deterministic stall-injection test.
- **Enrollment is destructive / lockout (abandonment, #1 safety risk).** Rekeying the keyring to a
  TPM-only secret can lock the user out if interrupted. *Mitigation:* transactional enroll, recovery
  secret backed up **before** rekey, rollback on failure; `recover`/`unenroll` always restore.
- **Overclaiming runtime-root resistance (security/honesty).** No Linux has VBS-class isolation;
  TEEs don't fit (SGX removed from client, TDX/SEV wrong-direction & server-only, TrustZone ARM-only
  & vendor-gated). *Mitigation:* **root explicitly out of scope**, documented in `threat-model.md`;
  deliver the at-rest + anti-hammering guarantee (cryptohome's core) and claim exactly that.
- **Bus sniffing / interposer (security).** PCR-only sealing + cleartext bus = key lifted off SPI
  (Dolos/BitLocker, TPM Genie). *Mitigation:* PIN authValue (never PCR-only) + **mandatory HMAC/
  parameter-encryption sessions**.
- **Weak keygen / RNG (security).** ROCA. *Mitigation:* seal a self-generated random blob (not a TPM
  RSA key); ECC; mix `getrandom` + TPM RNG.
- **Side channels (security).** TPM-FAIL, Hertzbleed. *Mitigation:* constant-time PIN handling; rely
  on DA-lockout, not comparison-timing; don't roll our own crypto.
- **Biometric spoof / host-trust (security).** Win Hello IR-replay (CVE-2021-34466); root can forge
  `verify-match`. *Mitigation:* biometric is **host-trusted convenience, never the sole gate**; PIN
  authValue is the real gate; IR-reflectance liveness in Mug. **No fprintd/libfprint changes.**
- **TOCTOU / confused deputy (security).** *Mitigation:* unseal inside PAM auth gated by TPM policy;
  session-bound single-use match; strict gate ordering.
- **Memory disclosure (security).** Cold boot, swap, ptrace, core dump. *Mitigation:* `mlock` +
  `zeroize` ASAP, disable core dumps, minimize key lifetime.
- **Dependency vulns (supply chain).** RUSTSEC-2023-0044 in `tss-esapi` (FFI UAF). *Mitigation:* pin
  `tss-esapi ≥ 7.1.0`; `cargo audit`/`deny`/`vet` in CI; fuzz our own parsers (Phase 6).
- **Unstable private GNOME D-Bus API (dep churn).** *Mitigation:* isolate behind `KeyringBackend`,
  prefer stable `gnome-keyring-daemon --unlock`, integration-test the real daemon.
- **Azure vTPM PCRs differ from bare metal (portability).** *Mitigation:* MVP policy is PIN authValue
  only, no PCR binding; PCR(7) + signed-policy is a deferred opt-in.
- **Hardware-dependent tests (fragility).** *Mitigation:* local QEMU+swtpm + libfprint virtual driver
  + `python-dbusmock`; real-vTPM exit tests gated to the Azure acceptance harness. **Nothing runs on
  the host.**
- **Cloud cost (Azure).** *Mitigation:* cheapest B-series/spot, tagged, deallocate-when-idle,
  one-command `teardown.sh`, kill-by note in NOTES.md.
- **On-disk format lock-in (data model).** *Mitigation:* `version` field in `Metadata` from day one.
- **PAM loaded into many services (concurrency).** *Mitigation:* abort in SSH/remote, idempotent
  unlock, bounded timeouts, no shared mutable global state, reap helper/swtpm processes.

## 7. Extension Points

- **`PolicyOR` multi-factor / PCR binding** — hook: `tess-tpm` policy builder takes a list of branches
  + a policy-type in `Metadata`; MVP passes one (PIN).
- **`AuthGate` factors** — hook: fprint (MVP) and Mug face (P5) both implement the same bounded gate.
- **`SecretStash`** — hook: heap impl now; `keyctl logon` kernel-keyring impl later (minor hardening).
- **`KeyringBackend`** — hook: Secret Service (GNOME ref) now; KWallet/KeePassXC via the same trait.
- **Measured boot (future bar-raise toward the ChromeOS model)** — hook: optional PCR policy +
  signed-policy update; raises the cost of *persistent* root, never claims runtime-root isolation.
- **Tamper-evidence** — hook: `auditd` rules in packaging (audit only, explicitly not a boundary).

## 8. Teardown

- **Cloud:** `deploy/azure/teardown.sh` deletes the `project=LinuxTPMKeyring` resource group; listed
  back before deletion. Optional contributor VM: `deploy/qemu/down.sh`. **Azure cost is capped at ~$50 over the
  current week**: provision a burstable VM sized for Rust builds (default **Standard_B4ms** — 4 vCPU /
  16 GB; scale to B8ms only for a heavy build, deallocate immediately after). **Deallocate whenever
  idle and at end-of-work** — the user is away from the laptop, so a forgotten running VM is the main
  cost risk. Record the kill-by date in `NOTES.md`. CI testing runs on free GitHub-hosted runners
  (swtpm), not Azure, so the VM is only up for real-vTPM acceptance + interactive debugging.
- **Release (wind-down only):** the `.deb` is *built* in Phase 4 for the install path, but a
  publishing/release CI workflow (`.github/workflows/release.yml` that ships the `.deb` as an
  artifact/release) is **only added during Phase 9 wind-down, once everything works** — never at
  bootstrap, never mid-build.
- **Worktrees:** `git worktree remove …` after each merge; `rm -rf ../linux-tpm-keyring-wt/` at end.
- **Local host:** `tess unenroll` restores password keyring; `tess install --uninstall` removes
  PAM wiring; `rm -rf references/` at wind-down. *(These run only on a real deployment target, never
  the developer's host.)*

## 9. License Choice

**Chosen: `MIT`.** Every runtime dep is permissive (`tss-esapi` Apache-2.0; the rest MIT or
MIT/Apache-2.0). Both reference repos (`boltgolt/howdy`, `Tunahanyrd/tpm-keyring-unlock`) are MIT —
the only inherited obligation is attribution. We interact with LGPL/GPL system components
(`libfprint`/`fprintd`, `gnome-keyring`) only over D-Bus/`dlopen`, which doesn't propagate copyleft.
*Alternative:* Apache-2.0 for its patent grant (recorded as an ADR). Bias toward MIT.

## 10. Threat Model (summary — full version in `docs/threat-model.md`)

**What we protect:** the GNOME login keyring **at rest**. The encryption key is a random blob sealed
in *your* TPM under *your* PIN authValue; it is not derivable from anything on disk, and PIN guessing
is hardware-rate-limited by the TPM DA lockout. Stolen/powered-off laptop, stolen disk, stolen
sealed blob → all useless without the PIN on the original TPM.

**Explicitly out of scope:** a **root/kernel adversary on a live, running machine.** Root can keylog
the PIN or read the released key from process memory. **No Linux system defends this without
VBS-class isolation, which does not exist on commodity hardware** — SGX is removed from client CPUs;
TDX/SEV protect a VM *from the host* (wrong direction) and are server-only; TrustZone is ARM-only and
vendor-gated; "Linux VBS" (Heki/LVBS) is an unmerged research PoC. ChromeOS cryptohome — the closest
shipped FOSS analogue — makes the *same* concession ("root = exposure until reboot") and relies on
verified boot + TPM at-rest, which is precisely our position.

**Consequences of this decision:** we **don't** build VBS, **don't** use any TEE, and **don't**
modify fprintd/libfprint. The fingerprint/face leg is **host-trusted convenience**, never the sole
gate; the PIN authValue carries the real hardware guarantee. Attested match-on-sensor biometrics
(which would need libfprint + fprintd + sensor-vendor TEE changes) only defend the root adversary we
scoped out, so they're deliberately out of scope, not a TODO.

**Attack-class → control** (from the prior-vuln survey): bus-sniff → HMAC/encrypted sessions + no
PCR-only; weak keygen (ROCA) → self-gen random blob + ECC; side channel (TPM-FAIL) → constant-time +
DA-lockout; biometric spoof (Hello IR-replay) → host-trusted, PIN gate, IR liveness; TOCTOU → unseal
bound to PAM session; memory disclosure (cold boot) → mlock/zeroize + minimal lifetime; dep UAF
(RUSTSEC-2023-0044) → pin `tss-esapi ≥ 7.1.0`.

**Seeded ADRs** (written at bootstrap): PIN-authValue-over-PCR + mandatory HMAC sessions; root-out-of-
scope / no-VBS threat model; userspace `tss-esapi` over kernel trusted-keys; eBPF rejected; Secret
Service abstraction; hand-rolled PAM FFI; MIT license.
