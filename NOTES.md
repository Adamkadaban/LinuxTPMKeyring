# Notes

Append-only operational journal — solved problems, gotchas, dead-ends, surprising behavior. See the
**Operational Memory** section of [`AGENTS.md`](./AGENTS.md) for the read-on-entry / write-on-exit
ritual. Newest entries at the bottom of each section.

## Trusted issue authors

- Adamkadaban

## Azure cost tracking

- Budget: ~$50 for the week beginning 2026-06-21. Default VM: Standard_B4ms. **Kill-by: 2026-06-28.**
- Deallocate whenever idle; delete all `project=LinuxTPMKeyring` resources at wind-down via
  `deploy/azure/teardown.sh`. The user is away from the laptop — a forgotten running VM is the main risk.

## Bootstrap research findings (2026-06-21)

Captured from the Phase 1 research so future sessions don't re-derive them.

- **Kernel:** no kernel component needed. Confirmed on stock Debian 13 (6.12): BTF=y, BPF_LSM=y,
  but **`CONFIG_TRUSTED_KEYS` is NOT set** — kernel TPM2 trusted keys unavailable → use userspace
  `tss-esapi`. eBPF anti-tamper rejected (root can unload BPF-LSM; not a boundary). See ADR-0004.
- **Threat model:** root/runtime out of scope; no commodity TEE fits (SGX removed from client CPUs;
  TDX/SEV protect VM-from-host, wrong direction + server-only; TrustZone ARM-only + vendor-gated).
  "Linux VBS" = Heki/LVBS, unmerged research PoC. ChromeOS cryptohome makes the same concession.
  See ADR-0002.
- **Reference repo `tpm-keyring-unlock`:** MIT Go, shells out to tpm2-tools. Seals the *password*
  (not a random key), PCR-7-only (no PIN/auth, unseals for any caller on the box), writes an unsalted
  SHA-256 of the password to disk. Cautionary; reuse only its D-Bus `UnlockWithMasterPassword`
  plumbing + enroll UX.
- **fprintd:** consumed unmodified over `net.reactivated.Fprint`. Host-match → root can forge
  `verify-match`; fine because biometric is convenience and PIN authValue is the real gate. No
  fprintd/libfprint changes for the MVP.
- **Dep health:** `tss-esapi` pin **≥7.1.0** (RUSTSEC-2023-0044 FFI use-after-free). Avoid `pamsm`
  (GPL-3.0) and stale `pam`/`pam-sys` (~2.5yr cold) → hand-rolled `libc` PAM FFI (Mug already does
  this). `zbus` org renamed dbus2→z-galaxy; `pam-rs` tozny→lvkv (verify, don't panic). "pure-Rust
  tpm2-rs" is a dead experiment — `tss-esapi` is the only serious choice. See ADR-0003, ADR-0006.
- **Testing substrate:** swtpm faithfully emulates DA-lockout/NVRAM persistence → full functional
  substitute for dev/CI; Azure Gen2 Trusted-Launch vTPM is the only "real" acceptance gate. fprintd
  via libfprint virtual driver (`FP_VIRTUAL_DEVICE`/`FP_VIRTUAL_IMAGE`) + python-dbusmock.
- **Mug (Phase 5):** existing `~/Desktop/Mug` Rust skeleton (PAM FFI, V4L2, ONNX `ort`) is the seed.
  Brio exposes a separate greyscale IR V4L2 node; IR emitter is off by default → needs a UVC XU
  enable (cf. `linux-enable-ir-emitter`, also Rust). No FOSS "libfprint-for-face" exists; AOSP's
  matcher is a proprietary blob. IR-reflectance is the realistic liveness signal. Slint recommended
  for the greeter UI (software renderer).

## 2026-06-21 — swtpm test substrate + tess-tpm connect smoke test (issue #2)

**Resolution:** Added `testing/swtpm/run.sh` (mssim/TCP socket mode, ports 2321/2322, persistent
`--tpmstate`, pidfile, bounded start/stop with SIGTERM→SIGKILL reap) and a `sim`-feature-gated
`tess-tpm` smoke test that drives the script and asserts the mssim command port accepts a TCP
connection, with an RAII `Drop` guard that stops swtpm + wipes its temp state dir.
`testing/swtpm/run.sh` · `crates/tess-tpm/src/lib.rs` · PR #5.

Gotchas worth remembering:
- Phase 0 deliberately does **not** pull in `tss-esapi`; the issue's "read a TPM property" is
  deferred to Phase 1 — a TCP-reachability check is the Phase 0 contract (per the wave task brief).
- swtpm is feature-gated (`sim`) OFF by default so `cargo test --workspace` stays hardware-free and
  green; CI adds an explicit `cargo test -p tess-tpm --features sim` step (swtpm installed there).
- **swtpm IS actually installed on this dev host (`/usr/bin/swtpm`)** despite the bootstrap
  assumption that it isn't. The `sim` test was therefore only compiled (`--no-run`), never executed
  locally, to honour "nothing runs against a TPM on the host". The default workspace test excludes
  it entirely (not `cfg(feature=sim)`), so no swtpm process is ever spawned by local validation.
- shellcheck is not installed on this host; scripts were validated with `bash -n` only. CI/contributors
  should run shellcheck.

## 2026-06-21 — Azure provisioning scripts + `tess doctor` (issue #3)

**Resolution:** Added `deploy/azure/{main.bicep,provision.sh,deallocate.sh,teardown.sh}` and a real
read-only `tess doctor` (`crates/tess-cli/src/doctor.rs:1`). Scripts were authored + validated only
(shellcheck via `koalaman/shellcheck` docker = clean; `bash -n` clean; `az bicep build` compiles) —
**NOT executed**, zero Azure resources created. Default image `Debian:debian-13:13-gen2:latest`
(Gen2 required for Trusted Launch / vTPM); default size `Standard_B4ms`; key-only SSH via
`TESS_SSH_PUBKEY`. `tess doctor` does presence-only probes (`Path::exists`, binary-on-`PATH`); never
opens D-Bus or touches secrets — read-only, but per policy run it in CI or on the Azure VM, not the
host. PR #6.

## 2026-06-21 — Phase 0 exit test passed on real Azure vTPM
**Resolution:** provision.sh→ssh→build→`tess doctor`→teardown.sh ran end-to-end on a Debian 13 Gen2 Trusted-Launch VM; /dev/tpmrm0 + /dev/tpm0 present, ACPI "VRTUAL VTPM MSFT", tpm_version_major=2, doctor verdict READY. RG deleted, $0 left running. deploy/azure/* scripts work for real.

## 2026-06-21 — tss-esapi wired: ESAPI context + ECC primary + salted HMAC/param-encryption session (issue #8)
**Resolution:** Added `tss-esapi = "7.7"` to the workspace and `tess-tpm`; `TctiConfig::open_context()` opens a live `tss_esapi::Context`, `create_primary()` makes the deterministic ECC P-256 restricted-storage primary under the owner hierarchy, `start_salted_hmac_session()` opens the salted HMAC + AES-128-CFB param-encryption (SHA-256, decrypt+encrypt+continue) session for #9/#10. `crates/tess-tpm/src/esapi.rs:1` · `crates/tess-tpm/src/lib.rs:46` · PR for #8.

Gotchas worth remembering:
- **swtpm needs the swtpm TCTI, NOT mssim.** The issue assumed `TctiNameConf::Mssim`, but swtpm's
  `--ctrl` control channel speaks swtpm's own protocol; the mssim TCTI's platform commands fail with
  `WARNING ... Failed to send MS_SIM_NV_ON platform command` → `Could not initialize TCTI file: mssim`.
  Switched to `TctiNameConf::Swtpm(NetworkTPMConfig)` (libtss2-tcti-swtpm) and it works. Same
  host/port; the swtpm TCTI also hard-wires the control port to command+1, so the sim test reserves a
  *consecutive* (P, P+1) port pair (the old Phase-0 reachability test used two arbitrary ephemerals,
  which is fine for a pure TCP probe but would break a real TCTI).
- `NetworkTPMConfig`/`DeviceConfig` are built via `FromStr`: `host=127.0.0.1,port=2321` and
  `/dev/tpmrm0` respectively (verified in `tss-esapi-7.7.0/src/tcti_ldr.rs`).
- ECC storage-primary template: `PublicEccParametersBuilder::new_restricted_decryption_key(
  SymmetricDefinitionObject::AES_128_CFB, EccCurve::NistP256)` + object attrs
  fixed_tpm/fixed_parent/sensitive_data_origin/user_with_auth/restricted/decrypt (NOT sign_encrypt).
  The template builds with no TPM → unit-testable on any host.
- `create_primary` authorizes the owner hierarchy with `execute_with_nullauth_session` (a transient
  encrypted null-auth HMAC session ESAPI sets up + flushes); the *salted* session is separate, salted
  by the primary as tpmKey for subsequent seal/unseal.
- **No transient secret material in this layer yet** — the PIN authValue + random key (and their
  `SecretBytes`/`zeroize`/`mlock` handling) arrive with seal/unseal in #9/#10. `forbid(unsafe_code)`
  stays via the workspace lint; tss-esapi's safe API needs no `unsafe`.
- swtpm sim integration test spawns swtpm **foreground** (no `--daemon`) so the `Child` handle reaps
  reliably in a `Drop` guard (SIGTERM→SIGKILL + state-dir wipe); the daemon path left a stale pid and
  noisy `kill: No such process` because swtpm self-exits on client disconnect. `pgrep -a swtpm` clean
  after every run.

## 2026-06-21 — seal/unseal a random key under a PIN PolicyAuthValue (issue #9)
**Resolution:** `generate_sealing_key()` XOR-mixes `getrandom` with TPM `GetRandom` (256-bit);
`seal()` computes the `PolicyAuthValue` digest via a trial session, builds a keyedhash data object
(`userWithAuth` authValue = PIN, authPolicy = that digest, DA-protected) and creates it under the
salted HMAC/param-encryption session, returning an in-memory `SealedObject {public, private}`;
`unseal()` loads it, runs a salted encrypting policy session, satisfies `PolicyAuthValue`, and
returns the key as `SecretBytes`. `crates/tess-tpm/src/seal.rs:52` · PR for #9.

Gotchas worth remembering:
- **Wrong PIN = TPM `AuthFail` (rc 0x98e), not a wrapper error.** Map via
  `tss_esapi::Error::Tss2Error(rc).kind() == AuthFail|BadAuth` → `Error::WrongPin` →
  `tess_core::Error::Auth` (distinguishable from a real TPM fault). The esys C layer logs the 0x98e
  to stderr even when handled — that ERROR line in the wrong-PIN sim test is expected, not a failure.
- **`unseal` needs `tr_set_auth(object, pin)` before the policy unseal**, even with `PolicyAuthValue`:
  ESAPI folds the object's authValue into the policy-session HMAC, so the PIN must be set on the
  loaded handle or the HMAC is computed with an empty auth and fails.
- The sealed object is **keyedhash** (`PublicAlgorithm::KeyedHash`, `KeyedHashScheme::Null`), not ECC;
  `with_keyed_hash_unique_identifier(Digest::default())`. Leave `noDA` **unset** so wrong PINs trip
  DA-lockout — the whole anti-hammering point. Don't set `sensitive_data_origin` (we supply the data).
- Persistence of the pub/priv blobs and DA-lockout reset are #10, deliberately not here — `SealedObject`
  is the typed handoff (`from_blobs`/`public()`/`private()`), `Public` already impls `Marshall`.

## 2026-06-21 — sealed-object persistence + DA-lockout handling (issue #10)
**Resolution:** Added secret-free persistence (`to_metadata`/`from_metadata`/`save`/`load`, base64
TPM2B blobs in the versioned `tess_core::Metadata`; `Public` via `Marshall`/`UnMarshall`, `Private`
via `value()`/`TryFrom<&[u8]>`), a read-only `read_lockout_state` (`get_capability` on the lockout
properties), and distinct `Error::Lockout` mapping (load + unseal paths) → `tess_core::Error::Lockout`.
`crates/tess-tpm/src/persist.rs:1` · `crates/tess-tpm/src/lockout.rs:1` · PR for #10.

Gotchas worth remembering:
- **`tss-esapi` 7.7.0 has NO safe wrapper for `TPM2_DictionaryAttackLockReset`** — its
  `dictionary_attack_functions.rs` is literally `// Missing function: DictionaryAttackLockReset`.
  Raw `tss-esapi-sys::Esys_DictionaryAttackLockReset` needs `unsafe` (forbidden outside `tess-pam`).
  7.7.0 is the latest 7.x; the safe wrapper lands in 8.x (alpha). So the privileged non-destructive
  lockout reset is deferred (tech-debt #16, ADR-0008); `reset_lockout` ships the PIN-holder recovery
  path only (refuse if hard-locked, else prove PIN via one unseal).
- **swtpm/libtpms DA defaults: `maxTries=3`, `lockoutInterval=1000s`, counter starts 0.** Measured
  empirically. Wrong PIN ticks the counter 1→2→3; at counter==maxTries the TPM hard-locks and the
  failure surfaces at **`TPM2_Load`** (not the later unseal) with the lockout RC — so map lockout on
  the load path too. A *successful* auth does **NOT** reset the counter on libtpms (stayed at 2 after
  a correct unseal); self-heal is one decrement per 1000s. So "reset via successful unseal" is a
  myth here — don't assert counter==0 after a good unseal.
- `Private` (TPM2B_PRIVATE buffer) does not impl `Marshall`; persist its `value()` bytes and rebuild
  with `Private::try_from(&[u8])`. Only `Public` (structured TPMT_PUBLIC) needs `Marshall`/`UnMarshall`.
- `get_capability(CapabilityType::TpmProperties, u32::from(PropertyTag::LockoutCounter), 1)` returns
  `CapabilityData::TpmProperties(list)`; find the tag in the list rather than trusting position.
- Extracted the swtpm sim harness into `tests/common/mod.rs` (shared by `esapi_sim.rs` +
  `persist_lockout_sim.rs`) to avoid duplicating ~120 lines. `pgrep -a swtpm` clean after every run.
- `cargo deny check` clean with `base64 = "0.22"` added (MIT/Apache); default `cargo test --workspace`
  stays swtpm-free and green.

## 2026-06-21 — hw-feature exit test + session-encryption assertion + doctor TPM detail (issue #11)
**Resolution:** Added an `hw`-gated single serial test against `/dev/tpmrm0`
(`crates/tess-tpm/tests/hw_device.rs:1`) reusing the existing seal/unseal/persist/lockout code; a
shared `encrypted_session_attributes()` (`crates/tess-tpm/src/esapi.rs:179`) routed through both the
HMAC and policy sessions with a hardware-free regression unit test asserting decrypt+encrypt+mask;
read-only `read_tpm_version` (`crates/tess-tpm/src/caps.rs:1`); `tess doctor` TPM detail
(`crates/tess-cli/src/doctor.rs:175`); and `deploy/azure/hw-exit-test.sh` (orchestrator-invoked).
PR for #11. The real Azure vTPM exit run is the orchestrator's; #11 stays open until it passes.

Gotchas worth remembering:
- **One real TPM = one global DA-lockout counter, so hw tests MUST be serial.** `cargo test` runs
  test fns in parallel; against the single `/dev/tpmrm0` device, concurrent seal/unseal/lockout
  fns would clobber each other's lockout state. The `sim` tests get away with parallelism because
  each spawns its *own* swtpm. The hw test is therefore one `#[test]` driving the whole
  round-trip→persist→wrong-PIN→hammer-to-lockout sequence end-to-end.
- **ESAPI 7.7 has no getter for a *started* session's attributes** (`SessionAttributes` is only
  read back off the builder output, never off a live `AuthSession`). So the session-encryption
  assertion tests the shared `encrypted_session_attributes()` source the helpers call, not the live
  session. `SessionAttributes::{decrypt,encrypt,continue_session}` accessors exist; the mask's
  getters do NOT (only setters), so assert the mask via `u8::from(mask)` bit math (TPMA_SESSION = u8,
  decrypt=bit5, encrypt=bit6).
- `PropertyTag::FamilyIndicator` packs ASCII "2.0\0" big-endian; decode printable non-NUL bytes,
  fall back to hex. `PropertyTag::Revision` is spec-rev×100 (138 = 1.38). Both read via the existing
  `lockout::read_property` (made `pub(crate)` for reuse from `caps.rs`).
- doctor's TPM detail opens a context only when `/dev/tpmrm0` exists and is fully best-effort: any
  open/cap-read failure becomes `present; TPM detail unavailable (<reason>)` — reason carried, not
  swallowed — and never changes the verdict (still node-presence only). Never run `tess doctor` on
  this host; only the pure formatter fns are unit-tested locally.
- `deploy/azure/hw-exit-test.sh`: SC2029 (client-side `REMOTE_DIR` expansion into the ssh command)
  is intentional and silenced with explicit `# shellcheck disable=SC2029`; docker shellcheck clean
  (exit 0). Runs no `az`, provisions/tears down nothing. Wraps cargo in `sudo --preserve-env` only
  when the login user can't r+w `/dev/tpmrm0`.
