# Notes

Append-only operational journal — solved problems, gotchas, dead-ends, surprising behavior. See the
**Operational Memory** section of [`AGENTS.md`](./AGENTS.md) for the read-on-entry / write-on-exit
ritual. Newest entries at the bottom of each section.

## Trusted issue authors

- Adamkadaban

## Azure cost tracking

- Budget: ~$50 for the week beginning 2026-06-21. Default VM: Standard_B4ms. **Kill-by: 2026-06-28.**
- **No active VM.** Phase 4 wave-3 acceptance run (#44) completed 2026-06-22 on `tess-vtpm` (B4ms,
  eastus); resource group `tess-vtpm-rg` **deleted** right after (both exit gates green). `$0` residual,
  confirmed via `az resource list --tag project=LinuxTPMKeyring` (empty) + `az group exists` (false).
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

## 2026-06-21 — KeyringBackend over Secret Service: in-place rekey + unlock (issue #20)
**Resolution:** `SecretServiceBackend` (`crates/tess-keyring/src/backend.rs:1`) impls
`tess_core::KeyringBackend` via `zbus` 5: `is_locked()` reads the collection `Locked` property with
an uncached `Properties.Get`; `unlock`/`rekey` go through GNOME's private
`org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface` (`UnlockWithMasterPassword` /
`ChangeWithMasterPassword`), all isolated behind the trait. Daemon-gated E2E suite proves the
keyring-preservation invariant against a real `gnome-keyring-daemon`. PR for #20.

Gotchas worth remembering:
- **The stable Secret Service `Unlock` raises an interactive `Prompt`** — there is no headless way in
  the spec to prove possession of a collection password. The private GuiltRidden interface is the
  only programmatic path; `ChangeWithMasterPassword(o, (oayays) original, (oayays) master)` re-wraps
  the master credential **in place** (items untouched — it only swaps the collection credential, see
  gnome-keyring `gkd_secret_change_with_secrets`). Verified signatures from the GNOME
  `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface.xml`, not training knowledge.
- **The `Secret` struct is `(oayays)`** = `(session: o, parameters: ay, value: ay, content_type: s)`.
  For a `plain` session (`OpenSession("plain", v"")`) parameters are empty and value is the raw
  password. zvariant `#[derive(Type)]` on a 4-field struct yields exactly `(oayays)` — unit-tested via
  `DbusSecret::SIGNATURE.to_string()`.
- **`gnome-keyring-daemon --unlock` reads the login password from stdin until EOF — newlines are part
  of the password** (`read_login_password` in `gkd-main.c`). The harness writes the raw bytes and
  closes the pipe; **never** append `\n`. `--unlock` (unlike `--login`) does the full startup and
  *creates* the login keyring if absent, so a throwaway `XDG_DATA_HOME` + private bus gives an
  isolated, real keyring with no host contact.
- **`secret-service`'s client reads `DBUS_SESSION_BUS_ADDRESS` (process-global)** so the two daemon
  tests serialize on a `static Mutex` and set the env inside the lock; the backend itself takes an
  explicit address (`connect_to`) and never touches the env, so it's race-free.
- **`#[zbus::proxy(gen_async = false)]` names the blocking proxy `<Trait>Proxy`** (no `Blocking`
  suffix) — only the async variant gets suffixed. Wrong password on `UnlockWithMasterPassword`
  surfaces as `zbus::Error::MethodError` → `tess_core::Error::Keyring`; the test asserts err-or-still-
  locked to be robust to either daemon behavior.
- `zbus`/`secret-service` both pinned to the **async-io** runtime (zbus default + `secret-service`
  `rt-async-io-crypto-rust`) so the blocking wrappers share one executor; mixing tokio + async-io
  panics at runtime. `cargo deny check` clean; `pgrep -af gnome-keyring-daemon` clean after every run
  (host daemon at `/run/user/1000` untouched).
## 2026-06-21 — fprintd client over net.reactivated.Fprint + deterministic mock (issue #21)
**Resolution:** `FprintClient` drives `Manager.GetDefaultDevice`→`Device.Claim`→subscribe
`VerifyStatus`→`VerifyStart("any")`→wait→`VerifyStop`/`Release` via zbus 5 `#[proxy]`; bounded by an
`async-io` `Timer` raced against each signal; `verify(deadline_ms)` (and `tess_core::AuthGate`) maps
match→Ok, no-match/other-terminal→`Error::Auth`, deadline→`Error::Timeout`. Headless tests run a
`python-dbusmock` mock under `dbus-run-session`. `crates/tess-fprint/src/lib.rs:1` ·
`testing/fprint-mock/fprintd_mock.py:1` · PR for #21.

Gotchas worth remembering:
- **`AuthGate::authorize` is sync but zbus 5 is async-first.** Bridge with `async_io::block_on` on an
  internal `async fn`; `async-io` auto-starts a global reactor thread, so its `Timer` fires under any
  `block_on` (no tokio, no manual runtime). zbus's `Connection` drives its own socket I/O on a
  separate thread, so `block_on` only awaits channels — works without an external executor.
- **Subscribe to `VerifyStatus` BEFORE `VerifyStart`** or a fast mock/reader can emit into the gap and
  the verify hangs to its deadline. zbus `receive_verify_status()` installs the match rule on await.
- **Bound the wait with `futures_util::future::select(stream.next(), Timer::after(remaining))`.**
  `Timer`'s `Future::Output` is `Instant` (not `()`), so the timeout arm is `Either::Right((_, _))`.
  Recompute `remaining` each loop so retry tokens (`verify-retry-*`) can't extend past the deadline.
- **Connect tests by explicit bus address (`connection::Builder::address`), not `Connection::session`**
  — passing the private bus address to `connect_address` avoids mutating the global
  `DBUS_SESSION_BUS_ADDRESS`, so the integration tests stay parallel-safe.
- **dbusmock can emit a signal from an `AddMethod` body**: the code string runs with `self` bound to
  the mock object, so `self.EmitSignal('net.reactivated.Fprint.Device','VerifyStatus','sb',[tok,True])`
  works. The `stall` scenario just leaves `VerifyStart`'s body empty → client times out.
- **Reap the whole group, not just the child.** Spawn `dbus-run-session` with `process_group(0)` and
  `nix::sys::signal::killpg(SIGTERM→SIGKILL)` in `Drop`; killing only the `dbus-run-session` PID
  orphans its `dbus-daemon` + the `dbusmock` server. `pgrep -af fprintd_mock|dbus-run-session` clean
  after every run. `nix` is a dev-dependency (safe `killpg`, no `unsafe`).
- Tests **skip-clean** if `python3`/`dbus-run-session`/`dbusmock` are missing, so default
  `cargo test --workspace` is green anywhere; CI (`dbus-x11` + `python3-dbusmock` already installed in
  `test.yml`) runs them for real. No `libfprint`/fprintd needed — only the D-Bus surface is mocked.
- `clippy::doc-lazy-continuation` fires on a doc line that starts after a wrapped `(... + ...)` list-
  looking fragment; reflowed the test module docstring to avoid the false list.
## 2026-06-21 — non-blocking PAM module + watchdog helper (issue #22)
**Resolution:** `tess-pam` is now a loadable `cdylib` (`libpam_tess.so` → `pam_tess.so`) + `rlib`.
Hand-rolled PAM FFI (`pam_get_item`/`pam_set_data`/`pam_get_data`/`pam_get_authtok` +
`pam_conv`/`pam_message`/`pam_response` + the four `pam_sm_*` entrypoints) confined to
`crates/tess-pam/src/ffi.rs` — the only `unsafe` in the workspace. `helper::run` supervises a child
under a `Watchdog { deadline, term_grace, poll }`: poll `try_wait`, on deadline SIGTERM → grace →
SIGKILL → bounded `try_wait` poll (no blocking `wait`); a child stuck in uninterruptible I/O is handed
to a detached reaper thread so the call returns bounded and the child is still reaped. `gate::{classify,
decide}` map the outcome to PAM codes (auth fails open to `PAM_AUTHINFO_UNAVAIL`; session always
`PAM_SUCCESS`); the gate aborts (auth `PAM_IGNORE`, session `PAM_SUCCESS`) for a remote session
(non-empty `PAM_RHOST`) and no-TPM. `crates/tess-pam/src/helper.rs:71` ·
`crates/tess-pam/src/gate.rs:1` · `crates/tess-pam/src/ffi.rs:1` · PR for #22.

Gotchas worth remembering:
- **A PAM-module rlib that references `pam_get_item` won't link into test binaries unless the symbol
  resolves.** `#[no_mangle]`/`#[export_name]` entrypoints are kept (treated as reachable) even in a
  test harness, so their calls into undefined `pam_*` symbols become link errors for `cargo test`.
  Fix: `build.rs` emits `cargo:rustc-link-lib=dylib=pam` — the `.so` and every test binary then link
  `libpam` and resolve the symbols. Needs `libpam0g-dev` (the `libpam.so` dev symlink) at build time;
  added to the CI apt list. The cdylib gains a harmless `NEEDED libpam.so.0` (always already loaded
  by the PAM application).
- **`[lib] name = "pam_tess"`** (not the default `tess_pam`) so the cdylib is `libpam_tess.so`; PAM
  loads modules by file name. Dependents/tests then `use pam_tess::...`.
- **SIGTERM-ignoring stall case must busy-loop, not `sleep`.** `sleep` dies on the default SIGTERM
  disposition (never exercises the SIGKILL escalation), and a `sh`/`sleep` pair would orphan the
  inner `sleep` on SIGKILL (a leaked child the reap-proof would catch). `sh -c "trap '' TERM; while
  :; do :; done"` ignores SIGTERM, has no child, and is killed+reaped cleanly within
  `deadline + 2 * term_grace` (a `term_grace` budget after SIGTERM and another after SIGKILL).
- **A `SIGKILL`ed child stuck in uninterruptible I/O won't die until its syscall returns**, so a
  blocking `wait()` after SIGKILL could exceed the hard bound. The watchdog instead polls `try_wait`
  for a bounded budget after SIGKILL and, in that pathological case, hands the child to a detached
  reaper thread (`Builder::spawn`, non-panicking) — the PAM thread stays bounded *and* the child is
  reaped. Only if even that thread can't be created (resource exhaustion) is the orphan left for the
  OS to reap at host-process exit; we deliberately do *not* add a global orphan registry to close
  that corner because PLAN forbids shared mutable global state, and the caller is never blocked
  regardless.
- **No PID-reuse race in the watchdog:** we signal the child only *before* the final `wait`, so while
  it may be an unreaped zombie its PID is still ours and cannot be recycled. `send_signal` swallows
  only `ESRCH` (already gone); other errno propagate.
- **`process_alive` keys off `ESRCH` only.** `kill(pid, 0)` returning `EPERM` means the process
  exists but isn't signalable, so only `ESRCH` proves it gone — the reap proof would otherwise flake
  under restricted permissions.
- **A privileged PAM module must not take its helper exec path from the environment.** The helper is
  resolved from a root-controlled `helper=PATH` PAM module argument, falling back to the compiled
  install path `/usr/lib/tess/tess-pam-helper`; the `TESS_PAM_HELPER` env override is compiled in
  only under `debug_assertions` (test harness), so release builds can't be redirected via env.
  Until the real helper (Phase 3) is installed, a missing-helper spawn fails open — correct
  non-blocking behaviour, unit-tested as the spawn-failure → `Unavailable` path.
- `pamtester` live-load smoke runs in CI only (host runs no PAM per project policy): the `test`
  workflow installs the built `pam_tess.so`, writes a `pam_permit`-backed `/etc/pam.d/tess-smoke`
  service, and drives `open_session`/`close_session`/`authenticate` to prove the module dlopens
  through libpam and a no-op session returns `PAM_SUCCESS`. The dlopen can't be a Rust test because
  `libloading` needs `unsafe` outside the `ffi` module (forbidden); pamtester keeps the unsafe in C.
  The bounded + reap proof is the pure-Rust `tests/stall_injection.rs`.

## 2026-06-22 — MVP acceptance on real Azure vTPM: sudo enroll can't reach the user's session bus
**Resolution:** First real-vTPM run of `mvp-e2e.sh` failed: `tess enroll` ran under `sudo` (because
`/dev/tpmrm0` was `root:root 0600` at first boot, then `tss:tss 0660` once the tpm2 udev rule
applied) and could reach the TPM but NOT the user's private D-Bus session bus — a session bus
authorizes only its **owner UID** over EXTERNAL auth, so root (a different UID) is refused even though
it can read the socket file ("Did not receive a reply / security policy blocked"). Fix: grant the
*invoking* user rw on `/dev/tpmrm0` (POSIX ACL via `setfacl`, `acl` added to the apt list) in a new
`ensure_tpm_access` step run before `compute_priv` in both phases, so enroll/the helper run as a
single same-UID process reaching both TPM and Secret Service (no sudo). ACL is reapplied each phase
since the device is recreated on boot. Both exit gates then PASSED on the real vTPM (TPM 2.0 spec
rev 138; full demo + reboot-persistence). Production must do the equivalent (tss-group/udev uaccess
for the seat user) → IOU #46. `deploy/azure/mvp-e2e-remote.sh:99` · PR for #44.

## 2026-06-22 — atomic, recoverable enrollment transaction (issue #26)
**Resolution:** `tess enroll` composes seal/rekey into a credential-first transactional flow:
generate `K` → back up + verify a recovery-secret-wrapped copy of `K` → seal under PIN + verify
unseal + persist → `rekey(old→K)` → verify unlock + item decrypt → commit; any failure rolls back
(restore credential first, then remove blobs; keep blobs only if credential restore fails).
`crates/tess-cli/src/enroll/mod.rs:1` · `crates/tess-cli/src/enroll/recovery.rs:1` · ADR-0009 · PR for #26.

Gotchas worth remembering:
- **Recovery must survive a TPM clear, so it cannot live in the TPM.** Scheme: `KEK =
  HKDF-SHA256(salt, R)` (R is full-entropy → fast KDF, not Argon2), then `K` AEAD-sealed under `KEK`
  with XChaCha20-Poly1305 (192-bit nonce → safe with random nonces). Stored in a *separate*
  `recovery.json` `{version,salt,nonce,ciphertext}`, never in `tess-core::Metadata` (keeps the
  TPM schema decoupled and the rollback symmetric). The happy-path test asserts the recovery secret
  and the TPM unseal recover the *same* `K`.
- **`tess-cli` needs a `[lib]` target** so integration tests can `use tess_cli::enroll::...`; a
  bin-only crate's `tests/` can't reach crate items. `src/lib.rs` exposes `enroll`/`doctor`; `main.rs`
  consumes the lib. Without it the rollback/enroll logic would only be testable as a subprocess.
- **Rollback ordering is the whole safety story.** Restore the keyring credential (`rekey(K→old)`)
  *before* deleting any blob; only delete once it's safely back on `old`. If the credential restore
  fails, KEEP the sealed + recovery blobs (the only way back in) and surface "run `tess recover`" —
  deleting them there would be the lockout the transaction exists to prevent. `Tx.new_key` is set
  only *after* a successful forward rekey, so a failed forward rekey (atomic D-Bus call) never
  triggers a spurious restore.
- **Fault injection without breaking the real path:** rekey-fail via a `KeyringBackend` decorator;
  verify-fail via the injected `verify_item` closure; persist-fail by pointing the metadata path at a
  child of a regular file so `create_dir_all` fails. The same decorator records whether `recovery.json`
  existed at first-rekey time, proving the recovery backup precedes the destructive step.
- **`hkdf`/`sha2` were already transitive deps** (via the secret-service crypto stack), so only
  `chacha20poly1305` is a genuinely new crate; `cargo deny` stays clean (no new license, advisories ok).
- **`EnrollOutcome` carries the one-time recovery secret**, so its `Debug` is hand-redacted (`<redacted>`)
  rather than derived — a derived `Debug` would leak the secret into any future log line.
- swtpm + throwaway gnome-keyring run together per integration test; `pgrep` for `tess-cli-sim`/swtpm/
  `gnome-keyring-daemon` is clean after the run (each guard reaps on drop, even on panic).

## 2026-06-22 — idempotent fail-open PAM installer (issue #30)
**Resolution:** `tess install` / `tess install --uninstall` wire `session optional pam_tess.so` into
`/etc/pam.d/common-session` via a re-runnable marked block, plus install/remove the module.
`crates/tess-cli/src/install/config.rs` is pure string edit+validate logic; `install/mod.rs` does the
filesystem side effects (backup → validate → atomic write → copy module). `deploy/pam/` holds the
snippet + placement doc. PR for #30.

Gotchas worth remembering:
- **Uninstall restores from the marked block, not the backup, to preserve later admin edits.**
  `config::remove_block` is the exact inverse of `add_block` for a newline-terminated stack (all real
  `pam.d` files), so an install→uninstall round-trip is byte-for-byte. The backup is a safety artifact
  (written once, never overwritten on re-install so it stays the *true* original) and is deleted on a
  clean uninstall. A backup-based restore would clobber any admin edits made after install.
- **Idempotency = strip-then-append.** `add_block` first calls `remove_block` then appends a fresh
  block, so running install twice yields an identical file with exactly one block — no duplicate-line
  drift. Asserted by counting `BEGIN_MARKER`/`SNIPPET_LINE` occurrences == 1.
- **The fail-open invariant is enforced, not just documented.** `validate_stack` parses every
  effective line and rejects any `pam_tess.so` line whose control flag is not fail-open (`optional`,
  or a bracket whose `default=ignore` and whose every non-`success` code is `ignore` — never
  `ok`/`done` (would grant a login) nor `die`/`bad`). `required`/`requisite`/`sufficient`
  tess lines are rejected *before* the file is written; the edit aborts and the original is untouched
  (it is never the temp file — temp-plus-rename atomic write). Non-tess `required` lines (e.g.
  `pam_unix`) still pass — the rule is tess-specific.
- **Module dir detection mirrors the CI smoke step:** bounded BFS for `pam_permit.so` under
  `/lib`,`/usr/lib`,`/lib64`,`/usr/lib64`, take its parent. Depth-capped and does not follow symlinked
  dirs, so a symlink loop can't trap it.
- **`thiserror` had to be added to `tess-cli`'s manifest** for the `ValidationError` derive — it was a
  workspace dep but only `tess-core` pulled it in before; without it `anyhow`'s `.context()` on a
  `Result<_, ValidationError>` won't compile (the error must impl `std::error::Error`). No new crate
  in the tree (`cargo deny` stays clean).
- **Tests use temp fixtures only.** `/etc/pam.d` appears in `tess-cli` solely as the
  `DEFAULT_SERVICE_FILE` const and one pure path-string assertion (`backup_path`); no test reads or
  writes a real PAM path. Round-trip/idempotency live in `install::tests` + `tests/install_roundtrip.rs`.
- **Install the module *before* committing the stack edit** (Copilot review #31): a module-copy
  failure then leaves the PAM stack untouched, and an installed-but-unreferenced module is inert, so
  the stack write is the single atomic commit point. Reordered to validate → install module → backup
  → atomic write.
- **`validate_stack` must pass `@include` directives through** — Debian `/etc/pam.d` files use
  `@include common-session`; rejecting them as malformed would abort installs on real systems. They
  can never be a `pam_tess.so` line, so they skip the fail-open check like comments.
- **Uninstall must not depend on module-dir detection.** Unwiring the stack + removing the backup is
  the lockout-relevant part; module removal is best-effort. An empty `plan.module_dir` (detection
  failed) skips module removal but still restores the stack.
## 2026-06-22 — lifecycle subcommands recover/unenroll/status/unlock/test (issue #28)
**Resolution:** `tess-cli` gains a `lifecycle` module composing #26's seal/unseal + recovery
(ADR-0009) + in-place rekey into the remaining flows — no crypto reimplemented. `unlock` =
unseal(pin)→`KeyringBackend::unlock`; `recover` = unwrap recovery blob (no TPM)→unlock, `--reseal`
seals the recovered key under a new PIN and atomically rewrites `metadata.json`; `unenroll` =
credential-first transactional rekey K→password then remove blobs; `status`/`test` are read-only
reports. `crates/tess-cli/src/lifecycle/mod.rs:1` · `crates/tess-cli/src/lifecycle/cli.rs:1` · PR for #28.

Gotchas worth remembering:
- **`unenroll` rollback is safer than `enroll`'s because the target credential is user-supplied.** The
  destructive rekey (K→password) is verified before any blob is removed; a failed verify rekeys back
  to K (blobs kept, still gate K). Blob removal is the last, non-destructive step — a removal failure
  leaves the keyring safely on the password with only orphaned files.
- **`recover` deliberately does not need the TPM.** It unwraps K from `recovery.json` and unlocks; the
  keyring credential is still K after a TPM clear (clearing the TPM doesn't change the keyring), so
  `unlock(K)` re-establishes access. The sim test simulates the clear by *deleting metadata.json* and
  recovering via the secret. `--reseal` is the only TPM-touching part of recover.
- **Read-only `status`/`test` surface errors as report strings, not failures.** A best-effort command
  that aborted on a missing keyring daemon or busy TPM would be useless; `Option<Result<bool,String>>`
  / `Result<_,String>` fields carry the reason so nothing is *swallowed* while the command still runs.
  `tess test` performs no unseal and no unlock on purpose — it must consume no DA attempt.
- **Shared `tcti::from_env()` and `doctor::read_caps(tcti)`** were factored out of `enroll::cli` /
  `doctor` so the lifecycle commands reuse one transport-selection and one read-only TPM cap probe
  instead of duplicating them.
- A `status` sim test that locks the keyring then asserts items decrypt will fail — locked items
  aren't unlocked. Assert items intact *before* locking to prove the locked-state report.
## 2026-06-22 — PAM session unseal → unlock wired into the watchdog'd helper (issue #29)
**Resolution:** `pam_sm_open_session` now obtains the PIN via `pam_get_authtok` (Zeroizing buffer,
never logged), hands it to the real `tess-pam-helper` child on stdin under the existing watchdog, and
the helper runs `tess_cli::session::unseal_and_unlock` (`persist::load` → `tess_tpm::unseal` →
`tess_keyring::unlock`). Session always returns `PAM_SUCCESS`; a secret-free `syslog` line records the
outcome. Auth no longer does PIN work — it declines so the stack falls through to the password
factor. `crates/tess-pam/src/ffi.rs:185` · `crates/tess-pam/src/helper.rs:90` ·
`crates/tess-cli/src/session.rs:1` · `crates/tess-cli/src/pam_helper.rs:1` · PR for #29.

Gotchas worth remembering:
- **Pass the PIN to the helper over a `memfd`, not a pipe.** A PAM module is a cdylib loaded into the
  login process, so Rust's runtime SIGPIPE→SIG_IGN install (which only runs for Rust *binaries* via
  `lang_start`) never happened — a write to a pipe whose read end the child already closed would
  deliver the host process's default SIGPIPE and **kill login**. `helper::run_with_input` instead
  writes the PIN into an anonymous in-memory file (`nix::sys::memfd::memfd_create`, safe wrapper,
  `fs` feature already on), rewinds it, and passes it as the child's stdin via `Stdio::from(File)`.
  No pipe (no SIGPIPE), no disk (no persisted secret), bounded single write. Avoids the whole
  `pthread_sigmask`/`sigwait`-drain dance (and nix 0.29 has no `sigtimedwait`, so a bounded drain
  wasn't even available without `unsafe` libc — forbidden outside `ffi`).
- **The helper is a second `[[bin]]` of `tess-cli`, not a new crate or a bin in `tess-pam`.** Putting
  it in `tess-cli` reuses the enroll/unlock composition (`TpmSealer`, `SecretServiceBackend`, the
  `tcti_from_env` selector now shared in `session.rs`) with zero duplication, and keeps `tess-pam`
  the minimal, only-`unsafe`-permitted crate (no TPM/D-Bus deps pulled into the security-sensitive
  cdylib). `CARGO_BIN_EXE_tess-pam-helper` is set for `tess-cli`'s own integration tests, so the E2E
  test (`tests/pam_helper_session.rs`) drives the real binary exactly as the module does — which is
  why the session-unlock E2E lives in `tess-cli`, while the bounded/reaped guarantees (now also
  exercising the stdin-fed path) stay in `tess-pam`'s `stall_injection.rs`.
- **Prompt for the PIN only after the abort check.** `env.aborts()` (remote `PAM_RHOST` or no TPM)
  short-circuits *before* `pam_get_authtok`, so SSH/remote logins and TPM-less hosts are never
  prompted. This also keeps the CI pamtester smoke green on TPM-less GitHub runners: no TPM → abort →
  session `PAM_SUCCESS` with no prompt and no helper spawn.
- **`syslog` is variadic FFI.** `libc::syslog(LOG_AUTHPRIV|LOG_INFO, c"%s".as_ptr(), msg.as_ptr())`
  with a fixed `%s` format avoids any format-string interpretation of the message; logging failure is
  ignored so it can never affect login. All log strings are static `&CStr` literals — no secret can
  reach them.
- **Deployment note (not a code shortcut):** the in-process `tess_keyring::unlock` needs a live
  session bus (`DBUS_SESSION_BUS_ADDRESS`) reachable from the helper. At real login the user's session
  bus may not be up yet; the stable `gnome-keyring-daemon --unlock` stdin path is the expected runtime
  unlock, with this in-process unlock covering an already-running daemon. Tests provide the private
  bus explicitly. Real-login bus wiring is Phase 4 (Azure E2E), already on the roadmap.
## 2026-06-22 — Phase 3 exit gate: one cross-cutting enroll→session→recover→unenroll E2E (issue #34)
**Resolution:** `crates/tess-cli/tests/phase3_e2e.rs` (`full_phase3_cycle_preserves_all_items`,
`--features sim,daemon-tests`) chains every Phase 3 surface on a single throwaway keyring seeded with
5 pre-existing secrets — enroll → real `tess-pam-helper` session → recover (after a simulated TPM
clear) → reseal → unenroll — asserting all 5 items survive intact at every transition. Test-only; no
Phase 3 code bug surfaced while wiring it. `crates/tess-cli/tests/phase3_e2e.rs:1` · PR for #34.

Gotchas worth remembering:
- **swtpm is single-client, so no two TPM contexts may be open at once.** Each `TpmSealer::open` is
  scoped in its own block (`{ … }`) so its context is dropped before the next consumer — the helper
  child, the next sealer, or the reseal — opens its own. The recover step needs no TPM (it unwraps the
  recovery blob), so it sits between sealer scopes cleanly. Forgetting a scope deadlocks the second
  opener against the still-connected first.
- **The session step must run the *real* helper, not the in-process `unseal_and_unlock`.** Driving
  `CARGO_BIN_EXE_tess-pam-helper` with the PIN on stdin (the PAM contract) is the faithful
  fresh-login simulation; the helper resolves metadata from `$XDG_DATA_HOME/tess`, so enroll writes
  the blobs into a tempdir `XDG_DATA_HOME` the child env points at. `run_helper` is parametrized on
  the PIN so the same path proves the *re-sealed* PIN after recovery, not just the original.
- **The preservation invariant counts the whole group, not just each named item.** Every seeded item
  carries a shared `("application","tess-phase3-e2e")` attribute; `assert_items_intact` searches that
  group and asserts `unlocked.len() == N` alongside the per-item decrypt — so a *lost or duplicated*
  item is caught, not only a *changed* one. The assertion takes a `step` label for legible failures.
- **Leak check distinguishes harness procs from the host's.** After the run, the only
  `gnome-keyring-daemon` is the host's real login daemon (`--control-directory=/run/user/1000/keyring`)
  and the only `dbus-daemon --session` is the host's systemd bus (`--address=systemd:`); the harness
  spawns its own private-bus `dbus-daemon --print-address` + keyring under a throwaway HOME, both
  reaped on `Drop`. No swtpm/tess-pam-helper left behind.

## 2026-06-22 — fprintd verify front gate ahead of the PIN, non-blocking (issue #36)
**Resolution:** `pam_tess.so` gains an optional fingerprint front gate selected by the
`fingerprint=yes` module argument (default PIN-only). The session phase resolves `PAM_USER`, passes a
`--fingerprint` flag + the user to the watchdog'd `tess-pam-helper`, and widens the watchdog to
`Watchdog::FINGERPRINT_DEADLINE` (12s). The helper runs one bounded `tess_fprint::FprintClient::verify`
(default 8s), logs the verdict, then runs the PIN unseal/unlock **regardless** of the fingerprint
result. Precedence: fingerprint (convenience) → PIN (real gate) → password fallthrough.
`crates/tess-pam/src/gate.rs:103` · `crates/tess-pam/src/ffi.rs:206` ·
`crates/tess-cli/src/session.rs:80` · PR for #36.

Gotchas worth remembering:
- **Scheme (a), the honest MVP: a fingerprint match cannot unseal alone.** The key is sealed under
  the PIN authValue, so the PIN is always required. The fingerprint is a host-trusted presence signal
  layered *on* the PIN, not a replacement — it does not skip the PIN prompt. True swipe-instead-of-PIN
  (scheme b) would need a TPM/recovery-protected stored PIN and its own ADR; deliberately out of scope.
- **Every fingerprint failure mode degrades to the PIN, never aborts the helper.** `no-match`/`timeout`/
  `unavailable` are logged and fall through; only a PIN-path failure makes the helper exit non-zero
  (and even then the session still opens with the keyring locked). The front gate can never freeze or
  fail login. `FingerprintGate` carries the verdict for the secret-free stderr line only.
- **The fprintd verify runs on its own private bus in tests, separate from the keyring bus.** The
  helper reads `TESS_FPRINT_BUS_ADDRESS` (debug/test builds only — release ignores the environment
  and always uses the system bus, like the `#[cfg(debug_assertions)]`-gated `TESS_PAM_HELPER`, so a
  caller can't redirect the privileged helper to an attacker-controlled bus) so the
  `python-dbusmock` fprintd mock and the throwaway gnome-keyring can each own a distinct
  `dbus-run-session`/`dbus-daemon`. `crates/tess-cli/tests/fprint_gate_session.rs` drives all three
  scenarios (match/no-match/stall) sequentially on one enrolled keyring to keep swtpm single-client.
- **`TESS_FPRINT_TIMEOUT_MS` keeps the stall test fast (debug/test builds only).** The mock `stall`
  scenario never emits, so the test sets a 500ms verify deadline; release builds ignore the override
  and always use the 8 s default so a caller can't push the helper into watchdog-kill territory. The
  helper then falls back to the PIN and the whole run finishes in ~2s for all three scenarios.
  swtpm/keyring/fprintd-mock/helper all reaped on drop.

## 2026-06-22 — Phase 4 docs finalized: threat-model + README to shipped MVP (issue #40)
**Resolution:** Rewrote `docs/threat-model.md` from stub to the full shipped model (at-rest guarantee,
root/runtime out of scope per ADR-0002, auth-not-attestation framing, fingerprint host-trusted vs PIN
gate, ADR-0009 recovery scheme limits, transactional enroll + uninstall, attack-class→control table)
and updated `README.md` to the shipped state (platform matrix, build-from-source install path, opt-in
fingerprint front gate, status MVP/phase-4). `docs/threat-model.md` · `README.md` · PR for #40.

Doc/behavior mismatch noted (no code fix — out of this docs PR's scope):
- **There is no `tess`-CLI `--fingerprint` flag.** Issue #40 and the task brief assume one, but
  `crates/tess-cli/src/main.rs` exposes only `--pin` (enroll/recover/unenroll/unlock), `--reseal`
  (recover), and the `install` path flags. The fingerprint front gate is enabled purely via the PAM
  **module argument** `fingerprint=yes` on the `session optional pam_tess.so` line — and `tess
  install` does NOT add it automatically (the installed line has no args). Multi-factor enroll UX
  (`tess enroll --pin --fingerprint --face`) is PLAN §5 Phase 5, not shipped. Documented the gate as
  the PAM arg, not a CLI flag, to stay accurate.
- **`.deb` / `deploy/install.sh` do not exist yet** (issue #38 still open). README describes the
  working build-from-source + `tess install` path and notes the packaged `.deb` is the smooth path
  landing with #38, incl. the helper resolving from `/usr/lib/tess/tess-pam-helper`.
## 2026-06-22 — Debian packaging: cargo-deb .deb + one-command install.sh (issue #38)
**Resolution:** `[package.metadata.deb]` in `crates/tess-cli/Cargo.toml` builds package `tess`;
`cargo build --release -p tess-cli -p tess-pam && cargo deb -p tess-cli --no-build` produces
`target/debian/tess_<ver>_amd64.deb`. `deploy/install.sh` is the one-command path; `deploy/debian/postinst`
prints next steps without touching pam.d. `crates/tess-cli/Cargo.toml` · `deploy/install.sh` ·
`deploy/debian/postinst` · `.github/workflows/test.yml` · PR for #38.

Gotchas worth remembering:
- **`--no-build` + a prior build of `tess-cli` + `tess-pam` is mandatory.** `cargo deb -p tess-cli`
  on its own only builds the `tess-cli` package, so the `tess-pam` cdylib `libpam_tess.so` (a
  different workspace member) is absent and packaging fails. Build `-p tess-cli -p tess-pam` first
  (tess-cli pulls in the other workspace libs as deps), then package without a rebuild — the
  deterministic path used by `install.sh` and CI alike. Asset paths use the special
  `target/release/...` prefix cargo-deb rewrites to the real target dir.
- **Three runtime paths must match what the PAM module/installer resolve.** `tess` → `/usr/bin/tess`;
  `tess-pam-helper` → `/usr/lib/tess/tess-pam-helper` (the compiled `DEFAULT_HELPER_PATH` in
  `crates/tess-pam/src/gate.rs`); `libpam_tess.so` → `pam_tess.so` under
  `/usr/lib/x86_64-linux-gnu/security/` (Debian 13 amd64 multiarch security dir, where
  `pam_permit.so` lives). A drift here would make the installed helper unreachable at login.
- **`depends = "$auto, gnome-keyring"`, `recommends = "fprintd"`.** `$auto` resolves the linked
  tpm2-tss libs (libtss2-esys/-mu/-tctildr) + libc/libpam from the packaged ELFs via dpkg-shlibdeps;
  gnome-keyring is reached over D-Bus (not linked) so it is named explicitly. fprintd is the optional
  fingerprint front gate — tess is PIN-only without it — so Recommends, not Depends, is the
  Debian-correct relationship (apt installs Recommends by default, but fprintd stays removable and
  `deploy/install.sh --no-recommends` / `apt --no-install-recommends` skips it).
- **The package never edits `/etc/pam.d`.** Lockout safety: PAM wiring stays in the explicit,
  fail-open `tess install`. The `postinst` only prints instructions and `exit 0`s. CI runs
  `dpkg -c` (contents-only) and never `dpkg -i`, so it can't perturb the runner.
- **CI build host is Ubuntu, not Debian 13**, so `$auto` resolves Ubuntu package names — fine,
  because the CI step asserts only the three artifact *paths* via `dpkg -c`, not the depends line. A
  real Debian 13 `.deb` is produced by `install.sh` on the target.

## 2026-06-22 — Copilot review #42: packaged `tess install` needs `--module` (issue #38)
**Resolution:** After a `.deb` install `tess install` fails — `default_module_src()`
(`crates/tess-cli/src/install/cli.rs:126`) looks for the module *next to the `tess` binary*, and a
packaged `/usr/bin/tess` has none beside it. Fix is the documented override: point `tess install` at
the packaged module with `--module /usr/lib/x86_64-linux-gnu/security/pam_tess.so`. `deploy/install.sh`
passes it automatically; README + `postinst` show the explicit form for the manual/`--no-pam` path.
The redundant re-copy (dpkg already placed the module there) is an idempotent no-op. `deploy/install.sh:157`
· `deploy/debian/postinst:15` · `README.md` · PR #42.
## 2026-06-22 — Scripted MVP vTPM E2E acceptance harness (issue #39)
**Resolution:** `deploy/azure/mvp-e2e.sh` (driver) + `deploy/azure/mvp-e2e-remote.sh` (VM-side body,
phases `full`/`reboot`) + `deploy/azure/reboot-persistence.sh` drive the Phase 4 demo on an
already-provisioned Trusted-Launch vTPM VM: install → build (or `.deb`) → throwaway login keyring →
`tess enroll` (random key sealed to the real vTPM under a PIN) → scripted fprint+PIN session via the
real `tess-pam-helper` → assert the keyring unlocks with no password (`tess status` +
`secret-tool` probe). Scripts only; the orchestrator owns provision/teardown (no `az` here). All
three shellcheck-clean + `bash -n`-valid; no Rust touched. `deploy/azure/mvp-e2e-remote.sh:1` · PR for #39.

Gotchas worth remembering:
- **`rpassword` 7.5.4 reads the keyring password from `/dev/tty`, not stdin.** `DEFAULT_INPUT_PATH`
  is `"/dev/tty"`, so `tess enroll`'s "Current keyring password:" prompt fails over a tty-less
  `ssh host bash -s`. The harness wraps enroll in `script -qec "<cmd>" /dev/null`, which allocates a
  PTY so `/dev/tty` exists; the password is fed on `script`'s stdin (`printf '%s\n' | script ...`),
  the PIN via `--pin`. `--pin` is acceptable here only because it is a throwaway demo VM value.
- **Persistent state under the remote dir is what makes reboot-persistence real.** `XDG_DATA_HOME`
  points at `$REMOTE_DIR/e2e-state/data` (NOT a `/tmp` tempdir), so both the sealed `tess` metadata
  and gnome-keyring's `login.keyring` (rekeyed to the sealed key) survive the reboot. After reboot a
  fresh `gnome-keyring-daemon --components=secrets` (no `--unlock`) loads that login keyring LOCKED;
  the helper unseals the key from the rebooted vTPM and `UnlockWithMasterPassword` re-unlocks it with
  no password. `reboot-persistence.sh` does NOT re-upload — it reuses what `mvp-e2e.sh` left.
- **Two private buses, like the `fprint_gate_session` test.** The keyring runs on a `dbus-daemon
  --session` bus; the `python-dbusmock` fprintd mock runs under its own `setsid dbus-run-session` (so
  the whole group is reapable via `kill -- -PGID`). The helper's debug build honours
  `TESS_FPRINT_BUS_ADDRESS`/`TESS_FPRINT_TIMEOUT_MS` to reach the mock; a release `.deb` ignores them,
  the front gate degrades to the PIN, and the keyring still unlocks — so the assertion is the unlock
  outcome, never the fingerprint log line.
- **Sudo-for-TPM forwards the session/keyring env.** Reusing `hw-exit-test.sh`'s `type -P`/sanitized-
  PATH idea, the `PRIV` prefix is `sudo --preserve-env=HOME,...,DBUS_SESSION_BUS_ADDRESS,XDG_*,
  TESS_FPRINT_* env PATH=<abs-only>` so root reuses the login user's bus, keyring state and the mock
  bus. The build runs as the user (no sudo) so only the small `tess` blob is root-owned; the `EXIT`
  trap chowns the state dir back and reaps dbus/keyring/mock.
- **`secret-tool lookup` is `timeout`-bounded.** Looking up the probe while still locked would try to
  spawn a prompt on a headless bus and hang; `timeout 20 secret-tool lookup ...` makes a failed
  unlock surface as FAIL, not a hang. The probe is seeded while unlocked, before the explicit
  D-Bus `Secret.Service.Lock`.

## 2026-06-22 — code comments back-referenced in-repo docs (ADR/AGENTS pointers)
**Resolution:** stripped `(see docs/adr/0001)` and `(see AGENTS.md)` from doc comments, keeping the rationale; rest of skeleton was already clean. crates/tess-core/src/lib.rs:76,119 · #13
## 2026-06-22 — qemu/swtpm helper polish (deferred #5 review items)
**Resolution:** `wait_for_port` uses `bash -c '…' _ "$host" "$port"` ($1/$2 + SC2016 disable); `up.sh` gates swtpm reuse on `/proc/<pid>/comm` (failing fast when a live PID's comm is unreadable rather than clobbering its socket) and clears a stale `"${SWTPM_SOCK}"` + `"${SWTPM_PIDFILE}"` before relaunch; checksum-fail paths `rm -f "${BASE_IMG}.tmp"` before `die`. testing/swtpm/run.sh:60 · deploy/qemu/up.sh:75 · #7
## 2026-06-22 — production install must grant the enrolling user TPM access (tss group / udev)
**Resolution:** `.deb` ships a udev rule tagging `/dev/tpm*`+`/dev/tpmrm*` `uaccess` (active seat user
gets an ACL automatically — no group step on a normal login) with MODE 0660 + GROUP tss as a
headless/SSH fallback (ownership left to root — tess provisions the group, not a `tss` user); the
`70-` prefix runs before systemd's 73-seat-late.rules so uaccess is honored. postinst creates the
`tss` group + reloads udev + prints the headless `usermod` step; `install.sh` adds `$SUDO_USER`/current
user to `tss`. `deploy/udev/70-tess-tpm.rules:10` · `deploy/install.sh:185` · `deploy/debian/postinst:13` · #46

## 2026-06-22 — Phase 6 wave 1: three cargo-fuzz harnesses + seeded corpora + CI (issue #51)
**Resolution:** `cargo fuzz init` scaffolds `fuzz/` (own `[workspace]`, excluded from the stable
workspace so nightly sanitizer flags don't perturb the build/lint/test gates). Three libFuzzer
targets, all panic-free by design (they discard the parser `Result`): `fuzz_metadata` →
`serde_json::from_slice::<tess_core::Metadata>` then `tess_tpm::persist::from_metadata`;
`fuzz_tpm_blob` → replicates the pre-FFI `Public::unmarshall` + `Private::try_from` calls (u16-LE
length prefix splits the two slices); `fuzz_dbus_reply` → strongest untrusted-input parser
(recovery-blob `unwrap_key` JSON+base64+AEAD and grouped-hex `recovery::decode`). No `tess-*` crate
touched — every entry point was already `pub`, so no wrapper and no `unsafe`. `.github/workflows/fuzz.yml`
runs a short PR smoke (`-max_total_time=30`, 20-min job cap) and a nightly cron/dispatch long run
(`-max_total_time=300`, 40-min cap). `fuzz/fuzz_targets/fuzz_dbus_reply.rs:1` · #51

Gotchas worth remembering:
- **The genuine D-Bus reply surfaces are too thin to fuzz.** `tess_fprint`'s fprintd `VerifyStatus`
  interpretation (`classify_verify_result`) is a fixed four-arm string match; `tess_keyring`'s only
  reply decode is a single `Locked` bool. Neither parses variable-length attacker bytes nor can
  panic, so per the deliverable's fallback `fuzz_dbus_reply` targets the recovery-blob reload path
  (`recovery.json` is on-disk and attacker-tamperable; `unwrap_key` runs serde + length-bounded
  base64 + XChaCha20-Poly1305 open — the most parsing logic available). Documented in the harness.
- **Corpus seeds are minimal/hand-built, not real TPM artifacts.** Real sealed blobs need a TPM
  (never run on this host), so `fuzz_metadata`/`fuzz_tpm_blob` seeds are structurally-valid but
  TPM-invalid (parse + reject deep), and the `fuzz_dbus_reply` recovery-blob seed has correct field
  lengths/valid base64 (parses + AEAD-rejects under the harness's fixed key). The fuzzer-generated
  corpus entries are deleted before commit; only the curated named seeds are tracked.
- **`fuzz/.gitignore` keeps `corpus` tracked** (drops the cargo-fuzz default `corpus` ignore) so the
  seeds ship; `target`/`artifacts`/`coverage` stay ignored.

## 2026-06-22 — Phase 6 wave 2: cargo vet + minimal-versions CI + auditd config (issue #52)
**Resolution:** `cargo vet` with a **self-contained exemptions store** — all 175 deps exempted, no
external `[imports]`. The Mozilla/Google/etc. audit-set imports were tried first but broke `cargo vet
--locked` in CI: the fetched upstream `audits.toml` notes reformat between cargo-vet versions, so
`imports.lock` drifts and `--locked` fails non-deterministically. Dropping imports makes the gate
reproducible (no upstream fetch). New `vet` job in `test.yml`, `minimal-versions` in its own nightly
workflow; auditd rules ship in the `.deb` at `/usr/share/tess/auditd/tess.rules`.
`supply-chain/config.toml` · `.github/workflows/minimal-versions.yml` · `deploy/auditd/tess.rules:1` · #52

Gotchas worth remembering:
- **`tss-esapi`/`secret-service`/`zbus` left exempted, NOT certified.** A `safe-to-deploy`
  cargo-vet certification is a shareable security attestation; honestly attesting the FFI-heavy
  `tss-esapi` (+ `-sys`) or the large async `zbus`/`secret-service` stack needs a real deep review
  out of scope for this wave. Fabricating it would pollute an importable audit set, so they stay as
  exemptions — still pinned (`tss-esapi ≥ 7.1.0`, RUSTSEC-2023-0044) and `cargo audit`/`deny`-gated.
  `cargo vet certify --criteria safe-to-deploy --who … --notes … --accept-all` is non-interactive
  and works; the blocker was honesty, not mechanics.
- **`-Z minimal-versions`, NOT `-Z direct-minimal-versions`.** direct-minimal fails to even resolve
  this graph (`getrandom = "0.4"` floor conflicts when only direct deps are minimized while
  transitives stay latest). Full `-Z minimal-versions` + `cargo +nightly check --workspace
  --all-targets` builds clean for the default feature set — no lower-bound bumps were needed.
- **The minimal-versions job deliberately omits `--all-features`.** `--all-features` enables
  `tss-esapi` optional features we never compile, which drag in an old transitive `num-bigint`
  whose own under-declared floor (`div_ceil(&n64)`) won't build on current nightly. That floor is
  not ours to fix; the default-feature `--all-targets` check is the meaningful proof of our bounds.
- **auditd is tamper-EVIDENCE, not a boundary.** Watches the installed binaries/PAM module/helper/
  udev rule/`common-session` only; per-user `~/.local/share/tess` blobs are unwatched (system-wide
  ruleset can't enumerate per-user paths, and they're already inert without TPM+PIN / recovery
  secret). Shipped to `/usr/share/tess`, never `/etc/audit/rules.d` — opt-in only; root can disable
  auditd, so it's forensic-only. Framing duplicated in the file header, `threat-model.md`, README.

## 2026-06-22 — privileged DA-lockout reset bound to the recovery secret (issue #16)

**Resolution:** lockout authValue = `HKDF-SHA256(R, salt="", info="tess-lockout-auth-v1")` set via the
safe `Context::hierarchy_change_auth(AuthHandle::Lockout, …)` under the salted-HMAC/param-enc session;
reset shells out to `tpm2_dictionarylockout --clear-lockout --auth file:-`. `crates/tess-tpm/src/lockout.rs:204` (reset_lockout) · `set_lockout_auth:129` · #16

- **tpm2-tools auth via stdin, not argv.** `--auth file:-` reads the **raw** authValue bytes from
  stdin, which exactly match the raw `TPM2B_AUTH` set by `hierarchy_change_auth` (no `hex:`/`str:`
  needed). Feeding it on stdin keeps the secret off `/proc/<pid>/cmdline`. `TPM2TOOLS_TCTI` (env, not
  secret) points tpm2-tools at the same TPM: `swtpm:host=…,port=…` in tests, `device:/dev/tpmrm0` in
  prod (`TctiConfig::tpm2_tools_tcti`). Exit 0 = success; wrong auth → non-zero (saw exit 3, rc 0x98e).
- **swtpm is single-client; drop the ESAPI `Context` before shelling out.** A held tss-esapi
  connection blocks a second client — the `tpm2_dictionarylockout` subprocess hangs until the context
  is dropped. swtpm does **not** exit on client disconnect (no `--terminate`), so the sim test closes
  the context (inner scope), runs the reset, then reopens + re-derives the deterministic primary.
- **A wrong lockout-auth attempt self-locks the lockout hierarchy** for `lockoutRecovery` (1000s on
  swtpm) and returns `TPM_RC_LOCKOUT` (0x921) — fine for the "wrong secret fails" test (each test uses
  its own swtpm). Hammering the *PIN* (object userAuth) trips the DA counter but does **not** lock the
  lockout hierarchy, so the correct-auth reset still works after a PIN-hammer hard lockout.
- **Detect a pre-existing lockout owner without spending a DA attempt:** read `TPMA_PERMANENT`
  (`PropertyTag::Permanent`) and test the `lockoutAuthSet` bit (0x4) — a read, not a trial auth. Enroll
  skips binding (warns) when it's already set; unenroll only clears when it owns it.
- tpm2-tools is now a CI system dep (`.github/workflows/test.yml`) and a documented runtime dep for
  the hard-lockout recovery path. Supersedes ADR-0008 → ADR-0011.
## 2026-06-22 — Phase 5 wave 1: `mug` secure IR face crate (Brio facts + 2nd confined unsafe)
**Resolution:** New workspace crate `crates/mug` delivers active-IR-reflectance liveness (the
security core), a pluggable model-free matcher, IR capture behind a trait + synthetic source, the
Brio IR-emitter enable, and a 0600 zeroized enroll store. Default crate is `#![deny(unsafe_code)]`;
all raw V4L2/UVC ioctls confined to one `#[allow(unsafe_code)]` `mug::sys` module — a **second**
allowed-unsafe location (was: only `tess-pam::ffi`), recorded in `docs/adr/0012`, AGENTS.md invariant
amended. `crates/mug/src/liveness.rs:1` · `crates/mug/src/sys.rs:1` · PR for Phase 5.

Brio hardware-discovery FACTS (one-time, on the user's real Logitech Brio — never re-run on host):
- USB `046d:085e`, bus `usb-0000:00:14.0-1.2`. `/dev/video2` = RGB (YUYV/MJPG); **`/dev/video4` = IR
  sensor, pixelformat `GREY` 8-bit, single discrete 340×340 @ 30fps**; video3/video5 = metadata.
- **IR emitter is OFF by default** (empty-scene video4 reads near-black, mean ~10/255); enabled by a
  Brio-specific UVC extension-unit `SET_CUR` (cf. `linux-enable-ir-emitter`). Node selection: pick the
  046d/085e node advertising `GREY`, reference via `/dev/v4l/by-id/...` not a hardcoded `/dev/video4`.

Gotchas worth remembering:
- **No heavy deps in wave 1 — deliberate.** `v4l`/`ort`/`image`/`ndarray` were NOT added. `v4l` still
  can't drive the UVC XU emitter (the security-relevant part) and adds a `libv4l`/`-sys` + registry
  subtree that churns `cargo deny` / `cargo vet --locked` for code CI can't exercise (no camera). The
  real capture+emitter path uses only `libc` + `nix` (with the `ioctl` feature) raw ioctls in
  `mug::sys`, so Cargo.lock gains ONLY the `mug` entry → vet/deny stay green untouched.
- **`v4l2_format` must be exactly 208 bytes or the `_IOWR` size field mismatches.** Modelled as
  `type_:u32 + _pad:u32 + fmt:[u8;200]`; the kernel union's pointer members force align-8 hence the
  explicit pad. `pix` (`v4l2_pix_format`, 48B) overlays `fmt` at offset 0. `crates/mug/src/sys.rs`.
- **Matcher stays model-free in CI via trait+mock, NOT a tiny test ONNX.** `EmbeddingExtractor` trait
  + `PooledExtractor` (average-pool→**mean-center**→L2-normalize). Mean-centering is load-bearing:
  without it every all-positive brightness vector clusters in cosine space and distinct scenes look
  identical (live-vs-screen distance was 0.047). Centered, it encodes spatial structure → screen/photo
  land far from a live enroll. The `ort` ArcFace/SFace backend is the documented drop-in (model path
  from config/env; absent ⇒ factor unavailable ⇒ degrade to PIN). No model ships.
- **Liveness thresholds (0..255 GREY) that separate the synthetic fixtures:** hard gates `mean_delta
  ≥12`, `delta_std ≥16`, `gradient_energy ≥5`, screen guard `baseline>70 & delta<20`, saturation
  `>50%`, plus composite score ≥0.45. Flat photo clears mean but fails std (uniform); glossy/curved
  photo clears mean+std but fails gradient (no high-freq relief — this is *why* the gradient gate
  exists); screen fails mean + emission guard (bright baseline, tiny differential). Live = radial
  falloff + feature relief + skin-texture noise + speculars passes all. Procedural fixtures in
  `liveness::synth` (deterministic xorshift, no `rand` dep), proven in unit + integration tests.
- **Synthetic IR substrate mirrors tess-fprint's virtual-driver pattern:** `MUG_VIRTUAL_IR_DIR` env
  → `VirtualIrDevice` serving `ir_off.grey`/`ir_on.grey`; `MUG_STORE_DIR` relocates the enroll store
  for tests. Headless: no camera, no model, no `unsafe` exercised. 27 mug tests green.

## 2026-06-22 — removed the auditd config (deferred per maintainer)
**Resolution:** auditd ruleset was forensic-only (root can disable it), not a security boundary; dropped the `.deb` asset, CI assertion, README/threat-model sections, and PLAN deliverable. cargo-vet certification of critical crates deferred to #58. Earlier auditd mentions in this journal (the Phase 6 wave-2 entry and its gotchas) are **historical and superseded by this removal** — auditd no longer ships (the earlier entry's
`deploy/auditd/tess.rules:1` citation is now a dead path, deleted here). `crates/tess-cli/Cargo.toml:84` · `.github/workflows/fuzz.yml:41` · #58

## 2026-06-22 — Phase 5 wave 2: model-B face-or-PIN unlock (sealed `A_face`) (issue #60)
**Resolution:** `tess enroll --face` seals the SAME keyring key `K` a second time under a fresh
independent authValue `A_face` → `metadata-face.json`; `A_face` is stored 0600 at `face-unlock.key`
and the face template lands in the mug store. `tess unlock --face` runs a bounded liveness-gated
match (`mug::verify`) then unseals `K` via `A_face` with no PIN typed, falling back to the PIN on any
face failure. `crates/mug/src/gate.rs:1` (`verify`/`FaceGate`) · `crates/tess-cli/src/enroll/mod.rs`
(`commit_face`/`FaceEnroll`) · `crates/tess-cli/src/face.rs:1` · #60

Key facts / gotchas:
- **`A_face` is generated, never derived.** It's drawn from `sealer.generate_key()` (the same
  getrandom+TPM-RNG mix as `K`), NOT from the PIN or recovery secret — a distinct on-disk credential.
  The `a_face_is_independent_*` sim test asserts the face-sealed object does NOT unseal with the PIN
  (only with `A_face`), and that both sealed copies recover the same `K`.
- **Face is fully transactional, additive.** `commit_face` runs BEFORE the destructive keyring rekey
  (capture template first → seal+verify+persist `metadata-face.json` → write `face-unlock.key` →
  mug `store.save`), each step recorded in `Tx`; rollback removes the three face artifacts in reverse
  (file + mug `store.remove`). A face-step failure therefore rolls back the whole enroll with the
  keyring never touched (restored to `old`) — never stranded, never weakening the existing guarantees.
- **`VirtualIrDevice` can't be both source and emitter at once** (`capture_liveness_pair` needs two
  distinct `&mut`). Added `VirtualIrDevice::split{,_from_env}` → `(VirtualIrSource, VirtualIrEmitter)`
  sharing an `Rc<Cell<bool>>`. Rc keeps `FaceGate` `!Send`, fine (single-threaded unlock/PAM thread).
- **Reversed/rotated synth frames are NOT a reliable "wrong face"** at the default 0.34 match
  threshold — a 180°-rotated live face still embeds at distance ~0.13 under the 64-dim mock (it IS a
  match). The fallback sim test injects a `screen_pair` spoof instead: it fails LIVENESS → face gate
  errors → PIN fallback unlocks. (A liveness-failed face is a valid "failed face" for the fallback.)
- **mug is now a tess-cli `[dependencies]` AND `[dev-dependencies]`** (the latter so the integration
  test can use `mug::liveness::synth` to write `.grey` fixtures). mug is a local path crate, so
  Cargo.lock gains only a `+ mug` line under tess-cli's deps — `cargo deny`/`cargo vet --locked` stay
  green, no new external crate.
- **`current_username()` keys the mug store off `$USER`/`$LOGNAME`.** enroll and unlock must agree;
  the sim suite pins `USER=tess-face-test` and `MUG_STORE_DIR`/`MUG_VIRTUAL_IR_DIR` to temp dirs.
- PAM-session face integration is deliberately NOT in this PR (separate follow-up; PLAN wave-2 box
  left unticked for it).

## 2026-06-23 — Phase 5: wire the face factor into the PAM session, non-blocking (issue #62)
**Resolution:** `face=yes` PAM module arg threads gate → ffi → `tess-pam-helper --face`, mirroring the
fingerprint front gate but for model-B (face *releases* the key with no PIN). Precedence in the helper:
face → fingerprint → PIN → password fallthrough. `crates/tess-pam/src/gate.rs:110` (`FACE_FLAG`/`face`/
`face_enabled`) · `crates/tess-pam/src/ffi.rs:253` (`session_deadline` + empty-stdin-for-face) ·
`crates/tess-cli/src/session.rs:107` (`run_pam_helper`/`face_front_unlock`) · #62

Key facts / gotchas:
- **Face can unlock with NO password, so the session gate must spawn the helper even when `get_pin`
  returns None.** `evaluate` still short-circuits a None PIN to `Unavailable` (no spawn) for the
  PIN-only/fingerprint-only cases; the *session gate* converts `None → Some(&[])` (empty stdin) only
  when `spec.face` is set, so the helper runs and the face path can try while the PIN fallback finds
  nothing to unseal with. The auth gate still passes `None` → never spawns at auth (auth only
  declines; unlock is the session phase's job).
- **Widened watchdog deadline:** `Watchdog::FACE_DEADLINE = 9s` (face capture ~2.5s + unseal headroom);
  with both biometrics the budget is `FINGERPRINT_DEADLINE + FACE_DEADLINE = 21s` (the backstop for
  both running sequentially before the PIN). Each leg is also bounded internally, so 21s is only the
  pathological-hang ceiling, never the normal wait.
- **Never-freeze chain is unchanged and load-bearing:** the helper is the same watchdog'd child
  (`helper::supervise` → SIGTERM → SIGKILL → reap, bounded by `deadline + 2*term_grace`,
  `crates/tess-pam/src/helper.rs:128`). A hung face capture is killed+reaped exactly like any hung
  helper; the stall test feeds the empty stdin the face-no-pin path uses and asserts bounded + reaped
  (`process_alive`) + auth fall-through + session success
  (`crates/tess-pam/tests/stall_injection.rs` `hung_face_capture_*`).
- **No new `unsafe`, no new deps.** All changes are in `#![deny(unsafe_code)]` / `#![forbid]` crates
  outside `tess-pam::ffi`; `Cargo.lock` untouched, `cargo vet --locked` and `cargo deny` stay green.
- **Test harness broken-pipe tolerance:** a face unlock exits *before* reading stdin, so the harness's
  `write_all(pin)` can hit `BrokenPipe` — that's a valid "child already unlocked" outcome, not a
  failure. `run_pam_helper_face` feeds an EMPTY stdin for the no-password proof (a success then can
  only be face: the PIN path would read an empty PIN and error). `crates/tess-cli/tests/common/mod.rs`.
- **User resolution for the mug store stays `$USER`/`$LOGNAME`** (`current_username()`), which the sim
  suite pins. Threading the PAM-resolved login user through to the mug store for real greeters/$HOME
  is part of real-hardware capture (#63); the matcher model is #56.

## 2026-06-23 — modernized to edition 2024 / Rust 1.96 + refreshed deps
**Resolution:** edition 2021→2024, rust-version 1.82→1.96 (latest stable). Edition 2024 made `std::env::set_var`/`remove_var` unsafe; confined the test-only env mutation to a new `tess-testenv` crate (one `#[allow(unsafe_code)]` module) so every shipping crate stays `forbid`/`deny(unsafe_code)`. Bumped nix 0.29→0.31, hkdf 0.12→0.13, sha2 0.10→0.11 (recovery crypto; deny/vet green, no dup digest). Kept tss-esapi 7.7 (8.0 alpha; RUSTSEC-pinned) and chacha20poly1305 0.10 (0.11 RC). `crates/tess-testenv/src/env.rs:1` · `docs/adr/0013`

## 2026-06-23 — Phase 5: wire real Brio IR capture (#63); `ort` matcher (#56) reported BLOCKED
**Resolution:** `tess-cli::face` now selects an IR capture backend via `MUG_IR_BACKEND`
(`auto`/`virtual`/`hardware`) through a pure, unit-tested `resolve_backend`; hardware builds
`find_brio_ir_node()` then `V4l2IrDevice::open(&node, …)` + a `BrioEmitter` bound to the same node (no new unsafe — all behind `mug::sys`, ADR-0012), virtual
substrate stays the CI/default path, both symmetric across enroll/unlock. `crates/tess-cli/src/face.rs`
(`resolve_backend`/`build_hardware_backend`/`select_backend`) · `docs/adr/0014` · #63

Key facts / gotchas:
- **#56 (`ort` matcher) is BLOCKED, not landed — deliberately no `ort` dep, no `face-model` feature.**
  crates.io has NO stable `ort`: `max_stable_version=null`; the whole `1.x` line is *yanked* (→ fails
  `cargo deny` `yanked = "deny"`) and `2.x` is `rc`-only (task forbids alpha/rc). On top of that `ort`
  2.x's default features include `download-binaries`, which fetches a prebuilt native ONNX Runtime at
  build time → non-hermetic, un-vettable. Per the issue's own escape hatch: left as trait + mock,
  reported for a maintainer decision. `cargo check -p mug --features face-model` therefore errors
  "does not contain this feature" — expected.
- **Selection is hardware-independent in tests.** `resolve_backend(requested, virtual_set, brio_probe)`
  takes the camera probe as a closure, so the 9 face unit tests never read `/dev/v4l/by-id` (the one
  env-driven test only exercises the Virtual branch, which never probes) — deterministic on CI and on
  a dev host that happens to have a camera. `MUG_VIRTUAL_IR_DIR` set ⇒ Virtual without reading the dir
  contents (split_from_env only reads the env var), so `template_source_from_env()` is `Ok` with no
  fixtures.
- **Brio emitter SET_CUR payloads are env-tunable** (`MUG_IR_EMITTER_ON_HEX`/`_OFF_HEX`, hex with
  `0x`/`:`/`,`/space tolerated; default `01`/`00`). Exact bytes are device-confirmed in the manual
  smoke; a wrong value fails safe (emitter stays off → liveness can't pass → degrade to PIN), so a
  placeholder default is acceptable for the opt-in, manually-validated path.
- **Real face *matching* still needs #56's model.** With the mock matcher on real Brio frames,
  liveness (the security core) is real but identity discrimination is weak — documented honestly in
  README + architecture.md. Real-Brio capture/photo-rejection is a documented manual smoke on a dedicated test machine (throwaway keyring/TPM) with the Brio, never on the daily-driver host and never
  CI (hardware never runs in CI/Azure).
- **No `Cargo.lock` churn:** mug gained zero deps, tess-cli gained zero deps. `cargo deny check` and
  `cargo vet --locked` (186 exempted) stay green. fmt/clippy(`-D warnings`)/check/test(workspace)/
  release build all green; sim suites compile (`--no-run`) — run in CI, not on host.

## 2026-06-23 — wired the real ONNX face matcher with self-contained tract (#56)
**Resolution:** `ort` was unusable (1.x yanked, 2.x rc-only + non-hermetic native download — fails deny/the no-prerelease rule). Used `tract-onnx` (self-contained, hermetic, stable — builds SIMD kernels via `cc`) behind the off-by-default `face-model` feature instead; `Matcher<Box<dyn EmbeddingExtractor>>` picks mock vs `TractExtractor` (model from `MUG_MODEL_PATH`, none ships). tract Tensor data access is `into_tensor().try_as_plain()?.as_slice::<f32>()` (no `to_array_view`/`as_slice` on the codegenerated Tensor). deny ok; vet regenerated (271 exempted). `crates/mug/src/matcher.rs` · `docs/adr/0015` · #56

## 2026-06-23 — face identity matching now fails closed without a real model (#56)
**Resolution:** the model-free mock does NO identity discrimination (accepts any live face), so `build_matcher` now errors instead of falling back to it for real enroll/unlock; the mock is gated behind a test-only `TESS_ALLOW_MOCK_FACE=1` opt-in (set in `face_unlock.rs`/`pam_helper_face.rs`; child PAM helper inherits it). README documents model download (OpenCV Zoo SFace / InsightFace ArcFace) + the `[1,C,H,W]`, `(p-127.5)/127.5`, channel-replicated input contract. `crates/tess-cli/src/face.rs` · `docs/adr/0016` · #56

## 2026-06-24 — configurable face-model input scaling (#68)
**Resolution:** added `MugConfig.pixel_scale` (`PixelScale`: `symmetric` default / `unit` / `standardized{mean,std}`); `TractExtractor::from_path` takes it and `extract` applies it per pixel (IR is single-channel, so channel order is moot — only scaling matters). `std=0`/non-finite rejected at load as `MatcherUnavailable`. `#[serde(default)]` keeps old configs loadable. `crates/mug/src/config.rs` · `crates/mug/src/matcher.rs` · #68

## 2026-06-24 — pixel_scale was inert without a config loader (#68)
**Resolution:** `template_source_from_env`/`verify_from_env` built `MugConfig::default()`, so `pixel_scale` (and all tunables) couldn't be set at runtime. Added `load_config()` reading a JSON `MugConfig` from `MUG_CONFIG` (malformed/unreadable = error, never silent default); both entrypoints use it. Also tightened `Standardized` validation: reject non-finite `mean` and `std <= 0` at load. `crates/tess-cli/src/face.rs` · #68

## 2026-06-24 — cargo-vet certified the security-critical crates (#58)
**Resolution:** focused safe-to-deploy source reviews (build.rs, unsafe, side-effects, RustSec/OSV) of the 5 critical groups → `cargo vet certify`: tss-esapi 7.7.0 + tss-esapi-sys 0.6.0, secret-service 5.1.0 + zbus 5.16.0, chacha20poly1305 0.10.1 + hkdf 0.12.4/0.13.0 + getrandom 0.2.17/0.4.3, rpassword 7.5.4, nix 0.31.3 (11 audits; exemptions 271→260). `certify --accept-all` auto-drops the matching exemption. **Gotcha:** kept the store imports-free (CI runs `cargo vet --locked`, no upstream fetch, per the workflow comment) — `cargo vet import`+`prune` strips exemptions for import-covered crates, which then strand when imports are removed; certify-only avoids that. `supply-chain/audits.toml` · #58

## 2026-06-24 — added `tess face-test` read-only diagnostic (#71)
**Resolution:** capture→liveness→match diagnostic that touches neither keyring nor TPM, so users can verify identity + photo-rejection without `enroll --face` (which rekeys the keyring). `build_matcher` gained an `allow_mock` param (face-test passes true — seals nothing, so the mock is fine when no model); real enroll/unlock still pass false (fail-closed). `run_face_test` returns a `FaceTestOutcome` (ReferenceRejected/ProbeRejected/Compared) for testability; a `pause` callback (Enter on CLI, frame-swap in tests) interleaves captures. `crates/tess-cli/src/face.rs` · `crates/tess-cli/src/main.rs` · #71

## 2026-06-24 — Brio emitter unit/selector/node made configurable (#73)
**Resolution:** real-Brio `UVC SET_CUR … ENOENT` = the hardcoded emitter XU coords (unit 0x04/selector 0x06) or node don't match that Brio. Added `MUG_IR_EMITTER_UNIT`/`MUG_IR_EMITTER_SELECTOR` (hex u8) + `MUG_IR_EMITTER_NODE` (path; emitter XU may be on a different node than GREY capture). Discover working values with `linux-enable-ir-emitter`. `crates/tess-cli/src/face.rs` (`emitter_coord`/`parse_hex_u8`) · #73

## 2026-06-24 — LFW validation: the real mug pipeline separates identities cleanly
**Resolution:** `crates/mug/tests/lfw_validation.rs` (`#[ignore]`d, `face-model`) runs the *shipped* detect→align→embed→cosine over LFW pairs (grayscale = IR-emulation; raw `.grey` prepared host-side, no Python in the validation logic). 999 test pairs: genuine mean cosine-dist 0.353, impostor 0.916; @ the **evaluated** threshold 0.60 (SFace calibration — *not* the model-agnostic `MugConfig::default` 0.34) → true-accept 95.2%, true-reject **100%**, balanced-acc 97.6%; best thr 0.665 → 98.1% balanced-acc, EER ~3.3%. Confirms the cosine+threshold decision (our code, not the model) is well-calibrated and only matches when it should. Run: `MUG_DETECTOR_MODEL=… MUG_MODEL_PATH=… LFW_DIR=… cargo test --release -p mug --features face-model --test lfw_validation -- --ignored --nocapture`.
## 2026-06-24 — Brio IR emitter auto-warms on streaming; SET_CUR is harmful by default (#80)
**Resolution:** raw capture of `/dev/video4` with NO control writes shows frames 0–~30 black (mean ~1) then frame ~39 lit (mean ~91) — the IR emitter **auto-enables after ~1 s of continuous streaming** and stays on while streaming (Windows Hello works the same way; the sensor reads black with the emitter off even in a lit room, since it only sees near-IR). So the off/on differential is "cold first frame" vs "a later warmed frame", captured on a fresh cold open. Added `mug::WarmingDevice`/`WarmingBrioDevice` (generic, unit-tested): cold capture = first dark frame, warm capture streams until brightness ≥ WARM_MIN_MEAN(24) and ≥ cold+WARM_MIN_DELTA(14) or deadline. **Gotcha:** poking the *wrong* default `SET_CUR` (unit 0x04, absent on this Brio) doesn't just ENOENT — it puts the capture node into `POLLERR (revents 0x8)` device-hangup on the next poll. So `SET_CUR` is now **opt-in** (`build_hardware_backend` only builds a `BrioEmitter` when an emitter env var is set); default is pure streaming warmup. `crates/mug/src/camera/hw.rs` (`WarmingDevice`) · `crates/tess-cli/src/face.rs` (`emitter_env_configured`) · #80. **2nd gotcha (the real blocker):** the Brio IR node's Device Caps `0x04200001` = Video Capture + Streaming but **no `V4L2_CAP_READWRITE`** — it does *not* support the `read()` I/O method, so mug's `file.read()` capture hit `POLLERR` even after SET_CUR was removed. Fixed by implementing V4L2 **MMAP streaming** in `sys` (`MmapStream`: REQBUFS/QUERYBUF/mmap/QBUF/STREAMON → poll/DQBUF/copy/QBUF → STREAMOFF/munmap on drop; ABI sizes pinned by const-assert, `v4l2_buffer`==88) and switching `V4l2IrDevice` to it. **Validated on the real Brio:** `face-test` reference capture now streams cleanly (no POLLERR), warmup gives `liveness PASS mean_delta 157, baseline 9.6`, and an empty scene returns `NoFace`. `crates/mug/src/sys.rs` (`MmapStream`) · #80.

## 2026-06-24 — Copilot review of #80/#82: fail-closed frames, endian-safe mmap, tunable warmup
**Resolution:** three review fixes on PR #82. (1) `MmapStream::dequeue` zero-padded a short `bytesused` frame — padding the dark emitter-OFF baseline with zeros inflates the liveness delta toward a false accept; now any `bytesused != expected_len` (or under-sized mapping) requeues the buffer then returns an error → `MugError::Camera` → PIN fallback (fail closed). (2) The MMAP `m.offset` was read as `buf.m & 0xffff_ffff`, correct only on little-endian; the C union's `__u32 offset` is the first 4 bytes *in memory*, so read it via `u32::from_ne_bytes(m.to_ne_bytes()[..4])` (endian-safe). (3) Warmup thresholds were hardcoded consts; #80's proposed work wanted them tunable, so added `mug::WarmupConfig` + serde `WarmupThresholds` (`warmup` block in `MugConfig`, `#[serde(default)]`), `WarmingDevice::split_with_config`, and a poll-slice `.max(1)` clamp so `poll_ms:0` can't busy-spin. Added the #80-acceptance stall test (`StallSource` that always times out → warm loop stays bounded and yields `Timeout`) and a threshold-governs-warm test. `crates/mug/src/sys.rs` · `crates/mug/src/camera/hw.rs` · `crates/mug/src/config.rs` · `crates/tess-cli/src/face.rs` · PR #82.

## 2026-06-24 — live face-preview viewer: separate non-workspace crate, not a tess subcommand
**Resolution:** the live IR viewer (detect box + landmarks + aligned crop + match verdict, driving the real `mug` pipeline) needs a windowing crate; `minifb 0.28` drags ~36 transitive crates into the lockfile (wayland/x11 on Linux; sdl2/winapi/web-sys/wasm/redox across all platforms in the lock). Putting it behind a `tess-cli` `face-gui` feature — even off-by-default — still injects all of them into the workspace `Cargo.lock`, so `cargo vet --locked` (CI gate) demands `safe-to-deploy` exemptions for ~36 unaudited GUI crates in an auth project, and `cargo deny check` must clear them. Instead shipped it as `tools/face-preview/` **excluded from the workspace** (`[workspace] exclude`), path-depending on `mug` (so it exercises the exact shipped detect→align→embed→cosine code) with its **own** `Cargo.lock` the workspace gates never see. Run: `cargo run --manifest-path tools/face-preview/Cargo.toml --release` with `MUG_DETECTOR_MODEL`/`MUG_MODEL_PATH`. Zero workspace supply-chain churn; `.deb` unchanged. `tools/face-preview/` · `docs/adr/0018` · README "Watch the pipeline live".

## 2026-06-24 — mlock secret buffers without unsafe in tess-core (#87)
**Resolution:** `SecretBytes` was zeroize-only → cleartext keys could be paged to **swap** (an at-rest leak the threat-model commits to closing; `mlock` does *not* cover hibernation/suspend-to-disk, which snapshots all RAM regardless — that's a separate operator mitigation). `mlock` needs unsafe libc, forbidden in `tess-core` (`#![forbid(unsafe_code)]`; unsafe only in tess-pam/mug/tess-testenv). Used the **`region`** crate: `region::lock(ptr,len)` is a *safe* fn returning an RAII `LockGuard` that munlocks on drop, so tess-core stays unsafe-free. `SecretBytes` is now `{ _lock: Option<LockGuard>, data: Vec<u8> }`; **field declaration order `_lock` before `data`** + a manual `Drop` that zeroizes gives wipe→unlock→free (guard munlocks the still-allocated pages before the Vec frees). Locking is **best-effort**: a low `RLIMIT_MEMLOCK` logs a note and proceeds (never blocks auth). `Clone` re-locks its fresh allocation. Test asserts the `/proc/self/status` `VmLck` delta when permitted and degrades gracefully otherwise (host/CI memlock is 8 MiB → the assertion runs). Supply-chain: `region` adds `region`+`bitflags 1.x`(+macOS `mach2`/Windows `windows-sys 0.52`, never compiled here); 4 cargo-vet exemptions (`cargo vet fmt` to canonicalize), `cargo deny` clean. ADR-0019. `crates/tess-core/src/lib.rs` · #87.

## 2026-06-24 — face research: passive IR liveness is correct (not blink); multi-frame match (#89)
**Resolution:** researched liveness/anti-spoof best practice (Windows Hello docs, Wikipedia liveness/biometric-spoofing, 3 decision-policy subagents). Findings: (1) Hello/Face ID use **passive active-illumination IR reflectance, no blink/motion** — pipeline find-face→landmarks→orientation→representation→threshold; motion liveness is a *remote-KYC* technique (deepfake-injection threat) with friction+replay weakness, not used for local device unlock. (2) Microsoft documents the photo/screen IR-invisibility we observed (*"IR doesn't display in photos … do not display on an LCD display"*) — casual spoofs rejected at *detection*, before liveness (empirically Brio: phone 9/9, glossy Polaroid 15/15 not detected as a face). (3) Residual risk = 3-D mask / IR-faithful print (no depth sensor; no ISO 30107-3 claim); PIN is the real gate (multi-factor). (4) Single-shot/first-match-wins (howdy `compare.py`, fprintd) is vulnerable to a transient false-match. **So:** don't add blink; make `verify` multi-frame. Implemented: `verify` aggregates cosine distance over up to MATCH_FRAMES(5) quality-gated frames within the deadline (detector miss → frame dropped from the vote), requires the **median** over ≥MIN_MATCH_FRAMES(3) to clear the threshold (majority — a transient fluke can't carry it; even-count uses upper-middle, conservative); too few → `InsufficientFrames` → PIN. `decide_match`/`frame_distance` unit-tested + scripted-source end-to-end (transient false-match rejected, consistent match accepted, too-few → no-decision). `crates/mug/src/gate.rs` · `docs/adr/0020` · #89. **fprintd one-shot GH issue:** none found — fprintd/libfprint track on gitlab.freedesktop.org (GitHub search is noise); their verify is first-match-wins by design but I found no filed issue calling it a weakness.

## 2026-06-24 — secure-practices research sweep (5 parallel agents) → 4 IOUs filed
**Resolution:** deep online-research pass (face PAD/liveness, multi-frame fusion, TPM sealing, Rust
secret handling, fprintd/PAM) validating the shipped design; codebase already matches best practice on
almost every axis. Durable findings:
- **TPM (`tess-tpm`) is near-textbook** — salted HMAC session, `nonce=None` (so GHSA-w3vw-ccc5-qr8v UAF
  never applied — it only fires with explicit `Some(nonce)`), AES-128-CFB decrypt+encrypt param
  encryption, ECC P-256, `PolicyAuthValue`, `noDA` clear, host-`getrandom`⊕TPM-`GetRandom` mixing.
  Confirmed vs Pulse Security BitLocker LPC-sniff + NCC *TPM Genie*. **Only gap:** no SRK Name pinning
  → an *active* interposer can substitute the salt key; `esapi.rs` overclaimed "defeats an interposer."
  → **#93** (this PR implements it).
- **Advisory-ID error** (confirmed at rustsec.org): PLAN.md (5×)+AGENTS.md cite `RUSTSEC-2023-0044`
  (which is the **OpenSSL** `set_host` over-read, CVE-2023-53159) for the tss-esapi UAF; the real one is
  `GHSA-w3vw-ccc5-qr8v` (no CVE; patched 6.1.2/7.1.0). Pin `≥7.1.0` is correct, only the citation wrong.
  → **#92**.
- **`SecretBytes` `Vec<u8>`** → prefer `Box<[u8]>` (zeroize realloc caveat) + **no core-dump
  suppression** (`RLIMIT_CORE=0`/`PR_SET_DUMPABLE`; mlock doesn't cover core dumps). → **#94**.
- **Liveness/multiframe** (ADR-0020 validated, not overclaiming): passive active-illumination IR is
  correct (Hello/Face ID, no blink); harden with face-localized + randomized-timing reflectance (anti
  CVE-2021-34466 whole-frame bypass) and **decorrelate** the #89 burst (frames are correlated →
  quorum ≠ `far^K`, real FAR floor is PIN+anti-hammering). → **#95**.
- **fprintd is single-shot/first-match-wins** (proven from upstream `pam/pam_fprintd.c`) + 3-try retry
  loop; no score fusion. NIST SP 800-63B §4.2.1: biometric is a factor, never a standalone authenticator.

## 2026-06-24 — SRK Name pinning: detect an active TPM-bus interposer (#93)
**Resolution:** the salted session defeats a *passive* bus sniffer but not an *active* interposer that
substitutes its own key as the session **salt key** (ESAPI salts to the primary's public, read off the
bus from `CreatePrimary` — substitutable). Fix = pin the primary's **Name** (SHA-256 fingerprint) at
enroll, re-verify at unseal. Implemented: `esapi::primary_name(ctx,primary)` (`Esys_TR_GetName`);
`SealedObject` carries `expected_primary_name`; `seal()` records it; **`unseal()` verifies it before
loading anything and fails closed with `Error::PrimaryNameMismatch`** (→ PIN fallback). Persisted as new
required `Metadata.primary_name` (base64); `METADATA_VERSION` 1→2 (v1 rejected, re-enroll). Pure
`primary_name_matches` (empty-expected = fail closed) unit-tested; sim tests assert Name is stable
across re-derivation and that a tampered pinned Name is rejected while the genuine object still unseals.
**TOFU model:** detects an interposer introduced *after* enroll; one active *during* enroll is the
residual (out of scope, like the live-machine adversary) — documented. Zero orchestration-layer changes
(threaded via `SealedObject`+`persist`). No new deps (uses existing tss-esapi). `crates/tess-tpm/src/{esapi.rs,seal.rs,persist.rs}` · `crates/tess-core/src/lib.rs` · `docs/adr/0021` · threat-model.md/architecture.md · #93.

## 2026-06-25 — liveness on the aligned crop + warm-loop detection retry (#79; addresses #95)
**Resolution:** two real-hardware problems with the shipped face path, both fixed. (1) **Whole-frame liveness rejected real faces** — the emitter return is a small part of a mostly-dark 340×340 frame, so the gradient gate (5.0) saw ~2.4–3.6 on a genuine face → REJECT; on the aligned face **crop** the same face is ~9–12 → PASS (`tools/face-collect` live data: whole-frame rejected 8/9 detected, crop passed 9/9; `tess face-test` live: liveness 0.81/grad 9.3, identity 0.0016). Fix: `mug::localized_liveness(pair,detector,cfg)` (detect on lit frame → align both OFF/ON → analyze crop; whole-frame fallback when no detector), used by `verify`, enroll (`MugTemplateSource` — so enrolled score calibrates on the same signal verify checks), and `face-test` (`capture_and_report`). (2) **Single-shot detection → PIN on a miss** (~50% first-try miss on a cold capture; user flagged it). Fix: restructured `verify` from `capture_liveness_pair`+identity-loop to **cold OFF baseline + warm-frame loop**: the first warm frame with a detectable live face clears liveness, that+subsequent warm frames feed the identity median, a no-face frame is **skipped** (detection retry) not fatal; bounded by deadline + `MAX_CAPTURE_ATTEMPTS`(12) so it never busy-spins (instant-capture test sources) or blocks login. A static spoof fails liveness every frame → retry doesn't weaken anti-spoof. **Gotcha:** the first warm capture needs the full remaining budget (emitter warmup ~1s via streaming); later warm captures are cheap (`warmed` flag → PER_FRAME_BUDGET_MS). All 67 mug tests pass incl. new (crop passes structured face, uniform whole-frame step rejected, NoFace propagates, detector-misses-first-frames still authenticates) + the scripted #91 multi-frame tests unchanged (they consume `off` first then warm — preserved). ADR-0023 (extends 0020; also records FAR-floor = PIN+anti-hammering / frames-correlated≠far^K from #95). `crates/mug/src/gate.rs` · `crates/mug/src/lib.rs` · `crates/tess-cli/src/face.rs` · `docs/adr/0023` · README/threat-model/architecture · #79. **HOLD merge:** the warm-loop verify restructure changes real-hardware capture flow and is NOT live-validated (user asleep, locked) — needs a live enroll+unlock (or face-test) pass before merge. #95's randomized-timing/illumination-decorrelation are impractical on the Brio auto-warm model (documented in ADR-0023, not forced). Enroll path still single-shot → follow-up issue.
## 2026-06-26 — corrected the wrong advisory ID for the tss-esapi FFI UAF (#92)
**Resolution:** confirmed at the source — `RUSTSEC-2023-0044` is the **OpenSSL** `set_host` buffer
over-read (CVE-2023-53159), not tss-esapi; the tss-esapi `Context::start_auth_session` use-after-free is
**GHSA-w3vw-ccc5-qr8v** (no CVE, patched 7.1.0/6.1.2, only triggers with `Some(nonce)` — we pass
`None`). Swapped the ID in all normative docs/config (PLAN.md, AGENTS.md, threat-model.md, ADR-0006,
Cargo.toml, deny.toml); left this journal's two earlier `tss-esapi` citations (in the bootstrap
dep-health note and the supply-chain exemptions note) intact per append-only discipline — this entry is
the correction of record. PR #92.

## 2026-06-26 — SecretBytes Box<[u8]> backing + core-dump suppression (#94)
**Resolution:** two residual secret-hygiene gaps from the 2026-06-24 sweep. (1) `SecretBytes.data`
`Vec<u8>` → **`Box<[u8]>`**: a boxed slice can't reallocate, so `zeroize` wipes the whole live buffer
with no stale heap copy (the `zeroize` `Vec` caveat). `new(Vec<u8>)` keeps its signature (~80 callers)
but now copies into an exact-size box and zeroizes the source `Vec`, avoiding the `into_boxed_slice()`
realloc-leaves-a-copy trap on a slack-capacity input. (2) **Core dumps**: `mlock` doesn't cover them, so
`tess_cli::harden::disable_core_dumps()` sets `RLIMIT_CORE`=0 (soft+hard) at both secret-touching
entrypoints — `tess` (`main.rs`) and `tess-pam-helper` (`pam_helper.rs`). Used the **safe `nix`
setrlimit** wrapper (tess-cli is `forbid(unsafe)`, so libc's unsafe `setrlimit` is out; `nix` was
already a workspace dep — added its `resource` feature + moved it from tess-cli dev-deps to deps; **zero
new crates in Cargo.lock**, no cargo-vet churn). Lowering the hard limit never needs privilege and can't
be undone — safe to call unconditionally; failure is logged once, never fatal. Threat-model updated
(core dumps now closed by tess; hibernation still operator-level). `crates/tess-core/src/lib.rs` ·
`crates/tess-cli/src/harden.rs` · `crates/tess-cli/src/{main.rs,pam_helper.rs}` · #94.

