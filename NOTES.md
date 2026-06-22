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
`cargo build --release --workspace && cargo deb -p tess-cli --no-build` produces
`target/debian/tess_<ver>_amd64.deb`. `deploy/install.sh` is the one-command path; `deploy/debian/postinst`
prints next steps without touching pam.d. `crates/tess-cli/Cargo.toml` · `deploy/install.sh` ·
`deploy/debian/postinst` · `.github/workflows/test.yml` · PR for #38.

Gotchas worth remembering:
- **`--no-build` + a prior `cargo build --release --workspace` is mandatory.** `cargo deb -p tess-cli`
  on its own only builds the `tess-cli` package, so the `tess-pam` cdylib `libpam_tess.so` (a
  different workspace member) is absent and packaging fails. Building the whole workspace first, then
  packaging without a rebuild, is the deterministic path used by `install.sh` and CI alike. Asset
  paths use the special `target/release/...` prefix cargo-deb rewrites to the real target dir.
- **Three runtime paths must match what the PAM module/installer resolve.** `tess` → `/usr/bin/tess`;
  `tess-pam-helper` → `/usr/lib/tess/tess-pam-helper` (the compiled `DEFAULT_HELPER_PATH` in
  `crates/tess-pam/src/gate.rs`); `libpam_tess.so` → `pam_tess.so` under
  `/usr/lib/x86_64-linux-gnu/security/` (Debian 13 amd64 multiarch security dir, where
  `pam_permit.so` lives). A drift here would make the installed helper unreachable at login.
- **`depends = "$auto, gnome-keyring"`, `recommends = "fprintd"`.** `$auto` resolves the linked
  tpm2-tss libs (libtss2-esys/-mu/-tctildr) + libc/libpam from the packaged ELFs via dpkg-shlibdeps;
  gnome-keyring is reached over D-Bus (not linked) so it is named explicitly. fprintd is the optional
  fingerprint front gate — tess is PIN-only without it — so Recommends, not Depends, is the
  Debian-correct relationship (avoids pulling the fingerprint stack onto readers-less machines).
- **The package never edits `/etc/pam.d`.** Lockout safety: PAM wiring stays in the explicit,
  fail-open `tess install`. The `postinst` only prints instructions and `exit 0`s. CI runs
  `dpkg -c` (contents-only) and never `dpkg -i`, so it can't perturb the runner.
- **CI build host is Ubuntu, not Debian 13**, so `$auto` resolves Ubuntu package names — fine,
  because the CI step asserts only the three artifact *paths* via `dpkg -c`, not the depends line. A
  real Debian 13 `.deb` is produced by `install.sh` on the target.
