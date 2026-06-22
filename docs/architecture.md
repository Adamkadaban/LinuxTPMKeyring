# Architecture

> Stub — fleshed out as crates land. Authoritative roadmap is in [`PLAN.md`](../PLAN.md).

## Crates

| Crate | Type | Responsibility |
|---|---|---|
| `tess-core` | lib | Shared types, versioned `Metadata` schema, config, errors, secret hygiene (`zeroize`/`secrecy`/`mlock`), the `KeyringBackend` / `AuthGate` / `SecretStash` traits |
| `tess-tpm` | lib | TPM2 seal/unseal of a random key under a PIN `PolicyAuthValue`, with mandatory HMAC + parameter-encryption sessions; ECC primary; DA-lockout aware |
| `tess-keyring` | lib | `SecretServiceBackend` (`KeyringBackend`) over the freedesktop Secret Service API; in-place rekey (enroll) + unlock (runtime); GNOME private calls isolated behind the trait |
| `tess-fprint` | lib | `fprintd` client over `net.reactivated.Fprint` (consumed unmodified) + a mock harness |
| `tess-pam` | cdylib + rlib | `pam_tess.so`: non-blocking gate → unseal → unlock, via a watchdog'd helper process. The only `unsafe` in the workspace |
| `tess-cli` | bin | the `tess` binary: `enroll`, `recover`, `unenroll`, `status`, `unlock`, `test`, `doctor`, `install` |

## Flow (MVP)

```
login → PAM (auth: PIN via conv, bounded helper) → tess-tpm::unseal(pin) → random key
      → tess-keyring::unlock(key) over Secret Service → GNOME login keyring unlocked
```

Enrollment rekeys the keyring in place (transactional, with a recovery secret) — see the
keyring-preservation invariant in `PLAN.md` §2.

## Test substrates

- **swtpm** (mssim/socket TCTI) for the TPM — runs in CI on GitHub-hosted runners.
- **libfprint virtual driver** + `python-dbusmock` for fprintd — headless, deterministic.
- **Azure Gen2 Trusted-Launch vTPM** for real-TPM acceptance (the only "real" exit-test gate).

### swtpm (TPM emulator)

`testing/swtpm/run.sh {start|stop|status}` launches `swtpm` in socket (TCP) mode with a
persistent `--tpmstate` directory and a pidfile. By convention the command/server port is
`2321` and the control port is `2322` (command + 1); both, the host, the state dir, and the pidfile
are overridable via `TESS_SWTPM_*` env vars. `start` blocks until the command port accepts a connection
(bounded by `TESS_SWTPM_START_TIMEOUT`); `stop` reaps the process (SIGTERM then SIGKILL) so nothing
leaks.

`tess-tpm`'s `TctiConfig::Swtpm { host, port }` is the matching transport. `TctiConfig::swtpm_from_env()`
resolves the address from `TESS_SWTPM_HOST` / `TESS_SWTPM_PORT` (default `127.0.0.1:2321`), mirroring
the script's env contract. `TctiConfig::open_context()` opens a live `tss_esapi::Context`: the swtpm
transport uses the **swtpm TCTI** (swtpm's control channel speaks its own protocol, not the IBM
mssim one — the mssim TCTI's platform commands fail against swtpm), and `TctiConfig::DeviceManager`
uses the device TCTI against `/dev/tpmrm0`. From a context, `tess_tpm::create_primary()` creates the
deterministic ECC NIST-P256 restricted-storage primary under the owner hierarchy, and
`tess_tpm::start_salted_hmac_session()` opens the salted HMAC + AES-128-CFB parameter-encryption
session (SHA-256) that every later seal/unseal runs under to defeat TPM bus interposers.

The swtpm TCTI implicitly uses `command_port + 1` as its control port, and `TctiConfig` exposes only
the command port — so swtpm must be launched with its control port set to command + 1. The
`run.sh` `TESS_SWTPM_CTRL_PORT` override exists for the script's own control plumbing; setting it to
anything other than command + 1 will make `open_context()` fail to connect.

## Seal / unseal (`tess-tpm`)

The core key-protection flow, gated by a PIN `PolicyAuthValue` and run under the salted HMAC +
parameter-encryption session so neither the PIN authValue nor the recovered key crosses the TPM bus
in the clear:

- `generate_sealing_key(context)` produces a 256-bit key by XOR-mixing OS randomness (`getrandom`)
  with the TPM's `GetRandom`. The key is unpredictable unless *both* sources are subverted, and it is
  never a TPM-born asymmetric key (avoids ROCA-class weaknesses and a malicious TPM RNG).
- `seal(context, primary, pin, secret)` computes the `PolicyAuthValue` policy digest via a trial
  session, builds a keyedhash (sealed data) object whose `userWithAuth` authValue is the PIN and
  whose authPolicy is that digest, and creates it under `primary` with the salted session. The object
  is **dictionary-attack protected** (no `noDA`), so wrong PINs count toward TPM lockout. It returns a
  `SealedObject` holding the public + private TPM2B blobs — the in-memory handoff the persistence
  layer marshals and stores (persistence and DA-lockout reset are a separate concern).
- `unseal(context, primary, sealed, pin)` loads the object, starts a real policy session (salted and
  encrypting), satisfies `PolicyAuthValue` with the PIN as the object's authValue, and unseals,
  returning the key as a zeroizing `SecretBytes`. A wrong PIN surfaces as a distinct wrong-PIN error
  (mapped to `tess_core::Error::Auth`), not a generic TPM fault, so callers can react. All transient
  handles (sessions, the loaded object) are flushed regardless of outcome.

## Persistence (`tess-tpm`)

A `SealedObject` lives only in memory; enrollment must persist it so a later boot can reload and
unseal. The blobs are stored inside the versioned `tess_core::Metadata`, never in a bespoke format:

- `to_metadata(sealed)` marshals the structured `TPMT_PUBLIC` to its canonical TPM wire form and
  takes the `TPM2B_PRIVATE` buffer verbatim, base64-encoding each into `Metadata.sealed_public` /
  `sealed_private` with `policy = PinAuthValue` and `version = METADATA_VERSION`.
- `from_metadata(metadata)` validates the schema version, base64-decodes both blobs, unmarshals the
  public area and rebuilds the private buffer, yielding a `SealedObject` ready for `unseal` under the
  same TPM's deterministic primary.
- `save(metadata, path)` writes pretty JSON atomically (temp sibling + rename, mode `0600`); `load`
  reads it back and re-checks the version.

**No secret or secret-hash ever reaches disk** — only the public area, the (TPM-encrypted, primary-
bound) private blob, and a policy descriptor. The blobs are inert without the TPM that created the
primary and the PIN that gates the object. A reload survives a simulated reboot because the ECC
primary is re-derived deterministically from the owner seed.

## DA-lockout handling (`tess-tpm`)

The sealed object is dictionary-attack protected, so wrong PINs accrue against the TPM's global
lockout counter and eventually trip a hard lockout (anti-hammering — the at-rest defence's teeth).

- `read_lockout_state(context)` reads `TPM2_PT_LOCKOUT_COUNTER` / `MAX_AUTH_FAIL` /
  `LOCKOUT_INTERVAL` via `TPM2_GetCapability` into a `LockoutState { counter, max_auth_fail,
  interval }` with `is_locked_out()` / `remaining_attempts()` helpers (read-only, no auth).
- A TPM lockout response code maps to a distinct `tess_tpm::Error::Lockout` →
  `tess_core::Error::Lockout`, so callers tell "locked out" apart from "wrong PIN" (`Error::Auth`)
  and from a TPM fault. On a hard lockout even `TPM2_Load` of the object is refused; that path is
  mapped too.
- `pin_holder_recover(context, primary, sealed, pin)` is the PIN-holder recovery path: it refuses
  when already hard-locked and otherwise proves the PIN with one successful unseal. It does **not**
  reset the DA counter; the name `reset_lockout` is reserved for the privileged, non-destructive
  `TPM2_DictionaryAttackLockReset` — deferred because the pinned `tss-esapi` exposes no safe wrapper
  and `unsafe` FFI is disallowed in this crate (see ADR-0008, tracked in #16).

Two crate features gate the transports that need a TPM:

```sh
cargo test -p tess-tpm --features sim   # starts swtpm, opens an ESAPI context, creates the ECC
                                        # primary, seals/unseals, persists + reloads, exercises DA
                                        # lockout, tears swtpm down
cargo test -p tess-tpm --features hw    # the same core against a real /dev/tpmrm0 (Azure vTPM only)
```

`sim` exercises swtpm; `hw` targets `/dev/tpmrm0` and is validated only on the Azure vTPM, never on
the dev host. Both are off by default, so plain `cargo test --workspace` stays green and
hardware-free; with `sim` enabled the integration test skips cleanly if `swtpm` is not on `PATH`.

## Hardware validation (`tess-tpm`, `hw` feature)

The `hw`-gated test (`crates/tess-tpm/tests/hw_device.rs`) is the body of the Phase 1 exit test on a
real TPM. It opens an ESAPI context over the device TCTI against `/dev/tpmrm0` and drives the exact
same `seal`/`unseal`/`persist`/lockout code the `sim` tests do — no crypto is duplicated — through
one serial sequence: confirm a TPM 2.0 family indicator; seal a random 32-byte key under a PIN and
unseal it back; persist + reload across a re-derived primary and unseal again; assert a wrong PIN
maps to `WrongPin` and ticks the DA counter; then hammer wrong PINs until the TPM surfaces a distinct
`Lockout`. It is one test (not several) on purpose: a real TPM has a single global DA-lockout
counter, so parallel tests would interfere. When `/dev/tpmrm0` is absent it skips with a notice, so
the feature still compiles on a hardware-free host without ever touching a TPM.

### Session-encryption assertion

Every seal/unseal session must be parameter-encrypted in **both** directions so neither the PIN
authValue (command parameters) nor the unsealed key (response parameters) crosses the TPM bus in the
clear. ESAPI exposes no getter for a started session's attributes, so the attribute set is factored
into `encrypted_session_attributes()` — shared by the HMAC session and the policy session — and a
unit test (`seal_unseal_sessions_enable_parameter_encryption`) asserts `decrypt`, `encrypt`, and
`continue_session` are set and that the attribute mask actually applies the decrypt/encrypt bits. A
regression that drops parameter encryption from the shared helper fails that test in the default,
hardware-free `cargo test --workspace`.


### Local QEMU vTPM VM (optional, contributors only)

`deploy/qemu/up.sh` / `down.sh` bring up a throwaway Debian 13 KVM guest with an swtpm vTPM and
key-only SSH for manual end-to-end exercise. **The agent and CI never run these on the developer's
host** — they exist purely as a contributor convenience and only ever talk to an emulated TPM.

## Keyring backend (`tess-keyring`)

`SecretServiceBackend` implements `tess_core::KeyringBackend` over the freedesktop **Secret Service**
API (`org.freedesktop.secrets`) via `zbus`. gnome-keyring is the reference daemon, and the headless
`unlock`/`rekey` below target its private interface. KWallet (KDE Frameworks ≥ 5.97 with
`apiEnabled=true`) and KeePassXC expose the same Secret Service API, so `is_locked` works against
them, but headless unlock/rekey on non-GNOME daemons (via the stable `Unlock` + `Prompt` path) is
future work. KWallet's native `pam_kwallet` path (keyed to the login password, not separately
unlockable) is out of scope.

- `is_locked()` reads the collection's `Locked` property with a fresh (uncached) `Properties.Get`,
  so it reflects the daemon's live state after an out-of-band lock/unlock.
- `unlock(secret)` and `rekey(old, new)` need to *prove possession* of a collection password
  headlessly, which the stable spec can't do (`Unlock` raises an interactive `Prompt`). They use
  GNOME's private `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface`
  (`UnlockWithMasterPassword` / `ChangeWithMasterPassword`, the call Seahorse's "change password"
  uses). `rekey` re-wraps the collection's master credential **in place** — every stored item stays
  intact, never a fresh shadow keyring. The runtime login unlock is expected to use the stable
  `gnome-keyring-daemon --unlock` stdin path; the in-process `unlock` re-unlocks an already-running
  daemon.

Every dependency on the unstable private interface lives in `SecretServiceBackend`, behind the trait,
so churn there never reaches callers. Released key material is carried in `SecretBytes` and the
backend's own D-Bus `Secret` buffer is zeroized as soon as each call returns; intermediate copies
inside `zbus`'s message encoding are outside our control and not guaranteed to be wiped. The value
crosses the *per-user* session-bus socket through a `plain` session without D-Bus-layer encryption;
that socket is owned by the user and a root/runtime adversary is out of scope, so the at-rest
guarantee is unaffected.

The `daemon-tests` feature gates an end-to-end suite that stands up a private `dbus-daemon` plus
`gnome-keyring-daemon` (secrets component) against a throwaway `XDG_DATA_HOME`, then reaps both even on
panic:

```sh
cargo test -p tess-keyring --features daemon-tests   # CI installs dbus-x11 + gnome-keyring
```

It asserts the keyring-preservation invariant (store N items → `rekey(old → new)` → `unlock(new)` →
all N still decrypt), the lock/unlock state transitions, and that a wrong secret never unlocks. The
suite uses throwaway keyrings only and skips cleanly when the daemons are absent, so the default
`cargo test --workspace` stays green and daemon-free.
## Fingerprint verify (`tess-fprint`)

`tess-fprint` is a thin client over fprintd's `net.reactivated.Fprint` D-Bus API, consumed
**unmodified** — exactly as `pam_fprintd` does, with no patches to fprintd or libfprint. A successful
fingerprint match is **host-trusted convenience layered on top of the PIN authValue, never the sole
gate**: the PIN sealed in the TPM is the real authorization, and this client never holds, derives, or
releases key material — it only reports whether the local fprintd matched a finger.

`FprintClient` follows the same call sequence `pam_fprintd` uses: `Manager.GetDefaultDevice` →
`Device.Claim` → subscribe to the `VerifyStatus` signal → `Device.VerifyStart("any")` → wait for a
terminal `VerifyStatus(result, done)` → `VerifyStop` → `Release` (the device is always released, best
effort, before returning on the graceful paths). The `verify(deadline_ms)` method (also exposed
through the `tess_core::AuthGate` trait) maps results precisely and is **always bounded**: the
`VerifyStatus` wait is bounded by `deadline_ms` and runs `VerifyStop`/`Release` cleanup on the way
out, while an outer `deadline_ms + CLEANUP_GRACE` wall-clock backstop additionally caps the D-Bus
setup calls (`GetDefaultDevice`, `Claim`, …) so the call can never block past that ceiling even on a
wedged bus or unresponsive service. The grace (1s) exists so the graceful timeout path can finish its
cleanup; only a genuinely wedged bus reaches the backstop, where the future is cancelled and fprintd
releases the claim when this client's connection drops. The reported `Timeout` carries `deadline_ms`:

- `verify-match` → `Ok(())`
- `verify-no-match` → `tess_core::Error::Auth` ("fingerprint did not match")
- any other terminal token (`verify-disconnected`, `verify-unknown-error`, …) → `Error::Auth` carrying
  the token; transient tokens (`verify-retry-*`, `verify-swipe-too-short`) are waited through
- deadline elapsed → `tess_core::Error::Timeout`

Result classification (`classify_verify_result`) is a pure function unit-tested without a bus, so the
match/no-match/retry/terminal-failure decision logic is covered in the default `cargo test`.
`FprintClient::system` connects to fprintd on the system bus (production); `connect_address` connects
to an explicit private bus address (tests), which keeps the suite parallel-safe with no global
`DBUS_SESSION_BUS_ADDRESS` mutation.

### Mock harness (`testing/fprint-mock/`)

`testing/fprint-mock/fprintd_mock.py` is a deterministic `python-dbusmock` mock of just the slice of
`net.reactivated.Fprint` the client consumes. It is launched under a private session bus so nothing
touches the developer's real bus, real fprintd, or any reader:

```sh
dbus-run-session -- python3 testing/fprint-mock/fprintd_mock.py {match|no-match|stall}
```

It prints the private bus address on its first stdout line, then scripts `VerifyStart` per scenario:
`match` emits `VerifyStatus("verify-match", true)`, `no-match` emits `verify-no-match`, and `stall`
returns from `VerifyStart` but never emits — so a bounded client must time out. The integration tests
(`crates/tess-fprint/tests/fprint_mock.rs`) spawn one harness per scenario in its own process group,
read the address, run `verify`, and assert `Ok` / no-match `Auth` / bounded `Timeout`; a `Drop` guard
SIGTERM-then-SIGKILLs the whole process group (the `dbus-run-session`, its `dbus-daemon`, and the
`dbusmock` server) so no harness process leaks. When the tooling (`python3`, `dbus-run-session`,
`python3-dbusmock`) is absent the tests skip cleanly, so plain `cargo test --workspace` stays green on
any machine; CI installs the tooling and runs them for real. No real fingerprint hardware is ever
touched.

## Deploy targets

| Path | Purpose |
|---|---|
| `deploy/azure/main.bicep` | Declarative Gen2 Trusted-Launch Debian 13 VM: `securityType=TrustedLaunch`, vTPM + secure boot on, key-only SSH, every resource tagged `project=LinuxTPMKeyring`. |
| `deploy/azure/provision.sh` | One-command bring-up: creates the resource group and deploys `main.bicep` via `az deployment group create`; prints the `ssh` command. Region/size/name/key are env-overridable. |
| `deploy/azure/deallocate.sh` | Stops (deallocates) the VM to halt compute billing without deleting it. |
| `deploy/azure/teardown.sh` | Lists the tagged resources, then (after explicit confirmation) deletes the whole resource group. |
| `deploy/azure/hw-exit-test.sh` | Runs the Phase 1 hardware exit test against an **already-provisioned** VM: tars the workspace over SSH, installs the toolchain + tpm2-tss deps, runs `cargo test -p tess-tpm --features hw` against `/dev/tpmrm0`, then `tess doctor`. Provisions/tears down nothing and runs no `az` — lifecycle stays with the orchestrator. Inputs: `TESS_HW_SSH`, `TESS_SSH_KEY`. |

The Azure vTPM is the only real TPM 2.0 acceptance gate; its PCR values differ from bare metal, so
the MVP TPM policy binds the PIN authValue only (no PCR binding). Cost discipline — deallocate when
idle, delete at wind-down, kill-by date — is tracked in [`NOTES.md`](../NOTES.md) and the teardown
plan in [`PLAN.md`](../PLAN.md) §8.

## `tess doctor`

`tess doctor` (`crates/tess-cli/src/doctor.rs`) performs read-only readiness probes — `/dev/tpmrm0`
and `/dev/tpm0` presence, a Secret Service daemon binary on `PATH` (the daemon is *not* contacted),
and `fprintd` on `PATH` — and prints an OK/MISSING table with a one-line verdict. When `/dev/tpmrm0`
is present it additionally opens a **read-only** ESAPI context to report the TPM version and
DA-lockout state (`present; TPM 2.0 (spec rev N); DA lockout C/M`) via `TPM2_GetCapability` only — no
seal/unseal, no authorization, no secret. That capability read is best-effort: any failure (no
runtime TCTI library, a busy TPM) downgrades to `present; TPM detail unavailable (<reason>)` and
never panics or fails the verdict, which still depends only on the device node's presence. It never
opens a D-Bus session, touches a secret, or unlocks anything; per project policy it runs in CI or on
a fresh Azure VM for self-check, not the developer host. Only the TPM resource manager is required
for the verdict.

## Non-blocking PAM module (`tess-pam`)

`pam_tess.so` is the login-time gate. Its overriding constraint is that it must **never freeze
login**: no blocking TPM, D-Bus, or camera I/O ever runs on the PAM thread. The crate is built as a
`cdylib` (`libpam_tess.so` → installed as `pam_tess.so`) plus an `rlib` so the safe logic is unit-
and integration-testable.

### Confined FFI

The PAM C ABI is hand-rolled in `crates/tess-pam/src/ffi.rs` — the **only** `unsafe` in the
workspace. Every other crate is `#![forbid(unsafe_code)]`; `tess-pam` sets `#![deny(unsafe_code)]`
at the crate root and `#[allow(unsafe_code)]` on the `ffi` module alone. The module declares the
small frozen surface it needs (`pam_get_item`, `pam_set_data`/`pam_get_data`, `pam_get_authtok`, and
the `pam_conv`/`pam_message`/`pam_response` structs), exports the four entrypoints
(`pam_sm_authenticate`/`pam_sm_setcred`/`pam_sm_open_session`/`pam_sm_close_session`), and wraps the
raw calls in safe functions (e.g. reading `PAM_RHOST`) so the rest of the crate stays safe Rust. The
`.so` links `libpam` (via `build.rs`), which also lets the test binaries resolve the `pam_*` symbols
without a live PAM stack.

### Watchdog'd helper + fail-open

Heavy work runs in a short-lived child process supervised by `helper::run` under a hard
`Watchdog { deadline, term_grace, poll }`. The supervisor polls `try_wait`; on deadline it sends
`SIGTERM`, waits `term_grace`, escalates to `SIGKILL`, and polls `try_wait` for another `term_grace`.
In the normal timeout path the child is killed and reaped (no zombies, no leaks) and the call returns
within `deadline + 2 * term_grace`. In the pathological case where even `SIGKILL` cannot terminate the
child promptly (uninterruptible I/O), the call still returns within that bound, but the child may
linger and its reap is deferred to a detached thread — so the PAM thread is never blocked and the
child still cannot leak as a permanent zombie. A run yields a `Reaped { pid, termination }` that
`gate::classify` maps to `Authorized` / `Declined` / `Unavailable` (a spawn or syscall error is
`Unavailable` — fail open, never authorization).

`gate::decide` turns that into a PAM code per phase:

- **Auth** returns `PAM_SUCCESS` only on an explicit `Authorized`; `Declined`, timeout, and spawn
  failure all return `PAM_AUTHINFO_UNAVAIL`, so a `[success=done default=ignore]` stack falls through
  to the password factor.
- **Session** always returns `PAM_SUCCESS` — a slow or failed unseal degrades to "keyring stays
  locked, login proceeds", never a frozen or failed login.

Before running anything the gate aborts when no gesture is available: a remote session (a non-empty
`PAM_RHOST` — the authoritative PAM-provided signal, not an environment variable) or no TPM device
(`/dev/tpmrm0`/`/dev/tpm0` absent). Auth
aborts with `PAM_IGNORE` (fall through to password); a session open aborts with `PAM_SUCCESS` so it
never disturbs login under any control flag. The helper executable is resolved from a root-controlled
PAM module argument (`helper=PATH` in the PAM config), falling back to the compiled install path
`/usr/lib/tess/tess-pam-helper`; release builds ignore the environment so a caller cannot substitute
the helper in the privileged PAM context (debug/test builds additionally honour `TESS_PAM_HELPER` for
the test harness). The real unseal → keyring-unlock helper is wired in a later phase; until it is
installed, a missing-helper spawn fails open, which is the correct non-blocking behaviour.

### "Login never freezes" test

`crates/tess-pam/tests/stall_injection.rs` injects three helper states — slow-but-eventually-OK,
hang-forever (SIGTERM-ignoring, forcing SIGKILL escalation), and clean-failure — and asserts each
finishes within a hard bound, maps to the correct PAM code, and leaves the child neither alive nor a
zombie (`process_alive(pid)` is false after the run). Pure unit tests cover the timeout / fail-open /
abort decision logic. A `pamtester`/`pam_wrapper` smoke load of a no-op session is left to CI per the
"nothing runs on the dev host" policy.

