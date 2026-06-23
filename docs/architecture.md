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
login → PAM session → [fingerprint front gate (optional, convenience)]
      → PIN via conv (the real gate) → bounded helper → tess-tpm::unseal(pin) → random key
      → tess-keyring::unlock(key) over Secret Service → GNOME login keyring unlocked
```

The precedence is **fingerprint (host-trusted convenience) → PIN (the real TPM gate) → password
fallthrough**. The fingerprint match is layered *on* the PIN, never in place of it: the random key is
sealed under the PIN authValue, so the PIN is always required to unseal — a fingerprint match alone
cannot release the key. See "Session flow" below for the honest limitation.

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

## Enrollment transaction (`tess-cli`)

`tess enroll` composes the three building blocks — `tess-tpm` (seal/unseal), `tess-keyring` (in-place
rekey), and `tess-core` (metadata) — into the project's #1 safety-critical path. It rekeys the login
keyring from its password-derived wrapping key to a fresh random key sealed in the TPM, **transactionally**:
a crash or error at any step must leave the keyring either fully-old or fully-enrolled, never a
half-rekeyed lockout. The flow (`crates/tess-cli/src/enroll/mod.rs`) is strictly ordered:

1. generate the random keyring key `K` (`generate_sealing_key`);
2. **back up the recovery secret first** — wrap `K` under a user-saved recovery secret, verify the
   wrap round-trips, and persist the recovery blob *before anything destructive*;
3. seal `K` under the PIN, verify it unseals with that PIN, then persist the sealed blobs + metadata;
4. verify the supplied old credential opens the keyring, then `rekey(old → K)` in place (destructive);
5. verify the keyring unlocks with `K`, is no longer locked, and a known pre-existing item still
   decrypts;
6. commit.

A `Tx` accumulator records exactly which destructive steps ran (recovery written, metadata written,
keyring rekeyed). On any failure it rolls back **in reverse, credential-first**: it restores the
original keyring credential (`rekey(K → old)`), and only once the keyring is safely back on `old`
removes the just-written blobs. The one path that deliberately *keeps* the blobs is a failure to
restore the credential during rollback — then the sealed and recovery blobs are the only way back in,
so they are preserved and the error tells the user to run `tess recover` with the saved recovery
secret. Verifying the unseal in step 3 *before* the rekey means a broken TPM path can never strand the
keyring on a key the PIN can't recover. All key material lives in `SecretBytes`/`Zeroizing`; nothing
secret reaches disk except the TPM-sealed blob and the recovery-wrapped blob (neither
plaintext-recoverable).

The `KeySealer` trait (`enroll::sealer`) abstracts seal/unseal so the transaction's rollback logic is
unit-testable without a TPM; `TpmSealer` is the production impl owning the ESAPI context + ECC primary
(the only place `tss-esapi` types appear in `tess-cli`). The CLI prompts for the PIN (or takes
`--pin`) and the current keyring password without echo, selects the swtpm transport when
`TESS_SWTPM_HOST`/`TESS_SWTPM_PORT` are set (else `/dev/tpmrm0`), and persists to
`$XDG_DATA_HOME/tess/{metadata,recovery}.json`.

### Recovery-secret scheme (TPM-independent)

The TPM unseal path dies if the TPM is cleared or the PIN is lost, so enrollment additionally backs
`K` up under a high-entropy **recovery secret** `R` the user saves offline (`enroll::recovery`). The
scheme — committed in [ADR-0009](adr/0009-recovery-secret-wrapping-scheme.md):

1. `R` — 256 bits from the OS CSPRNG, shown once as a transcription-friendly grouped-hex string.
2. `KEK = HKDF-SHA256(salt, R, info)` with a fresh random salt — `R` is already high-entropy, so an
   extract/expand KDF (not a slow password hash) suffices and keeps recovery instant.
3. AEAD-seal `K` under `KEK` with **XChaCha20-Poly1305** and a fresh random 192-bit nonce.
4. Persist only `{version, salt, nonce, ciphertext}` — never `K`, `R`, or any hash of either.

The recovery blob is recoverable **without the TPM** (decrypt with `KEK` re-derived from the
user-entered `R`) yet inert without `R`: the ciphertext is indistinguishable from random and the
Poly1305 tag rejects a wrong secret or tampering. `R` is at least as strong as the PIN, so this never
weakens the at-rest guarantee. `tess recover` (wave 2) decrypts the blob back to `K` to re-unlock and
re-seal. Crypto is delegated to audited RustCrypto crates (`chacha20poly1305`, `hkdf`, `sha2`) — no
hand-rolled primitives.

### Tests

The rollback bookkeeping and the recovery wrap/unwrap (round-trip, wrong-secret rejection, tamper
detection, blob save/load) are pure unit tests in the default, hardware-free `cargo test --workspace`.
The end-to-end transaction is gated behind `sim` + `daemon-tests`
(`crates/tess-cli/tests/enroll_transaction.rs`), driving the real swtpm and a throwaway
`gnome-keyring-daemon`:

```sh
cargo test -p tess-cli --features sim,daemon-tests
```

It asserts the happy path seals + rekeys + verifies and that **both** unlock paths (TPM-unseal with
the PIN, and the TPM-independent recovery secret) recover the *same* key; and — the load-bearing
safety assertion — that a failure injected at each destructive step (rekey, item-verify, persist)
rolls back with all three pre-existing items intact and no sealed/recovery blobs left behind, and that
the recovery backup is always created before the destructive rekey. Throwaway keyrings only; every
swtpm/dbus/keyring process is reaped on drop.

## CLI lifecycle (`tess-cli`)

The remaining subcommands (`crates/tess-cli/src/lifecycle/`) compose the same seal/unseal, recovery
(ADR-0009), and in-place-rekey blocks as enrollment — **no cryptography is reimplemented**. Each core
flow is a pure-ish function taking its collaborators (a `KeySealer`, a `KeyringBackend`, the `Paths`),
so it is driven by the `sim` + `daemon-tests` suite without prompts; a thin `lifecycle::cli` layer
gathers PINs / passwords / the recovery secret without echo and builds the real `TpmSealer` +
`SecretServiceBackend`.

- `tess unlock` — one-shot manual unlock: reload the sealed metadata, `tess-tpm::unseal` it with the
  PIN, and `KeyringBackend::unlock` with the recovered key, confirming the collection actually opened.
  Changes only the keyring's lock state; writes/removes no blob.
- `tess recover` — re-establish access when the TPM path is gone (cleared TPM, lost PIN, changed
  PCRs). It unwraps the keyring key from the TPM-independent recovery blob with the user-entered
  recovery secret and unlocks the keyring — working with **no TPM at all**. With `--reseal` it then
  seals the recovered key under a new PIN against the current TPM and atomically rewrites
  `metadata.json`, restoring the normal PIN-unlock path (the keyring credential is unchanged, so only
  the sealed metadata is rewritten; the recovery blob still wraps the same key).
- `tess unenroll` — transactionally rekey the login keyring from the TPM-sealed key back to a
  user-supplied password and remove the sealed + recovery blobs, restoring stock behaviour with every
  item intact. It reuses enrollment's **credential-first rollback** discipline: prove the PIN and
  recover the current key, rekey in place to the new password, **verify the keyring opens with the
  password before removing any blob**, and on a failed verification rekey back to the TPM-sealed key
  (keeping the blobs, which still gate that key) rather than stranding the user. Blob removal is the
  final, non-destructive step.
- `tess status` — a read-only snapshot: enrollment state (sealed metadata present), recovery-blob
  presence, keyring lock state (`is_locked`), and TPM version + DA-lockout via the shared read-only
  cap probe (`doctor::read_caps`). Every component is best-effort — an unreadable one carries its
  reason in the report rather than failing the command.
- `tess test` — a side-effect-free "would the session unlock path work right now?" verdict. It checks
  enrollment + metadata loadability, TPM reachability and DA-lockout, and keyring reachability, then
  prints the blocking reasons (or `WOULD SUCCEED`). It performs **no** unseal and **no** unlock, so it
  consumes no DA attempt and changes nothing.

The report rendering and the dry-run verdict logic are pure unit tests in the default, hardware-free
`cargo test --workspace`. The end-to-end flows are gated behind `sim` + `daemon-tests`
(`crates/tess-cli/tests/lifecycle.rs`):

```sh
cargo test -p tess-cli --features sim,daemon-tests
```

It proves `unlock` round-trips with the PIN; `recover` restores access after a simulated TPM clear
(the sealed metadata is dropped, recovery via the secret still unlocks) and `--reseal` re-establishes
the PIN path; `unenroll` returns the keyring to a password with all three pre-existing items intact
and the blobs removed; and `status` reports the real enrollment / keyring-lock / TPM state. Throwaway
keyrings only; every swtpm/dbus/keyring process is reaped on drop.

## Phase 3 exit gate (`tess-cli`)

`crates/tess-cli/tests/phase3_e2e.rs` (`full_phase3_cycle_preserves_all_items`, gated `sim` +
`daemon-tests`) is the single cross-cutting Phase 3 exit test. On one throwaway login keyring seeded
with **five** pre-existing secrets it runs the whole lifecycle in order — `enroll` (seal + in-place
rekey) → a simulated fresh login session driving the **real `tess-pam-helper` binary** (PIN on stdin,
the contract the PAM module uses) → `recover` after a simulated TPM clear → `reseal` under a new PIN
(re-proving the session path with the helper) → `unenroll` back to a password — and asserts the
project's #1 safety property after **every** transition: all five secrets present, unlocked, and
decrypting to their original values, with the group count unchanged (no loss or duplication). The
swtpm + private-bus keyring harness from `tests/common` is reused; every spawned process (swtpm,
dbus-daemon, keyring, helper) is reaped under bounded waits.

```sh
cargo test -p tess-cli --features sim,daemon-tests
```

This is the **CI/swtpm leg** of the Phase 3 exit test; the real-TPM (Azure vTPM) leg is exercised in
Phase 4.

## Deploy targets

| Path | Purpose |
|---|---|
| `deploy/azure/main.bicep` | Declarative Gen2 Trusted-Launch Debian 13 VM: `securityType=TrustedLaunch`, vTPM + secure boot on, key-only SSH, every resource tagged `project=LinuxTPMKeyring`. |
| `deploy/azure/provision.sh` | One-command bring-up: creates the resource group and deploys `main.bicep` via `az deployment group create`; prints the `ssh` command. Region/size/name/key are env-overridable. |
| `deploy/azure/deallocate.sh` | Stops (deallocates) the VM to halt compute billing without deleting it. |
| `deploy/azure/teardown.sh` | Lists the tagged resources, then (after explicit confirmation) deletes the whole resource group. |
| `deploy/azure/hw-exit-test.sh` | Runs the Phase 1 hardware exit test against an **already-provisioned** VM: tars the workspace over SSH, installs the toolchain + tpm2-tss deps, runs `cargo test -p tess-tpm --features hw` against `/dev/tpmrm0`, then `tess doctor`. Provisions/tears down nothing and runs no `az` — lifecycle stays with the orchestrator. Inputs: `TESS_HW_SSH`, `TESS_SSH_KEY`, `TESS_HW_DIR`. |
| `deploy/install.sh` | One-command Debian 13 install: build (or take `--deb`) the `.deb`, install it with its runtime dependencies, then wire the fail-open PAM module via `tess install`. Idempotent; never edits `/etc/pam.d` directly. |
| `deploy/debian/postinst` | Package post-install script. Prints the next steps (`tess install`, `tess enroll`); deliberately does **not** touch `/etc/pam.d`, so installing the package can never lock a user out. |
| `deploy/azure/mvp-e2e.sh` | Phase 4 MVP acceptance harness against an **already-provisioned** VM: tars the workspace over SSH and runs the full demo on the guest — install deps, build tess (or install a `.deb` if present), `tess enroll` (a random key sealed to the real vTPM under a PIN), a scripted virtual-fprint + PIN session through the real `tess-pam-helper`, then asserts the login keyring is UNLOCKED with no password (`tess status` + a `secret-tool` probe). Provisions/tears down nothing, runs no `az`. Inputs: `TESS_HW_SSH`, `TESS_SSH_KEY`, `TESS_HW_DIR`. |
| `deploy/azure/reboot-persistence.sh` | Run after `mvp-e2e.sh` against the same VM: reboots the guest, waits (bounded) for it to return, then re-runs only the session unlock over the *persisted* (locked) login keyring — proving the sealed key survives a reboot. The PIN-only policy (no PCR binding) means no reboot brittleness. Same inputs as `mvp-e2e.sh`. |
| `deploy/azure/mvp-e2e-remote.sh` | The VM-side body the two drivers pipe over SSH (`bash -s -- full` / `bash -s -- reboot`). Reuses `hw-exit-test.sh`'s sudo + sanitized-PATH handling: the build runs **unprivileged**, and only the TPM-touching `tess` / `tess-pam-helper` invocations (enroll, status, the session unseal) are wrapped in sudo, and only when the login user can't access `/dev/tpmrm0` directly. Reaps every spawned process (private `dbus-daemon`, `gnome-keyring-daemon`, the `python-dbusmock` fprintd mock) in an `EXIT` trap. Never run directly on the host. |

**Orchestrator invocation.** The wave-3 acceptance step provisions a Trusted-Launch VM
(`provision.sh`), then runs, against that VM, `TESS_HW_SSH=tess@<ip> deploy/azure/mvp-e2e.sh`
followed by `deploy/azure/reboot-persistence.sh` (same env). A zero exit from both is the MVP demo
PASS; the orchestrator then tears down (`teardown.sh`). The harness scripts themselves never call
`az`, never provision, and never run against the developer host — every seal/unseal/keyring action
happens on the Azure guest. The session is driven through `tess-pam-helper` directly (the same path
`pam_tess.so` spawns); the helper's debug build wires the scripted fprintd mock bus, while a release
`.deb` build degrades the fingerprint front gate to the PIN — either way the keyring unlocks, since
the PIN authValue is the real gate and the fingerprint is host-trusted convenience.

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
workspace. Every other crate forbids unsafe through the workspace lint
(`[workspace.lints.rust] unsafe_code = "forbid"`, inherited via `[lints] workspace = true`);
`tess-pam` opts out of that inheritance and instead sets `#![deny(unsafe_code)]`
at the crate root with `#[allow(unsafe_code)]` on the `ffi` module alone. The module declares the
small frozen surface it needs (`pam_get_item`, `pam_set_data`/`pam_get_data`, `pam_get_authtok`, and
the `pam_conv`/`pam_message`/`pam_response` structs), exports the four entrypoints
(`pam_sm_authenticate`/`pam_sm_setcred`/`pam_sm_open_session`/`pam_sm_close_session`), and wraps the
raw calls in safe functions (reading `PAM_RHOST`, obtaining the PIN via `pam_get_authtok` into a
zeroizing buffer, and a secret-free `syslog` line) so the rest of the crate stays safe Rust. The
`.so` links `libpam` (via `build.rs`), which also lets the test binaries resolve the `pam_*` symbols
without a live PAM stack.

### Session flow: fingerprint → PIN → unseal → unlock

The session phase (`pam_sm_open_session`) performs the real work, non-blocking:

1. **Abort early** if no gesture is possible — a remote session (non-empty `PAM_RHOST`) or no TPM
   device — returning `PAM_SUCCESS` without prompting (SSH logins are never prompted for a PIN).
2. **Obtain the PIN** through the PAM conversation (`pam_get_authtok`, which returns a cached
   `PAM_AUTHTOK` from a prior phase or prompts). The bytes live in a `zeroize::Zeroizing` buffer,
   are never logged, and are handed to the helper on its standard input — not via argv or the
   environment (which `ps`/`/proc` expose), and not via a disk file (which would persist the secret).
   The transfer uses an anonymous in-memory file (`memfd`), so there is no pipe whose broken read end
   could raise `SIGPIPE` and kill the login process.
3. **Run the helper** `tess-pam-helper` under the watchdog. When the fingerprint front gate is
   enabled (see below), the helper first runs **one bounded fprintd verify** and logs the verdict,
   then — *regardless of the verify result* — reads the PIN, loads the sealed object from
   `$XDG_DATA_HOME/tess/metadata.json`, opens the TPM (`tess_tpm::unseal`), and unlocks the login
   keyring (`tess_keyring::unlock`). It exits `0` on a successful unlock, non-zero on any failure; the
   PIN and the unsealed key never reach argv, the environment, disk, or the output. The helper is a
   second binary of the `tess-cli` crate so it shares the enroll/unlock composition
   (`tess_cli::session::unseal_and_unlock`) rather than duplicating it.
4. **Always return `PAM_SUCCESS`** and log the outcome (unlocked / wrong-PIN / timeout / no-gesture)
   to `LOG_AUTHPRIV` without any secret. On timeout or failure the keyring simply stays locked and
   login proceeds.

#### Fingerprint front gate (`fingerprint=yes`)

The module argument `fingerprint=yes` enables an fprintd verify ahead of the PIN unseal; **the
default is PIN-only** (the safe default — no fingerprint dependency unless explicitly opted in). When
enabled, the module resolves `PAM_USER`, hands it and a `--fingerprint` flag to the helper, and
widens the watchdog deadline (`Watchdog::FINGERPRINT_DEADLINE`, 12 s) so a real swipe has room ahead
of the unseal. Inside the helper the verify is itself bounded through
`tess_fprint::FprintClient::verify`, well inside the watchdog ceiling, and connects to the system
fprintd. Both the verify deadline (default 8 s) and the fprintd bus are fixed in release builds: a
caller's environment cannot change them, so it cannot redirect the privileged helper to an
attacker-controlled D-Bus address or push the verify into watchdog-kill territory. The only
*fingerprint-related* environment the release helper reads is `TESS_FPRINT_USER`, a trusted channel
the PAM module sets from `PAM_USER` (and clears when no user is resolved) to select whose finger
fprintd matches. (The helper still reads the non-fingerprint deployment vars it always has —
`DBUS_SESSION_BUS_ADDRESS`, `XDG_DATA_HOME`, and the `TESS_SWTPM_*` transport selector.)
Debug/test builds additionally honour `TESS_FPRINT_TIMEOUT_MS` (shorten the deadline) and
`TESS_FPRINT_BUS_ADDRESS` (point at a private `python-dbusmock` bus), mirroring how `TESS_PAM_HELPER`
is debug-gated.

**Precedence: fingerprint (convenience) → PIN (the real gate) → password fallthrough.** Every
fingerprint outcome — `match`, `no-match`, `timeout`, `unavailable`/absent — falls through to the
PIN unseal; only the PIN can release the sealed key. A no-match or stalled reader never blocks login
and never fails the session; it is logged and the PIN path runs.

**Honest limitation.** Because the key is sealed under the PIN authValue, **a fingerprint match alone
cannot unseal it — the PIN is still required.** In this MVP the fingerprint is therefore a
host-trusted *presence/convenience* signal layered on the PIN, not a PIN replacement: it does not
skip the PIN prompt. A scheme where a fingerprint *releases* a stored PIN (true Windows-Hello-style
"swipe instead of type") would need that PIN to be itself TPM/recovery-protected and is deliberately
out of scope here; it would require its own ADR. The biometric remains host-trusted convenience,
never the sole gate — a root adversary can forge a `verify-match`, which is exactly why it can never
stand in for the TPM-sealed PIN authValue.

The auth phase (`pam_sm_authenticate`) does **not** authenticate the user or unlock the keyring (that
is the session phase's job): it declines (`PAM_AUTHINFO_UNAVAIL`, or `PAM_IGNORE` when aborting) so a
`[success=done default=ignore]` stack falls through to the password factor.

#### Face release path (`face=yes`)

The module argument `face=yes` enables a **model-B** face release ahead of the PIN; **the default is
PIN-only** and it may be combined with `fingerprint=yes`. When enabled, the module hands the helper a
`--face` flag and widens the watchdog deadline (`Watchdog::FACE_DEADLINE`, 9 s; with both biometrics
the budget is the sum, the backstop for both running sequentially). Because face — unlike the
fingerprint front gate — can release the key with **no PIN typed**, the session gate runs the helper
even when no password was supplied: it hands an empty stdin so the face path can try while the PIN
fallback simply finds nothing to unseal with. Inside the helper the precedence is **face → fingerprint
(if enabled) → PIN → password fallthrough**: the helper attempts a bounded, liveness-gated
`mug::verify`; on a pass it unseals the keyring key via the independent on-disk authValue `A_face`
(mode 0600) and unlocks the keyring, then exits successfully with the PIN never read. On **any** face
outcome other than a clean unlock — not enrolled, no capture backend, no match, liveness rejection,
capture timeout, or a TPM/keyring fault — it logs a secret-free reason and falls through to the PIN.

**Honest limitation.** The face match is a userspace, host-trusted *presence/convenience* signal, not
a cryptographic binding: there is no TEE/VBS on commodity Linux, so a root adversary on a live machine
can forge a match. That is exactly why face is **never the sole gate** — the PIN authValue remains the
real TPM gate, the same key is merely sealed a second time under `A_face`, and the at-rest guarantee
(disk-only theft) is unchanged because the key is never on disk. The bounded capture plus the watchdog
mean a wedged camera degrades to the PIN within the deadline rather than freezing login.

### Watchdog'd helper + fail-open

Heavy work runs in a short-lived child process supervised by `helper::run` under a hard
`Watchdog { deadline, term_grace, poll }`. The supervisor polls `try_wait`; on deadline it sends
`SIGTERM`, waits `term_grace`, escalates to `SIGKILL`, and polls `try_wait` for another `term_grace`.
In the normal timeout path the child is killed and reaped (no zombies, no leaks) and the call returns
within `deadline + 2 * term_grace`. In the pathological case where even `SIGKILL` cannot terminate the
child promptly (uninterruptible I/O), the call still returns within that bound, but the child may
linger and its reap is deferred to a detached thread — so the PAM thread is never blocked and the
child is still reaped once the kernel can deliver the kill. Only in the extreme corner where even
that reaper thread cannot be created (resource exhaustion) is the orphan left for the OS to reap at
host-process exit; the caller is never blocked in any path. A run yields a `RunOutcome { pid, termination }` that
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
the test harness). A missing or non-enrolled helper exits non-zero (or fails to spawn), which the
gate treats as fail-open — the correct non-blocking behaviour.

### "Login never freezes" test

`crates/tess-pam/tests/stall_injection.rs` injects three helper states — slow-but-eventually-OK,
hang-forever (SIGTERM-ignoring, forcing SIGKILL escalation), and clean-failure — and asserts each
finishes within a hard bound, maps to the correct PAM code, and leaves the child neither alive nor a
zombie (`process_alive(pid)` is false after the run), including the stdin-fed (`run_with_input`) path
the session phase uses. Pure unit tests cover the timeout / fail-open / abort decision logic. The
end-to-end session path is proved in `crates/tess-cli/tests/pam_helper_session.rs` (`sim` +
`daemon-tests`): it enrolls against an isolated swtpm and a throwaway `gnome-keyring-daemon`, locks
the keyring, runs the real `tess-pam-helper` binary exactly as the module does (PIN on stdin, bounded
wait, reap), and asserts the keyring flips to unlocked with every pre-existing item intact. A CI step
additionally installs the compiled `pam_tess.so` and drives it with `pamtester` (backed by
`pam_permit`), proving the module dlopens through libpam and that a no-op session returns
`PAM_SUCCESS` — host-side execution is never run on the developer machine. The fingerprint front
gate is proved end-to-end in `crates/tess-cli/tests/fprint_gate_session.rs` (`sim` + `daemon-tests`):
it enrolls against swtpm + a throwaway keyring, then drives the real helper with `--fingerprint` and
the `python-dbusmock` fprintd mock across three scenarios — `match`, `no-match`, and `stall` — and
asserts that in every case the **PIN** unlocks the keyring (the fingerprint never substitutes for it),
that the no-match and stall cases fall back to the PIN within a hard bound, and that the helper logs
the expected verdict. Every spawned process (swtpm, dbus, keyring, fprintd mock, helper) is reaped.


## PAM wiring & installer (`tess install`)

`tess install` (`crates/tess-cli/src/install/`) wires `pam_tess.so` into the system PAM stack and
installs the module, idempotently and fail-safe. It splits cleanly into pure string logic and
filesystem side effects so the safety-critical edit is exhaustively unit-testable without touching
the host.

### Fail-open by construction

The only line tess adds is `session optional pam_tess.so`. `optional` means a tess session failure
(no TPM, a slow or declined unseal, a missing helper) is ignored and login proceeds with the keyring
left locked — it can never be the reason a login fails. The MVP wires only the session phase; there
is no auth gate yet. When an auth factor lands it must be equally fail-open
(`auth [success=done default=ignore] pam_tess.so`), and the validator enforces this: every
`pam_tess.so` line must use a fail-open control flag (`optional`, or a bracket whose `default` is
`ignore` and where every non-`success` return code falls through to `ignore` — never `ok`/`done`,
which would grant a login, nor `die`/`bad`, which would block one). A `required`/`requisite`/`sufficient`
tess line is rejected before any write.

### Idempotent, reversible edit

The tess line lives inside a re-runnable marked block (`# >>> tess >>>` … `# <<< tess <<<`).
`config::add_block` strips any existing block before appending a fresh one, so re-running install
yields an identical file with no duplication; `config::remove_block` is its exact inverse for a
newline-terminated stack, so an install→uninstall round-trip restores the original bytes. The
filesystem layer (`install`/`uninstall`) backs up the original service file once (before the first
edit, never overwriting the true original on re-run), runs `validate_stack` on the candidate **before
writing**, and commits via a temp-file-plus-rename atomic write that preserves the file's mode — a
crash mid-write can never leave a truncated PAM stack. Uninstall removes the block (validated),
deletes the installed module on a best-effort basis, and removes the backup; when module-dir
detection fails it still un-wires the stack (the lockout-relevant part) and leaves the module in
place rather than aborting. It is a no-op when nothing is installed.

### Module-directory detection

The PAM module directory is detected by locating a stock module (`pam_permit.so`) under `/lib`,
`/usr/lib`, `/lib64`, `/usr/lib64` and taking its parent — the same locate-`pam_permit.so` approach
the CI smoke test uses (CI itself only searches `/lib` and `/usr/lib`), so it works across the
multiarch layouts Debian and others use. `--service`, `--module`, and `--module-dir` override the
defaults.

### Tests

`install::config` unit tests cover the edit/validate logic (round-trip, idempotency, fail-open
acceptance/rejection, malformed-line rejection); `install` unit tests and
`crates/tess-cli/tests/install_roundtrip.rs` drive the full install→uninstall flow against a
throwaway fixture inside a `TempDir`, asserting byte-for-byte restoration, idempotency, mode
preservation, and safe no-op uninstall. No test ever reads or writes the host's real `/etc/pam.d` or
module directory.
