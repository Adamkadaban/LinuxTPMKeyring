# Architecture

> Stub — fleshed out as crates land. Authoritative roadmap is in [`PLAN.md`](../PLAN.md).

## Crates

| Crate | Type | Responsibility |
|---|---|---|
| `tess-core` | lib | Shared types, versioned `Metadata` schema, config, errors, secret hygiene (`zeroize`/`secrecy`/`mlock`), the `KeyringBackend` / `AuthGate` / `SecretStash` traits |
| `tess-tpm` | lib | TPM2 seal/unseal of a random key under a PIN `PolicyAuthValue`, with mandatory HMAC + parameter-encryption sessions; ECC primary; DA-lockout aware |
| `tess-keyring` | lib | `KeyringBackend` over the freedesktop Secret Service API; rekey (enroll) + unlock (runtime) |
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

`testing/swtpm/run.sh {start|stop|status}` launches `swtpm` in mssim/socket (TCP) mode with a
persistent `--tpmstate` directory and a pidfile. By convention the mssim command/server port is
`2321` and the control port is `2322`; both, the host, the state dir, and the pidfile are
overridable via `TESS_SWTPM_*` env vars. `start` blocks until the command port accepts a connection
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

Two crate features gate the transports that need a TPM:

```sh
cargo test -p tess-tpm --features sim   # starts swtpm, opens an ESAPI context, creates the ECC
                                        # primary, starts the salted session, tears swtpm down
```

`sim` exercises swtpm; `hw` targets `/dev/tpmrm0` and is validated only on the Azure vTPM, never on
the dev host. Both are off by default, so plain `cargo test --workspace` stays green and
hardware-free; with `sim` enabled the integration test skips cleanly if `swtpm` is not on `PATH`.

### Local QEMU vTPM VM (optional, contributors only)

`deploy/qemu/up.sh` / `down.sh` bring up a throwaway Debian 13 KVM guest with an swtpm vTPM and
key-only SSH for manual end-to-end exercise. **The agent and CI never run these on the developer's
host** — they exist purely as a contributor convenience and only ever talk to an emulated TPM.

## Deploy targets

| Path | Purpose |
|---|---|
| `deploy/azure/main.bicep` | Declarative Gen2 Trusted-Launch Debian 13 VM: `securityType=TrustedLaunch`, vTPM + secure boot on, key-only SSH, every resource tagged `project=LinuxTPMKeyring`. |
| `deploy/azure/provision.sh` | One-command bring-up: creates the resource group and deploys `main.bicep` via `az deployment group create`; prints the `ssh` command. Region/size/name/key are env-overridable. |
| `deploy/azure/deallocate.sh` | Stops (deallocates) the VM to halt compute billing without deleting it. |
| `deploy/azure/teardown.sh` | Lists the tagged resources, then (after explicit confirmation) deletes the whole resource group. |

The Azure vTPM is the only real TPM 2.0 acceptance gate; its PCR values differ from bare metal, so
the MVP TPM policy binds the PIN authValue only (no PCR binding). Cost discipline — deallocate when
idle, delete at wind-down, kill-by date — is tracked in [`NOTES.md`](../NOTES.md) and the teardown
plan in [`PLAN.md`](../PLAN.md) §8.

## `tess doctor`

`tess doctor` (`crates/tess-cli/src/doctor.rs`) performs read-only readiness probes — `/dev/tpmrm0`
and `/dev/tpm0` presence, a Secret Service daemon binary on `PATH` (the daemon is *not* contacted),
and `fprintd` on `PATH` — and prints an OK/MISSING table with a one-line verdict. It never opens a
D-Bus session, touches a secret, or unlocks anything; per project policy it runs in CI or on a fresh
Azure VM for self-check, not the developer host. Only the TPM resource manager is required for the verdict.
