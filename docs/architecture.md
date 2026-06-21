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
the script's env contract. The Phase 0 connect smoke test lives behind the crate's `sim` feature:

```sh
cargo test -p tess-tpm --features sim   # starts swtpm, asserts the mssim port accepts, tears down
```

It is off by default, so plain `cargo test --workspace` stays green and hardware-free; with `sim`
enabled it skips cleanly if `swtpm` is not on `PATH`. A real TPM-property read replaces the
reachability check in Phase 1 once `tss-esapi` is wired in.

### Local QEMU vTPM VM (optional, contributors only)

`deploy/qemu/up.sh` / `down.sh` bring up a throwaway Debian 13 KVM guest with an swtpm vTPM and
key-only SSH for manual end-to-end exercise. **The agent and CI never run these on the developer's
host** — they exist purely as a contributor convenience and only ever talk to an emulated TPM.
