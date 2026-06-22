#!/usr/bin/env bash
#
# hw-exit-test.sh — Phase 1 real-TPM exit test against an ALREADY-PROVISIONED Azure vTPM VM.
#
# This script is invoked by the orchestrator against an existing Gen2 Trusted-Launch VM (one that
# exposes a real vTPM at /dev/tpmrm0). It does NOT provision or tear down anything and runs NO `az`
# command — lifecycle is the orchestrator's job (deploy/azure/provision.sh, teardown.sh). It only:
#
#   1. tars this workspace and copies it to the VM over SSH,
#   2. installs the Rust toolchain + tpm2-tss build deps on the VM if missing,
#   3. builds and runs `cargo test -p tess-tpm --features hw` against /dev/tpmrm0,
#   4. runs `tess doctor` for a read-only readiness/lockout report,
#   5. reports overall pass/fail via its exit code.
#
# Required environment:
#   TESS_HW_SSH    SSH target of the running VM, e.g. "tess@20.1.2.3"
# Optional:
#   TESS_SSH_KEY   path to the SSH private key            (default: ~/.ssh/id_ed25519)
#   TESS_HW_DIR    remote working directory               (default: ~/tess-hw)

set -euo pipefail

SSH_TARGET="${TESS_HW_SSH:-}"
SSH_KEY="${TESS_SSH_KEY:-${HOME}/.ssh/id_ed25519}"
REMOTE_DIR="${TESS_HW_DIR:-tess-hw}"

if [[ -z "${SSH_TARGET}" ]]; then
  echo "error: set TESS_HW_SSH to the VM's SSH target (e.g. tess@20.1.2.3)." >&2
  exit 2
fi
if [[ ! -f "${SSH_KEY}" ]]; then
  echo "error: SSH private key not found at '${SSH_KEY}'. Set TESS_SSH_KEY." >&2
  exit 2
fi
# REMOTE_DIR is interpolated into remote shell command strings — including `rm -rf -- '${REMOTE_DIR}'`
# — so constrain it tightly: a safe charset (no quotes/whitespace/metacharacters), a *relative* path
# (no leading `/`), and no `.`/`..` path segments, so a mis-set TESS_HW_DIR can't delete the caller's
# current directory or an unintended directory on the VM, nor break the remote quoting.
if [[ ! "${REMOTE_DIR}" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  echo "error: TESS_HW_DIR must match ^[A-Za-z0-9._/-]+\$ (got: '${REMOTE_DIR}')." >&2
  exit 2
fi
if [[ "${REMOTE_DIR}" == /* ]]; then
  echo "error: TESS_HW_DIR must be a relative path, not absolute (got: '${REMOTE_DIR}')." >&2
  exit 2
fi
case "/${REMOTE_DIR}/" in
  */./* | */../*)
    echo "error: TESS_HW_DIR must not contain '.' or '..' path segments (got: '${REMOTE_DIR}')." >&2
    exit 2
    ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

SSH_OPTS=(
  -i "${SSH_KEY}"
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=20
  -o ServerAliveInterval=30
)

echo ">> Phase 1 hardware exit test"
echo "   target     : ${SSH_TARGET}"
echo "   key        : ${SSH_KEY}"
echo "   repo root  : ${REPO_ROOT}"
echo "   remote dir : ${REMOTE_DIR}"
echo

echo ">> Uploading workspace (excluding target/, .git/, references/) ..."
# REMOTE_DIR is intentionally expanded client-side so the local caller controls the remote path.
# shellcheck disable=SC2029
tar czf - \
  --exclude=./target \
  --exclude=./.git \
  --exclude=./references \
  -C "${REPO_ROOT}" . \
  | ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" \
      "rm -rf -- '${REMOTE_DIR}' && mkdir -p -- '${REMOTE_DIR}' && tar xzf - -C '${REMOTE_DIR}'"

echo ">> Building and running the hw suite on the VM ..."
# The remote script is self-contained: install prerequisites, build, run the hw test against
# /dev/tpmrm0, then run `tess doctor`. TPM access needs read+write on the device node; use sudo only
# when the login user lacks it (Azure admin users have passwordless sudo).
set +e
# REMOTE_DIR is intentionally expanded client-side to seed the remote shell's working directory.
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "REMOTE_DIR='${REMOTE_DIR}' bash -s" <<'REMOTE'
set -euo pipefail

cd -- "${REMOTE_DIR}"

if [[ ! -e /dev/tpmrm0 ]]; then
  echo "error: /dev/tpmrm0 is not present on the VM — this is not a vTPM-enabled guest." >&2
  exit 1
fi

echo ">> Installing build prerequisites (idempotent) ..."
if ! command -v cc >/dev/null 2>&1 || ! dpkg -s libtss2-dev >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential pkg-config libtss2-dev curl ca-certificates
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo ">> Installing the Rust toolchain via rustup ..."
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
# rustup writes this env file; source it only if present — a cargo installed another way (apt, a
# pre-baked image) won't have it, and sourcing a missing file under `set -e` would abort.
if [[ -f "${HOME}/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "${HOME}/.cargo/env"
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is not on PATH after toolchain setup." >&2
  exit 1
fi

# Wrap a command with sudo only when the login user can't read+write the TPM device directly,
# preserving the toolchain PATH and build cache (HOME) so root reuses the user's target/ + registry.
# sudo resolves the command via secure_path (not the inherited PATH), so a rustup-installed cargo in
# ~/.cargo/bin is invisible to `sudo cargo`. Resolve the binary to an absolute path first and run it
# under `env` with the caller's PATH so sub-tools (rustc, the linker) are also found.
tpm_run() {
  if [[ -r /dev/tpmrm0 && -w /dev/tpmrm0 ]]; then
    "$@"
  else
    local bin
    bin="$(type -P "$1")" || {
      echo "error: '$1' is not an external command on PATH." >&2
      return 1
    }
    shift
    sudo --preserve-env=HOME,CARGO_HOME,RUSTUP_HOME env "PATH=${PATH}" "${bin}" "$@"
  fi
}

echo ">> cargo test -p tess-tpm --features hw"
tpm_run cargo test -p tess-tpm --features hw -- --nocapture

echo ">> tess doctor"
tpm_run cargo run -q -p tess-cli -- doctor

echo ">> Remote hw suite completed."
REMOTE
status=$?
set -e

echo
if [[ "${status}" -eq 0 ]]; then
  echo ">> PASS — hw exit test succeeded on ${SSH_TARGET}."
else
  echo ">> FAIL — hw exit test failed on ${SSH_TARGET} (exit ${status})." >&2
fi
exit "${status}"
