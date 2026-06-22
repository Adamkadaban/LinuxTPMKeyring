#!/usr/bin/env bash
#
# mvp-e2e.sh — scripted MVP acceptance harness against an ALREADY-PROVISIONED Azure vTPM VM.
#
# Invoked by the orchestrator against an existing Gen2 Trusted-Launch Debian 13 VM (one that exposes a
# real vTPM at /dev/tpmrm0). It does NOT provision or tear down anything and runs NO `az` command —
# lifecycle is the orchestrator's job (deploy/azure/provision.sh, teardown.sh). It only:
#
#   1. tars this workspace and copies it to the VM over SSH,
#   2. runs deploy/azure/mvp-e2e-remote.sh (phase `full`) on the VM, which installs deps, builds tess
#      (or installs a .deb if present), creates a throwaway login keyring, `tess enroll`s a random key
#      sealed to the real vTPM under a PIN, drives a scripted virtual-fprint + PIN session through the
#      real `tess-pam-helper`, and asserts the GNOME login keyring ends UNLOCKED with no password,
#   3. reports overall PASS/FAIL via its exit code.
#
# Pair with deploy/azure/reboot-persistence.sh (run afterwards against the same VM) to prove the
# sealed key survives a guest reboot.
#
# Required environment:
#   TESS_HW_SSH    SSH target of the running VM, e.g. "tess@20.1.2.3"
# Optional:
#   TESS_SSH_KEY   path to the SSH private key            (default: ~/.ssh/id_ed25519)
#   TESS_HW_DIR    remote working / persistent-state dir  (default: tess-e2e — a relative path under
#                  the SSH login home; `~` and absolute paths are rejected by validation)

set -euo pipefail

SSH_TARGET="${TESS_HW_SSH:-}"
SSH_KEY="${TESS_SSH_KEY:-${HOME}/.ssh/id_ed25519}"
REMOTE_DIR="${TESS_HW_DIR:-tess-e2e}"

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
REMOTE_SCRIPT="${SCRIPT_DIR}/mvp-e2e-remote.sh"

if [[ ! -f "${REMOTE_SCRIPT}" ]]; then
  echo "error: remote driver not found at '${REMOTE_SCRIPT}'." >&2
  exit 2
fi

SSH_OPTS=(
  -i "${SSH_KEY}"
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=20
  -o ServerAliveInterval=30
)

echo ">> MVP acceptance harness (Azure vTPM)"
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

echo ">> Running the MVP acceptance demo on the VM ..."
set +e
# REMOTE_DIR is intentionally expanded client-side to seed the remote shell's working directory.
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "REMOTE_DIR='${REMOTE_DIR}' bash -s -- full" < "${REMOTE_SCRIPT}"
status=$?
set -e

echo
if [[ "${status}" -eq 0 ]]; then
  echo ">> PASS — MVP acceptance demo succeeded on ${SSH_TARGET}."
else
  echo ">> FAIL — MVP acceptance demo failed on ${SSH_TARGET} (exit ${status})." >&2
fi
exit "${status}"
