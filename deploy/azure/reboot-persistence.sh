#!/usr/bin/env bash
#
# reboot-persistence.sh — prove the TPM-sealed key survives a guest reboot.
#
# Run AFTER deploy/azure/mvp-e2e.sh against the SAME already-provisioned Azure vTPM VM: that run left
# an enrolled, persistent login keyring (rekeyed to the sealed key) under the remote state dir. This
# script reboots the guest, waits for it to come back, then re-runs only the session unlock
# (deploy/azure/mvp-e2e-remote.sh phase `reboot`): a fresh keyring daemon loads the persisted login
# keyring LOCKED, the helper unseals the key from the rebooted vTPM, and the keyring re-unlocks with
# no password. Because the MVP policy binds the PIN authValue only (no PCR), the unseal is not
# reboot-brittle.
#
# It runs NO `az` command and provisions / tears down nothing — the orchestrator owns the VM
# lifecycle. It does NOT re-upload the workspace: it relies on the build + state mvp-e2e.sh left.
#
# Required environment:
#   TESS_HW_SSH    SSH target of the running VM, e.g. "tess@20.1.2.3"
# Optional:
#   TESS_SSH_KEY   path to the SSH private key            (default: ~/.ssh/id_ed25519)
#   TESS_HW_DIR    remote working / persistent-state dir  (default: ~/tess-e2e; must match mvp-e2e.sh)

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
REMOTE_SCRIPT="${SCRIPT_DIR}/mvp-e2e-remote.sh"

if [[ ! -f "${REMOTE_SCRIPT}" ]]; then
  echo "error: remote driver not found at '${REMOTE_SCRIPT}'." >&2
  exit 2
fi

SSH_OPTS=(
  -i "${SSH_KEY}"
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=10
  -o ServerAliveInterval=30
)

# Bounded reconnect budget: ~5 minutes for the guest to reboot and accept SSH again.
RECONNECT_ATTEMPTS=60
RECONNECT_INTERVAL=5

echo ">> Reboot-persistence check (Azure vTPM)"
echo "   target     : ${SSH_TARGET}"
echo "   remote dir : ${REMOTE_DIR}"
echo

echo ">> Capturing pre-reboot boot id ..."
BOOT_BEFORE="$(ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
[[ -n "${BOOT_BEFORE}" ]] || { echo "error: could not reach the VM before reboot." >&2; exit 2; }
echo "   boot id    : ${BOOT_BEFORE}"

echo ">> Rebooting the guest ..."
# `sudo reboot` tears the connection down, so SSH returns non-zero; that is expected, not a failure.
set +e
ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" 'sudo systemctl reboot' >/dev/null 2>&1
set -e
sleep 15

echo ">> Waiting for the guest to come back (bounded) ..."
ready=0
for _ in $(seq 1 "${RECONNECT_ATTEMPTS}"); do
  BOOT_NOW="$(ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)"
  if [[ -n "${BOOT_NOW}" && "${BOOT_NOW}" != "${BOOT_BEFORE}" ]]; then
    ready=1
    echo "   back up; new boot id: ${BOOT_NOW}"
    break
  fi
  sleep "${RECONNECT_INTERVAL}"
done
if [[ "${ready}" -ne 1 ]]; then
  echo ">> FAIL — guest did not reboot and reconnect within the budget." >&2
  exit 1
fi

echo ">> Re-running the session unlock after reboot ..."
set +e
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "REMOTE_DIR='${REMOTE_DIR}' bash -s -- reboot" < "${REMOTE_SCRIPT}"
status=$?
set -e

echo
if [[ "${status}" -eq 0 ]]; then
  echo ">> PASS — sealed key survived reboot and re-unlocked the keyring on ${SSH_TARGET}."
else
  echo ">> FAIL — reboot-persistence check failed on ${SSH_TARGET} (exit ${status})." >&2
fi
exit "${status}"
