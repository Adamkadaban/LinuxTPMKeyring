#!/usr/bin/env bash
#
# Bring up a local Debian 13 KVM guest with an emulated TPM 2.0 (swtpm vTPM) and
# key-only SSH, for manually exercising tess against a software TPM end-to-end.
#
# FOR EXTERNAL CONTRIBUTORS ONLY. The project's agent and CI never run this on
# the developer's host — automated tests use GitHub-hosted runners (swtpm) and
# real-TPM acceptance runs on an Azure Gen2 Trusted-Launch vTPM. This script is
# a convenience for contributors who want a throwaway vTPM VM on their own box.
# It only ever talks to an emulated TPM; it never touches the host's real TPM.
#
# Usage:
#   deploy/qemu/up.sh            # download image (first run), start swtpm + qemu
#   deploy/qemu/down.sh          # stop qemu + swtpm, reap processes
#   ssh -p 2222 debian@127.0.0.1 # log in once the guest has booted
#
# Requirements: qemu-system-x86_64, swtpm, cloud-localds (cloud-image-utils),
# wget, an SSH public key. KVM acceleration is used when /dev/kvm is available.
#
# Environment overrides:
#   QEMU_RUNDIR     work/state dir (default: <script dir>/.run)
#   QEMU_SSH_PORT   host port forwarded to guest 22 (default: 2222)
#   QEMU_SSH_PUBKEY public key to install (default: ~/.ssh/id_ed25519.pub)
#   QEMU_MEM        guest memory (default: 2048)
#   QEMU_CPUS       guest vCPUs (default: 2)
#   QEMU_IMAGE_URL  Debian 13 generic cloud image URL

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

RUNDIR="${QEMU_RUNDIR:-${SCRIPT_DIR}/.run}"
SSH_PORT="${QEMU_SSH_PORT:-2222}"
SSH_PUBKEY="${QEMU_SSH_PUBKEY:-${HOME}/.ssh/id_ed25519.pub}"
MEM="${QEMU_MEM:-2048}"
CPUS="${QEMU_CPUS:-2}"
IMAGE_URL="${QEMU_IMAGE_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2}"

BASE_IMG="${RUNDIR}/debian-13-generic-amd64.qcow2"
OVERLAY_IMG="${RUNDIR}/guest.qcow2"
SEED_IMG="${RUNDIR}/seed.img"
SWTPM_DIR="${RUNDIR}/swtpm"
SWTPM_SOCK="${SWTPM_DIR}/swtpm-sock"
SWTPM_PIDFILE="${RUNDIR}/swtpm.pid"
QEMU_PIDFILE="${RUNDIR}/qemu.pid"

log() { printf '[qemu-up] %s\n' "$*" >&2; }
die() {
  printf '[qemu-up] error: %s\n' "$*" >&2
  exit 1
}

require() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found on PATH"; }

require qemu-system-x86_64
require qemu-img
require swtpm
require wget
require cloud-localds
require sha512sum

[ -f "${SSH_PUBKEY}" ] || die "SSH public key not found at ${SSH_PUBKEY} (set QEMU_SSH_PUBKEY)"

mkdir -p "${RUNDIR}" "${SWTPM_DIR}"

if [ ! -f "${BASE_IMG}" ]; then
  log "downloading Debian 13 cloud image"
  wget -O "${BASE_IMG}.tmp" "${IMAGE_URL}"
  # Verify against Debian's published SHA512SUMS (same directory as the image). For stronger
  # assurance, also verify SHA512SUMS.sign with the Debian cloud signing key (out of scope here).
  log "verifying image checksum against published SHA512SUMS"
  sums_url="${IMAGE_URL%/*}/SHA512SUMS"
  img_name="${IMAGE_URL##*/}"
  expected="$(wget -qO- "${sums_url}" | awk -v f="${img_name}" '$2 == f {print $1}')"
  [ -n "${expected}" ] || die "could not find ${img_name} in ${sums_url}"
  actual="$(sha512sum "${BASE_IMG}.tmp" | awk '{print $1}')"
  [ "${expected}" = "${actual}" ] || die "checksum mismatch for ${img_name} (expected ${expected}, got ${actual})"
  mv "${BASE_IMG}.tmp" "${BASE_IMG}"
fi

if [ ! -f "${OVERLAY_IMG}" ]; then
  log "creating qcow2 overlay"
  qemu-img create -f qcow2 -F qcow2 -b "${BASE_IMG}" "${OVERLAY_IMG}" 20G >/dev/null
fi

log "building cloud-init seed (key-only SSH; password auth disabled)"
PUBKEY_CONTENT="$(cat "${SSH_PUBKEY}")"
USER_DATA="${RUNDIR}/user-data.yaml"
cat >"${USER_DATA}" <<EOF
#cloud-config
ssh_pwauth: false
disable_root: true
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - "${PUBKEY_CONTENT}"
packages:
  - tpm2-tools
EOF
cloud-localds "${SEED_IMG}" "${USER_DATA}"

started_swtpm=0
# If anything below fails after we start swtpm (e.g. qemu can't launch), stop the swtpm we
# started so it isn't orphaned. Only fires on a non-zero exit, so a successful daemonized qemu
# keeps its vTPM.
cleanup_on_error() {
  local rc=$?
  if [ "${rc}" -ne 0 ] && [ "${started_swtpm}" -eq 1 ] && [ -f "${SWTPM_PIDFILE}" ]; then
    log "error (exit ${rc}); stopping swtpm started by this run"
    kill "$(cat "${SWTPM_PIDFILE}")" 2>/dev/null || true
    rm -f "${SWTPM_PIDFILE}"
  fi
}
trap cleanup_on_error EXIT

if [ -f "${SWTPM_PIDFILE}" ] && kill -0 "$(cat "${SWTPM_PIDFILE}")" 2>/dev/null; then
  log "swtpm already running"
else
  log "starting swtpm vTPM"
  swtpm socket \
    --tpm2 \
    --tpmstate "dir=${SWTPM_DIR}" \
    --ctrl "type=unixio,path=${SWTPM_SOCK}" \
    --flags startup-clear \
    --daemon \
    --pid "file=${SWTPM_PIDFILE}"
  started_swtpm=1
fi

ACCEL=()
if [ -w /dev/kvm ]; then
  ACCEL=(-enable-kvm -cpu host)
else
  log "warning: /dev/kvm not available — falling back to TCG (slow)"
  ACCEL=(-cpu max)
fi

log "starting qemu (SSH on 127.0.0.1:${SSH_PORT})"
qemu-system-x86_64 \
  "${ACCEL[@]}" \
  -machine q35 \
  -m "${MEM}" \
  -smp "${CPUS}" \
  -drive "file=${OVERLAY_IMG},if=virtio,format=qcow2" \
  -drive "file=${SEED_IMG},if=virtio,format=raw" \
  -chardev "socket,id=chrtpm,path=${SWTPM_SOCK}" \
  -tpmdev "emulator,id=tpm0,chardev=chrtpm" \
  -device tpm-tis,tpmdev=tpm0 \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
  -device virtio-net-pci,netdev=net0 \
  -nographic \
  -pidfile "${QEMU_PIDFILE}" \
  -daemonize

log "guest booting. SSH in with:  ssh -p ${SSH_PORT} debian@127.0.0.1"
log "tear down with:  ${SCRIPT_DIR}/down.sh"
