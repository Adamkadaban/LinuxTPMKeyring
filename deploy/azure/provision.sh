#!/usr/bin/env bash
#
# provision.sh — bring up a Gen2 Trusted-Launch Debian 13 VM with a real vTPM 2.0.
#
# WARNING: this provisions a billable Azure VM (bills by the second). Deallocate when idle
# (deploy/azure/deallocate.sh) and delete at wind-down (deploy/azure/teardown.sh). The developer's
# host TPM/keyring is never used — only this Azure VM and CI. The vTPM here is the only "real"
# TPM 2.0 acceptance gate; swtpm covers CI.
#
# Configurable via environment variables (sane defaults shown):
#   TESS_RG          resource group name      (default: tess-vtpm-rg)
#   TESS_LOCATION    Azure region             (default: eastus)
#   TESS_VM_NAME     VM name                  (default: tess-vtpm)
#   TESS_VM_SIZE     VM size                  (default: Standard_B4ms)
#   TESS_ADMIN_USER  admin username           (default: tess)
#   TESS_SSH_PUBKEY  path to SSH PUBLIC key   (default: ~/.ssh/id_ed25519.pub)
#   TESS_SSH_SOURCE  CIDR/IP allowed to SSH   (default: auto-detect caller IP, as /32 for IPv4
#                    or /128 for IPv6; set explicitly to override, e.g. "203.0.113.4/32" or "*")
#
# Image: Debian 13 (Trixie) Gen2 marketplace image "Debian:debian-13:13-gen2:latest".
# Gen2 is mandatory for Trusted Launch / vTPM. Override the image* params in main.bicep
# if Debian renames the SKU.

set -euo pipefail

RG="${TESS_RG:-tess-vtpm-rg}"
LOCATION="${TESS_LOCATION:-eastus}"
VM_NAME="${TESS_VM_NAME:-tess-vtpm}"
VM_SIZE="${TESS_VM_SIZE:-Standard_B4ms}"
ADMIN_USER="${TESS_ADMIN_USER:-tess}"
SSH_PUBKEY="${TESS_SSH_PUBKEY:-${HOME}/.ssh/id_ed25519.pub}"
PROJECT_TAG="LinuxTPMKeyring"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BICEP_FILE="${SCRIPT_DIR}/main.bicep"

if ! command -v az >/dev/null 2>&1; then
  echo "error: the Azure CLI ('az') is not installed or not on PATH." >&2
  exit 1
fi

if [[ ! -f "${SSH_PUBKEY}" ]]; then
  echo "error: SSH public key not found at '${SSH_PUBKEY}'." >&2
  echo "       Set TESS_SSH_PUBKEY to your public key, or generate one with:" >&2
  echo "         ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519" >&2
  exit 1
fi

# A .pub file holds a single key on one line. Take only the first line so a stray
# trailing newline or extra content can't leak into the Bicep parameter.
SSH_PUBKEY_DATA="$(head -n1 "${SSH_PUBKEY}")"

case "${SSH_PUBKEY_DATA}" in
  ssh-* | ecdsa-* | sk-*) ;;
  *)
    echo "error: '${SSH_PUBKEY}' does not look like an SSH public key." >&2
    echo "       Point TESS_SSH_PUBKEY at the .pub file, never a private key." >&2
    exit 1
    ;;
esac

# Narrow the SSH firewall rule to the caller's public IP unless overridden. Falls
# back to "*" (any source) with a loud warning if auto-detection fails.
if [[ -n "${TESS_SSH_SOURCE:-}" ]]; then
  SSH_SOURCE="${TESS_SSH_SOURCE}"
elif CALLER_IP="$(curl -fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null)" && [[ -n "${CALLER_IP}" ]]; then
  # ipify may return IPv6; use the matching host mask (/128) so the NSG CIDR is valid.
  if [[ "${CALLER_IP}" == *:* ]]; then
    SSH_SOURCE="${CALLER_IP}/128"
  else
    SSH_SOURCE="${CALLER_IP}/32"
  fi
else
  SSH_SOURCE="*"
  echo "!! WARNING: could not auto-detect your public IP; SSH will be open to ANY source ('*')." >&2
  echo "!!          Set TESS_SSH_SOURCE=<ip>/<mask> to restrict it." >&2
fi

echo ">> Provisioning Gen2 Trusted-Launch Debian 13 VM (vTPM enabled)"
echo "   resource group : ${RG}"
echo "   location       : ${LOCATION}"
echo "   vm name        : ${VM_NAME}"
echo "   vm size        : ${VM_SIZE}"
echo "   admin user     : ${ADMIN_USER}"
echo "   ssh public key : ${SSH_PUBKEY}"
echo "   ssh source     : ${SSH_SOURCE}"
echo "   tag            : project=${PROJECT_TAG}"
echo

echo ">> Creating resource group (idempotent) ..."
az group create \
  --name "${RG}" \
  --location "${LOCATION}" \
  --tags "project=${PROJECT_TAG}" \
  --output none

echo ">> Deploying VM via Bicep (Trusted Launch + vTPM + secure boot, key-only SSH) ..."
az deployment group create \
  --resource-group "${RG}" \
  --template-file "${BICEP_FILE}" \
  --parameters \
    location="${LOCATION}" \
    vmName="${VM_NAME}" \
    vmSize="${VM_SIZE}" \
    adminUsername="${ADMIN_USER}" \
    sshPublicKey="${SSH_PUBKEY_DATA}" \
    allowedSshSource="${SSH_SOURCE}" \
    projectTag="${PROJECT_TAG}" \
  --output none

PUBLIC_IP="$(az vm show \
  --resource-group "${RG}" \
  --name "${VM_NAME}" \
  --show-details \
  --query publicIps \
  --output tsv)"

echo
echo ">> VM is up. The vTPM should expose /dev/tpmrm0 inside the guest."
echo "   Connect with:"
echo
echo "     ssh ${ADMIN_USER}@${PUBLIC_IP}"
echo
echo "   Then self-check readiness:"
echo
echo "     ssh ${ADMIN_USER}@${PUBLIC_IP} tess doctor"
echo
echo ">> Remember: deallocate when idle (deploy/azure/deallocate.sh),"
echo "   delete at wind-down (deploy/azure/teardown.sh)."
