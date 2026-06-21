#!/usr/bin/env bash
#
# deallocate.sh — stop (deallocate) the tess dev VM to halt compute billing, WITHOUT
# deleting it. Use this whenever the VM is idle; the disk persists (small storage cost),
# so you can start it again later. To delete everything, use teardown.sh instead.
#
# Configurable via environment variables:
#   TESS_RG       resource group   (default: tess-vtpm-rg)
#   TESS_VM_NAME  VM name           (default: tess-vtpm)

set -euo pipefail

RG="${TESS_RG:-tess-vtpm-rg}"
VM_NAME="${TESS_VM_NAME:-tess-vtpm}"

if ! command -v az >/dev/null 2>&1; then
  echo "error: the Azure CLI ('az') is not installed or not on PATH." >&2
  exit 1
fi

echo ">> Deallocating VM '${VM_NAME}' in resource group '${RG}' (stops compute billing) ..."
az vm deallocate \
  --resource-group "${RG}" \
  --name "${VM_NAME}" \
  --output none

echo ">> VM '${VM_NAME}' is deallocated. Compute billing has stopped (disk still incurs storage cost)."
echo "   Start it again with:  az vm start --resource-group ${RG} --name ${VM_NAME}"
echo "   Delete it entirely with:  deploy/azure/teardown.sh"
