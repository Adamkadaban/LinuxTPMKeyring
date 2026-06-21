#!/usr/bin/env bash
#
# teardown.sh — delete the tess Azure dev VM and everything in its resource group.
#
# Deletes the WHOLE resource group (which holds only project=LinuxTPMKeyring resources
# created by provision.sh). It first LISTS what will be deleted, then requires explicit
# confirmation before doing anything irreversible.
#
# Confirm in one of two ways:
#   • interactively: re-run is not needed; type the resource group name when prompted, or
#   • non-interactively: pass --yes  OR  set TESS_CONFIRM=yes
#
# Configurable via environment variables:
#   TESS_RG   resource group to delete   (default: tess-vtpm-rg)

set -euo pipefail

RG="${TESS_RG:-tess-vtpm-rg}"
PROJECT_TAG="LinuxTPMKeyring"
CONFIRM="${TESS_CONFIRM:-}"

for arg in "$@"; do
  case "${arg}" in
    --yes | -y) CONFIRM="yes" ;;
    *)
      echo "error: unknown argument '${arg}' (expected --yes/-y or none)." >&2
      exit 2
      ;;
  esac
done

if ! command -v az >/dev/null 2>&1; then
  echo "error: the Azure CLI ('az') is not installed or not on PATH." >&2
  exit 1
fi

RG_EXISTS="$(az group exists --name "${RG}" --output tsv 2>/dev/null || true)"
if [[ -z "${RG_EXISTS}" ]]; then
  echo "error: could not query resource group '${RG}' — is 'az' logged in and the subscription set?" >&2
  exit 1
fi
if [[ "${RG_EXISTS}" != "true" ]]; then
  echo ">> Resource group '${RG}' does not exist — nothing to tear down."
  exit 0
fi

# Safety guard: refuse to delete a resource group that isn't ours. If TESS_RG is
# mispointed at an unrelated group, the project=LinuxTPMKeyring tag check stops us
# from nuking it.
GROUP_TAG="$(az group show --name "${RG}" --query "tags.project" --output tsv 2>/dev/null || true)"
if [[ "${GROUP_TAG}" != "${PROJECT_TAG}" ]]; then
  echo "error: resource group '${RG}' is not tagged project=${PROJECT_TAG}" >&2
  echo "       (found: '${GROUP_TAG:-<none>}'). Refusing to delete a group tess did not create." >&2
  echo "       If this is intentional, retag the group or point TESS_RG at the right group." >&2
  exit 1
fi

echo ">> The following resources in group '${RG}' (tag project=${PROJECT_TAG}) will be DELETED:"
echo
az resource list \
  --resource-group "${RG}" \
  --query "[].{name:name, type:type, location:location}" \
  --output table
echo

if [[ "${CONFIRM}" != "yes" ]]; then
  printf 'Type the resource group name "%s" to confirm deletion: ' "${RG}"
  read -r REPLY
  if [[ "${REPLY}" != "${RG}" ]]; then
    echo ">> Confirmation did not match. Aborting; nothing was deleted."
    exit 1
  fi
fi

echo ">> Deleting resource group '${RG}' ..."
az group delete --name "${RG}" --yes --no-wait

echo ">> Delete requested (running asynchronously). Verify with:"
echo
echo "     az group exists --name ${RG}"
echo "     az resource list --tag project=${PROJECT_TAG} --output table"
echo
echo ">> A follow-up list should show nothing remaining once deletion completes."
