#!/usr/bin/env bash
#
# Tear down the local Debian 13 KVM guest and its swtpm vTPM started by up.sh.
#
# FOR EXTERNAL CONTRIBUTORS ONLY. The project's agent and CI never run this on
# the developer's host. Reaps both the qemu and swtpm processes; no leaks.
#
# Usage:
#   deploy/qemu/down.sh
#
# Environment overrides:
#   QEMU_RUNDIR        work/state dir (default: <script dir>/.run)
#   QEMU_STOP_TIMEOUT  seconds to wait for graceful exit (default: 5)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

RUNDIR="${QEMU_RUNDIR:-${SCRIPT_DIR}/.run}"
STOP_TIMEOUT="${QEMU_STOP_TIMEOUT:-5}"
QEMU_PIDFILE="${RUNDIR}/qemu.pid"
SWTPM_PIDFILE="${RUNDIR}/swtpm.pid"

log() { printf '[qemu-down] %s\n' "$*" >&2; }

reap() {
  local label="$1" pidfile="$2"
  if [ ! -f "${pidfile}" ]; then
    log "${label}: not running (no pidfile)"
    return 0
  fi

  local pid
  pid="$(cat "${pidfile}" 2>/dev/null || true)"
  if [ -z "${pid}" ] || ! kill -0 "${pid}" 2>/dev/null; then
    log "${label}: stale pidfile; removing"
    rm -f "${pidfile}"
    return 0
  fi

  log "${label}: stopping pid ${pid}"
  kill "${pid}" 2>/dev/null || true

  local deadline=$((SECONDS + STOP_TIMEOUT))
  while ((SECONDS < deadline)); do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.1
  done

  if kill -0 "${pid}" 2>/dev/null; then
    log "${label}: did not exit in ${STOP_TIMEOUT}s; sending SIGKILL"
    kill -9 "${pid}" 2>/dev/null || true
  fi

  rm -f "${pidfile}"
  log "${label}: stopped"
}

reap qemu "${QEMU_PIDFILE}"
reap swtpm "${SWTPM_PIDFILE}"
