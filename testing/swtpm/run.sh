#!/usr/bin/env bash
#
# Launch a software TPM (swtpm) in mssim/socket (TCP) mode for unattended dev/CI
# testing of tess-tpm. Never run against a real TPM or the developer's host TPM;
# this only starts an isolated software emulator with its own state directory.
#
# Usage:
#   testing/swtpm/run.sh start    # start swtpm, wait until the command port accepts
#   testing/swtpm/run.sh stop     # stop swtpm and reap the process
#   testing/swtpm/run.sh status   # report whether the daemon is running
#
# Ports (mssim TCTI convention): command/server on 2321, control on 2322.
#
# Environment overrides:
#   TESS_SWTPM_BIN        swtpm binary (default: swtpm)
#   TESS_SWTPM_STATE_DIR  persistent TPM state dir (default: <script dir>/state)
#   TESS_SWTPM_PORT       command/server TCP port (default: 2321)
#   TESS_SWTPM_CTRL_PORT  control TCP port        (default: 2322)
#   TESS_SWTPM_HOST       bind/connect host       (default: 127.0.0.1)
#   TESS_SWTPM_PIDFILE    pidfile path            (default: <state dir>/swtpm.pid)
#   TESS_SWTPM_START_TIMEOUT  seconds to wait for the port (default: 10)
#   TESS_SWTPM_STOP_TIMEOUT   seconds to wait for exit     (default: 5)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

SWTPM_BIN="${TESS_SWTPM_BIN:-swtpm}"
STATE_DIR="${TESS_SWTPM_STATE_DIR:-${SCRIPT_DIR}/state}"
PORT="${TESS_SWTPM_PORT:-2321}"
CTRL_PORT="${TESS_SWTPM_CTRL_PORT:-2322}"
HOST="${TESS_SWTPM_HOST:-127.0.0.1}"
PIDFILE="${TESS_SWTPM_PIDFILE:-${STATE_DIR}/swtpm.pid}"
START_TIMEOUT="${TESS_SWTPM_START_TIMEOUT:-10}"
STOP_TIMEOUT="${TESS_SWTPM_STOP_TIMEOUT:-5}"

log() { printf '[swtpm] %s\n' "$*" >&2; }

pid_is_swtpm() {
  local comm
  comm="$(cat "/proc/$1/comm" 2>/dev/null || true)"
  [[ "${comm}" == *swtpm* ]]
}

is_running() {
  [ -f "${PIDFILE}" ] || return 1
  local pid
  pid="$(cat "${PIDFILE}" 2>/dev/null || true)"
  [ -n "${pid}" ] || return 1
  kill -0 "${pid}" 2>/dev/null || return 1
  # A reused PID owned by an unrelated process must not count as "running".
  pid_is_swtpm "${pid}"
}

wait_for_port() {
  local host="$1" port="$2" deadline
  deadline=$((SECONDS + START_TIMEOUT))
  while ((SECONDS < deadline)); do
    # Bound each connect attempt (a blackholed host could otherwise block far past START_TIMEOUT).
    if timeout 1 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "${host}" "${port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

start() {
  if is_running; then
    log "already running (pid $(cat "${PIDFILE}")); command port ${HOST}:${PORT}"
    return 0
  fi

  if ! command -v "${SWTPM_BIN}" >/dev/null 2>&1; then
    log "error: '${SWTPM_BIN}' not found on PATH; install swtpm/swtpm-tools"
    return 1
  fi

  if ! command -v timeout >/dev/null 2>&1; then
    log "error: 'timeout' (coreutils) not found on PATH; required to bound the startup wait"
    return 1
  fi

  mkdir -p "${STATE_DIR}"

  log "starting on ${HOST}: command=${PORT} control=${CTRL_PORT} state=${STATE_DIR}"
  "${SWTPM_BIN}" socket \
    --tpm2 \
    --server "type=tcp,bindaddr=${HOST},port=${PORT}" \
    --ctrl "type=tcp,bindaddr=${HOST},port=${CTRL_PORT}" \
    --tpmstate "dir=${STATE_DIR}" \
    --flags startup-clear \
    --daemon \
    --pid "file=${PIDFILE}"

  if ! wait_for_port "${HOST}" "${PORT}"; then
    log "error: command port ${HOST}:${PORT} did not come up within ${START_TIMEOUT}s"
    stop || true
    return 1
  fi

  log "ready (pid $(cat "${PIDFILE}")); command port ${HOST}:${PORT}"
}

stop() {
  if [ ! -f "${PIDFILE}" ]; then
    log "not running (no pidfile)"
    return 0
  fi

  local pid
  pid="$(cat "${PIDFILE}" 2>/dev/null || true)"
  if [ -z "${pid}" ] || ! kill -0 "${pid}" 2>/dev/null; then
    log "stale pidfile; removing"
    rm -f "${PIDFILE}"
    return 0
  fi

  # Guard against a stale pidfile whose PID has been reused by an unrelated process.
  local comm
  comm="$(cat "/proc/${pid}/comm" 2>/dev/null || true)"
  if ! pid_is_swtpm "${pid}"; then
    log "pid ${pid} is '${comm}', not swtpm (reused PID); removing pidfile without killing"
    rm -f "${PIDFILE}"
    return 0
  fi

  log "stopping pid ${pid}"
  kill "${pid}" 2>/dev/null || true

  local deadline=$((SECONDS + STOP_TIMEOUT))
  while ((SECONDS < deadline)); do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.1
  done

  if kill -0 "${pid}" 2>/dev/null; then
    log "did not exit in ${STOP_TIMEOUT}s; sending SIGKILL"
    kill -9 "${pid}" 2>/dev/null || true
  fi

  rm -f "${PIDFILE}"
  log "stopped"
}

status() {
  if is_running; then
    log "running (pid $(cat "${PIDFILE}")); command port ${HOST}:${PORT}"
    return 0
  fi
  log "not running"
  return 1
}

main() {
  local cmd="${1:-}"
  case "${cmd}" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    *)
      printf 'usage: %s {start|stop|status}\n' "${0##*/}" >&2
      return 2
      ;;
  esac
}

main "$@"
