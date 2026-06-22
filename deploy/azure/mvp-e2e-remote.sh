#!/usr/bin/env bash
#
# mvp-e2e-remote.sh — the VM-side body of the scripted MVP acceptance demo.
#
# This runs INSIDE an already-provisioned Gen2 Trusted-Launch Debian 13 guest (real vTPM at
# /dev/tpmrm0). It is never executed on the developer host: the drivers (mvp-e2e.sh,
# reboot-persistence.sh) pipe it over SSH with `bash -s`. It runs NO `az` command and provisions or
# tears down nothing — the orchestrator owns the VM lifecycle.
#
# Two phases (argv[1]):
#
#   full    install deps + build tess (or use an installed .deb), create a throwaway login keyring,
#           seed a probe item, `tess enroll` (sealing a random key to the real vTPM under a PIN),
#           save the recovery secret, drive a scripted virtual-fprint + PIN session through the real
#           `tess-pam-helper`, and assert the keyring ends UNLOCKED with no password typed.
#
#   reboot  (run after a guest reboot, against the persistent state `full` left behind) start a fresh
#           keyring daemon over the *persisted* login keyring (locked), unseal the key from the
#           rebooted vTPM via the helper, and assert it unlocks — proving the sealed key survives a
#           reboot (the MVP policy binds the PIN authValue only, no PCR, so there is no reboot
#           brittleness).
#
# All secrets here are THROWAWAY demo values for an ephemeral acceptance VM, never real credentials.
#
# Required environment:
#   REMOTE_DIR   the uploaded-workspace / persistent-state directory on the guest (relative path).

set -euo pipefail

PHASE="${1:-}"
REMOTE_DIR="${REMOTE_DIR:?REMOTE_DIR must be set by the caller}"

# Throwaway demo credentials — only ever meaningful on this ephemeral acceptance VM.
readonly TEST_PIN='1234'
readonly KEYRING_PW='tess-e2e-keyring-pw'
readonly PROBE_ATTR_APP='tess-e2e'
readonly PROBE_ATTR_NAME='mvp-probe'
readonly PROBE_LABEL='tess-e2e MVP probe'
readonly PROBE_SECRET='unlocked-with-no-password'
readonly FPRINT_TIMEOUT_MS='5000'
readonly LOGIN_COLLECTION='/org/freedesktop/secrets/collection/login'

# Environment forwarded into the privileged (sudo) tess invocations so root reuses the login user's
# session bus, keyring state, build cache, and the scripted fprint mock bus.
readonly PRESERVE_ENV='HOME,CARGO_HOME,RUSTUP_HOME,DBUS_SESSION_BUS_ADDRESS,XDG_DATA_HOME,XDG_CONFIG_HOME,XDG_RUNTIME_DIR,TESS_FPRINT_BUS_ADDRESS,TESS_FPRINT_TIMEOUT_MS,TESS_FPRINT_USER'

log()  { printf '>> %s\n' "$*"; }
warn() { printf '!! %s\n' "$*" >&2; }
die()  { printf '>> FAIL: %s\n' "$*" >&2; exit 1; }

# --- process / ownership cleanup ------------------------------------------------------------------

DBUS_PID=''
KEYRING_PID=''
MOCK_PGID=''
USED_SUDO=0

reap_pid() {
  local pid="$1"
  [[ -n "${pid}" ]] || return 0
  kill -TERM "${pid}" 2>/dev/null || return 0
  for _ in $(seq 1 50); do
    kill -0 "${pid}" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -KILL "${pid}" 2>/dev/null || true
}

reap_group() {
  local pgid="$1"
  [[ -n "${pgid}" ]] || return 0
  kill -TERM "-${pgid}" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "-${pgid}" 2>/dev/null || return 0
    sleep 0.1
  done
  kill -KILL "-${pgid}" 2>/dev/null || true
}

cleanup() {
  reap_group "${MOCK_PGID}"
  reap_pid "${KEYRING_PID}"
  reap_pid "${DBUS_PID}"
  # A sudo build/seal leaves root-owned files under the persistent state dir; hand them back to the
  # login user so a later non-root run (or `tess status`) stays usable. Best-effort, never blocks.
  if [[ "${USED_SUDO}" -eq 1 ]]; then
    sudo -n chown -R "$(id -u):$(id -g)" "${STATE_DIR}" 2>/dev/null || true
  fi
}

# --- privileged execution (TPM access) ------------------------------------------------------------

# Forward only absolute PATH entries to a sudo child so cargo's sub-tools can never be resolved from
# the cwd or other relative locations under root. Drops empty/relative components.
sanitized_path() {
  local out='' part
  while IFS= read -r -d ':' part || [[ -n "${part}" ]]; do
    [[ "${part}" == /* ]] && out="${out:+${out}:}${part}"
  done <<< "${PATH}:"
  printf '%s' "${out}"
}

# Build the PRIV array: a command prefix that runs a binary with TPM access. Empty when the login
# user can already read+write /dev/tpmrm0; otherwise a sudo wrapper that preserves the session/keyring
# env and a sanitized PATH (Azure admin users have passwordless sudo).
PRIV=()
compute_priv() {
  if [[ -r /dev/tpmrm0 && -w /dev/tpmrm0 ]]; then
    PRIV=()
  else
    USED_SUDO=1
    PRIV=(sudo "--preserve-env=${PRESERVE_ENV}" env "PATH=$(sanitized_path)")
  fi
}

# --- state directories ----------------------------------------------------------------------------

setup_dirs() {
  cd -- "${REMOTE_DIR}"
  WORK="$(pwd)"
  STATE_DIR="${WORK}/e2e-state"
  export XDG_DATA_HOME="${STATE_DIR}/data"
  export XDG_CONFIG_HOME="${STATE_DIR}/config"
  export XDG_RUNTIME_DIR="${STATE_DIR}/run"
  mkdir -p "${XDG_DATA_HOME}" "${XDG_CONFIG_HOME}"
  # XDG_DATA_HOME (keyring + sealed blobs) is deliberately persistent so the reboot phase can re-unlock
  # it. XDG_RUNTIME_DIR is per-boot ephemeral by spec — recreate it fresh each run so stale dbus /
  # gnome-keyring sockets left from before a reboot can't block the daemons from starting.
  rm -rf -- "${XDG_RUNTIME_DIR}"
  mkdir -p "${XDG_RUNTIME_DIR}"
  chmod 700 "${XDG_RUNTIME_DIR}"
  RECOVERY_FILE="${STATE_DIR}/recovery-secret.txt"
  ENROLL_OUT="${STATE_DIR}/enroll.out"
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || die "required command '$1' is not on PATH"
}

# --- dependency install + build -------------------------------------------------------------------

install_deps() {
  log "Installing build + demo prerequisites (idempotent) ..."
  if ! command -v cc >/dev/null 2>&1 \
    || ! dpkg -s libtss2-dev >/dev/null 2>&1 \
    || ! command -v gnome-keyring-daemon >/dev/null 2>&1 \
    || ! command -v secret-tool >/dev/null 2>&1 \
    || ! command -v dbus-run-session >/dev/null 2>&1; then
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      build-essential pkg-config libtss2-dev curl ca-certificates \
      dbus gnome-keyring libsecret-tools \
      python3 python3-dbus python3-dbusmock python3-gi
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    log "Installing the Rust toolchain via rustup ..."
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
  fi
  if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
  fi

  for bin in dbus-daemon dbus-run-session dbus-send gnome-keyring-daemon secret-tool python3 script setsid; do
    require_bin "${bin}"
  done
}

# Print the absolute path of an EXTERNAL command (never a shell function/alias/builtin), or fail.
# These binaries are run under sudo, so — like hw-exit-test.sh's tpm_run — resolve with `type -P` and
# require an absolute path so the privileged invocation can't depend on the cwd or a relative PATH
# entry. (`command -v` would happily return a function name or a relative path.)
resolve_external() {
  local resolved
  resolved="$(type -P "$1" 2>/dev/null)" || return 1
  [[ "${resolved}" == /* ]] || return 1
  printf '%s' "${resolved}"
}

# Resolve the tess + helper binaries: prefer an installed .deb (production install path), else the
# debug build from the uploaded source. The debug build additionally honours the scripted fprint mock
# bus (a release .deb ignores it and the front gate degrades to the PIN — the keyring still unlocks).
resolve_binaries() {
  local deb installed_tess installed_helper
  deb="$(find "${WORK}/deploy/debian" "${WORK}/target/debian" -maxdepth 1 -name '*.deb' 2>/dev/null | head -n1 || true)"
  if [[ -n "${deb}" ]]; then
    log "Installing packaged tess from ${deb} ..."
    sudo dpkg -i "${deb}" || sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -f
  fi
  if installed_tess="$(resolve_external tess)" \
    && installed_helper="$(resolve_external tess-pam-helper)"; then
    TESS_BIN="${installed_tess}"
    HELPER_BIN="${installed_helper}"
    log "Using installed binaries: ${TESS_BIN}, ${HELPER_BIN}"
    return
  fi
  require_bin cargo
  log "Building tess from source (debug) ..."
  cargo build -p tess-cli
  TESS_BIN="${WORK}/target/debug/tess"
  HELPER_BIN="${WORK}/target/debug/tess-pam-helper"
  [[ -x "${TESS_BIN}" ]] || die "tess binary not found at ${TESS_BIN}"
  [[ -x "${HELPER_BIN}" ]] || die "tess-pam-helper binary not found at ${HELPER_BIN}"
}

# --- session bus + keyring ------------------------------------------------------------------------

start_dbus() {
  local addr_file="${STATE_DIR}/dbus.addr"
  : > "${addr_file}"
  dbus-daemon --session --nofork --print-address=1 > "${addr_file}" 2>/dev/null &
  DBUS_PID=$!
  for _ in $(seq 1 50); do
    [[ -s "${addr_file}" ]] && break
    kill -0 "${DBUS_PID}" 2>/dev/null || die "dbus-daemon exited before announcing an address"
    sleep 0.1
  done
  DBUS_ADDRESS="$(head -n1 "${addr_file}")"
  [[ -n "${DBUS_ADDRESS}" ]] || die "dbus-daemon did not print a bus address"
  export DBUS_SESSION_BUS_ADDRESS="${DBUS_ADDRESS}"
}

wait_for_secrets() {
  for _ in $(seq 1 100); do
    if dbus-send --session --print-reply --dest=org.freedesktop.DBus \
        /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner \
        string:org.freedesktop.secrets 2>/dev/null | grep -q 'boolean true'; then
      return 0
    fi
    sleep 0.1
  done
  die "org.freedesktop.secrets never came up on the private bus"
}

# Start gnome-keyring's secrets component. With a password on stdin it creates+unlocks the login
# keyring (phase `full`); with no password it loads the persisted login keyring LOCKED (phase
# `reboot`), exactly as a fresh boot before any login unlock.
start_keyring() {
  local mode="$1"
  if [[ "${mode}" == unlock ]]; then
    printf '%s' "${KEYRING_PW}" \
      | gnome-keyring-daemon --foreground --components=secrets --unlock >/dev/null 2>&1 &
  else
    gnome-keyring-daemon --foreground --components=secrets >/dev/null 2>&1 < /dev/null &
  fi
  KEYRING_PID=$!
  wait_for_secrets
}

# Lock the login collection over D-Bus (no prompt, no password) so the helper's unlock is meaningful.
lock_login_collection() {
  python3 - "${LOGIN_COLLECTION}" <<'PY'
import sys
import dbus

login_path = sys.argv[1]
bus = dbus.SessionBus()
service = bus.get_object("org.freedesktop.secrets", "/org/freedesktop/secrets")
props = dbus.Interface(service, "org.freedesktop.DBus.Properties")
secret = dbus.Interface(service, "org.freedesktop.Secret.Service")
collections = [str(c) for c in props.Get("org.freedesktop.Secret.Service", "Collections")]
targets = [c for c in collections if c.endswith("/login")] or [login_path]
secret.Lock(targets)
PY
}

# --- fprint mock ----------------------------------------------------------------------------------

start_fprint_mock() {
  local addr_file="${STATE_DIR}/fprint.addr"
  : > "${addr_file}"
  setsid dbus-run-session -- \
    python3 "${WORK}/testing/fprint-mock/fprintd_mock.py" match > "${addr_file}" 2>/dev/null &
  local pid=$!
  MOCK_PGID="${pid}"
  for _ in $(seq 1 100); do
    [[ -s "${addr_file}" ]] && break
    kill -0 "${pid}" 2>/dev/null || die "fprintd mock exited before announcing a bus address"
    sleep 0.1
  done
  FPRINT_BUS="$(head -n1 "${addr_file}")"
  [[ -n "${FPRINT_BUS}" ]] || die "fprintd mock did not print a bus address"
  local fprint_user
  fprint_user="$(id -un)"
  export TESS_FPRINT_BUS_ADDRESS="${FPRINT_BUS}"
  export TESS_FPRINT_TIMEOUT_MS="${FPRINT_TIMEOUT_MS}"
  export TESS_FPRINT_USER="${fprint_user}"
}

# --- tess invocations -----------------------------------------------------------------------------

# Run `tess enroll` under a PTY (rpassword reads the current keyring password from /dev/tty, which
# only exists with a controlling terminal — `script` provides one over the tty-less SSH channel). The
# PIN goes via --pin; the keyring password is fed on the PTY's stdin. Output (incl. the one-time
# recovery secret) is captured for extraction.
run_enroll() {
  local inner
  inner="$(printf '%q ' "${PRIV[@]}" "${TESS_BIN}" enroll --pin "${TEST_PIN}")"
  set +e
  printf '%s\n' "${KEYRING_PW}" | script -qec "${inner}" /dev/null > "${ENROLL_OUT}" 2>&1
  local rc=${PIPESTATUS[1]}
  set -e
  [[ "${rc}" -eq 0 ]] || { sed 's/^/   enroll: /' "${ENROLL_OUT}" >&2; die "tess enroll failed (exit ${rc})"; }

  # The recovery secret is the lone grouped-hex token (lowercase hex in hyphen-separated 4-byte
  # groups) enroll prints exactly once. Persist it 0600 for the operator, mirroring a real enroll.
  local secret
  secret="$(grep -Eo '[0-9a-f]{8}(-[0-9a-f]{8})+' "${ENROLL_OUT}" | head -n1 || true)"
  [[ -n "${secret}" ]] || die "could not extract the recovery secret from enroll output"
  ( umask 077; printf '%s\n' "${secret}" > "${RECOVERY_FILE}" )
  log "Recovery secret saved to ${RECOVERY_FILE}"
}

# Drive the real PAM helper exactly as the module does: PIN on stdin, the fingerprint front gate
# enabled. The fingerprint is host-trusted convenience; the PIN is what unseals the key.
run_session() {
  log "Driving the scripted fingerprint + PIN session through tess-pam-helper ..."
  set +e
  printf '%s' "${TEST_PIN}" \
    | timeout --signal=KILL 90 "${PRIV[@]}" "${HELPER_BIN}" --fingerprint
  local rc=${PIPESTATUS[1]}
  set -e
  [[ "${rc}" -eq 0 ]] || die "tess-pam-helper session failed (exit ${rc})"
}

tess_status() {
  "${PRIV[@]}" "${TESS_BIN}" status
}

# --- assertions -----------------------------------------------------------------------------------

assert_keyring_locked() {
  tess_status | grep -Eq 'keyring:[[:space:]]+locked' \
    || die "expected the keyring to be locked before the session unlock"
}

assert_keyring_unlocked() {
  tess_status | grep -Eq 'keyring:[[:space:]]+unlocked' \
    || die "tess status does not report the keyring as unlocked after the session"
}

# The probe item is only readable when the collection is unlocked; reading it back without typing a
# password is the end-to-end proof. Bounded so a still-locked collection can never hang the harness.
assert_probe_readable() {
  local got
  got="$(timeout 20 secret-tool lookup "${PROBE_ATTR_APP}" "${PROBE_ATTR_NAME}" 2>/dev/null || true)"
  [[ "${got}" == "${PROBE_SECRET}" ]] \
    || die "probe item was not readable after the session (keyring not truly unlocked)"
}

seed_probe() {
  printf '%s' "${PROBE_SECRET}" \
    | secret-tool store --label="${PROBE_LABEL}" "${PROBE_ATTR_APP}" "${PROBE_ATTR_NAME}"
}

# --- phases ---------------------------------------------------------------------------------------

phase_full() {
  log "Phase: full MVP acceptance demo"
  [[ -e /dev/tpmrm0 ]] || die "/dev/tpmrm0 is absent — this guest has no vTPM"
  install_deps
  resolve_binaries
  compute_priv

  start_dbus
  start_keyring unlock
  seed_probe

  log "Enrolling: sealing a fresh random key to the vTPM under the PIN ..."
  run_enroll

  start_fprint_mock
  lock_login_collection
  assert_keyring_locked

  run_session
  assert_keyring_unlocked
  assert_probe_readable
  log "PASS — keyring unlocked with no password (sealed to the real vTPM, fingerprint + PIN session)."
}

phase_reboot() {
  log "Phase: reboot persistence re-unlock"
  [[ -e /dev/tpmrm0 ]] || die "/dev/tpmrm0 is absent — this guest has no vTPM"
  install_deps
  resolve_binaries
  compute_priv

  [[ -f "${XDG_DATA_HOME}/tess/metadata.json" ]] \
    || die "no enrollment metadata under ${XDG_DATA_HOME}/tess — run mvp-e2e.sh (phase full) first"

  start_dbus
  start_keyring locked
  lock_login_collection
  assert_keyring_locked

  run_session
  assert_keyring_unlocked
  assert_probe_readable
  log "PASS — sealed key survived the reboot and re-unlocked the persisted keyring with no password."
}

main() {
  setup_dirs
  trap cleanup EXIT
  case "${PHASE}" in
    full)   phase_full ;;
    reboot) phase_reboot ;;
    *)      die "unknown phase '${PHASE}' (expected 'full' or 'reboot')" ;;
  esac
}

main
