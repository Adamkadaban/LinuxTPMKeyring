#!/usr/bin/env bash
#
# install.sh — one-command install of tess on Debian 13.
#
# Builds (or takes a prebuilt) .deb, installs it together with its runtime dependencies, then wires
# the fail-open PAM session module via the explicit `tess install`. This script never edits
# /etc/pam.d itself: all PAM wiring goes through `tess install`, which validates and backs up the
# stack and uses an `optional` (fail-open) control flag, so it can never lock you out of login.
#
# Intended for a deployment target (an Azure VM or a user's machine), never the developer host.

set -euo pipefail

# Where the .deb installs the PAM module. `tess install` looks for the module next to the `tess`
# binary by default, and a packaged `/usr/bin/tess` has none beside it, so point `tess install` at
# the packaged module explicitly. Matches the `assets` dest in crates/tess-cli/Cargo.toml.
readonly pam_module="/usr/lib/x86_64-linux-gnu/security/pam_tess.so"

# Resolve paths from the script's own location so it works regardless of the caller's CWD: the build
# needs the workspace root, while a caller-supplied `--deb` is relative to where they invoked us.
orig_pwd=$PWD
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)

usage() {
	cat <<'EOF'
Usage: deploy/install.sh [options]

Options:
  --deb PATH       Install this prebuilt .deb instead of building from source.
  --no-pam         Install the package but skip `tess install` (no PAM wiring).
  --no-recommends  Pass --no-install-recommends to apt, so the optional fprintd
                   fingerprint stack (a Recommends) is not pulled in.
  --yes            Assume yes and run apt non-interactively (adds -y and sets
                   DEBIAN_FRONTEND=noninteractive so it never blocks on a prompt).
  -h, --help       Show this help and exit.

With no --deb, the script builds tess-cli and tess-pam in release mode and runs `cargo deb` to produce the
.deb, then installs it (pulling in runtime dependencies). apt installs Recommends by default, so
fprintd comes along unless you pass --no-recommends. Unless --no-pam is given it runs `tess install`
to wire the fail-open PAM session module. Re-running is safe: the apt install and `tess install` are
both idempotent.
EOF
}

deb=""
run_pam=1
noninteractive=""
apt_args=()

while [ "$#" -gt 0 ]; do
	case "$1" in
	--deb)
		[ "$#" -ge 2 ] || {
			echo "error: --deb requires a path argument" >&2
			exit 2
		}
		deb=$2
		shift 2
		;;
	--deb=*)
		deb=${1#--deb=}
		shift
		;;
	--no-pam)
		run_pam=0
		shift
		;;
	--no-recommends)
		apt_args+=("--no-install-recommends")
		shift
		;;
	--yes)
		apt_args+=("-y")
		noninteractive=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	--)
		shift
		break
		;;
	-*)
		echo "error: unknown option: $1" >&2
		usage >&2
		exit 2
		;;
	*)
		echo "error: unexpected argument: $1" >&2
		exit 2
		;;
	esac
done

if [ "$#" -gt 0 ]; then
	echo "error: unexpected trailing arguments: $*" >&2
	exit 2
fi

run_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	elif command -v sudo >/dev/null 2>&1; then
		sudo "$@"
	else
		echo "error: root privileges required to run: $*" >&2
		echo "       re-run this script as root, or install sudo." >&2
		exit 1
	fi
}

# Run apt-get with root privileges. With --yes, also set DEBIAN_FRONTEND=noninteractive so apt never
# blocks on a prompt (e.g. a conffile decision) in automation. `env` carries the variable across the
# sudo boundary, which resets the environment by default.
apt_get() {
	if [ -n "$noninteractive" ]; then
		run_root env DEBIAN_FRONTEND=noninteractive apt-get "$@"
	else
		run_root apt-get "$@"
	fi
}

require_debian_13() {
	local arch
	arch=$(dpkg --print-architecture 2>/dev/null || echo unknown)
	if [ "$arch" != "amd64" ]; then
		echo "error: tess packaging targets Debian 13 amd64; detected architecture: $arch." >&2
		echo "       The .deb and the PAM module path ($pam_module) are amd64-specific." >&2
		exit 1
	fi
	if [ ! -r /etc/os-release ]; then
		echo "error: /etc/os-release not found; this installer targets Debian 13 (trixie)." >&2
		exit 1
	fi
	# shellcheck disable=SC1091
	. /etc/os-release
	if [ "${ID:-}" = "debian" ] && [ "${VERSION_ID:-}" = "13" ]; then
		return
	fi
	echo "error: tess targets Debian 13 (trixie); detected ${PRETTY_NAME:-unknown}." >&2
	if [ "${TESS_SKIP_OS_CHECK:-0}" = "1" ]; then
		echo "       TESS_SKIP_OS_CHECK=1 set — continuing anyway." >&2
		return
	fi
	echo "       Set TESS_SKIP_OS_CHECK=1 to override at your own risk." >&2
	exit 1
}

build_deb() {
	command -v cargo >/dev/null 2>&1 || {
		echo "error: cargo not found; install the Rust toolchain first." >&2
		exit 1
	}
	# Build prerequisites for linking + bindgen (tss-esapi FFI, the PAM module). Idempotent: apt is a
	# no-op for already-installed packages. Mirrors the build deps in .github/workflows/test.yml.
	echo "==> installing build prerequisites"
	apt_get update
	apt_get install "${apt_args[@]}" \
		build-essential pkg-config libclang-dev libtss2-dev libpam0g-dev
	if ! command -v cargo-deb >/dev/null 2>&1; then
		echo "==> installing cargo-deb"
		cargo install cargo-deb --locked
		# `cargo install` drops the binary in the cargo bin dir, which isn't on PATH when cargo came
		# from a distro package — prepend it so the `cargo deb` subcommand below resolves.
		PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
		export PATH
	fi
	echo "==> building tess (release) and packaging the .deb"
	# Only the two crates the .deb assets come from: tess-cli (tess + tess-pam-helper bins) and
	# tess-pam (the libpam_tess.so cdylib). tess-cli pulls in the other workspace libs as deps.
	cargo build --release -p tess-cli -p tess-pam
	# `cargo deb` prints the path of the produced .deb on stdout; build progress goes to stderr.
	deb=$(cargo deb -p tess-cli --no-build)
}

# Add the human running this installer to the `tss` group so they can read/write /dev/tpmrm0 and run
# `tess enroll`/`unlock`/`status`. The packaged udev rule also tags the device uaccess (the active
# seat user gets access automatically), but the group add covers headless/SSH and is harmless
# otherwise. The group change only takes effect in a NEW login session — surface that loudly. Pick
# the real user, not root: $SUDO_USER when invoked via sudo, else the current user when the script is
# run unprivileged (it sudo's only the individual root operations).
grant_tpm_access() {
	local user
	user=${SUDO_USER:-}
	if [ -z "$user" ] && [ "$(id -u)" -ne 0 ]; then
		user=$(id -un)
	fi
	if [ -z "$user" ] || [ "$user" = "root" ]; then
		cat >&2 <<'EOF'
==> note: could not determine a non-root login user to grant TPM access.
    Add your login user to the tss group manually, then log out and back in:
      sudo usermod -aG tss <your-login-user>
EOF
		return
	fi
	# The package postinst creates the group; create defensively for a prebuilt --deb that predates it.
	getent group tss >/dev/null 2>&1 || run_root groupadd --system tss
	if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx tss; then
		echo "==> $user is already in the tss group (TPM access already granted)"
		return
	fi
	echo "==> adding $user to the tss group for TPM device access"
	run_root usermod -aG tss "$user"
	cat <<EOF
==> $user was added to the 'tss' group. Group membership applies only to NEW login
    sessions — log out and back in (or reboot) before running 'tess enroll'.
EOF
}

install_deb() {
	local path=$1
	# A relative path is either the cargo-deb output (relative to repo_root) or a caller-provided
	# --deb (relative to their original CWD). Prefer repo_root when the file exists there, else fall
	# back to orig_pwd. An absolute path is used as-is (and satisfies apt's slash requirement).
	case "$path" in
	/*) ;;
	*)
		if [ -f "$repo_root/$path" ]; then
			path="$repo_root/$path"
		else
			path="$orig_pwd/$path"
		fi
		;;
	esac
	[ -f "$path" ] || {
		echo "error: .deb not found: $path" >&2
		exit 1
	}
	echo "==> installing $path with its runtime dependencies"
	apt_get update
	# `--` so a package path beginning with `-` can never be parsed as an apt option under root.
	apt_get install "${apt_args[@]}" -- "$path"
}

require_debian_13

# The build runs cargo against the workspace, so operate from the repo root regardless of CWD.
cd -- "$repo_root"

if [ -n "$deb" ]; then
	echo "==> using prebuilt .deb: $deb"
else
	build_deb
fi

install_deb "$deb"

grant_tpm_access

if [ "$run_pam" -eq 1 ]; then
	echo "==> wiring the fail-open PAM session module via tess install"
	run_root tess install --module "$pam_module"
	cat <<'EOF'
==> done. Next, as your login user on this machine (in a fresh login session if you were just
    added to the tss group above):
  tess enroll                 # set a PIN, seal a random key, rekey your keyring (transactional)
Undo the PAM wiring at any time with:  sudo tess install --uninstall
EOF
else
	cat <<EOF
==> package installed; PAM wiring skipped (--no-pam).
  sudo tess install --module $pam_module   # wire the fail-open PAM session module when ready
  tess enroll                                                       # then enroll (fresh session if just added to tss)
EOF
fi
