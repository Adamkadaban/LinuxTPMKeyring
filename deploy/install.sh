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
  --deb PATH   Install this prebuilt .deb instead of building from source.
  --no-pam     Install the package but skip `tess install` (no PAM wiring).
  --yes        Pass -y to apt for non-interactive installs.
  -h, --help   Show this help and exit.

With no --deb, the script builds the workspace in release mode and runs `cargo deb` to produce the
.deb, then installs it (pulling in runtime dependencies). Unless --no-pam is given it runs
`tess install` to wire the fail-open PAM session module. Re-running is safe: the apt install and
`tess install` are both idempotent.
EOF
}

deb=""
run_pam=1
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
	--yes)
		apt_args+=("-y")
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
	else
		sudo "$@"
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
	if ! command -v cargo-deb >/dev/null 2>&1; then
		echo "==> installing cargo-deb"
		cargo install cargo-deb --locked
		# `cargo install` drops the binary in the cargo bin dir, which isn't on PATH when cargo came
		# from a distro package — prepend it so the `cargo deb` subcommand below resolves.
		PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
		export PATH
	fi
	echo "==> building tess (release) and packaging the .deb"
	cargo build --release --workspace
	# `cargo deb` prints the path of the produced .deb on stdout; build progress goes to stderr.
	deb=$(cargo deb -p tess-cli --no-build)
}

install_deb() {
	local path=$1
	# Resolve a caller-relative path against the directory the script was invoked from, since the
	# build path cd's into the repo root. An absolute path also satisfies apt's requirement that a
	# local-file argument contain a slash.
	case "$path" in
	/*) ;;
	*) path="$orig_pwd/$path" ;;
	esac
	[ -f "$path" ] || {
		echo "error: .deb not found: $path" >&2
		exit 1
	}
	echo "==> installing $path with its runtime dependencies"
	run_root apt-get update
	run_root apt-get install "${apt_args[@]}" "$path"
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

if [ "$run_pam" -eq 1 ]; then
	echo "==> wiring the fail-open PAM session module via tess install"
	run_root tess install --module "$pam_module"
	cat <<'EOF'
==> done. Next, on this machine:
  tess enroll                 # set a PIN, seal a random key, rekey your keyring (transactional)
Undo the PAM wiring at any time with:  tess install --uninstall
EOF
else
	cat <<EOF
==> package installed; PAM wiring skipped (--no-pam).
  sudo tess install --module $pam_module   # wire the fail-open PAM session module when ready
  tess enroll                                                       # then enroll
EOF
fi
