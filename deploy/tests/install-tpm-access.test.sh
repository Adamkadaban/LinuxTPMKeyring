#!/usr/bin/env bash
#
# Static checks for the TPM-access install wiring: the packaged udev rule is well-formed and grants
# the `tss` group rw on the TPM devices, and the install scripts add the right user to that group and
# tell them to re-login. Runs without root, a TPM, or a package install — pure file assertions plus a
# static-lint pass (shellcheck) on the scripts it covers. Exit non-zero on any failure.

set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/../.." && pwd)
rule="$root/deploy/udev/70-tess-tpm.rules"
install_sh="$root/deploy/install.sh"
postinst="$root/deploy/debian/postinst"

fail=0
check() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then
		printf 'ok   - %s\n' "$desc"
	else
		printf 'FAIL - %s\n' "$desc" >&2
		fail=1
	fi
}

check "udev rule file exists" test -f "$rule"
check "rule grants tss group on /dev/tpmrm*" \
	grep -Eq 'KERNEL=="tpmrm\[0-9\]\*".*GROUP="tss"' "$rule"
check "rule grants tss group on /dev/tpm*" \
	grep -Eq 'KERNEL=="tpm\[0-9\]\*".*GROUP="tss"' "$rule"
check "rule sets MODE 0660" grep -q 'MODE="0660"' "$rule"
check "rule tags devices uaccess (seat-user access)" grep -q 'TAG+="uaccess"' "$rule"

check "install.sh selects SUDO_USER" grep -q 'SUDO_USER' "$install_sh"
check "install.sh never grants root" grep -qF '= "root" ]' "$install_sh"
check "install.sh adds the user to tss" grep -q 'usermod -aG tss' "$install_sh"
check "install.sh warns to re-login" grep -qi 'log out' "$install_sh"

check "postinst ensures the tss group exists" grep -q 'getent group tss' "$postinst"
check "postinst reloads udev" grep -q 'udevadm control --reload-rules' "$postinst"
check "postinst documents the usermod step" grep -q 'usermod -aG tss' "$postinst"

if command -v shellcheck >/dev/null 2>&1; then
	check "install.sh is shellcheck-clean" shellcheck "$install_sh"
	check "postinst is shellcheck-clean" shellcheck "$postinst"
	check "this test is shellcheck-clean" shellcheck "${BASH_SOURCE[0]}"
else
	printf 'skip - shellcheck not installed\n'
fi

if [ "$fail" -ne 0 ]; then
	echo "TPM-access install checks FAILED." >&2
	exit 1
fi
echo "All TPM-access install checks passed."
