# PAM wiring for `pam_tess.so`

`pam_tess.so` unseals the TPM-sealed keyring key and unlocks the GNOME login keyring at session
open. It is wired into the **session** stack with a fail-open control flag so it can **never lock a
user out**: if anything goes wrong (no TPM, a slow or declined unseal, a missing helper) the module
returns `PAM_SUCCESS` and login proceeds with the keyring left locked — exactly as it was before
tess was installed.

## The snippet

`tess-session.pam` holds the line `tess install` inserts, delimited by re-runnable markers:

```pam
session optional pam_tess.so
```

`optional` means a tess failure is ignored. The MVP wires **only** the session phase; there is no
auth gate yet. When an auth factor is added later it must use an equally fail-open control flag:

```pam
auth [success=done default=ignore] pam_tess.so
```

`[success=done default=ignore]` makes a successful tess auth complete the stack while **any** other
result (decline, timeout, error) is ignored, falling through to the password factor. Never wire
`pam_tess.so` as `required`, `requisite`, or `sufficient` — those can fail a login.

## Placement

The target on Debian 13 is `/etc/pam.d/common-session`, the shared session stack included by the
login services (`login`, `gdm-password`, `sshd`, …). Place the tess line **after**
`pam_unix.so` (so the user session is established) and **after** `pam_gnome_keyring.so`'s
`session` line if present, so tess runs once the keyring daemon's own session hook has set up the
collection. Because the line is `optional`, ordering only affects whether the unlock happens, never
whether login succeeds.

A typical `common-session` after `tess install`:

```pam
session [default=1] pam_permit.so
session requisite    pam_deny.so
session required     pam_permit.so
session optional     pam_umask.so
session required     pam_unix.so
session optional     pam_gnome_keyring.so auto_start
# >>> tess >>>
session optional pam_tess.so
# <<< tess <<<
```

## Module installation

`tess install` also copies the built `pam_tess.so` into the system PAM module directory. That
directory is detected the same way the CI smoke test does — by locating a stock module
(`pam_permit.so`) under `/lib` and `/usr/lib` and taking its parent directory — so it works across
the multiarch layouts Debian and other distros use (`/lib/x86_64-linux-gnu/security`,
`/usr/lib64/security`, …).

## Removal

`tess install --uninstall` removes the marked block from `common-session` (restoring the original
stack), deletes the installed `pam_tess.so`, and removes the backup tess wrote before editing. It is
idempotent and safe to run when tess is not installed.
