# Tessera Face Unlock Status — GNOME Shell extension (PROTOTYPE)

A thin, **pure-view** GNOME Shell 48 extension that draws a Windows-Hello-style status glyph
("Looking for you… / Got it") on the **lock screen** while tessera's face unlock runs.

> **Status: design-reference prototype.** Not wired into the tessera `.deb`, not installed, and the Rust
> daemon (`org.tessera.ScanState1`) it subscribes to is not implemented yet. This directory exists to
> make the [login-UI design](../docs/research/gui-login-design.md) /
> [ADR-0022](../docs/adr/0022-login-ui-pam-text-plus-unlock-dialog-extension.md) concrete and testable.
> It is intentionally **outside the Rust workspace** (like `tools/face-preview`) so it adds zero
> supply-chain / `cargo vet` surface.

## What it does (and what it must never do)

- Subscribes to the **root-owned system-bus** signal `org.tessera.ScanState1.StateChanged(s)` and maps
  each state to a glyph + label.
- Runs on the lock screen via `session-modes: ["user","unlock-dialog"]`. It does **not** run in the GDM
  greeter (separate `gnome-shell` as the `gdm` user) — by design: the first sign-in after boot uses the
  **PIN**, which is what derives the keyring wrapping secret.
- It is **advisory only**. It calls no authentication method, never dismisses the unlock dialog, and
  treats the signal as cosmetic. The real gate is PAM + the TPM-sealed key (PIN authValue). A forged
  signal can only paint a wrong glyph; it cannot unlock anything.

## Why a direct D-Bus subscription (not gaze's approach)

GunduLabs/gaze paints its text by monkeypatching `ShellUserVerifier` and launching a `gdm-face`
background PAM service — a fragile dependence on private Shell internals that mixes view with auth. We
keep the **foreground PAM-conversation text** as the universal layer (renders at greeter *and* lock with
no GUI) and use this extension purely for the lock-screen **glyph**, via a clean, stable D-Bus contract.

## Try it (on a Debian 13 / GNOME 48 test box — never the dev laptop)

```sh
# Install for the current user
cp -r gnome-extension ~/.local/share/gnome-shell/extensions/tessera-facestatus@tessera.local
# Wayland: log out / back in (Shell only scans extension dirs at session start), then:
gnome-extensions enable tessera-facestatus@tessera.local

# Drive the glyph by hand (stand in for the daemon) from a root shell:
#   the real daemon owns org.tessera.ScanState1 on the system bus; for a quick
#   visual test you can emit the signal from a throwaway owner and relax the
#   policy on a test box only.
```

The unstable Shell internals this depends on (`Main.screenShield._dialog`, the `UnlockDialog` actor
tree) must be re-verified against `js/ui/unlockDialog.js` and `js/ui/screenShield.js` on each GNOME major
bump. Pinned to GNOME **48** (Debian 13) for now.
