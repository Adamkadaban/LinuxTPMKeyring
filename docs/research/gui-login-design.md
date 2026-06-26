# Design: seamless face-unlock login UI on GNOME (actionable layer)

**Status:** Proposed design (not yet scheduled). Turns the exploration in
[`gui-login-integration.md`](./gui-login-integration.md) into a concrete, buildable contract: the D-Bus
interface, the lock-screen trust boundary, the PAM wiring, and the extension lifecycle. Pairs with
[ADR-0022](../adr/0022-login-ui-pam-text-plus-unlock-dialog-extension.md).

**One-line decision:** ship two independent layers — **(A)** a non-blocking PAM module that emits
status text on the *foreground* `gdm-password` stack (universal, works at greeter + lock screen, no GUI
code), and **(B)** a thin **pure-view** GNOME Shell extension that subscribes to a **root-owned
system-bus signal** and draws a Hello-style glyph on the **lock screen only**. We deliberately **diverge
from gaze**, which paints its text by monkeypatching `ShellUserVerifier` — fragile and conflates "draw a
glyph" with "drive auth."

---

## 1. Target platform (pinned)

- **Debian 13 "trixie" → GNOME Shell 48** (`gnome-shell 48.7-0+deb13u2`). Extension API is the **GNOME
  45+ ESM era**: `import` from `resource:///…`, `export default class extends Extension`.
- Wayland by default ⇒ only `gnome-shell` may draw on the lock screen ⇒ the *only* way to render custom
  lock UI is an in-process Shell extension (a standalone overlay app is structurally impossible —
  `ext-session-lock-v1`).
- Pin `metadata.json` `shell-version` to `["48"]`; widen only after testing each future bump against
  `unlockDialog.js` / `screenShield.js`.

## 2. Architecture & components

```
                    ┌─────────────────────────── system D-Bus ───────────────────────────┐
                    │  org.tessera.ScanState1  (root-owned, read-only State + signal)      │
 camera/IR ──▶ tessera-scand (root)  ──emit StateChanged(s)──▶  (subscribers, sender-filtered)
                    │        │                                                              │
                    │        └── consumed by ──▶ pam_tess.so (root, in gdm-password stack)  │
                    └────────────────────────────────────────────────────────────────────┘
                             │ PAM conversation (PAM_TEXT_INFO / PAM_ERROR_MSG)
                             ▼
                       gnome-shell ShellUserVerifier ──renders text──▶ greeter + lock screen
                             ▲
                             │ Gio.DBusProxy (system bus), StateChanged → glyph
                       tessera-facestatus@… extension  (unlock-dialog mode, pure view)
```

| Component | Runs as | Bus role | Auth authority? |
|---|---|---|---|
| `tessera-scand` daemon | root system service | **owns** `org.tessera.ScanState1`, **emits** state | No — publishes state only, exposes **no** unlock method |
| `pam_tess.so` | root (auth stack) | reads daemon state; returns the PAM verdict | **Yes** — the real gate (face match → `PAM_SUCCESS`, else fall through) |
| Shell extension | the user (inside locked `gnome-shell`) | **sender-filtered subscriber** | No — pure view, never calls an auth method |

The PAM module (layer A) is **load-bearing and sufficient on its own**; the extension (layer B) is
optional polish. They share the daemon's state machine but are otherwise decoupled — the extension can
be absent, disabled, or broken by a GNOME upgrade without affecting authentication.

## 3. D-Bus contract — `org.tessera.ScanState1`

- **Bus:** system bus. *Rationale:* the producer of truth is a root component at auth time; root has no
  session bus, and at the greeter there is no user session yet. A locked `gnome-shell` can already reach
  the system bus (it talks to `net.reactivated.Fprint` there today), so the consumer side works.
- **Name owner:** root only (enforced by the D-Bus policy in §5). Well-known name
  `org.tessera.ScanState1`, object `/org/tessera/ScanState1`, interface `org.tessera.ScanState1`.

| Member | Kind | Signature | Meaning |
|---|---|---|---|
| `State` | property (read-only) | `s` | current state string (prime the glyph on subscribe) |
| `StateChanged` | signal | `s state` | emitted on every state transition (coalesced; emit on change only) |

**State enum** (machine-readable string, mirrors gaze's `CaptureStatus`/`VerifyResult` split, trimmed):

| String | Glyph | Label |
|---|---|---|
| `idle` | neutral | (hidden) |
| `scanning` | eye/searching | "Looking for you…" |
| `need-light` | dim | "Need more light…" |
| `no-face` | searching | "Look at the camera…" |
| `matched` | ✓ | "Got it" |
| `no-match` | ✗ | "Couldn't recognize you" |

The signal is **directed/unicast** to active subscribers where possible (gaze sets a signal destination
to the claiming sender); for the broadcast view-extension case, sender-filtering on the consumer side
(§5) is the trust anchor.

## 4. The keyring caveat that shapes the whole UX (tessera-specific)

gaze keeps face-auth **off at GDM login by default** because a face-only login never enters the password
and therefore **leaves `gnome-keyring` locked** — apps then keep prompting. For tessera this is decisive,
not incidental: **unlocking the keyring is the entire point.** Therefore:

- **First sign-in after boot = PIN.** The PIN authValue releases the TPM-sealed key that derives the
  keyring wrapping secret. Face cannot substitute here, because face does not produce that secret. This
  matches the greeter gap (a per-user extension can't run in the `gdm` greeter anyway) and the TPM
  at-rest model (the cold-boot authentication is the one that must be strong).
- **Lock-screen re-unlock = face (convenience).** Post-login the keyring is already unlocked in memory
  (GNOME does not re-lock it on session lock), so the lock screen is "only" a shield; using the face leg
  for the re-unlock convenience case is safe and is where layer B shines.

Document verbatim: *"Face unlock is available at the lock screen and for re-authentication; the first
sign-in after boot uses your PIN to establish the session and unlock your keyring."*

## 5. Lock-screen trust boundary (security)

Two rules hold the whole thing together; if both hold, a forged signal is **cosmetic only, never an auth
bypass** (the attacker is an already-present unprivileged local process and gains no new capability — the
glyph can't advance the PAM conversation, release the TPM key, or satisfy `pam_authenticate`).

1. **Root-only ownership + sender-filtered subscription.** Only root may own
   `org.tessera.ScanState1`; the extension subscribes with an explicit `sender=` (well-known name) match,
   so the bus drops any signal whose sender isn't the root owner. (A bare interface/member match would
   let any uid `dbus-send` a fake `matched`.) D-Bus broadcast signals can't be restricted by a
   `send_destination` policy, so name-ownership + consumer-side sender match — not a send-policy — is the
   real control.
2. **The glyph is advisory, never authoritative.** The extension exposes/uses **no** method that can
   influence auth: it never calls the GDM `UserVerifier`, never pokes PAM/fprintd, never calls
   `org.gnome.ScreenSaver.SetActive(false)`, never early-dismisses the unlock dialog. It validates the
   payload against the known enum and falls back to a neutral glyph on anything unexpected. The daemon
   exposes only the read-only `State` + `StateChanged` — no unlock method exists to abuse.

`/usr/share/dbus-1/system.d/org.tessera.ScanState1.conf` (packages use `/usr/share`; `/etc` is for the
admin):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.tessera.ScanState1"/>
    <allow send_destination="org.tessera.ScanState1"/>
  </policy>
  <policy context="default">
    <deny  own="org.tessera.ScanState1"/>
    <allow send_destination="org.tessera.ScanState1"
           send_interface="org.freedesktop.DBus.Properties"/>
    <allow send_destination="org.tessera.ScanState1"
           send_interface="org.freedesktop.DBus.Introspectable"/>
    <allow receive_sender="org.tessera.ScanState1" receive_type="signal"/>
    <!-- defense in depth: refuse our signal interface from non-root -->
    <deny  send_interface="org.tessera.ScanState1" send_type="signal"/>
  </policy>
</busconfig>
```

Run `tessera-scand` as a `Type=dbus` systemd service, `User=root`, `BusName=org.tessera.ScanState1`,
hardened (`NoNewPrivileges=`, `ProtectSystem=strict`, `SystemCallFilter=@system-service`, minimal caps).

## 6. PAM wiring (layer A — the universal MVP)

gnome-shell's `ShellUserVerifier` (`js/gdm/util.js`) **only shows** a service's `PAM_TEXT_INFO`/
`PAM_ERROR_MSG` if that service is the **foreground** service (`gdm-password` when password auth is on);
non-foreground services are suppressed (the sole exception is fingerprint, whose text is *replaced* by a
canned hint). That suppression **is** howdy's "silent pause." So our module must live on the **foreground
`gdm-password`** stack.

`/etc/pam.d/gdm-password` — insert as the first `auth` rule, **above** `@include common-auth`:

```pam
auth    [success=done default=ignore]   pam_tess.so timeout=3000 emit_status
@include common-auth
```

- `success=done` → a real face match satisfies auth with no password prompt (Hello-style).
- `default=ignore` → **every** other outcome (timeout, no-match, helper crash, camera busy,
  `PAM_AUTHINFO_UNAVAIL`, `PAM_IGNORE`) contributes nothing and falls through to PIN/password — the
  non-freeze guarantee, declaratively.
- The slow work (camera/TPM/D-Bus) runs in a **forked, watchdog'd helper** with a hard wall-clock
  timeout; the PAM thread only waits on a bounded timeout, never blocks. (Existing project invariant.)
- Placed in `gdm-password` (not `common-auth`) ⇒ GDM-only (greeter + lock), doesn't touch sudo/ssh.
- Same `gdm-password` service backs the locked reauth (`open_reauthentication_channel`), so this single
  wiring renders our text at **both** greeter and lock screen.

## 7. Extension lifecycle (layer B — lock-screen polish)

- `metadata.json`: `session-modes: ["user","unlock-dialog"]`, `shell-version: ["48"]`. No privilege
  needed for `unlock-dialog` (only `gdm` mode requires a system install enabled for the gdm user).
- **Shell calls `disable()`/`enable()` across every lock/unlock transition** even with `unlock-dialog`
  declared — treat both as cold starts. Trigger off the documented `Main.sessionMode` `'updated'` signal
  (`currentMode === 'unlock-dialog'`); optionally `Main.screenShield` `'locked-changed'` for the precise
  moment (guard `Main.screenShield` may be null in the greeter context).
- **Render via additive injection** (lowest-risk monkeypatch posture): add a child actor to
  `Main.screenShield._dialog` (the `UnlockDialog`), never replace existing actors, never anchor to
  `_authPrompt` (it's created/destroyed on demand). The `_dialog` is destroyed on unlock — re-mount on
  each lock. A top-panel indicator is **invisible** on the lock screen (curtain covers the panel), so
  it's not an option.
- Every `_dialog`/`_stack`/`_promptBox` access is a **private unstable internal** — guard defensively so
  a layout change degrades to "no glyph," not a Shell crash. Re-verify against `unlockDialog.js` /
  `screenShield.js` on each GNOME major bump.

A working ESM skeleton lives in [`/gnome-extension/`](../../gnome-extension/) (non-wired prototype, not
installed by the `.deb` yet).

## 8. Packaging & boundaries

- The extension is **JS/GJS, outside the Rust workspace** (like `tools/face-preview`) — zero
  supply-chain/`cargo vet` churn. Its own release cadence.
- The `.deb` would later install: `pam_tess.so` + the `gdm-password` edit (via `pam-auth-update`
  profile), the daemon unit + D-Bus policy, and (optionally) the extension system-wide with a dconf
  fallback enable (Shell only scans extension dirs at session start; on Wayland enabling needs a
  relogin, so write the dconf key).
- KDE/Plasma is a separate later integration (its own lock UI + `kde-fingerprint`-style PAM).

## 9. What we mirror vs avoid (from gaze, MIT)

**Mirror:** root system-bus daemon owning one name + single object; typed state-machine enums with a
priority coalescer; `Claim`/`Release` single-owner arbitration with a wall-clock timeout **and** a
`NameOwnerChanged` auto-release watcher (maps to our camera/TPM exclusivity); PAM fall-through discipline
(`PAM_IGNORE` unenrolled, `PAM_AUTHINFO_UNAVAIL` on timeout, `[success=… default=ignore]`, hard timeout);
SSH/closed-lid abort defaults.

**Avoid:** monkeypatching `ShellUserVerifier`/PolkitAgent prototypes to inject status (fragile private
internals; conflates view and auth) — use a direct D-Bus subscription instead; the
`GAZE_CONFIRMATION_REQUEST` string-sentinel-over-PAM-conversation hack; and **never skip the
password/secret** the way face-only GDM login does — tessera's PIN authValue must still derive the
keyring wrapping key.

---

### Primary sources
- GNOME on Debian 13 (`gnome-shell 48.7`): https://tracker.debian.org/pkg/gnome-shell
- Extension anatomy / ESM / `session-modes`: https://gjs.guide/extensions/overview/anatomy.html ·
  https://gjs.guide/extensions/topics/session-modes.html
- Updates & breakage (additive vs invasive monkeypatching): https://gjs.guide/extensions/overview/updates-and-breakage.html
- `unlockDialog.js` / `screenShield.js` (gnome-48 internals): https://gitlab.gnome.org/GNOME/gnome-shell/-/raw/gnome-48/js/ui/unlockDialog.js ·
  https://gitlab.gnome.org/GNOME/gnome-shell/-/raw/gnome-48/js/ui/screenShield.js
- `ShellUserVerifier` foreground gating / fingerprint special-case: https://gitlab.gnome.org/GNOME/gnome-shell/-/blob/main/js/gdm/util.js
- GDM PAM→D-Bus relay: https://gitlab.gnome.org/GNOME/gdm/-/blob/main/daemon/gdm-session.c
- `dbus-daemon(1)` policy model / system-service integration: https://dbus.freedesktop.org/doc/dbus-daemon.1.html
- `pam_conv(3)` / `pam.d(5)`: https://man7.org/linux/man-pages/man3/pam_conv.3.html · https://man7.org/linux/man-pages/man5/pam.d.5.html
- GunduLabs/gaze (MIT — study, don't copy): https://github.com/GunduLabs/gaze
