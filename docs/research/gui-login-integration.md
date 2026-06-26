# Research: seamless face-unlock login UI on GNOME

**Status:** Research / exploration (not a committed decision). Captures the night's research so we can
decide the GUI direction deliberately. Spawned from the question "how do we display the face-unlock at
login — a GNOME extension? something else?"

**One-line answer:** PAM already gives us text status "for free" at both the login greeter and the lock
screen; for a *Hello-style glyph + animation* we add a small GNOME Shell extension that runs **only on
the lock screen** (not the boot greeter) — and that greeter gap is **good**, because it makes the
cold-boot first unlock use the PIN, which is exactly the at-rest posture the TPM design already depends
on. This is the architecture the maintained Rust/GNOME project **gaze** already ships.

---

## 1. The crux: the GDM greeter and the lock screen are two different processes

There are **two** `gnome-shell` processes, owned by two different users:

| | **GDM greeter** (boot login) | **Lock screen** (re-unlock) |
|---|---|---|
| Process owner | the `gdm` system user | your uid |
| gnome-shell mode | `gdm` (`isGreeter`, `LoginDialog`) | `unlock-dialog` (`isLocked`, `UnlockDialog`) |
| When | first login at boot, **no session yet** | unlock of an already-authenticated session |
| Loads *your* extensions? | **No** (different user, different dconf) | **Yes** (it's your own shell, locked) |

So a normal per-user GNOME Shell **extension runs on the lock screen but not in the GDM greeter** — the
greeter is a separate shell as the `gdm` user that never sees your `~/.local/.../extensions`. Running in
the greeter requires a *system-wide* install **and** enabling it for the `gdm` user **and**
`session-modes: ["gdm"]` — a locked-down, admin-only path we will not take.

Sources: gnome-shell `js/ui/sessionMode.js`; gjs.guide *Session Modes* / *Anatomy* (`session-modes`:
`user` / `unlock-dialog` / `gdm`, default `["user"]`, added GNOME 42); ArchWiki *GDM* (the `gdm`-user
greeter + its own dconf).

## 2. Why "first login uses the PIN, face only afterwards" is a feature, not a bug

The author's intuition was right and it's **security-positive**:

- It **mirrors the TPM at-rest model.** Cold boot is when the sealed key is released behind the **PIN
  authValue** and the login keyring is unlocked — that first authentication is the one that must be
  strong. After login the keyring stays unlocked in memory (GNOME does **not** re-lock it on session
  lock — ArchWiki *GNOME/Keyring*), so the lock screen is "only" a shield. Using the biometric leg for
  the *re-unlock convenience* case while keeping the boot login on the PIN is consistent with our stated
  stance: **biometric is host-trusted convenience, never the sole gate; the PIN authValue is the real
  TPM gate.**
- It matches **Windows Hello**, where biometric explicitly substitutes the *something-you-know* factor
  only "with the assurances that users can fall back" (Microsoft, *Hello for Business*).
- It sidesteps the most fragile, update-prone surface (the greeter) entirely and keeps us inside scope
  (no GDM patching, no fprintd changes).

**Document it plainly, don't overclaim:** *"Face unlock is available at the lock screen and for
re-authentication; the first sign-in after boot uses your PIN to establish the session."*

## 3. PAM conversation gives us text UI for free (the MVP)

A PAM module's only channel to the user is the **conversation function** (`PAM_TEXT_INFO`,
`PAM_ERROR_MSG`, `PAM_PROMPT_ECHO_OFF/ON`) — text only, no graphics. In GDM that conversation is
marshalled over D-Bus (`Gdm.UserVerifier`) and rendered by gnome-shell's `AuthPrompt` as a status label
under the password entry, **identically at the greeter and the lock screen**, with screen-reader
announcement. So emitting a short `PAM_TEXT_INFO("Looking for your face…")` and an `PAM_ERROR_MSG` on
failure already gives a styled status line **with zero GUI code** — and already beats Howdy (which shows
nothing and is infamous for a silent login pause).

**Critical constraint:** that text only renders if it rides the **foreground** `gdm-password` stack.
gnome-shell **suppresses** messages from non-foreground services (the way it suppresses fprintd's and
substitutes its own hard-coded "(or place finger on reader)" hint). So our helper should emit its status
on the foreground stack, staying strictly non-blocking (fork the watchdog'd helper, return fast, hard
timeout → PIN fallback).

Sources: `pam_conv(3)`; GDM `daemon/gdm-session.c` (PAM→D-Bus); gnome-shell `js/gdm/util.js`
(`ShellUserVerifier`), `js/gdm/authPrompt.js` (`AuthPrompt.setMessage`).

## 4. We can't piggyback fprintd's nice graphics

fprintd's fingerprint affordance (icon, "place finger" hint, error wiggle) is **special-cased in
gnome-shell**: hard-coded service name `gdm-fingerprint`, gated on a real **fprintd D-Bus device**
(`net.reactivated.Fprint`), with a hard-coded hint string and animation. There is **no generic biometric
registration** — no `gdm-face` path, no `subject_type` plumbing. A face service gets generic PAM text at
best. Lighting up native face graphics would require **patching gnome-shell**, which is out of scope.
(Also: the `gdm-fingerprint` parallel stack is only *started* when real fingerprint hardware is
detected, so it isn't a reliable home for a pure-face product.)

## 5. Wayland forbids a standalone overlay app

On Wayland, only the compositor's **privileged** lock client may draw while the session is locked
(`ext-session-lock-v1`; "the compositor may restrict this protocol to a special client launched by the
compositor itself"). On GNOME that privileged client **is gnome-shell**. Clients can't know global
positions, can't grab input, can't stack over the lock UI. So a separate "draw a scanning overlay" app
is **structurally impossible** on Wayland (Debian 13 GNOME is Wayland-by-default). The **only** way to
draw custom lock-screen UI is **in-process to gnome-shell — i.e. a Shell extension**. (X11 could do it
via override-redirect + keyboard grab — exactly the insecurity Wayland closed; not an option.)

Sources: Wayland *Protocol & Model of Operation*; `ext-session-lock-v1` (wayland.app).

## 6. Options compared

| Option | Boot greeter | Lock screen | sudo/polkit/tty | Wayland | Custom glyph/anim | Fragility |
|---|---|---|---|---|---|---|
| **(a) Pure PAM (text)** | ✅ text | ✅ text | ✅ | ✅ | ❌ | ⭐ very low (stable PAM ABI) |
| **(b) `unlock-dialog` extension** | ❌ (separate greeter) | ✅ full UI | ❌ | ✅ | ✅ | ⚠️ medium-high (Shell JS churns per release) |
| (c) Custom GDM greeter/theme | ✅ | ➖ | ❌ | ⚠️ | ✅ | 🚫 highest (distro-specific, update-reverted) |
| (d) Standalone overlay app | ❌ | 🚫 impossible on Wayland | ❌ | 🚫 | ✅ | 🚫 ruled out |
| (e) Hook GDM's fingerprint path | ➖ PAM only | ➖ | ➖ | ⚠️ | ❌ (no API) | 🚫 high (no contract; ≈ (c)) |

## 7. Prior art

- **GunduLabs/gaze** (Rust, GNOME, maintained) — **already ships exactly (a)+(b):** a `gazed` D-Bus
  daemon + `pam-gaze` PAM module (login/sudo) + a `gaze-gnome-extension` **for lock-screen auth** + a
  GTK4/Adwaita enrollment GUI; its installer only adds the extension when a GNOME session is detected,
  and toggles it via `gsettings`. Strong validation of the recommended split, and a near-exact model for
  our own daemon+PAM+extension shape.
- **boltgolt/howdy** — pure PAM (a), no UI; the canonical *login-blocking* anti-pattern our
  non-blocking watchdog design exists to avoid (issues: silent pause, login hangs, confusing fallback).
- **sovren-software/visage**, **Slimbook-Team/slimbookface**, **archledger/linhello**,
  **rexackermann/linux-hello**, **LLJY/howy** — all converge on **PAM for correctness + a separate
  management/UI**; none attempt native greeter graphics.

## 8. Recommendation (for when we pick this up)

Adopt the gaze-validated split; reject (c)/(d)/(e-UI).

1. **(a) PAM is the load-bearing MVP.** Non-blocking helper wired into `gdm-password` (foreground, so
   status text renders), the lock-unlock service, `sudo`, and `polkit`. Emit short
   `PAM_TEXT_INFO`/`PAM_ERROR_MSG` ("Looking for your face…" / "Got it" / "Couldn't recognize you").
   Universal coverage, lowest fragility, works on Wayland and X11. Watchdog timeout → PIN fallback
   (never freeze login). **This already gives a usable, Howdy-beating experience with no GUI.**
2. **(b) A thin `unlock-dialog` GNOME Shell extension for lock-screen polish.** `session-modes:
   ["user","unlock-dialog"]`; subscribes to the helper's scan state over D-Bus; renders an **abstract
   face/eye glyph + "Looking for you… → Got it"** (mirroring Hello — **no camera preview**, both for
   Wayland and privacy); auto-starts on lock presentation; keeps the password field visible as one-tap
   fallback. Keep all logic in the Rust daemon and the extension a dumb view, so the per-GNOME-release
   port is cheap. Must tolerate `enable()`/`disable()` churn on every lock/unlock transition.
3. **Embrace the greeter gap.** First sign-in after boot = PIN (the at-rest establishment moment);
   face for re-unlock. Documented as intended behavior.

**Scope/effort notes:** (a) is a natural extension of the existing PAM helper (mostly: choose the right
`pam.d` service wiring + emit conversation messages + a D-Bus status signal). (b) is a separate,
small JS/GJS component on its own branch with its own release cadence — explicitly *not* in the Rust
workspace, like the `tools/face-preview` precedent. Neither requires patching GDM, gnome-shell, or
fprintd. KDE/Plasma is a later, separate integration (its own lock UI + `kde-fingerprint` PAM).

---

### Primary sources
- gnome-shell `js/ui/sessionMode.js`, `js/gdm/util.js`, `js/gdm/authPrompt.js`
  (https://gitlab.gnome.org/GNOME/gnome-shell)
- GDM `daemon/gdm-session.c` (https://gitlab.gnome.org/GNOME/gdm)
- gjs.guide — Session Modes & Anatomy (https://gjs.guide/extensions/topics/session-modes.html,
  https://gjs.guide/extensions/overview/anatomy.html#session-modes)
- `pam_conv(3)` / `pam_prompt(3)` (https://www.man7.org/linux/man-pages/man3/pam_conv.3.html)
- Wayland model + `ext-session-lock-v1` (https://wayland.freedesktop.org/docs/html/ch04.html,
  https://wayland.app/protocols/ext-session-lock-v1)
- ArchWiki *GDM*, *GNOME/Keyring*, *Fprint* (incl. CVE-2024-37408)
- GunduLabs/gaze (https://github.com/GunduLabs/gaze); boltgolt/howdy (https://github.com/boltgolt/howdy)
- Microsoft *Windows Hello for Business* (https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/)
