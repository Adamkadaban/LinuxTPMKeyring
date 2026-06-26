# 0022 — Login-UI: foreground PAM text + a pure-view unlock-dialog Shell extension

## Status

Proposed. Captures the decision for the seamless face-unlock login UI (issue #98) so a later
implementation phase doesn't relitigate it. No code ships under this ADR yet; it records the chosen
architecture and the alternatives rejected. Supersedes nothing.

## Context

Face unlock needs to *look* seamless — a Windows-Hello-style "Looking for you… / Got it" at the point of
authentication — without weakening the model (biometric is host-trusted convenience; the PIN authValue
is the real TPM gate) and without patching GDM, gnome-shell, or fprintd (out of scope).

Constraints established by research ([`gui-login-design.md`](../research/gui-login-design.md),
[`gui-login-integration.md`](../research/gui-login-integration.md)):

- **Debian 13 ships GNOME Shell 48** (ESM extension era); Wayland by default.
- On Wayland **only `gnome-shell` may draw on the lock screen** (`ext-session-lock-v1`) — a standalone
  overlay app is structurally impossible. Custom lock UI ⇒ an in-process Shell extension.
- The **GDM greeter and the lock screen are different `gnome-shell` processes** (gdm user vs the user);
  a per-user extension runs on the lock screen but **not** in the greeter.
- gnome-shell **suppresses** `PAM_TEXT_INFO` from non-foreground PAM services (this is howdy's silent
  pause); only the **foreground `gdm-password`** stack's text renders.
- A face-only GDM login **leaves the keyring locked** — fatal for tessera, whose purpose is unlocking
  the keyring; the keyring wrapping secret is derived from the **PIN authValue**, which face can't
  produce. So the first-login-uses-PIN gap is *required*, not merely tolerable.
- The reference project **GunduLabs/gaze** (MIT) ships a daemon + PAM + lock-screen extension, but paints
  its status text by **monkeypatching `ShellUserVerifier`** and launching a `gdm-face` background PAM
  service — a fragile dependence on private Shell internals that conflates "draw a glyph" with "drive
  auth."

## Decision

Ship the UI as **two decoupled layers**, and **diverge from gaze's monkeypatch transport**:

1. **Layer A — non-blocking PAM text (load-bearing MVP).** `pam_tess.so` on the **foreground
   `gdm-password`** stack, `[success=done default=ignore]`, forked watchdog'd helper with a hard
   timeout. Emits `PAM_TEXT_INFO`/`PAM_ERROR_MSG` so gnome-shell renders status at **both** greeter and
   lock screen with zero GUI code. Timeout/no-match always falls through to PIN/password (never freezes
   login). This alone beats howdy and is sufficient on its own.

2. **Layer B — pure-view `unlock-dialog` Shell extension (polish, lock-screen only).** A thin extension
   (`session-modes:["user","unlock-dialog"]`, `shell-version:["48"]`) that subscribes to a
   **root-owned system-bus signal** `org.tessera.ScanState1.StateChanged(s)` and draws an abstract
   face/eye glyph (no camera preview). It is a **pure view**: it exposes/uses no auth-influencing method.
   Rendered by **additive injection** of a child actor into the `UnlockDialog`, defensively guarded so a
   GNOME layout change degrades to "no glyph," not a crash.

3. **Embrace the greeter gap.** First sign-in after boot = PIN (establishes the session and unlocks the
   keyring); face for lock-screen re-unlock. Documented as intended behavior.

**Security invariants** (containment): the scan-state daemon owns its name as **root only**; the
extension subscribes with a **sender filter** (well-known name), so a forged signal from an unprivileged
process is dropped — and even if shown, the glyph is **advisory, never authoritative** (PAM+TPM hold the
only unlock authority; no daemon method can unlock anything). A forged "✓" is therefore cosmetic, never a
bypass.

## Consequences

- **Good:** Layer A is universal, lowest-fragility, Wayland+X11, and a natural extension of the existing
  PAM helper. Layer B is independently shippable, outside the Rust workspace (no `cargo vet`/supply-chain
  churn, like `tools/face-preview`), and can break on a GNOME upgrade without touching auth correctness.
  The trust boundary makes the lock-screen D-Bus channel safe to expose.
- **Cost:** Layer B depends on **private, unstable** Shell internals (`Main.screenShield._dialog`, the
  `UnlockDialog` actor tree) — must be re-verified against `unlockDialog.js`/`screenShield.js` on each
  GNOME major bump; pinned to GNOME 48 for now. The Shell re-runs `disable()`/`enable()` on every
  lock/unlock transition, so the extension must tolerate cold starts.
- **Scope:** no GDM/gnome-shell/fprintd patching; KDE/Plasma is a separate later integration.

## Alternatives considered

- **Monkeypatch `ShellUserVerifier` to route text (gaze's approach).** Rejected as the *primary*
  transport: fragile (private internals churn per release), and conflates view with auth. We keep the
  foreground PAM-conversation text (Layer A) for the *text* and use a clean D-Bus subscription for the
  *glyph* (Layer B).
- **Custom GDM greeter/theme.** Rejected — distro-specific, reverted on update, out of scope; and the
  greeter gap is desirable anyway.
- **Standalone overlay app drawing on the lock screen.** Rejected — impossible on Wayland.
- **Hook GDM's fingerprint graphics path (`gdm-fingerprint`).** Rejected — hard-coded to a real fprintd
  device, no generic face hook; would require patching gnome-shell.
- **Top-panel indicator instead of injecting the dialog.** Rejected — the panel is covered by the lock
  curtain, so it's invisible exactly when needed.
- **Publish scan-state on the session bus.** Rejected — the root auth-time producer has no session bus,
  and the greeter has no user session; the system bus is the only bus reachable by both producer and a
  locked consumer.
