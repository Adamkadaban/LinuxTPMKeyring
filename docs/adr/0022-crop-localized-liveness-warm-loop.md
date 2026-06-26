# 0022 — Liveness on the aligned face crop, with warm-loop detection retry

## Status

Accepted. Extends [ADR-0020](0020-passive-ir-liveness-and-multiframe-match.md) (passive IR liveness +
multi-frame median match); does not supersede it.

## Context

ADR-0020 settled *what* the liveness signal is (passive active-illumination IR, emitter OFF→ON
differential) and *how* identity is decided (median over quality-gated frames). Bring-up on the real
Brio exposed two problems with *where* and *when* that signal was measured:

1. **Whole-frame liveness rejects real faces.** The shipped gate analyzed the differential over the
   whole 340×340 IR frame. On a real face the structured reflectance return is a *small* part of a
   mostly-dark frame, so the gradient statistic is diluted: a genuine live face measured gradient
   ~2.4–3.6 against a 5.0 gate and was **rejected**, while the *same* face measured on the aligned
   crop measured ~9–12 and passes cleanly. Confirmed on hardware (`tools/face-collect`: whole-frame
   rejected 8/9 detected live frames; crop passed 9/9) and end-to-end (`tess face-test`: liveness
   score 0.81, gradient 9.3, identity match 0.0016). This is the #79 thesis.

2. **Single-shot detection drops to the PIN.** Liveness ran on exactly one captured pair; if the
   detector missed the one warm frame (cold/unsettled frame, or a transient miss), `verify` returned
   `NoFace` and fell straight to the PIN. Observed ~50 % first-try miss on a cold capture — a
   convenience factor that fails half the time isn't usable (the goal is Windows-Hello seamlessness).

## Decision

**1. Measure liveness on the aligned face crop.** `mug::localized_liveness(pair, detector, cfg)`
detects on the lit frame, aligns both OFF and ON frames with those landmarks, and analyzes the crop
pair; with no detector (model-free test path) it falls back to whole-frame analysis. Used by
`verify` (unlock), `MugTemplateSource` (enroll — so the enrolled liveness score calibrates on the
*same* signal `verify` checks), and `tess face-test`.

**2. Restructure `verify` to a cold baseline + warm-frame loop with detection retry.** Capture one
cold OFF baseline, then stream warm frames: the *first* warm frame with a detectable, live face
clears the liveness gate, and that frame plus the subsequent warm frames feed the identity median. A
frame with **no detectable face is skipped** (the next warm frame is tried) instead of failing the
unlock. Bounded by the wall-clock deadline and a capture cap (`MAX_CAPTURE_ATTEMPTS`), so it never
blocks login. Subsequent warm captures are cheap (the emitter stays auto-warmed while streaming), so
the retries fit the deadline.

**3. Name the real false-accept floor (carrying ADR-0020's median forward).** The median over warm
frames improves resilience to *transient* per-frame noise, but burst frames are statistically
**correlated** (Nandakumar/Ross/Jain, BTAS'09, exclude successive video frames from independence-based
fusion): aggregate FAR is **not** `far^K`, and the median does **not** defend a presentation attack or
look-alike that fools every correlated frame at once. The real false-accept floor is the **PIN
authValue + TPM dictionary-attack lockout**; the face leg is host-trusted convenience.

## Consequences

- Real faces pass liveness on commodity Brio hardware (the headline correctness fix); enrollment
  calibrates its liveness score on the crop, matching what `verify` checks.
- A transient detection miss **retries within the deadline** instead of dropping to the PIN, which is
  what makes the unlock feel seamless. A static spoof (photo/screen) fails liveness on **every** warm
  frame, so the retry rescues only a genuine user — it does **not** weaken anti-spoof.
- The gate stays non-blocking: the deadline + capture cap bound the loop; a wedged camera still
  degrades to the PIN within the watchdog budget.
- **Residual / follow-ups (documented, not closed here):**
  - The **enroll** path is still single-shot (no warm-loop retry); a detection miss fails the one-time,
    interactive enroll, which the user simply re-runs. Tracked as a follow-up.
  - #95's **randomized emitter timing** and **illumination-varied burst decorrelation** are
    impractical on the Brio's auto-warm streaming model (we don't control per-frame illumination — the
    emitter auto-warms and stays on while streaming). Documented as a hardware constraint rather than
    forced; face-localized liveness (#79) is the part of #95 that this delivers.
- Still **not** a guarantee against a fabricated 3-D mask or IR-faithful print (single passive IR
  sensor, no depth; no ISO/IEC 30107-3 PAD claim) — unchanged from ADR-0020. The PIN remains authoritative.

## Alternatives considered

- **Keep whole-frame liveness.** Rejected: it rejects genuine faces on real hardware (the bug this
  ADR fixes).
- **Retry the whole `capture_liveness_pair` on a miss.** Rejected: each pair re-cools then re-warms
  the emitter (~1.5 s), so a few re-captures don't fit a short PAM deadline, and against an
  instant-capture test source a wall-clock retry busy-spins. Selecting the liveness frame from the
  *already-warm* identity loop reuses cheap warm captures and is bounded by the capture cap.
- **Add a blink/motion challenge to "prove" liveness.** Rejected in ADR-0020 (friction,
  replay-defeatable, not what local IR systems do); unchanged.
- **Compute aggregate FAR as `far^K` and tighten the threshold accordingly.** Rejected: burst frames
  are correlated, so that overstates security; the PIN + anti-hammering are the FAR floor.
