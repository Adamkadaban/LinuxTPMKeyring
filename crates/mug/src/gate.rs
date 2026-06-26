//! The bounded, non-blocking face authentication gate.
//!
//! [`verify`] composes the whole pipeline — capture an IR frame pair (bounded by the deadline),
//! gate it through active-illumination liveness, embed the emitter-ON frame, and match it against
//! the enrolled template — into one fallible operation. [`FaceGate`] wraps that behind
//! [`tess_core::AuthGate`] so the face factor slots into the same `authorize(deadline_ms)` interface
//! as the fingerprint gate. A pass releases the keyring key Hello-style; any failure (timeout,
//! liveness rejection, no match) is a typed error the caller turns into a PIN fallback — the gate
//! never blocks past its deadline and never decides the unlock on its own beyond returning success.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use tess_core::AuthGate;

use crate::align::{ALIGNED_FACE_SIZE, align_face};
use crate::camera::{FramePair, IrEmitter, IrFrame, IrSource};
use crate::detect::{FaceDetector, locate_and_align};
use crate::error::{MugError, Result};
use crate::liveness::{LivenessConfig, LivenessReport, analyze};
use crate::matcher::{EmbeddingExtractor, Matcher};
use crate::store::FaceEnrollment;

/// Target number of quality-gated identity frames to aggregate the match over (the liveness ON frame
/// plus warm follow-ups), bounded by the deadline. Aggregating shrinks the per-frame distance jitter.
const MATCH_FRAMES: usize = 5;
/// Minimum quality-gated frames required to make a decision. Fewer (deadline hit, or the detector
/// kept finding no face) is a no-decision → the caller falls through to the PIN. ≥3 means a single
/// transient frame can't carry the majority/median decision.
const MIN_MATCH_FRAMES: usize = 3;
/// Per-frame capture budget while collecting the warm identity frames (a warmed frame arrives well
/// within this; a slower one just yields fewer frames within the deadline).
const PER_FRAME_BUDGET_MS: u64 = 150;
/// Upper bound on warm captures per verify, on top of the wall-clock deadline: enough to warm up,
/// clear liveness, and collect `MATCH_FRAMES` identity frames while tolerating a few detection
/// misses, but bounded so an instant-capture source (the test substrate) can't busy-spin to the
/// deadline when no frame ever passes.
const MAX_CAPTURE_ATTEMPTS: usize = 12;

/// Run the full face-verification pipeline within `deadline_ms`. Returns `Ok(())` only when a
/// captured frame is live *and* the **majority** of quality-gated identity frames match `enrolled`
/// within `enrolled.match_threshold`; otherwise a typed [`MugError`] — e.g. timeout, liveness
/// rejection, insufficient frames, or no match, plus any propagated camera/emitter/matcher error.
///
/// Capture is one cold (emitter-OFF) baseline followed by a warm-frame loop. The **first** warm frame
/// with a detectable, live face clears the liveness gate (measured on the aligned face crop when a
/// `detector` is set, so the emitter return isn't diluted by the dark background); that frame and the
/// subsequent warm frames feed the identity median, and a frame with no detectable face is dropped
/// from the vote. Because the liveness frame is *selected* from the warm loop rather than fixed to a
/// single capture, a transient detection miss retries on the next warm frame instead of falling
/// straight through to the PIN — while a static spoof, which fails liveness on every frame, gains
/// nothing. Bounded by the wall-clock deadline and a capture cap, so it never blocks login.
pub fn verify<S, E, X>(
    source: &mut S,
    emitter: &mut E,
    matcher: &Matcher<X>,
    detector: Option<&dyn FaceDetector>,
    enrolled: &FaceEnrollment,
    liveness_cfg: &LivenessConfig,
    deadline_ms: u64,
) -> Result<()>
where
    S: IrSource,
    E: IrEmitter,
    X: EmbeddingExtractor,
{
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let effective_cfg = LivenessConfig {
        score_threshold: enrolled.liveness.score_threshold,
        ..liveness_cfg.clone()
    };

    // Cold OFF baseline (emitter off): the dark frame the liveness differential subtracts.
    emitter.set_enabled(false)?;
    let cold_off = source.capture((deadline_ms / 2).min(remaining_ms(deadline)))?;

    // Warm phase. Enable the emitter (restored OFF on every exit by the guard) and stream warm frames.
    // The first warm frame with a detectable, live face clears the liveness gate (cold vs that warm
    // crop); that frame and the subsequent warm frames feed the identity median. A frame with no
    // detectable face is skipped (detection retry) rather than failing the unlock, so a single missed
    // detection on a cold/unsettled frame no longer drops straight to the PIN. A static spoof fails
    // liveness on every frame, so the retry only rescues a genuine user — it does not weaken
    // anti-spoof. Bounded by the deadline and the capture cap, so login never blocks.
    let _emitter_off = EmitterOffGuard::enabled(emitter)?;
    let mut distances: Vec<f32> = Vec::with_capacity(MATCH_FRAMES);
    let mut live = false;
    let mut warmed = false;
    let mut last_reject: Option<MugError> = None;
    let mut attempts = 0usize;

    while distances.len() < MATCH_FRAMES && attempts < MAX_CAPTURE_ATTEMPTS {
        attempts += 1;
        let remaining = remaining_ms(deadline);
        if remaining == 0 {
            break;
        }
        // The first warm capture must stream long enough for the emitter to auto-warm; once warm,
        // later captures return immediately and take only the small per-frame budget.
        let budget = if warmed {
            remaining.min(PER_FRAME_BUDGET_MS)
        } else {
            remaining
        };
        let warm = match source.capture(budget) {
            Ok(frame) => {
                warmed = true;
                frame
            }
            // No frame in this slice; keep trying until the deadline / cap (bounded, never blocks).
            Err(MugError::Timeout(_)) => continue,
            Err(e) => return Err(e),
        };

        // Liveness gate on the first usable warm frame. A detection miss skips to the next frame; a
        // genuine liveness failure is remembered and retried (a spoof fails every frame anyway).
        if !live {
            let pair = FramePair::new(cold_off.clone(), warm.clone())?;
            match localized_liveness(&pair, detector, &effective_cfg) {
                Ok(report) if report.passed => live = true,
                Ok(report) => {
                    last_reject = Some(MugError::LivenessRejected(
                        report
                            .reason
                            .unwrap_or_else(|| "below liveness threshold".into()),
                    ));
                    continue;
                }
                Err(MugError::NoFace) => continue,
                Err(e) => return Err(e),
            }
        }

        // Identity distance for this (live) frame; a frame with no detectable face is dropped.
        if let Some(d) = frame_distance(matcher, detector, &warm, enrolled)? {
            distances.push(d);
        }
    }

    if !live {
        // A concrete liveness rejection (a face was seen but failed the gates) surfaces as
        // `LivenessRejected`; but if no frame ever reached the liveness gate — every warm capture
        // timed out or never yielded a detectable face — that is the camera being unavailable, which
        // must stay a `Timeout` at the `AuthGate` boundary, not be misclassified as an auth failure.
        return Err(last_reject.unwrap_or(MugError::Timeout(deadline_ms)));
    }
    decide_match(&mut distances, enrolled.match_threshold, MIN_MATCH_FRAMES)
}

/// Milliseconds left until `deadline`, saturating to 0. Bounds every capture so the gate stays within
/// its wall-clock deadline and never blocks login.
fn remaining_ms(deadline: Instant) -> u64 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_millis() as u64
}

/// RAII guard that enables the IR emitter for the warm identity loop and restores it to **OFF** on
/// drop — on success, a no-match, an early error, or a deadline break alike. Disabling is best-effort
/// (a failure is logged, never masks the real verify result), mirroring `capture_liveness_pair`.
struct EmitterOffGuard<'e, E: IrEmitter> {
    emitter: &'e mut E,
}

impl<'e, E: IrEmitter> EmitterOffGuard<'e, E> {
    fn enabled(emitter: &'e mut E) -> Result<Self> {
        emitter.set_enabled(true)?;
        Ok(Self { emitter })
    }
}

impl<E: IrEmitter> Drop for EmitterOffGuard<'_, E> {
    fn drop(&mut self) {
        if let Err(e) = self.emitter.set_enabled(false) {
            eprintln!(
                "mug: warning: failed to restore IR emitter to off after verify (best-effort): {e}"
            );
        }
    }
}

/// Liveness measured on the **aligned face crop** rather than the whole frame, when a detector is
/// configured: detect the face on the lit frame, align both the OFF and ON frames with those same
/// landmarks, and analyze the resulting crop pair. Whole-frame analysis dilutes the emitter return
/// across the dark IR background — the face's reflectance gradient is washed out — so on a real Brio
/// frame the whole-frame gradient gate rejects a genuine face while the crop passes cleanly. Without
/// a detector (the model-free mock path) it falls back to whole-frame analysis. A `NoFace` from the
/// detector propagates so the caller falls through to the PIN.
pub fn localized_liveness(
    pair: &FramePair,
    detector: Option<&dyn FaceDetector>,
    cfg: &LivenessConfig,
) -> Result<LivenessReport> {
    match detector {
        Some(d) => {
            let det = d.detect(&pair.emitter_on)?;
            let off_crop = align_face(&pair.emitter_off, &det.landmarks, ALIGNED_FACE_SIZE)?;
            let on_crop = align_face(&pair.emitter_on, &det.landmarks, ALIGNED_FACE_SIZE)?;
            let crop_pair = FramePair::new(off_crop, on_crop)?;
            analyze(&crop_pair, cfg)
        }
        None => analyze(pair, cfg),
    }
}

/// Distance of one frame to the enrolled template, or `None` when the frame fails the quality gate
/// (a detector is configured but found no face) so it is dropped from the vote instead of matched
/// against the background. Without a detector (model-free mock path) the frame is embedded directly.
fn frame_distance<X: EmbeddingExtractor>(
    matcher: &Matcher<X>,
    detector: Option<&dyn FaceDetector>,
    frame: &IrFrame,
    enrolled: &FaceEnrollment,
) -> Result<Option<f32>> {
    match detector {
        Some(d) => match locate_and_align(d, frame, ALIGNED_FACE_SIZE) {
            Ok(aligned) => Ok(Some(matcher.distance(&aligned, &enrolled.embedding)?)),
            Err(MugError::NoFace) => Ok(None),
            Err(e) => Err(e),
        },
        None => Ok(Some(matcher.distance(frame, &enrolled.embedding)?)),
    }
}

/// Decide identity by **majority**: the median distance over the quality-gated frames must clear the
/// threshold. Requires ≥`min_frames` frames (else a no-decision → PIN). The median means a single
/// transient below-threshold frame cannot authenticate an impostor (it is outvoted), while a genuine
/// user's occasional bad frame is tolerated. For an even count the upper-middle is used (conservative,
/// biasing toward false-reject — the PIN catches rejects).
fn decide_match(distances: &mut [f32], threshold: f32, min_frames: usize) -> Result<()> {
    if distances.len() < min_frames {
        return Err(MugError::InsufficientFrames {
            captured: distances.len(),
            required: min_frames,
        });
    }
    distances.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = distances[distances.len() / 2];
    if median <= threshold {
        Ok(())
    } else {
        Err(MugError::NoMatch {
            distance: median,
            threshold,
        })
    }
}

/// A [`tess_core::AuthGate`] over the face pipeline. Owns the IR source, emitter, matcher, and the
/// enrolled template, so `authorize` is a single bounded call. The source and emitter live behind a
/// `RefCell` because capture mutates them while [`AuthGate::authorize`] takes `&self`; the gate is
/// single-threaded (driven on one unlock/PAM-helper thread), so no cross-thread synchronization is
/// needed.
pub struct FaceGate<S, E, X>
where
    S: IrSource,
    E: IrEmitter,
    X: EmbeddingExtractor,
{
    devices: RefCell<(S, E)>,
    matcher: Matcher<X>,
    detector: Option<Box<dyn FaceDetector>>,
    enrollment: FaceEnrollment,
    liveness_cfg: LivenessConfig,
}

impl<S, E, X> FaceGate<S, E, X>
where
    S: IrSource,
    E: IrEmitter,
    X: EmbeddingExtractor,
{
    pub fn new(
        source: S,
        emitter: E,
        matcher: Matcher<X>,
        detector: Option<Box<dyn FaceDetector>>,
        enrollment: FaceEnrollment,
        liveness_cfg: LivenessConfig,
    ) -> Self {
        Self {
            devices: RefCell::new((source, emitter)),
            matcher,
            detector,
            enrollment,
            liveness_cfg,
        }
    }
}

impl<S, E, X> AuthGate for FaceGate<S, E, X>
where
    S: IrSource,
    E: IrEmitter,
    X: EmbeddingExtractor,
{
    /// Face is a host-trusted convenience gate: a pass releases the sealed key, with the PIN as the
    /// always-available fallback. Bounded by `deadline_ms`; never blocks past it.
    fn authorize(&self, deadline_ms: u64) -> tess_core::Result<()> {
        let mut devices = self.devices.borrow_mut();
        let (source, emitter) = &mut *devices;
        verify(
            source,
            emitter,
            &self.matcher,
            self.detector.as_deref(),
            &self.enrollment,
            &self.liveness_cfg,
            deadline_ms,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camera::{IrFrame, VirtualIrDevice};
    use crate::liveness::synth;
    use crate::matcher::PooledExtractor;
    use crate::store::{FaceEnrollment, LivenessCalibration};

    const W: u32 = 128;
    const H: u32 = 128;

    fn write_pair(dir: &std::path::Path, pair: &crate::camera::FramePair) {
        std::fs::write(
            dir.join(VirtualIrDevice::OFF_FRAME),
            pair.emitter_off.as_bytes(),
        )
        .unwrap();
        std::fs::write(
            dir.join(VirtualIrDevice::ON_FRAME),
            pair.emitter_on.as_bytes(),
        )
        .unwrap();
    }

    fn enroll_from(
        frame: &IrFrame,
        matcher: &Matcher<PooledExtractor>,
        threshold: f32,
    ) -> FaceEnrollment {
        FaceEnrollment::new(
            matcher.embed(frame).unwrap(),
            threshold,
            LivenessCalibration {
                enrolled_score: 0.9,
                score_threshold: LivenessConfig::default().score_threshold,
            },
        )
    }

    #[test]
    fn verify_passes_for_the_enrolled_live_face() {
        let dir = tempfile::tempdir().unwrap();
        let pair = synth::live_pair(W, H);
        write_pair(dir.path(), &pair);
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.34);
        let enrolled = enroll_from(&pair.emitter_on, &matcher, 0.34);

        let (mut source, mut emitter) = VirtualIrDevice::split(dir.path(), W, H);
        verify(
            &mut source,
            &mut emitter,
            &matcher,
            None,
            &enrolled,
            &LivenessConfig::default(),
            2000,
        )
        .expect("the enrolled live face must verify");
    }

    #[test]
    fn verify_rejects_a_spoof_on_liveness() {
        let dir = tempfile::tempdir().unwrap();
        let live = synth::live_pair(W, H);
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.34);
        let enrolled = enroll_from(&live.emitter_on, &matcher, 0.34);
        // Serve a screen spoof at verify time.
        write_pair(dir.path(), &synth::screen_pair(W, H));

        let (mut source, mut emitter) = VirtualIrDevice::split(dir.path(), W, H);
        let err = verify(
            &mut source,
            &mut emitter,
            &matcher,
            None,
            &enrolled,
            &LivenessConfig::default(),
            2000,
        )
        .unwrap_err();
        assert!(matches!(err, MugError::LivenessRejected(_)), "got {err:?}");
    }

    #[test]
    fn verify_rejects_a_different_live_face_on_distance() {
        let dir = tempfile::tempdir().unwrap();
        let enrolled_pair = synth::live_pair(W, H);
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.34);
        let enrolled = enroll_from(&enrolled_pair.emitter_on, &matcher, 0.05);
        // A spatially-reversed live face still passes liveness but embeds far from the enrolled one.
        let mut off = enrolled_pair.emitter_off.as_bytes().to_vec();
        let mut on = enrolled_pair.emitter_on.as_bytes().to_vec();
        off.reverse();
        on.reverse();
        std::fs::write(dir.path().join(VirtualIrDevice::OFF_FRAME), off).unwrap();
        std::fs::write(dir.path().join(VirtualIrDevice::ON_FRAME), on).unwrap();

        let (mut source, mut emitter) = VirtualIrDevice::split(dir.path(), W, H);
        let err = verify(
            &mut source,
            &mut emitter,
            &matcher,
            None,
            &enrolled,
            &LivenessConfig::default(),
            2000,
        )
        .unwrap_err();
        assert!(matches!(err, MugError::NoMatch { .. }), "got {err:?}");
    }

    #[test]
    fn verify_restores_the_emitter_to_off_after_the_warm_loop() {
        // Regression (PR #91 review): the warm multi-frame loop enables the IR emitter; it must be
        // restored to OFF on exit via the RAII guard, so verify never leaves the illuminator running.
        let dir = tempfile::tempdir().unwrap();
        let pair = synth::live_pair(W, H);
        write_pair(dir.path(), &pair);
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.34);
        let enrolled = enroll_from(&pair.emitter_on, &matcher, 0.34);

        let (mut source, mut emitter) = VirtualIrDevice::split(dir.path(), W, H);
        verify(
            &mut source,
            &mut emitter,
            &matcher,
            None,
            &enrolled,
            &LivenessConfig::default(),
            2000,
        )
        .expect("the enrolled live face must verify");

        // The shared emitter state drives which fixture the source returns; an OFF read proves the
        // guard restored the emitter (the warm loop had set it ON).
        let after = source.capture(0).expect("post-verify capture");
        assert_eq!(
            after.as_bytes(),
            pair.emitter_off.as_bytes(),
            "verify must restore the IR emitter to OFF on exit"
        );
    }

    #[test]
    fn face_gate_authorizes_through_the_authgate_trait() {
        let dir = tempfile::tempdir().unwrap();
        let pair = synth::live_pair(W, H);
        write_pair(dir.path(), &pair);
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.34);
        let enrolled = enroll_from(&pair.emitter_on, &matcher, 0.34);
        let (source, emitter) = VirtualIrDevice::split(dir.path(), W, H);

        let gate = FaceGate::new(
            source,
            emitter,
            matcher,
            None,
            enrolled,
            LivenessConfig::default(),
        );
        gate.authorize(2000).expect("face gate authorizes");
    }

    #[test]
    fn verify_aligns_with_a_detector_before_matching() {
        use crate::align::ALIGNED_FACE_SIZE;
        use crate::detect::{Detection, FixedDetector, locate_and_align};

        let dir = tempfile::tempdir().unwrap();
        let pair = synth::live_pair(W, H);
        write_pair(dir.path(), &pair);
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.34);

        // A detector that returns the canonical template landmarks => the aligned crop is
        // deterministic. Enroll from that same aligned crop so verify's aligned probe matches.
        let detector = FixedDetector::new(Detection {
            bbox: (0.0, 0.0, W as f32, H as f32),
            landmarks: crate::align::FaceLandmarks::new([
                (38.2946, 51.6963),
                (73.5318, 51.5014),
                (56.0252, 71.7366),
                (41.5493, 92.3655),
                (70.7299, 92.2041),
            ]),
            score: 1.0,
        });
        let aligned = locate_and_align(&detector, &pair.emitter_on, ALIGNED_FACE_SIZE).unwrap();
        let enrolled = FaceEnrollment::new(
            matcher.embed(&aligned).unwrap(),
            0.34,
            LivenessCalibration {
                enrolled_score: 0.9,
                score_threshold: LivenessConfig::default().score_threshold,
            },
        );

        let (mut source, mut emitter) = VirtualIrDevice::split(dir.path(), W, H);
        verify(
            &mut source,
            &mut emitter,
            &matcher,
            Some(&detector),
            &enrolled,
            &LivenessConfig::default(),
            2000,
        )
        .expect("the detector-aligned face must verify against its aligned enrollment");
    }

    fn fixed_face_detector() -> crate::detect::FixedDetector {
        use crate::detect::{Detection, FixedDetector};
        FixedDetector::new(Detection {
            bbox: (0.0, 0.0, W as f32, H as f32),
            landmarks: crate::align::FaceLandmarks::new([
                (38.2946, 51.6963),
                (73.5318, 51.5014),
                (56.0252, 71.7366),
                (41.5493, 92.3655),
                (70.7299, 92.2041),
            ]),
            score: 1.0,
        })
    }

    #[test]
    fn localized_liveness_passes_a_structured_face_crop() {
        // #79: with a detector, liveness runs on the aligned crop. A structured live face passes.
        let detector = fixed_face_detector();
        let report = localized_liveness(
            &synth::live_pair(W, H),
            Some(&detector),
            &LivenessConfig::default(),
        )
        .unwrap();
        assert!(
            report.passed,
            "a structured live-face crop must pass liveness: {:?}",
            report.features
        );
    }

    #[test]
    fn localized_liveness_rejects_a_uniform_whole_frame_step() {
        // #95 acceptance: a uniform whole-frame brightness step that isn't a structured face return
        // must be rejected even when a face is (claimed) present — the crop is still flat, so the
        // structure gates (std / gradient) reject it.
        let detector = fixed_face_detector();
        let report = localized_liveness(
            &synth::flat_photo_pair(W, H),
            Some(&detector),
            &LivenessConfig::default(),
        )
        .unwrap();
        assert!(
            !report.passed,
            "a uniform whole-frame step must be rejected on the crop: {:?}",
            report.features
        );
    }

    #[test]
    fn localized_liveness_propagates_no_face() {
        // No detectable face → liveness can't run on a crop → NoFace propagates (caller → PIN).
        struct NoFaceDetector;
        impl FaceDetector for NoFaceDetector {
            fn detect(&self, _frame: &IrFrame) -> Result<crate::detect::Detection> {
                Err(MugError::NoFace)
            }
        }
        let report = localized_liveness(
            &synth::live_pair(W, H),
            Some(&NoFaceDetector),
            &LivenessConfig::default(),
        );
        assert!(matches!(report, Err(MugError::NoFace)));
    }

    #[test]
    fn verify_retries_detection_within_the_warm_loop() {
        // Reliability (#79, seamless unlock): a transient detection miss on the first warm frames
        // must NOT drop straight to the PIN — the warm loop keeps capturing until a face is detected,
        // then proceeds with liveness + identity as normal.
        let (off, on_a, _on_b) = scripted_frames();
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.34);
        // Enroll from the aligned face using the always-detecting fixed detector.
        let enroll_det = fixed_face_detector();
        let aligned = locate_and_align(&enroll_det, &on_a, ALIGNED_FACE_SIZE).unwrap();
        let enrolled = FaceEnrollment::new(
            matcher.embed(&aligned).unwrap(),
            0.34,
            LivenessCalibration {
                enrolled_score: 0.9,
                score_threshold: LivenessConfig::default().score_threshold,
            },
        );

        // A detector that returns NoFace for its first two calls (transient cold-frame misses), then
        // finds the face at the same template landmarks the enrollment used.
        struct FlakyDetector {
            misses: std::cell::Cell<usize>,
        }
        impl FaceDetector for FlakyDetector {
            fn detect(&self, _frame: &IrFrame) -> Result<crate::detect::Detection> {
                let n = self.misses.get();
                if n > 0 {
                    self.misses.set(n - 1);
                    return Err(MugError::NoFace);
                }
                Ok(crate::detect::Detection {
                    bbox: (0.0, 0.0, W as f32, H as f32),
                    landmarks: crate::align::FaceLandmarks::new([
                        (38.2946, 51.6963),
                        (73.5318, 51.5014),
                        (56.0252, 71.7366),
                        (41.5493, 92.3655),
                        (70.7299, 92.2041),
                    ]),
                    score: 1.0,
                })
            }
        }
        let detector = FlakyDetector {
            misses: std::cell::Cell::new(2),
        };

        // 1 cold + 7 warm (the first 2 warm frames miss detection, the next 5 match).
        let frames = vec![
            off,
            on_a.clone(),
            on_a.clone(),
            on_a.clone(),
            on_a.clone(),
            on_a.clone(),
            on_a.clone(),
            on_a,
        ];
        let mut source = ScriptedSource {
            frames: frames.into(),
            w: W,
            h: H,
        };
        let mut emitter = NoopEmitter;
        verify(
            &mut source,
            &mut emitter,
            &matcher,
            Some(&detector),
            &enrolled,
            &LivenessConfig::default(),
            2000,
        )
        .expect("a transient detection miss must retry within the warm loop, not fall to the PIN");
    }

    #[test]
    fn decide_match_requires_a_majority() {
        // A clear, consistent match / non-match.
        assert!(decide_match(&mut [0.2, 0.2, 0.2, 0.2, 0.2], 0.6, 3).is_ok());
        assert!(matches!(
            decide_match(&mut [0.8, 0.8, 0.8, 0.8, 0.8], 0.6, 3),
            Err(MugError::NoMatch { .. })
        ));
        // One transient below-threshold frame among non-matches must NOT authenticate (the median is
        // outvoted) — this is the false-match the single-shot path allowed.
        assert!(matches!(
            decide_match(&mut [0.2, 0.8, 0.8, 0.8, 0.8], 0.6, 3),
            Err(MugError::NoMatch { .. })
        ));
        // One transient above-threshold frame among matches is tolerated (genuine user, noisy frame).
        assert!(decide_match(&mut [0.2, 0.2, 0.2, 0.2, 0.9], 0.6, 3).is_ok());
        // Too few quality-gated frames is a no-decision (caller falls through to the PIN).
        assert!(matches!(
            decide_match(&mut [0.2, 0.2], 0.6, 3),
            Err(MugError::InsufficientFrames {
                captured: 2,
                required: 3
            })
        ));
    }

    /// A source that serves a fixed queue of frames in order, then reports `Timeout` once drained,
    /// with a tiny sleep so a drained loop doesn't busy-spin. Paired with [`NoopEmitter`] it lets a
    /// test script the exact frames the multi-frame loop sees.
    struct ScriptedSource {
        frames: std::collections::VecDeque<IrFrame>,
        w: u32,
        h: u32,
    }
    impl IrSource for ScriptedSource {
        fn dimensions(&self) -> (u32, u32) {
            (self.w, self.h)
        }
        fn capture(&mut self, _deadline_ms: u64) -> Result<IrFrame> {
            match self.frames.pop_front() {
                Some(f) => Ok(f),
                None => {
                    std::thread::sleep(std::time::Duration::from_millis(3));
                    Err(MugError::Timeout(0))
                }
            }
        }
    }
    struct NoopEmitter;
    impl IrEmitter for NoopEmitter {
        fn set_enabled(&mut self, _on: bool) -> Result<()> {
            Ok(())
        }
    }

    /// Build the `(off, A, B)` frames for the scripted multi-frame tests: a live off/on pair (A is
    /// the enrolled face), and B a spatially-reversed live face that passes liveness but embeds far.
    fn scripted_frames() -> (IrFrame, IrFrame, IrFrame) {
        let live = synth::live_pair(W, H);
        let off = live.emitter_off.clone();
        let on_a = live.emitter_on.clone();
        let mut reversed = on_a.as_bytes().to_vec();
        reversed.reverse();
        let on_b = IrFrame::new(W, H, reversed).unwrap();
        (off, on_a, on_b)
    }

    #[test]
    fn verify_rejects_a_transient_false_match_among_impostor_frames() {
        let (off, on_a, on_b) = scripted_frames();
        // Tight threshold so the reversed face B is a genuine impostor (mirrors the single-frame test).
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.05);
        let enrolled = enroll_from(&on_a, &matcher, 0.05);
        // Mostly impostor B, with a single matching A frame in the middle.
        let frames = vec![off, on_b.clone(), on_a, on_b.clone(), on_b.clone(), on_b];
        let mut source = ScriptedSource {
            frames: frames.into(),
            w: W,
            h: H,
        };
        let mut emitter = NoopEmitter;
        let err = verify(
            &mut source,
            &mut emitter,
            &matcher,
            None,
            &enrolled,
            &LivenessConfig::default(),
            2000,
        )
        .unwrap_err();
        assert!(
            matches!(err, MugError::NoMatch { .. }),
            "a single matching frame among impostor frames must not authenticate: {err:?}"
        );
    }

    #[test]
    fn verify_accepts_a_consistently_matching_sequence() {
        let (off, on_a, _on_b) = scripted_frames();
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.05);
        let enrolled = enroll_from(&on_a, &matcher, 0.05);
        let frames = vec![
            off,
            on_a.clone(),
            on_a.clone(),
            on_a.clone(),
            on_a.clone(),
            on_a,
        ];
        let mut source = ScriptedSource {
            frames: frames.into(),
            w: W,
            h: H,
        };
        let mut emitter = NoopEmitter;
        verify(
            &mut source,
            &mut emitter,
            &matcher,
            None,
            &enrolled,
            &LivenessConfig::default(),
            2000,
        )
        .expect("a consistently-matching sequence must authenticate");
    }

    #[test]
    fn verify_with_a_stalled_warm_capture_times_out() {
        // A camera that yields the cold frame then stalls (never a usable warm frame, no liveness
        // rejection recorded) must surface Timeout — factor unavailable — not LivenessRejected, so the
        // error typing at the AuthGate boundary stays correct (timeouts remain timeouts).
        let (off, on_a, _on_b) = scripted_frames();
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.34);
        let enrolled = enroll_from(&on_a, &matcher, 0.34);
        let frames = vec![off]; // cold only; every warm capture stalls (drained → Timeout)
        let mut source = ScriptedSource {
            frames: frames.into(),
            w: W,
            h: H,
        };
        let mut emitter = NoopEmitter;
        let err = verify(
            &mut source,
            &mut emitter,
            &matcher,
            None,
            &enrolled,
            &LivenessConfig::default(),
            120,
        )
        .unwrap_err();
        assert!(
            matches!(err, MugError::Timeout(_)),
            "a stalled warm capture must surface Timeout, got {err:?}"
        );
    }

    #[test]
    fn verify_with_too_few_frames_is_a_no_decision() {
        let (off, on_a, _on_b) = scripted_frames();
        let matcher = Matcher::new(PooledExtractor::new(64).unwrap(), 0.05);
        let enrolled = enroll_from(&on_a, &matcher, 0.05);
        // Only the liveness pair's frames; the identity loop then runs out → too few to decide.
        let frames = vec![off, on_a];
        let mut source = ScriptedSource {
            frames: frames.into(),
            w: W,
            h: H,
        };
        let mut emitter = NoopEmitter;
        let err = verify(
            &mut source,
            &mut emitter,
            &matcher,
            None,
            &enrolled,
            &LivenessConfig::default(),
            120,
        )
        .unwrap_err();
        assert!(
            matches!(err, MugError::InsufficientFrames { .. }),
            "too few quality-gated frames must be a no-decision (→ PIN), got {err:?}"
        );
    }
}
