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

use crate::align::ALIGNED_FACE_SIZE;
use crate::camera::{IrEmitter, IrFrame, IrSource, capture_liveness_pair};
use crate::detect::{FaceDetector, locate_and_align};
use crate::error::{MugError, Result};
use crate::liveness::{LivenessConfig, analyze};
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

/// Run the full face-verification pipeline within `deadline_ms`. Returns `Ok(())` only when the
/// captured pair is live *and* the **majority** of quality-gated identity frames match `enrolled`
/// within `enrolled.match_threshold`; otherwise a typed [`MugError`] (timeout, liveness rejection,
/// insufficient frames, or no match). When `detector` is set each frame is located +
/// aligned before embedding (so the embedding describes the face, not the whole scene), and a frame
/// with no detectable face is dropped from the vote rather than matched against the background (so a
/// per-frame no-face never surfaces as an error — too few face frames becomes `InsufficientFrames`).
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

    // Liveness is a hard gate before identity: a rejected pair never reaches the matcher. The score
    // threshold comes from the per-enrollment calibration (captured at enroll), with the rest of the
    // gate parameters from the caller's config. `capture_liveness_pair` returns ~as soon as the
    // emitter has warmed, leaving the rest of the deadline for the warm identity frames below.
    let pair = capture_liveness_pair(source, emitter, deadline_ms)?;
    let effective_cfg = LivenessConfig {
        score_threshold: enrolled.liveness.score_threshold,
        ..liveness_cfg.clone()
    };
    analyze(&pair, &effective_cfg)?.into_result()?;

    // Multi-frame identity: aggregate the match over several quality-gated frames so a single
    // transient below-threshold frame can't authenticate (see ADR-0020). The liveness ON frame is
    // the first sample; the emitter is warm, so follow-up frames arrive quickly.
    let mut distances: Vec<f32> = Vec::with_capacity(MATCH_FRAMES);
    if let Some(d) = frame_distance(matcher, detector, &pair.emitter_on, enrolled)? {
        distances.push(d);
    }
    // Re-enable the emitter for the warm follow-up frames behind an RAII guard so it is restored to
    // OFF on *every* exit path (the deadline break, an early `?` error, or the final decision) —
    // matching `capture_liveness_pair`'s cleanup, so `verify` never leaves the IR illuminator on.
    let _emitter_off = EmitterOffGuard::enabled(emitter)?;
    while distances.len() < MATCH_FRAMES {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        if remaining == 0 {
            break;
        }
        match source.capture(remaining.min(PER_FRAME_BUDGET_MS)) {
            Ok(frame) => {
                if let Some(d) = frame_distance(matcher, detector, &frame, enrolled)? {
                    distances.push(d);
                }
            }
            // No frame in this slice; keep trying until the wall-clock deadline (bounded — `remaining`
            // shrinks every iteration and the loop breaks at 0).
            Err(MugError::Timeout(_)) => continue,
            Err(e) => return Err(e),
        }
    }

    decide_match(&mut distances, enrolled.match_threshold, MIN_MATCH_FRAMES)
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
