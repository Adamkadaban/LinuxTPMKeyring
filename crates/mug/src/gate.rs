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

use tess_core::AuthGate;

use crate::camera::{IrEmitter, IrSource, capture_liveness_pair};
use crate::error::{MugError, Result};
use crate::liveness::{LivenessConfig, analyze};
use crate::matcher::{EmbeddingExtractor, Matcher};
use crate::store::FaceEnrollment;

/// Run the full face-verification pipeline within `deadline_ms`. Returns `Ok(())` only when the
/// captured pair is live *and* matches `enrolled` within `enrolled.match_threshold`; otherwise a
/// typed [`MugError`] (timeout, liveness rejection, or no match). The distance is checked against the
/// per-enrollment threshold (calibrated at enroll), not the matcher's global default.
pub fn verify<S, E, X>(
    source: &mut S,
    emitter: &mut E,
    matcher: &Matcher<X>,
    enrolled: &FaceEnrollment,
    liveness_cfg: &LivenessConfig,
    deadline_ms: u64,
) -> Result<()>
where
    S: IrSource,
    E: IrEmitter,
    X: EmbeddingExtractor,
{
    let pair = capture_liveness_pair(source, emitter, deadline_ms)?;
    // Liveness is a hard gate before identity: a rejected pair never reaches the matcher. The score
    // threshold comes from the per-enrollment calibration (captured at enroll), with the rest of the
    // gate parameters from the caller's config.
    let effective_cfg = LivenessConfig {
        score_threshold: enrolled.liveness.score_threshold,
        ..liveness_cfg.clone()
    };
    analyze(&pair, &effective_cfg)?.into_result()?;

    let distance = matcher.distance(&pair.emitter_on, &enrolled.embedding)?;
    if distance <= enrolled.match_threshold {
        Ok(())
    } else {
        Err(MugError::NoMatch {
            distance,
            threshold: enrolled.match_threshold,
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
        enrollment: FaceEnrollment,
        liveness_cfg: LivenessConfig,
    ) -> Self {
        Self {
            devices: RefCell::new((source, emitter)),
            matcher,
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
            &enrolled,
            &LivenessConfig::default(),
            2000,
        )
        .unwrap_err();
        assert!(matches!(err, MugError::NoMatch { .. }), "got {err:?}");
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
            enrolled,
            LivenessConfig::default(),
        );
        gate.authorize(2000).expect("face gate authorizes");
    }
}
