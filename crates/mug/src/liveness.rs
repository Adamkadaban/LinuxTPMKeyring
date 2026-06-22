//! Active-illumination IR liveness — the anti-spoof core.
//!
//! # Signal
//!
//! With the camera's IR emitter OFF then ON we get a frame pair `(off, on)`. The per-pixel
//! **differential** `delta = max(0, on - off)` is the light the emitter put onto the scene and that
//! the scene reflected back. A real, 3-D, skin face close to the lens produces a *strong* and
//! *spatially structured* return: a reflectance gradient that follows facial geometry (nose/forehead
//! brighter than recessed eye sockets and edges), high-frequency skin texture, and a few localized
//! specular highlights. A flat printed photo returns a *weak and/or spatially uniform* delta; a
//! self-emitting screen has a *bright baseline even with the emitter off* and barely changes when the
//! emitter switches on.
//!
//! # Decision
//!
//! We compute robust statistics over the delta and apply **hard gates** (any one failing rejects the
//! pair, so a single inflated statistic can't carry a spoof) plus a composite **score** for
//! calibration/telemetry:
//!
//! - `mean_delta` — must clear [`LivenessConfig::min_mean_delta`]; rejects weak/distant/flat returns.
//! - `delta_std` — must clear [`LivenessConfig::min_delta_std`]; rejects spatially *uniform* returns
//!   (the signature of a flat photo lit evenly).
//! - `gradient_energy` — must clear [`LivenessConfig::min_gradient_energy`]; rejects *smooth* returns
//!   with no high-frequency relief (a curved/glossy photo can fake mean+std but not skin texture).
//! - screen-emission guard — a bright `baseline_mean` with a weak differential is a self-lit screen.
//! - saturation guard — a frame that is mostly saturated is screen glare, not a face.
//!
//! All statistics are deterministic, so the live-vs-spoof boundary is unit-tested with procedural
//! fixtures (see [`synth`]) rather than committed binaries or real faces.
//!
//! This raises the spoofing bar far above Howdy's (which has none); it is not a guarantee against a
//! fabricated 3-D mask. Face is convenience layered on the TPM PIN, never the sole gate.

use crate::camera::FramePair;
use crate::error::{MugError, Result};

/// Tunable thresholds for [`analyze`]. Pixel-domain values are on the 0..255 GREY scale.
#[derive(Debug, Clone)]
pub struct LivenessConfig {
    /// Minimum mean active-illumination return. Below this the scene barely reflected the emitter
    /// (too far, too flat, or a self-lit screen the emitter doesn't drive).
    pub min_mean_delta: f32,
    /// Minimum spatial standard deviation of the return. A flat photo lit evenly returns a near-
    /// uniform delta with low std even when its mean is high.
    pub min_delta_std: f32,
    /// Minimum mean gradient magnitude of the return — high-frequency 3-D relief / skin texture. A
    /// smooth gradient (curved glossy photo) clears mean+std but not this.
    pub min_gradient_energy: f32,
    /// A `baseline_mean` (emitter-off brightness) above this with a differential below
    /// [`LivenessConfig::emission_min_delta`] is treated as a self-emitting screen.
    pub max_baseline_for_live: f32,
    /// See [`LivenessConfig::max_baseline_for_live`].
    pub emission_min_delta: f32,
    /// Reject if more than this fraction of the ON frame is saturated (screen glare / overexposure).
    pub max_saturated_fraction: f32,
    /// Composite-score pass threshold in `[0, 1]`, applied in addition to the hard gates.
    pub score_threshold: f32,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            min_mean_delta: 12.0,
            min_delta_std: 16.0,
            min_gradient_energy: 5.0,
            max_baseline_for_live: 70.0,
            emission_min_delta: 20.0,
            max_saturated_fraction: 0.5,
            score_threshold: 0.45,
        }
    }
}

/// Pixel level at/above which a pixel counts as a specular highlight when its differential is also
/// strong.
const SPECULAR_LEVEL: u8 = 235;
/// Differential required alongside [`SPECULAR_LEVEL`] for a specular highlight.
const SPECULAR_MIN_DELTA: f32 = 40.0;
/// Pixel level at/above which a pixel counts as saturated for the glare guard.
const SATURATION_LEVEL: u8 = 250;

// Normalization references for the composite score's saturating sub-scores.
const MEAN_REF: f32 = 60.0;
const STD_REF: f32 = 45.0;
const GRAD_REF: f32 = 25.0;
const SPEC_REF: f32 = 0.02;

/// Statistics extracted from a frame pair.
#[derive(Debug, Clone)]
pub struct LivenessFeatures {
    pub mean_delta: f32,
    pub delta_std: f32,
    pub gradient_energy: f32,
    pub specular_fraction: f32,
    pub saturated_fraction: f32,
    pub baseline_mean: f32,
    /// Composite score in `[0, 1]`.
    pub score: f32,
}

/// Outcome of [`analyze`]: the features, the pass/fail verdict, and — when failed — the first hard
/// gate that rejected the pair.
#[derive(Debug, Clone)]
pub struct LivenessReport {
    pub features: LivenessFeatures,
    pub passed: bool,
    pub reason: Option<String>,
}

impl LivenessReport {
    /// Convert a failed report into a [`MugError::LivenessRejected`]; `Ok(features)` when it passed.
    pub fn into_result(self) -> Result<LivenessFeatures> {
        if self.passed {
            Ok(self.features)
        } else {
            Err(MugError::LivenessRejected(
                self.reason
                    .unwrap_or_else(|| "below liveness threshold".into()),
            ))
        }
    }
}

/// Analyze a frame pair for active-illumination liveness.
pub fn analyze(pair: &FramePair, cfg: &LivenessConfig) -> Result<LivenessReport> {
    let (w, h) = pair.dimensions();
    if w < 3 || h < 3 {
        return Err(MugError::InvalidFrame(format!(
            "frame too small for liveness analysis: {w}x{h}"
        )));
    }
    let off = pair.emitter_off.as_bytes();
    let on = pair.emitter_on.as_bytes();
    let n = off.len();

    let mut delta = vec![0f32; n];
    let mut sum_delta = 0f64;
    let mut specular = 0usize;
    let mut saturated = 0usize;
    let mut baseline_sum = 0f64;

    for i in 0..n {
        let d = (on[i] as f32 - off[i] as f32).max(0.0);
        delta[i] = d;
        sum_delta += d as f64;
        baseline_sum += off[i] as f64;
        if on[i] >= SPECULAR_LEVEL && d >= SPECULAR_MIN_DELTA {
            specular += 1;
        }
        if on[i] >= SATURATION_LEVEL {
            saturated += 1;
        }
    }

    let mean_delta = (sum_delta / n as f64) as f32;
    let baseline_mean = (baseline_sum / n as f64) as f32;

    let var: f64 = delta
        .iter()
        .map(|&d| {
            let c = d as f64 - mean_delta as f64;
            c * c
        })
        .sum::<f64>()
        / n as f64;
    let delta_std = var.sqrt() as f32;

    let gradient_energy = mean_gradient(&delta, w as usize, h as usize);
    let specular_fraction = specular as f32 / n as f32;
    let saturated_fraction = saturated as f32 / n as f32;

    let score = composite_score(mean_delta, delta_std, gradient_energy, specular_fraction);

    let features = LivenessFeatures {
        mean_delta,
        delta_std,
        gradient_energy,
        specular_fraction,
        saturated_fraction,
        baseline_mean,
        score,
    };

    let reason = first_failing_gate(&features, cfg);
    Ok(LivenessReport {
        passed: reason.is_none(),
        reason,
        features,
    })
}

/// Mean magnitude of the per-pixel forward gradient `|dΔ/dx| + |dΔ/dy|` over interior pixels.
fn mean_gradient(delta: &[f32], w: usize, h: usize) -> f32 {
    let mut sum = 0f64;
    let mut count = 0u64;
    for y in 0..h - 1 {
        for x in 0..w - 1 {
            let c = delta[y * w + x];
            let dx = (delta[y * w + x + 1] - c).abs();
            let dy = (delta[(y + 1) * w + x] - c).abs();
            sum += (dx + dy) as f64;
            count += 1;
        }
    }
    if count == 0 {
        0.0
    } else {
        (sum / count as f64) as f32
    }
}

fn composite_score(mean_delta: f32, delta_std: f32, gradient: f32, specular: f32) -> f32 {
    let s_mean = (mean_delta / MEAN_REF).clamp(0.0, 1.0);
    let s_std = (delta_std / STD_REF).clamp(0.0, 1.0);
    let s_grad = (gradient / GRAD_REF).clamp(0.0, 1.0);
    let s_spec = (specular / SPEC_REF).clamp(0.0, 1.0);
    0.30 * s_mean + 0.30 * s_std + 0.30 * s_grad + 0.10 * s_spec
}

/// Return the first hard gate that rejects the pair, or `None` if all gates and the score pass.
fn first_failing_gate(f: &LivenessFeatures, cfg: &LivenessConfig) -> Option<String> {
    if f.mean_delta < cfg.min_mean_delta {
        return Some(format!(
            "weak active-illumination return (mean delta {:.1} < {:.1}); flat, distant, or screen",
            f.mean_delta, cfg.min_mean_delta
        ));
    }
    if f.baseline_mean > cfg.max_baseline_for_live && f.mean_delta < cfg.emission_min_delta {
        return Some(format!(
            "bright IR baseline {:.1} with weak differential {:.1}; likely a self-emitting screen",
            f.baseline_mean, f.mean_delta
        ));
    }
    if f.saturated_fraction > cfg.max_saturated_fraction {
        return Some(format!(
            "excessive saturation ({:.0}% of frame); likely screen glare",
            f.saturated_fraction * 100.0
        ));
    }
    if f.delta_std < cfg.min_delta_std {
        return Some(format!(
            "spatially uniform return (delta std {:.1} < {:.1}); likely a flat photo",
            f.delta_std, cfg.min_delta_std
        ));
    }
    if f.gradient_energy < cfg.min_gradient_energy {
        return Some(format!(
            "no 3-D relief in IR return (gradient {:.1} < {:.1}); likely a smooth/glossy photo",
            f.gradient_energy, cfg.min_gradient_energy
        ));
    }
    if f.score < cfg.score_threshold {
        return Some(format!(
            "composite liveness score {:.2} < {:.2}",
            f.score, cfg.score_threshold
        ));
    }
    None
}

/// Procedural synthetic IR frame-pair generators for tests and self-checks. No committed binaries,
/// no real faces: a deterministic PRNG drives skin texture so the live-vs-spoof boundary is
/// reproducible. These model the *statistics* the analyzer keys on, not photorealistic images.
pub mod synth {
    use crate::camera::{FramePair, IrFrame};

    /// Tiny deterministic xorshift PRNG so fixtures need no `rand` dependency and never flake.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed | 1)
        }
        fn next_u32(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            (x >> 32) as u32
        }
        /// Signed noise in `[-mag, mag]`.
        fn noise(&mut self, mag: f32) -> f32 {
            let u = (self.next_u32() as f32 / u32::MAX as f32) * 2.0 - 1.0;
            u * mag
        }
    }

    fn clamp_u8(v: f32) -> u8 {
        v.clamp(0.0, 255.0) as u8
    }

    fn gaussian(dx: f32, dy: f32, sigma: f32) -> f32 {
        (-(dx * dx + dy * dy) / (2.0 * sigma * sigma)).exp()
    }

    /// A live 3-D face: strong structured return = radial reflectance falloff (center/nose bright) +
    /// feature relief (brow, cheeks, dark eye sockets) + high-frequency skin texture + a couple of
    /// localized speculars. Passes every gate.
    pub fn live_pair(w: u32, h: u32) -> FramePair {
        let (wf, hf) = (w as f32, h as f32);
        let (cx, cy) = (wf / 2.0, hf * 0.46);
        let sigma = wf * 0.30;
        let mut rng = Rng::new(0x11FE_5EED ^ ((w as u64) << 16) ^ h as u64);
        let mut off = vec![0u8; (w * h) as usize];
        let mut on = vec![0u8; (w * h) as usize];

        for y in 0..h {
            for x in 0..w {
                let i = (y * w + x) as usize;
                let base = 10.0 + rng.noise(2.0);
                off[i] = clamp_u8(base);

                let (fx, fy) = (x as f32, y as f32);
                // Smooth reflectance falloff following the rough face shape.
                let mut refl = 120.0 * gaussian(fx - cx, fy - cy, sigma);
                // Feature relief: bright nose ridge + cheeks, dark recessed eye sockets.
                refl += 70.0 * gaussian(fx - cx, fy - cy * 1.15, sigma * 0.18); // nose
                refl -= 55.0 * gaussian(fx - cx * 0.62, fy - hf * 0.40, sigma * 0.16); // L eye
                refl -= 55.0 * gaussian(fx - cx * 1.38, fy - hf * 0.40, sigma * 0.16); // R eye
                                                                                       // High-frequency skin texture — the key to gradient energy / relief.
                refl += rng.noise(10.0);
                // A couple of small specular highlights (nose tip, forehead).
                refl += 200.0 * gaussian(fx - cx, fy - cy * 1.05, sigma * 0.05);
                refl += 160.0 * gaussian(fx - cx, fy - hf * 0.30, sigma * 0.05);

                on[i] = clamp_u8(base + refl.max(0.0));
            }
        }
        FramePair::new(
            IrFrame::new(w, h, off).unwrap(),
            IrFrame::new(w, h, on).unwrap(),
        )
        .unwrap()
    }

    /// A flat printed photo lit evenly: a strong but spatially *uniform* return. Clears the mean gate
    /// but fails the structure (std / gradient) gates.
    pub fn flat_photo_pair(w: u32, h: u32) -> FramePair {
        let mut rng = Rng::new(0xF1A7);
        let mut off = vec![0u8; (w * h) as usize];
        let mut on = vec![0u8; (w * h) as usize];
        for i in 0..(w * h) as usize {
            let base = 10.0 + rng.noise(2.0);
            off[i] = clamp_u8(base);
            on[i] = clamp_u8(base + 45.0 + rng.noise(2.0));
        }
        FramePair::new(
            IrFrame::new(w, h, off).unwrap(),
            IrFrame::new(w, h, on).unwrap(),
        )
        .unwrap()
    }

    /// A curved / glossy photo: a *smooth* high-amplitude radial return with no skin texture. Fakes
    /// the mean and std gates but fails the gradient/relief gate — the reason that gate exists.
    pub fn glossy_photo_pair(w: u32, h: u32) -> FramePair {
        let (wf, hf) = (w as f32, h as f32);
        let (cx, cy) = (wf / 2.0, hf / 2.0);
        let sigma = wf * 0.32;
        let mut rng = Rng::new(0x6105);
        let mut off = vec![0u8; (w * h) as usize];
        let mut on = vec![0u8; (w * h) as usize];
        for y in 0..h {
            for x in 0..w {
                let i = (y * w + x) as usize;
                let base = 10.0 + rng.noise(1.0);
                off[i] = clamp_u8(base);
                let refl = 140.0 * gaussian(x as f32 - cx, y as f32 - cy, sigma);
                on[i] = clamp_u8(base + refl);
            }
        }
        FramePair::new(
            IrFrame::new(w, h, off).unwrap(),
            IrFrame::new(w, h, on).unwrap(),
        )
        .unwrap()
    }

    /// A self-emitting screen (phone/LCD playing a face): a *bright baseline even with the emitter
    /// off*, barely changing when it switches on. Fails the mean gate and the screen-emission guard.
    pub fn screen_pair(w: u32, h: u32) -> FramePair {
        let mut rng = Rng::new(0x5C2EE);
        let mut off = vec![0u8; (w * h) as usize];
        let mut on = vec![0u8; (w * h) as usize];
        for i in 0..(w * h) as usize {
            let base = 120.0 + rng.noise(6.0);
            off[i] = clamp_u8(base);
            on[i] = clamp_u8(base + 6.0 + rng.noise(6.0));
        }
        FramePair::new(
            IrFrame::new(w, h, off).unwrap(),
            IrFrame::new(w, h, on).unwrap(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: u32 = 128;
    const H: u32 = 128;

    #[test]
    fn live_pair_passes_all_gates() {
        let pair = synth::live_pair(W, H);
        let report = analyze(&pair, &LivenessConfig::default()).unwrap();
        assert!(
            report.passed,
            "live pair must pass; reason={:?} features={:?}",
            report.reason, report.features
        );
    }

    #[test]
    fn flat_photo_is_rejected_for_uniformity() {
        let pair = synth::flat_photo_pair(W, H);
        let report = analyze(&pair, &LivenessConfig::default()).unwrap();
        assert!(
            !report.passed,
            "flat photo must be rejected: {:?}",
            report.features
        );
        // It must clear the mean gate (strong delta) and be rejected specifically on structure.
        assert!(report.features.mean_delta >= LivenessConfig::default().min_mean_delta);
        assert!(report.features.delta_std < LivenessConfig::default().min_delta_std);
    }

    #[test]
    fn glossy_photo_is_rejected_for_no_relief() {
        let cfg = LivenessConfig::default();
        let pair = synth::glossy_photo_pair(W, H);
        let report = analyze(&pair, &cfg).unwrap();
        assert!(
            !report.passed,
            "glossy photo must be rejected: {:?}",
            report.features
        );
        // Smooth gradient fakes mean+std but has no high-frequency relief.
        assert!(report.features.gradient_energy < cfg.min_gradient_energy);
    }

    #[test]
    fn screen_is_rejected_for_emission() {
        let pair = synth::screen_pair(W, H);
        let report = analyze(&pair, &LivenessConfig::default()).unwrap();
        assert!(
            !report.passed,
            "screen must be rejected: {:?}",
            report.features
        );
        assert!(report.features.baseline_mean > LivenessConfig::default().max_baseline_for_live);
    }

    #[test]
    fn live_scores_strictly_above_every_spoof() {
        let live = analyze(&synth::live_pair(W, H), &LivenessConfig::default())
            .unwrap()
            .features
            .score;
        for spoof in [
            synth::flat_photo_pair(W, H),
            synth::glossy_photo_pair(W, H),
            synth::screen_pair(W, H),
        ] {
            let s = analyze(&spoof, &LivenessConfig::default())
                .unwrap()
                .features
                .score;
            assert!(live > s, "live score {live} must exceed spoof score {s}");
        }
    }

    #[test]
    fn into_result_maps_rejection_to_error() {
        let report = analyze(&synth::screen_pair(W, H), &LivenessConfig::default()).unwrap();
        assert!(matches!(
            report.into_result(),
            Err(MugError::LivenessRejected(_))
        ));
    }

    #[test]
    fn tiny_frames_error_rather_than_panic() {
        let pair = FramePair::new(
            crate::camera::IrFrame::new(2, 2, vec![0; 4]).unwrap(),
            crate::camera::IrFrame::new(2, 2, vec![0; 4]).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            analyze(&pair, &LivenessConfig::default()),
            Err(MugError::InvalidFrame(_))
        ));
    }
}
