//! Pluggable IR face matcher.
//!
//! tess ships **no** face model. The embedding extractor is abstracted behind
//! [`EmbeddingExtractor`] so the real backend (an ArcFace/SFace ONNX network run via `ort`, operating
//! on the GREY IR crop, Hello-style) is a drop-in whose model path comes from configuration — and so
//! the headless test suite needs no model at all, driving a deterministic mock instead. When no
//! extractor is configured the face factor is simply unavailable and the caller degrades to the PIN.
//!
//! Matching is cosine-distance against the enrolled embedding with a tunable threshold. The matcher
//! never holds key material; a liveness-gated match authorizes the unlock, with the PIN as fallback.

use crate::camera::IrFrame;
use crate::error::{MugError, Result};

/// An L2-normalized face embedding.
pub type Embedding = Vec<f32>;

/// Extracts a face embedding from an IR frame. Implementations should return an L2-normalized vector
/// of fixed [`EmbeddingExtractor::dim`] length.
pub trait EmbeddingExtractor {
    /// Embedding dimensionality.
    fn dim(&self) -> usize;
    /// Extract an embedding from a GREY IR frame.
    fn extract(&self, frame: &IrFrame) -> Result<Embedding>;
}

/// Cosine distance `1 - cos(a, b)` in `[0, 2]`. Inputs are normalized defensively so callers can pass
/// raw or pre-normalized vectors. Returns an error on a length mismatch rather than panicking.
pub fn cosine_distance(a: &[f32], b: &[f32]) -> Result<f32> {
    if a.len() != b.len() {
        return Err(MugError::InvalidFrame(format!(
            "embedding length mismatch: {} vs {}",
            a.len(),
            b.len()
        )));
    }
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        return Err(MugError::InvalidFrame("zero-magnitude embedding".into()));
    }
    Ok((1.0 - (dot / (na * nb))).clamp(0.0, 2.0))
}

/// A face matcher: an embedding extractor plus a cosine-distance acceptance threshold.
pub struct Matcher<X: EmbeddingExtractor> {
    extractor: X,
    threshold: f32,
}

impl<X: EmbeddingExtractor> Matcher<X> {
    /// Build a matcher. `threshold` is the maximum cosine distance accepted as a match.
    pub fn new(extractor: X, threshold: f32) -> Self {
        Self {
            extractor,
            threshold,
        }
    }

    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    pub fn dim(&self) -> usize {
        self.extractor.dim()
    }

    /// Compute the embedding for `frame` (e.g. at enroll time).
    pub fn embed(&self, frame: &IrFrame) -> Result<Embedding> {
        self.extractor.extract(frame)
    }

    /// Cosine distance between `frame` and an enrolled embedding (no thresholding).
    pub fn distance(&self, frame: &IrFrame, enrolled: &Embedding) -> Result<f32> {
        let candidate = self.extractor.extract(frame)?;
        cosine_distance(&candidate, enrolled)
    }

    /// Verify `frame` against `enrolled`. Returns the matching distance on success, or
    /// [`MugError::NoMatch`] when it exceeds the threshold.
    pub fn verify(&self, frame: &IrFrame, enrolled: &Embedding) -> Result<f32> {
        let distance = self.distance(frame, enrolled)?;
        if distance <= self.threshold {
            Ok(distance)
        } else {
            Err(MugError::NoMatch {
                distance,
                threshold: self.threshold,
            })
        }
    }
}

/// A deterministic, model-free embedding extractor for tests and self-checks: average-pool the GREY
/// frame into `dim` buckets and L2-normalize. Identical frames yield identical embeddings; frames
/// with different spatial brightness distributions yield distant ones — enough to exercise the
/// cosine-distance/threshold logic without an ONNX model. **Not** a real face recognizer.
pub struct PooledExtractor {
    dim: usize,
}

impl PooledExtractor {
    pub fn new(dim: usize) -> Self {
        assert!(dim > 0, "embedding dim must be positive");
        Self { dim }
    }
}

impl EmbeddingExtractor for PooledExtractor {
    fn dim(&self) -> usize {
        self.dim
    }

    fn extract(&self, frame: &IrFrame) -> Result<Embedding> {
        let bytes = frame.as_bytes();
        if bytes.is_empty() {
            return Err(MugError::InvalidFrame("empty frame".into()));
        }
        let mut sums = vec![0f64; self.dim];
        let mut counts = vec![0u64; self.dim];
        let n = bytes.len();
        for (i, &p) in bytes.iter().enumerate() {
            // Contiguous segmentation of the flattened frame into `dim` buckets.
            let bucket = (i * self.dim) / n;
            sums[bucket] += p as f64;
            counts[bucket] += 1;
        }
        let mut emb: Vec<f32> = sums
            .iter()
            .zip(&counts)
            .map(|(&s, &c)| if c == 0 { 0.0 } else { (s / c as f64) as f32 })
            .collect();
        // Mean-center so the embedding encodes the *spatial brightness structure* rather than the
        // overall illumination level — otherwise every all-positive brightness vector clusters in
        // cosine space and distinct scenes look similar. A featureless (uniform) frame centers to
        // near-zero and is rejected as un-embeddable, which is the right call for a blank capture.
        let mean: f32 = emb.iter().sum::<f32>() / emb.len() as f32;
        for v in &mut emb {
            *v -= mean;
        }
        let norm: f32 = emb.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm <= f32::EPSILON {
            return Err(MugError::InvalidFrame(
                "frame has no spatial structure to embed".into(),
            ));
        }
        for v in &mut emb {
            *v /= norm;
        }
        Ok(emb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::synth;

    fn on_frame(pair: crate::camera::FramePair) -> IrFrame {
        pair.emitter_on
    }

    #[test]
    fn identical_frame_matches() {
        let matcher = Matcher::new(PooledExtractor::new(64), 0.15);
        let frame = on_frame(synth::live_pair(128, 128));
        let enrolled = matcher.embed(&frame).unwrap();
        let d = matcher.verify(&frame, &enrolled).unwrap();
        assert!(d <= 1e-5, "identical frame distance should be ~0, got {d}");
    }

    #[test]
    fn different_distribution_does_not_match() {
        let matcher = Matcher::new(PooledExtractor::new(64), 0.15);
        let enrolled = matcher
            .embed(&on_frame(synth::live_pair(128, 128)))
            .unwrap();
        // A flat/screen frame has a very different spatial brightness distribution.
        let other = on_frame(synth::screen_pair(128, 128));
        let err = matcher.verify(&other, &enrolled).unwrap_err();
        assert!(
            matches!(err, MugError::NoMatch { .. }),
            "expected NoMatch, got {err:?}"
        );
    }

    #[test]
    fn cosine_distance_rejects_length_mismatch() {
        assert!(cosine_distance(&[1.0, 0.0], &[1.0]).is_err());
    }

    #[test]
    fn cosine_distance_of_equal_vectors_is_zero() {
        let v = [0.2f32, 0.4, 0.4];
        let d = cosine_distance(&v, &v).unwrap();
        assert!(d.abs() < 1e-6);
    }
}
