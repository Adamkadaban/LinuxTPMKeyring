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
    let cosine = dot / (na * nb);
    if !cosine.is_finite() {
        // NaN/Inf inputs would clamp to NaN and escape the [0, 2] contract — reject instead.
        return Err(MugError::InvalidFrame(
            "non-finite cosine (NaN/Inf in embedding)".into(),
        ));
    }
    Ok((1.0 - cosine).clamp(0.0, 2.0))
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
    /// Build an extractor producing `dim`-length embeddings. `dim == 0` is rejected as
    /// [`MugError::MatcherUnavailable`] rather than panicking, since a zero dim can arrive from
    /// wave-2 config/plumbing and must degrade to the PIN, not abort.
    pub fn new(dim: usize) -> Result<Self> {
        if dim == 0 {
            return Err(MugError::MatcherUnavailable(
                "embedding dim must be positive".into(),
            ));
        }
        Ok(Self { dim })
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
            // Contiguous segmentation of the flattened frame into `dim` buckets. Use a u128
            // intermediate so a large `dim` (misconfigured) can't overflow `i * dim`.
            let bucket = ((i as u128 * self.dim as u128) / n as u128) as usize;
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

/// Lets a `Matcher` hold a boxed trait object, so a caller can pick the mock or a real backend at
/// runtime behind one `Matcher<Box<dyn EmbeddingExtractor>>` type.
impl EmbeddingExtractor for Box<dyn EmbeddingExtractor> {
    fn dim(&self) -> usize {
        (**self).dim()
    }
    fn extract(&self, frame: &IrFrame) -> Result<Embedding> {
        (**self).extract(frame)
    }
}

/// L2-normalize in place; returns an error if the vector has (near-)zero norm.
#[cfg(feature = "face-model")]
fn l2_normalize(emb: &mut [f32]) -> Result<()> {
    let norm = emb
        .iter()
        .map(|v| (*v as f64) * (*v as f64))
        .sum::<f64>()
        .sqrt();
    if !norm.is_finite() || norm <= f64::EPSILON {
        return Err(MugError::MatcherUnavailable(format!(
            "model produced a degenerate embedding (norm {norm}); not finite or near zero"
        )));
    }
    for v in emb.iter_mut() {
        *v = (*v as f64 / norm) as f32;
    }
    Ok(())
}

/// Nearest-neighbour resize of a GREY frame to `dst_w` x `dst_h`.
#[cfg(feature = "face-model")]
fn resize_gray(frame: &IrFrame, dst_w: usize, dst_h: usize) -> Vec<u8> {
    let (sw, sh) = (frame.width() as usize, frame.height() as usize);
    let src = frame.as_bytes();
    let mut out = vec![0u8; dst_w * dst_h];
    for y in 0..dst_h {
        let sy = if dst_h == 1 { 0 } else { y * sh / dst_h };
        for x in 0..dst_w {
            let sx = if dst_w == 1 { 0 } else { x * sw / dst_w };
            out[y * dst_w + x] = src[sy.min(sh - 1) * sw + sx.min(sw - 1)];
        }
    }
    out
}

/// A `tract`-backed ONNX face-embedding extractor (self-contained inference; no native ONNX Runtime,
/// though `tract` builds some SIMD kernels via `cc`, so a build-time C toolchain is required).
///
/// Loads a user-supplied fixed-shape NCHW model (e.g. ArcFace/SFace) and runs it on the GREY IR
/// crop. **No model ships with tess** — the path is supplied at runtime; when absent the caller
/// uses the deterministic mock and face is a liveness-gated convenience. Pixels are mapped to
/// `(p - 127.5) / 127.5` (the common ArcFace/SFace input scaling); a multi-channel model receives
/// the grayscale plane replicated across channels.
#[cfg(feature = "face-model")]
pub struct TractExtractor {
    model: std::sync::Arc<tract_onnx::prelude::TypedRunnableModel>,
    channels: usize,
    height: usize,
    width: usize,
    dim: usize,
}

#[cfg(feature = "face-model")]
impl TractExtractor {
    /// Load and optimize the ONNX model at `path`, deriving the input geometry and embedding
    /// dimensionality from the model's own input/output facts (which must be fully concrete).
    pub fn from_path(path: &str) -> Result<Self> {
        use tract_onnx::prelude::*;

        let typed = tract_onnx::onnx()
            .model_for_path(path)
            .map_err(|e| MugError::MatcherUnavailable(format!("load ONNX model {path}: {e}")))?
            .into_optimized()
            .map_err(|e| {
                MugError::MatcherUnavailable(format!("optimize ONNX model {path}: {e}"))
            })?;

        let input_shape = typed
            .input_fact(0)
            .map_err(|e| MugError::MatcherUnavailable(format!("read model input fact: {e}")))?
            .shape
            .as_concrete()
            .ok_or_else(|| {
                MugError::MatcherUnavailable(
                    "model input shape is not fully concrete; supply a fixed-shape face model"
                        .into(),
                )
            })?
            .to_vec();
        if input_shape.len() != 4 || input_shape[0] != 1 {
            return Err(MugError::MatcherUnavailable(format!(
                "expected an NCHW input of shape [1, C, H, W], got {input_shape:?}"
            )));
        }
        let (channels, height, width) = (input_shape[1], input_shape[2], input_shape[3]);

        let dim = typed
            .output_fact(0)
            .map_err(|e| MugError::MatcherUnavailable(format!("read model output fact: {e}")))?
            .shape
            .as_concrete()
            .and_then(|s| s.last().copied())
            .ok_or_else(|| {
                MugError::MatcherUnavailable("model output dimensionality is not concrete".into())
            })?;

        let model = typed
            .into_runnable()
            .map_err(|e| MugError::MatcherUnavailable(format!("make ONNX model runnable: {e}")))?;
        Ok(Self {
            model,
            channels,
            height,
            width,
            dim,
        })
    }
}

#[cfg(feature = "face-model")]
impl EmbeddingExtractor for TractExtractor {
    fn dim(&self) -> usize {
        self.dim
    }

    fn extract(&self, frame: &IrFrame) -> Result<Embedding> {
        use tract_onnx::prelude::*;

        if frame.as_bytes().is_empty() {
            return Err(MugError::InvalidFrame("empty frame".into()));
        }
        let plane = resize_gray(frame, self.width, self.height);
        let mut input = vec![0f32; self.channels * self.height * self.width];
        let plane_len = self.height * self.width;
        for (i, &p) in plane.iter().enumerate() {
            let v = (p as f32 - 127.5) / 127.5;
            for c in 0..self.channels {
                input[c * plane_len + i] = v;
            }
        }
        let tensor: Tensor = tract_ndarray::Array4::from_shape_vec(
            (1, self.channels, self.height, self.width),
            input,
        )
        .map_err(|e| MugError::MatcherUnavailable(format!("build input tensor: {e}")))?
        .into();
        let result = self
            .model
            .run(tvec!(tensor.into()))
            .map_err(|e| MugError::MatcherUnavailable(format!("run ONNX inference: {e}")))?;
        let out = result[0].clone().into_tensor();
        let plain = out
            .try_as_plain()
            .map_err(|e| MugError::MatcherUnavailable(format!("view model output: {e}")))?;
        let slice = plain
            .as_slice::<f32>()
            .map_err(|e| MugError::MatcherUnavailable(format!("read model output as f32: {e}")))?;
        let mut emb: Vec<f32> = slice.to_vec();
        if emb.is_empty() {
            return Err(MugError::MatcherUnavailable(
                "model produced an empty embedding".into(),
            ));
        }
        if emb.len() != self.dim {
            return Err(MugError::MatcherUnavailable(format!(
                "model output length {} does not match the declared embedding dim {}",
                emb.len(),
                self.dim
            )));
        }
        l2_normalize(&mut emb)?;
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
        let matcher = Matcher::new(PooledExtractor::new(64).expect("valid dim"), 0.15);
        let frame = on_frame(synth::live_pair(128, 128));
        let enrolled = matcher.embed(&frame).unwrap();
        let d = matcher.verify(&frame, &enrolled).unwrap();
        assert!(d <= 1e-5, "identical frame distance should be ~0, got {d}");
    }

    #[test]
    fn different_distribution_does_not_match() {
        let matcher = Matcher::new(PooledExtractor::new(64).expect("valid dim"), 0.15);
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

    #[test]
    fn zero_dim_extractor_is_recoverable() {
        match PooledExtractor::new(0) {
            Err(MugError::MatcherUnavailable(_)) => {}
            other => panic!("expected MatcherUnavailable, got {:?}", other.map(|_| ())),
        }
    }

    #[cfg(feature = "face-model")]
    #[test]
    fn tract_extractor_missing_model_errors_cleanly() {
        // A bad/absent model path must surface a MatcherUnavailable error (the caller degrades to the
        // PIN), never panic.
        match TractExtractor::from_path("/nonexistent/model.onnx") {
            Err(MugError::MatcherUnavailable(_)) => {}
            other => panic!("expected MatcherUnavailable, got {:?}", other.map(|_| ())),
        }
    }
}
