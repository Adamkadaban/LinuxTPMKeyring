//! IR face detection: locate the face (and its 5 landmarks) before embedding.
//!
//! Without a detector the matcher would embed the whole frame, so the embedding encodes the
//! background and "matches" even with no face present. This module finds the most prominent face and
//! its five landmarks, which [`crate::align`] then warps to the canonical template for the embedder.
//!
//! The real backend is **YuNet** (OpenCV Zoo / libfacedetection), an anchor-free detector run via
//! `tract` (the same engine as the embedder — no native ONNX Runtime). Its decode is a per-cell
//! `score = sqrt(cls·obj)`, `exp` box, and additive landmark offset across strides 8/16/32, followed
//! by greedy IoU NMS — all implemented here in safe Rust. No model ships with tess; the path is
//! supplied at runtime and an absent/invalid model degrades the face factor to the PIN.

use crate::align::{FaceLandmarks, align_face};
use crate::camera::IrFrame;
use crate::error::{MugError, Result};

/// YuNet's detection strides (feature-map downsampling factors).
#[cfg(feature = "face-model")]
const STRIDES: [usize; 3] = [8, 16, 32];
/// Default minimum `sqrt(cls·obj)` score for a detection. Cooperative single-face unlock can afford
/// a high bar — it directly rejects the "no face / background" case.
pub const DEFAULT_SCORE_THRESHOLD: f32 = 0.6;
/// Default IoU threshold for non-max suppression.
pub const DEFAULT_NMS_IOU: f32 = 0.3;

/// A detected face: bounding box `(x, y, w, h)` and 5 landmarks, both in **source-frame** pixel
/// coordinates, plus the detection score. Landmarks are in canonical template order (see
/// [`FaceLandmarks`]); YuNet's native order already matches it.
#[derive(Clone, Debug)]
pub struct Detection {
    pub bbox: (f32, f32, f32, f32),
    pub landmarks: FaceLandmarks,
    pub score: f32,
}

/// Locates the most prominent face in a GREY IR frame.
pub trait FaceDetector {
    /// Detect the best face, or [`MugError::NoFace`] if none clears the score threshold.
    fn detect(&self, frame: &IrFrame) -> Result<Detection>;
}

/// Detect a face and align it to a `size`×`size` crop ready for the embedder.
pub fn locate_and_align(
    detector: &dyn FaceDetector,
    frame: &IrFrame,
    size: u32,
) -> Result<IrFrame> {
    let det = detector.detect(frame)?;
    align_face(frame, &det.landmarks, size)
}

/// A fixed detector for tests/downstream wiring: returns a preset detection (or [`MugError::NoFace`]
/// when constructed empty), so the detect→align→embed path can be exercised without a model — the
/// detection analogue of [`crate::matcher::PooledExtractor`].
pub struct FixedDetector {
    detection: Option<Detection>,
}

impl FixedDetector {
    pub fn new(detection: Detection) -> Self {
        Self {
            detection: Some(detection),
        }
    }

    /// A detector that always reports "no face".
    pub fn none() -> Self {
        Self { detection: None }
    }
}

impl FaceDetector for FixedDetector {
    fn detect(&self, _frame: &IrFrame) -> Result<Detection> {
        self.detection.clone().ok_or(MugError::NoFace)
    }
}

/// A decoded detection in detector-input pixel coordinates (pre-mapping to the source frame).
#[cfg(any(feature = "face-model", test))]
#[derive(Clone, Debug)]
struct RawDet {
    x1: f32,
    y1: f32,
    w: f32,
    h: f32,
    lm: [(f32, f32); 5],
    score: f32,
}

/// Decode one YuNet stride into raw detections. `score_a`/`score_b` are the two per-cell score maps
/// (cls and obj — order-independent since the score is their geometric mean); `bbox` is 4 per cell,
/// `kps` is 10 (5 landmarks) per cell. Slices must be sized `rows*cols*{1,1,4,10}` respectively.
#[cfg(any(feature = "face-model", test))]
#[allow(clippy::too_many_arguments)]
fn decode_stride(
    score_a: &[f32],
    score_b: &[f32],
    bbox: &[f32],
    kps: &[f32],
    cols: usize,
    rows: usize,
    stride: usize,
    score_thresh: f32,
    out: &mut Vec<RawDet>,
) {
    let s = stride as f32;
    for r in 0..rows {
        for c in 0..cols {
            let idx = r * cols + c;
            let (a, b) = (score_a[idx], score_b[idx]);
            // clamp preserves NaN, so reject non-finite scores explicitly — a NaN score passes
            // `< thresh` (false) and would later poison NMS sorting/selection.
            if !a.is_finite() || !b.is_finite() {
                continue;
            }
            let score = (a.clamp(0.0, 1.0) * b.clamp(0.0, 1.0)).sqrt();
            if !score.is_finite() || score < score_thresh {
                continue;
            }
            let cx = (c as f32 + bbox[idx * 4]) * s;
            let cy = (r as f32 + bbox[idx * 4 + 1]) * s;
            // exp() can overflow to +inf for hostile/garbage model outputs; reject non-finite or
            // non-positive boxes so NMS/alignment never see inf/NaN geometry.
            let w = bbox[idx * 4 + 2].exp() * s;
            let h = bbox[idx * 4 + 3].exp() * s;
            if !(cx.is_finite() && cy.is_finite() && w.is_finite() && h.is_finite())
                || w <= 0.0
                || h <= 0.0
            {
                continue;
            }
            let mut lm = [(0.0f32, 0.0f32); 5];
            let mut lm_ok = true;
            for (n, p) in lm.iter_mut().enumerate() {
                let lx = (c as f32 + kps[idx * 10 + 2 * n]) * s;
                let ly = (r as f32 + kps[idx * 10 + 2 * n + 1]) * s;
                if !lx.is_finite() || !ly.is_finite() {
                    lm_ok = false;
                    break;
                }
                *p = (lx, ly);
            }
            if !lm_ok {
                continue;
            }
            out.push(RawDet {
                x1: cx - w / 2.0,
                y1: cy - h / 2.0,
                w,
                h,
                lm,
                score,
            });
        }
    }
}

/// Intersection-over-union of two axis-aligned boxes.
#[cfg(any(feature = "face-model", test))]
fn iou(a: &RawDet, b: &RawDet) -> f32 {
    let (ax2, ay2) = (a.x1 + a.w, a.y1 + a.h);
    let (bx2, by2) = (b.x1 + b.w, b.y1 + b.h);
    let ix1 = a.x1.max(b.x1);
    let iy1 = a.y1.max(b.y1);
    let ix2 = ax2.min(bx2);
    let iy2 = ay2.min(by2);
    let iw = (ix2 - ix1).max(0.0);
    let ih = (iy2 - iy1).max(0.0);
    let inter = iw * ih;
    let union = a.w * a.h + b.w * b.h - inter;
    if union <= 0.0 { 0.0 } else { inter / union }
}

/// Greedy IoU non-max suppression, highest score first.
#[cfg(any(feature = "face-model", test))]
fn nms(mut dets: Vec<RawDet>, iou_thresh: f32) -> Vec<RawDet> {
    dets.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut keep: Vec<RawDet> = Vec::new();
    'cand: for d in dets {
        for k in &keep {
            if iou(&d, k) > iou_thresh {
                continue 'cand;
            }
        }
        keep.push(d);
    }
    keep
}

#[cfg(feature = "face-model")]
pub use yunet::YuNetDetector;

#[cfg(feature = "face-model")]
mod yunet {
    use super::{
        DEFAULT_NMS_IOU, DEFAULT_SCORE_THRESHOLD, Detection, FaceDetector, RawDet, STRIDES,
        decode_stride, nms,
    };
    use crate::align::FaceLandmarks;
    use crate::camera::IrFrame;
    use crate::error::{MugError, Result};
    use tract_onnx::prelude::*;

    /// Upper bound on the detector input element count (`C*H*W`), mirroring the embedder's cap so a
    /// hostile/misconfigured model degrades to the PIN instead of triggering a giant allocation.
    const MAX_INPUT_ELEMS: usize = 16 * 1024 * 1024;

    /// A `tract`-backed YuNet face detector. Loads a fixed-shape NCHW model; runs it on the GREY IR
    /// frame (resized to the model input, raw 0–255 replicated across channels — YuNet expects no
    /// normalization); decodes + NMS-filters in safe Rust and returns the highest-scoring face.
    pub struct YuNetDetector {
        model: std::sync::Arc<TypedRunnableModel>,
        channels: usize,
        height: usize,
        width: usize,
        score_threshold: f32,
        nms_iou: f32,
    }

    impl YuNetDetector {
        /// Load and optimize the YuNet ONNX at `path`, deriving the input geometry from the model.
        pub fn from_path(path: &str) -> Result<Self> {
            let typed = tract_onnx::onnx()
                .model_for_path(path)
                .map_err(|e| {
                    MugError::MatcherUnavailable(format!("load detector model {path}: {e}"))
                })?
                .into_optimized()
                .map_err(|e| {
                    MugError::MatcherUnavailable(format!("optimize detector model {path}: {e}"))
                })?;

            let input_shape = typed
                .input_fact(0)
                .map_err(|e| {
                    MugError::MatcherUnavailable(format!("read detector input fact: {e}"))
                })?
                .shape
                .as_concrete()
                .ok_or_else(|| {
                    MugError::MatcherUnavailable(
                        "detector input shape is not concrete; supply a fixed-shape model".into(),
                    )
                })?
                .to_vec();
            if input_shape.len() != 4 || input_shape[0] != 1 {
                return Err(MugError::MatcherUnavailable(format!(
                    "expected detector NCHW input [1, C, H, W], got {input_shape:?}"
                )));
            }
            let (channels, height, width) = (input_shape[1], input_shape[2], input_shape[3]);
            let elems = channels
                .checked_mul(height)
                .and_then(|n| n.checked_mul(width))
                .filter(|&n| n > 0 && n <= MAX_INPUT_ELEMS)
                .ok_or_else(|| {
                    MugError::MatcherUnavailable(format!(
                        "detector input [1, {channels}, {height}, {width}] is zero-sized or exceeds \
                         the {MAX_INPUT_ELEMS}-element cap"
                    ))
                })?;
            let _ = elems;
            // Each stride's feature map must tile the input exactly.
            for s in STRIDES {
                if !height.is_multiple_of(s) || !width.is_multiple_of(s) {
                    return Err(MugError::MatcherUnavailable(format!(
                        "detector input {height}x{width} is not divisible by stride {s}"
                    )));
                }
            }

            let model = typed.into_runnable().map_err(|e| {
                MugError::MatcherUnavailable(format!("make detector runnable: {e}"))
            })?;
            Ok(Self {
                model,
                channels,
                height,
                width,
                score_threshold: DEFAULT_SCORE_THRESHOLD,
                nms_iou: DEFAULT_NMS_IOU,
            })
        }

        /// Override the detection score threshold (default [`DEFAULT_SCORE_THRESHOLD`]).
        pub fn with_score_threshold(mut self, t: f32) -> Self {
            self.score_threshold = t;
            self
        }

        /// Nearest-neighbour resize of the GREY frame to the model input plane (raw 0–255 → f32).
        fn input_plane(&self, frame: &IrFrame) -> Vec<f32> {
            let (sw, sh) = frame.dimensions();
            let (sw, sh) = (sw as usize, sh as usize);
            let src = frame.as_bytes();
            let mut plane = vec![0f32; self.width * self.height];
            for y in 0..self.height {
                let sy = (y * sh / self.height).min(sh.saturating_sub(1));
                for x in 0..self.width {
                    let sx = (x * sw / self.width).min(sw.saturating_sub(1));
                    plane[y * self.width + x] = f32::from(src[sy * sw + sx]);
                }
            }
            plane
        }
    }

    impl FaceDetector for YuNetDetector {
        fn detect(&self, frame: &IrFrame) -> Result<Detection> {
            let (sw, sh) = frame.dimensions();
            if sw == 0 || sh == 0 {
                return Err(MugError::InvalidFrame("empty frame".into()));
            }
            let plane = self.input_plane(frame);
            let mut input = vec![0f32; self.channels * plane.len()];
            for c in 0..self.channels {
                input[c * plane.len()..(c + 1) * plane.len()].copy_from_slice(&plane);
            }
            let tensor: Tensor = tract_ndarray::Array4::from_shape_vec(
                (1, self.channels, self.height, self.width),
                input,
            )
            .map_err(|e| MugError::MatcherUnavailable(format!("build detector input: {e}")))?
            .into();

            let outputs = self
                .model
                .run(tvec!(tensor.into()))
                .map_err(|e| MugError::MatcherUnavailable(format!("run detector: {e}")))?;

            // Group outputs by stride (from cell count) and role (from per-cell width: two 1-wide
            // score maps, one 4-wide box map, one 10-wide landmark map). Order-independent so the
            // decode is robust to the model's output ordering.
            let mut scores: [Vec<Vec<f32>>; 3] = [Vec::new(), Vec::new(), Vec::new()];
            let mut boxes: [Option<Vec<f32>>; 3] = [None, None, None];
            let mut kpss: [Option<Vec<f32>>; 3] = [None, None, None];
            for out in outputs.into_iter() {
                let tensor = out.into_tensor();
                let shape = tensor.shape();
                let total: usize = shape.iter().product();
                let c = *shape.last().unwrap_or(&0);
                if c == 0 || !total.is_multiple_of(c) {
                    continue;
                }
                let n = total / c;
                let Some(si) = STRIDES.iter().position(|&s| {
                    self.height.is_multiple_of(s)
                        && self.width.is_multiple_of(s)
                        && (self.height / s) * (self.width / s) == n
                }) else {
                    continue;
                };
                let Ok(plain) = tensor.try_as_plain() else {
                    continue;
                };
                let Ok(slice) = plain.as_slice::<f32>() else {
                    continue;
                };
                let data: Vec<f32> = slice.to_vec();
                match c {
                    1 => scores[si].push(data),
                    4 => boxes[si] = Some(data),
                    10 => kpss[si] = Some(data),
                    _ => {}
                }
            }

            let mut raw: Vec<RawDet> = Vec::new();
            let mut any_stride_complete = false;
            for (si, &s) in STRIDES.iter().enumerate() {
                let (cols, rows) = (self.width / s, self.height / s);
                let n = cols * rows;
                let (Some(bbox), Some(kps)) = (&boxes[si], &kpss[si]) else {
                    continue;
                };
                // Require exactly two score maps (cls + obj). Extra c==1 outputs would make the
                // chosen pair order-dependent, so treat that as an incompatible model (fail closed).
                if scores[si].len() != 2 || bbox.len() != n * 4 || kps.len() != n * 10 {
                    continue;
                }
                if scores[si][0].len() != n || scores[si][1].len() != n {
                    continue;
                }
                any_stride_complete = true;
                decode_stride(
                    &scores[si][0],
                    &scores[si][1],
                    bbox,
                    kps,
                    cols,
                    rows,
                    s,
                    self.score_threshold,
                    &mut raw,
                );
            }
            // No stride produced a complete YuNet tensor set => the model isn't a compatible
            // detector, not "a valid model that saw no face". Surface that as MatcherUnavailable so
            // the PIN fallback and logs reflect the real cause.
            if !any_stride_complete {
                return Err(MugError::MatcherUnavailable(
                    "detector outputs do not match the expected YuNet tensor set \
                     (scores+bbox+landmarks per stride)"
                        .into(),
                ));
            }

            let kept = nms(raw, self.nms_iou);
            let best = kept
                .into_iter()
                .max_by(|a, b| {
                    a.score
                        .partial_cmp(&b.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .ok_or(MugError::NoFace)?;

            // Map detector-input coordinates back to the source frame.
            let (kx, ky) = (
                sw as f32 / self.width as f32,
                sh as f32 / self.height as f32,
            );
            let lm = best.lm.map(|(x, y)| (x * kx, y * ky));
            Ok(Detection {
                bbox: (best.x1 * kx, best.y1 * ky, best.w * kx, best.h * ky),
                landmarks: FaceLandmarks::new(lm),
                score: best.score,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::align::ALIGNED_FACE_SIZE;

    fn template_landmarks() -> FaceLandmarks {
        FaceLandmarks::new([
            (38.2946, 51.6963),
            (73.5318, 51.5014),
            (56.0252, 71.7366),
            (41.5493, 92.3655),
            (70.7299, 92.2041),
        ])
    }

    #[test]
    fn decode_stride_emits_expected_box_and_landmarks() {
        // 2x2 grid, stride 8, a single hot cell at (r=0, c=1).
        let (cols, rows) = (2usize, 2usize);
        let n = cols * rows;
        let mut sa = vec![0f32; n];
        let mut sb = vec![0f32; n];
        sa[1] = 1.0;
        sb[1] = 1.0;
        let bbox = vec![0f32; n * 4]; // all offsets 0 -> w=h=exp(0)*8=8
        let kps = vec![0f32; n * 10]; // landmark offsets 0 -> lm = (c*8, r*8)
        let mut out = Vec::new();
        decode_stride(&sa, &sb, &bbox, &kps, cols, rows, 8, 0.5, &mut out);
        assert_eq!(out.len(), 1);
        let d = &out[0];
        assert!((d.score - 1.0).abs() < 1e-6);
        // center = ((1+0)*8, 0) = (8,0); w=h=8 -> x1=4, y1=-4
        assert!((d.x1 - 4.0).abs() < 1e-4 && (d.y1 + 4.0).abs() < 1e-4);
        assert!((d.w - 8.0).abs() < 1e-4 && (d.h - 8.0).abs() < 1e-4);
        assert!((d.lm[0].0 - 8.0).abs() < 1e-4 && d.lm[0].1.abs() < 1e-4);
    }

    #[test]
    fn decode_stride_filters_below_threshold() {
        let (cols, rows) = (2usize, 2usize);
        let n = cols * rows;
        let sa = vec![0.3f32; n];
        let sb = vec![0.3f32; n];
        let bbox = vec![0f32; n * 4];
        let kps = vec![0f32; n * 10];
        let mut out = Vec::new();
        decode_stride(&sa, &sb, &bbox, &kps, cols, rows, 8, 0.6, &mut out);
        assert!(out.is_empty(), "score 0.3 < 0.6 must be filtered");
    }

    #[test]
    fn decode_stride_skips_nonfinite_scores_and_boxes() {
        let (cols, rows) = (2usize, 2usize);
        let n = cols * rows;
        // cell 0: NaN score (clamp would keep the NaN and pass `< thresh`); cell 1: inf box dim.
        let mut sa = vec![1.0f32; n];
        let sb = vec![1.0f32; n];
        sa[0] = f32::NAN;
        let mut bbox = vec![0f32; n * 4];
        bbox[4 + 2] = f32::INFINITY; // cell 1 width = exp(inf) = inf
        let kps = vec![0f32; n * 10];
        let mut out = Vec::new();
        decode_stride(&sa, &sb, &bbox, &kps, cols, rows, 8, 0.5, &mut out);
        assert_eq!(out.len(), 2, "NaN-score and inf-box cells must be skipped");
        assert!(
            out.iter()
                .all(|d| d.w.is_finite() && d.h.is_finite() && d.score.is_finite()),
            "no non-finite geometry may survive"
        );
    }

    fn det(x1: f32, y1: f32, w: f32, h: f32, score: f32) -> RawDet {
        RawDet {
            x1,
            y1,
            w,
            h,
            lm: [(0.0, 0.0); 5],
            score,
        }
    }

    #[test]
    fn nms_suppresses_overlapping_keeps_disjoint() {
        let a = det(0.0, 0.0, 10.0, 10.0, 0.9);
        let b = det(1.0, 1.0, 10.0, 10.0, 0.8); // heavy overlap with a
        let c = det(100.0, 100.0, 10.0, 10.0, 0.7); // disjoint
        let kept = nms(vec![a, b, c], 0.3);
        assert_eq!(kept.len(), 2);
        assert!((kept[0].score - 0.9).abs() < 1e-6); // highest first
    }

    #[test]
    fn iou_of_identical_boxes_is_one() {
        let a = det(5.0, 5.0, 10.0, 10.0, 1.0);
        assert!((iou(&a, &a) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn iou_of_disjoint_boxes_is_zero() {
        let a = det(0.0, 0.0, 5.0, 5.0, 1.0);
        let b = det(100.0, 100.0, 5.0, 5.0, 1.0);
        assert_eq!(iou(&a, &b), 0.0);
    }

    #[test]
    fn fixed_detector_returns_preset_then_aligns() {
        let frame = IrFrame::new(220, 220, vec![80u8; 220 * 220]).unwrap();
        let detector = FixedDetector::new(Detection {
            bbox: (40.0, 40.0, 120.0, 140.0),
            landmarks: FaceLandmarks::new([
                (80.0, 100.0),
                (160.0, 100.0),
                (120.0, 140.0),
                (90.0, 180.0),
                (150.0, 180.0),
            ]),
            score: 0.95,
        });
        let aligned = locate_and_align(&detector, &frame, ALIGNED_FACE_SIZE).unwrap();
        assert_eq!(aligned.dimensions(), (ALIGNED_FACE_SIZE, ALIGNED_FACE_SIZE));
    }

    #[test]
    fn fixed_detector_none_reports_no_face() {
        let frame = IrFrame::new(112, 112, vec![0u8; 112 * 112]).unwrap();
        let detector = FixedDetector::none();
        assert!(matches!(detector.detect(&frame), Err(MugError::NoFace)));
        assert!(matches!(
            locate_and_align(&detector, &frame, 112),
            Err(MugError::NoFace)
        ));
    }

    #[test]
    fn template_landmarks_align_to_identity() {
        let frame = IrFrame::new(112, 112, vec![123u8; 112 * 112]).unwrap();
        let detector = FixedDetector::new(Detection {
            bbox: (0.0, 0.0, 112.0, 112.0),
            landmarks: template_landmarks(),
            score: 1.0,
        });
        let aligned = locate_and_align(&detector, &frame, ALIGNED_FACE_SIZE).unwrap();
        assert_eq!(aligned.dimensions(), (ALIGNED_FACE_SIZE, ALIGNED_FACE_SIZE));
    }
}
