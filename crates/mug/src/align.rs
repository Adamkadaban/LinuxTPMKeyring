//! Landmark-based face alignment to the canonical ArcFace/SFace template.
//!
//! ArcFace-family embedders (SFace included) are trained on faces warped so the eyes, nose, and
//! mouth corners sit at fixed pixel positions in the model's input. Feeding an unaligned crop makes
//! the embedding encode pose/position rather than identity, collapsing same-vs-different separation.
//! This module estimates the 2-D **similarity transform** (rotation + uniform scale + translation,
//! no shear) mapping five detected landmarks onto the canonical 112×112 template, then warps the
//! GREY IR frame through it with bilinear sampling.
//!
//! The estimator is the 2-D closed form of Umeyama (1991) — no SVD dependency — and every degenerate
//! landmark configuration (coincident, collinear, non-finite, near-zero scale) is rejected rather
//! than producing a garbage crop that could still embed and false-accept on the unlock path.

use crate::camera::IrFrame;
use crate::error::{MugError, Result};

/// The canonical aligned face size SFace expects (square, 112×112).
pub const ALIGNED_FACE_SIZE: u32 = 112;

/// Upper bound on the aligned-crop edge. A model declaring an absurd input size must degrade to the
/// PIN, never trigger a giant allocation on the auth path.
const MAX_ALIGNED_SIZE: u32 = 4096;

/// Canonical 5-point ArcFace destination template, in pixels, for a 112×112 crop. Order is by image
/// position: image-left eye, image-right eye, nose tip, image-left mouth corner, image-right mouth
/// corner (insightface `arcface_dst`; identical to OpenCV `FaceRecognizerSF`'s hardcoded template).
const ARCFACE_DST_112: [(f64, f64); 5] = [
    (38.2946, 51.6963),
    (73.5318, 51.5014),
    (56.0252, 71.7366),
    (41.5493, 92.3655),
    (70.7299, 92.2041),
];

// Degeneracy guards (pixel-space). Inter-eye distance is ~35 px at 112, so the demeaned source
// variance is in the hundreds for a real face; anything tiny is collinear/coincident.
const EPS_VAR: f64 = 1.0;
const EPS_SCALE: f64 = 1e-3;
const EPS_DET: f64 = 1e-9;

/// A point in source-frame pixel coordinates.
pub type Point = (f32, f32);

/// Five facial landmarks, **in canonical template order**: image-left eye, image-right eye, nose
/// tip, image-left mouth corner, image-right mouth corner. Detectors that label points by subject
/// side (e.g. YuNet emits right-eye/left-eye/nose/right-mouth/left-mouth, where the subject's right
/// eye is on image-left) must supply them already mapped into this positional order.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FaceLandmarks {
    pub points: [Point; 5],
}

impl FaceLandmarks {
    pub fn new(points: [Point; 5]) -> Self {
        Self { points }
    }
}

/// Align `frame` to the canonical template, producing a `size`×`size` GREY crop. `size` is normally
/// [`ALIGNED_FACE_SIZE`]; other sizes scale the template proportionally (insightface's `ratio =
/// size / 112`). Returns [`MugError::InvalidFrame`] for a degenerate landmark set or an out-of-range
/// size so the caller degrades to the PIN.
pub fn align_face(frame: &IrFrame, landmarks: &FaceLandmarks, size: u32) -> Result<IrFrame> {
    if size == 0 || size > MAX_ALIGNED_SIZE {
        return Err(MugError::InvalidFrame(format!(
            "aligned size {size} out of range (1..={MAX_ALIGNED_SIZE})"
        )));
    }

    let ratio = f64::from(size) / 112.0;
    let dst = ARCFACE_DST_112.map(|(x, y)| (x * ratio, y * ratio));
    let src = landmarks.points.map(|(x, y)| (f64::from(x), f64::from(y)));

    let forward = estimate_similarity(&src, &dst)?;
    let inverse = invert_affine(&forward)?;

    let (sw, sh) = frame.dimensions();
    let src_bytes = frame.as_bytes();
    let edge = size as usize;
    let mut out = vec![0u8; edge * edge];
    for v in 0..edge {
        for u in 0..edge {
            // OpenCV maps integer output coordinates directly (no +0.5 half-pixel offset).
            let (ux, vy) = (u as f64, v as f64);
            let sx = inverse[0] * (ux - forward[2]) + inverse[1] * (vy - forward[5]);
            let sy = inverse[2] * (ux - forward[2]) + inverse[3] * (vy - forward[5]);
            out[v * edge + u] = sample_bilinear(src_bytes, sw, sh, sx, sy);
        }
    }
    IrFrame::new(size, size, out)
}

/// Estimate the 2-D similarity transform (forward map, source → template) from five point
/// correspondences, as a row-major 2×3 matrix `[m00, m01, m02, m10, m11, m12]`.
fn estimate_similarity(src: &[(f64, f64); 5], dst: &[(f64, f64); 5]) -> Result<[f64; 6]> {
    for &(x, y) in src.iter().chain(dst.iter()) {
        if !x.is_finite() || !y.is_finite() {
            return Err(MugError::InvalidFrame("non-finite landmark".into()));
        }
    }

    const N: f64 = 5.0;
    let (mut smx, mut smy, mut dmx, mut dmy) = (0.0, 0.0, 0.0, 0.0);
    for i in 0..5 {
        smx += src[i].0;
        smy += src[i].1;
        dmx += dst[i].0;
        dmy += dst[i].1;
    }
    smx /= N;
    smy /= N;
    dmx /= N;
    dmy /= N;

    // A = dst_demeaned^T · src_demeaned / N, and the demeaned source variance.
    let (mut a00, mut a01, mut a10, mut a11) = (0.0, 0.0, 0.0, 0.0);
    let mut var_src = 0.0;
    for i in 0..5 {
        let (sx, sy) = (src[i].0 - smx, src[i].1 - smy);
        let (dx, dy) = (dst[i].0 - dmx, dst[i].1 - dmy);
        a00 += dx * sx;
        a01 += dx * sy;
        a10 += dy * sx;
        a11 += dy * sy;
        var_src += sx * sx + sy * sy;
    }
    a00 /= N;
    a01 /= N;
    a10 /= N;
    a11 /= N;
    var_src /= N;

    if var_src < EPS_VAR {
        return Err(MugError::InvalidFrame(
            "degenerate landmarks (coincident/collinear source)".into(),
        ));
    }

    let det_a = a00 * a11 - a01 * a10;
    if det_a <= 0.0 {
        // A mirror best-fit means the landmark order is wrong or the configuration is degenerate;
        // reject rather than silently align a reflected face.
        return Err(MugError::InvalidFrame(
            "degenerate landmarks (reflected/rank-deficient)".into(),
        ));
    }

    // For a 2×2 matrix, the Umeyama sum of singular values (with the reflection sign folded in)
    // equals sqrt(‖A‖_F² + 2·det A); the proper rotation angle is atan2(A10 − A01, A00 + A11).
    let fro2 = a00 * a00 + a01 * a01 + a10 * a10 + a11 * a11;
    let s_dot_d = (fro2 + 2.0 * det_a).max(0.0).sqrt();
    let scale = s_dot_d / var_src;
    if !scale.is_finite() || scale < EPS_SCALE {
        return Err(MugError::InvalidFrame(
            "degenerate landmarks (near-zero scale)".into(),
        ));
    }

    let theta = (a10 - a01).atan2(a00 + a11);
    let (c, s) = (theta.cos(), theta.sin());
    let (r00, r01, r10, r11) = (scale * c, -scale * s, scale * s, scale * c);
    let tx = dmx - (r00 * smx + r01 * smy);
    let ty = dmy - (r10 * smx + r11 * smy);
    Ok([r00, r01, tx, r10, r11, ty])
}

/// Invert the linear part of a 2×3 affine, returning the row-major 2×2 inverse `[i00, i01, i10,
/// i11]`. Rejects a singular matrix (it would map output pixels to non-finite source coordinates).
fn invert_affine(m: &[f64; 6]) -> Result<[f64; 4]> {
    let den = m[0] * m[4] - m[1] * m[3];
    if den.abs() < EPS_DET {
        return Err(MugError::InvalidFrame(
            "singular alignment transform".into(),
        ));
    }
    Ok([m[4] / den, -m[1] / den, -m[3] / den, m[0] / den])
}

/// Bilinear sample of a GREY plane with constant border 0 (matching OpenCV `BORDER_CONSTANT`): any
/// of the four neighbours outside the frame contributes 0, rather than clamping coordinates.
fn sample_bilinear(data: &[u8], w: u32, h: u32, sx: f64, sy: f64) -> u8 {
    if !sx.is_finite() || !sy.is_finite() {
        return 0;
    }
    let x0 = sx.floor();
    let y0 = sy.floor();
    let fx = sx - x0;
    let fy = sy - y0;
    let (x0, y0) = (x0 as i64, y0 as i64);
    let (w, h) = (i64::from(w), i64::from(h));
    let at = |x: i64, y: i64| -> f64 {
        // Bounds-check in signed space: casting to u32 first could wrap a large positive coordinate
        // past the `< w` check and then panic on the `as usize` index.
        if x >= 0 && y >= 0 && x < w && y < h {
            f64::from(data[(y as usize) * (w as usize) + (x as usize)])
        } else {
            0.0
        }
    };
    let p00 = at(x0, y0);
    let p10 = at(x0 + 1, y0);
    let p01 = at(x0, y0 + 1);
    let p11 = at(x0 + 1, y0 + 1);
    let val = p00 * (1.0 - fx) * (1.0 - fy)
        + p10 * fx * (1.0 - fy)
        + p01 * (1.0 - fx) * fy
        + p11 * fx * fy;
    val.round().clamp(0.0, 255.0) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Apply a forward 2×3 map to a point.
    fn map_point(m: &[f64; 6], p: (f64, f64)) -> (f64, f64) {
        (
            m[0] * p.0 + m[1] * p.1 + m[2],
            m[3] * p.0 + m[4] * p.1 + m[5],
        )
    }

    fn template_f32() -> [Point; 5] {
        ARCFACE_DST_112.map(|(x, y)| (x as f32, y as f32))
    }

    #[test]
    fn estimator_recovers_known_similarity() {
        // Build source landmarks by transforming the template with a known similarity, then assert
        // the estimator's forward map sends each source point back onto the template.
        let (theta, scale, tx, ty) = (0.4_f64, 1.7_f64, 12.0_f64, -5.0_f64);
        let (c, s) = (theta.cos(), theta.sin());
        let src: [(f64, f64); 5] = ARCFACE_DST_112.map(|(dx, dy)| {
            (
                scale * (c * dx - s * dy) + tx,
                scale * (s * dx + c * dy) + ty,
            )
        });
        let m = estimate_similarity(&src, &ARCFACE_DST_112).expect("non-degenerate");
        for (i, &p) in src.iter().enumerate() {
            let (mx, my) = map_point(&m, p);
            let (ex, ey) = ARCFACE_DST_112[i];
            assert!(
                (mx - ex).abs() < 1e-6 && (my - ey).abs() < 1e-6,
                "point {i}: mapped ({mx},{my}) expected ({ex},{ey})"
            );
        }
    }

    #[test]
    fn identity_landmarks_give_identity_crop() {
        // A 112×112 source with the landmarks already at the template positions must align to an
        // (essentially) identical crop.
        let size = ALIGNED_FACE_SIZE;
        let mut data = vec![0u8; (size * size) as usize];
        for y in 0..size {
            for x in 0..size {
                data[(y * size + x) as usize] = ((x * 7 + y * 3) % 251) as u8;
            }
        }
        let frame = IrFrame::new(size, size, data.clone()).unwrap();
        let lm = FaceLandmarks::new(template_f32());
        let out = align_face(&frame, &lm, size).unwrap();
        // Interior pixels (away from border interpolation) reproduce the source exactly.
        for y in 1..size - 1 {
            for x in 1..size - 1 {
                let idx = (y * size + x) as usize;
                assert_eq!(out.as_bytes()[idx], data[idx], "mismatch at ({x},{y})");
            }
        }
    }

    #[test]
    fn warps_rotated_face_upright() {
        // Place a bright marker near each landmark in a rotated source; after alignment the markers
        // should land near the canonical template positions.
        let size = ALIGNED_FACE_SIZE;
        let (theta, scale, tx, ty) = (0.3_f64, 1.4_f64, 30.0_f64, 20.0_f64);
        let (c, s) = (theta.cos(), theta.sin());
        let src_pts: [(f64, f64); 5] = ARCFACE_DST_112.map(|(dx, dy)| {
            (
                scale * (c * dx - s * dy) + tx,
                scale * (s * dx + c * dy) + ty,
            )
        });
        let sw = 220u32;
        let mut data = vec![20u8; (sw * sw) as usize];
        for &(px, py) in &src_pts {
            // A small filled block (not a single pixel) so the bilinear inverse warp still samples a
            // bright value near the template position after the ~1/scale downsampling.
            let (cx, cy) = (px.round() as i64, py.round() as i64);
            for dy in -3i64..=3 {
                for dx in -3i64..=3 {
                    let (x, y) = (cx + dx, cy + dy);
                    if x >= 0 && y >= 0 && (x as u32) < sw && (y as u32) < sw {
                        data[(y as usize) * (sw as usize) + (x as usize)] = 255;
                    }
                }
            }
        }
        let frame = IrFrame::new(sw, sw, data).unwrap();
        let lm = FaceLandmarks::new(src_pts.map(|(x, y)| (x as f32, y as f32)));
        let out = align_face(&frame, &lm, size).unwrap();
        // Each template point should have a bright pixel within a small radius.
        for &(ex, ey) in &ARCFACE_DST_112 {
            let mut best = 0u8;
            for dy in -2i64..=2 {
                for dx in -2i64..=2 {
                    let (x, y) = (ex.round() as i64 + dx, ey.round() as i64 + dy);
                    if x >= 0 && y >= 0 && (x as u32) < size && (y as u32) < size {
                        best =
                            best.max(out.as_bytes()[(y as usize) * (size as usize) + (x as usize)]);
                    }
                }
            }
            assert!(
                best > 150,
                "no bright marker near template ({ex},{ey}); got {best}"
            );
        }
    }

    #[test]
    fn rejects_coincident_landmarks() {
        let frame = IrFrame::new(112, 112, vec![0u8; 112 * 112]).unwrap();
        let lm = FaceLandmarks::new([(50.0, 50.0); 5]);
        assert!(matches!(
            align_face(&frame, &lm, 112),
            Err(MugError::InvalidFrame(_))
        ));
    }

    #[test]
    fn rejects_collinear_landmarks() {
        let frame = IrFrame::new(112, 112, vec![0u8; 112 * 112]).unwrap();
        let lm = FaceLandmarks::new([
            (10.0, 10.0),
            (30.0, 30.0),
            (50.0, 50.0),
            (70.0, 70.0),
            (90.0, 90.0),
        ]);
        assert!(matches!(
            align_face(&frame, &lm, 112),
            Err(MugError::InvalidFrame(_))
        ));
    }

    #[test]
    fn rejects_non_finite_landmarks() {
        let frame = IrFrame::new(112, 112, vec![0u8; 112 * 112]).unwrap();
        let mut pts = template_f32();
        pts[0].0 = f32::NAN;
        let lm = FaceLandmarks::new(pts);
        assert!(matches!(
            align_face(&frame, &lm, 112),
            Err(MugError::InvalidFrame(_))
        ));
    }

    #[test]
    fn rejects_out_of_range_size() {
        let frame = IrFrame::new(112, 112, vec![0u8; 112 * 112]).unwrap();
        let lm = FaceLandmarks::new(template_f32());
        assert!(matches!(
            align_face(&frame, &lm, 0),
            Err(MugError::InvalidFrame(_))
        ));
        assert!(matches!(
            align_face(&frame, &lm, MAX_ALIGNED_SIZE + 1),
            Err(MugError::InvalidFrame(_))
        ));
    }

    #[test]
    fn sample_bilinear_huge_coords_are_border_not_panic() {
        // A coordinate beyond u32 range must read as border 0 (not wrap past the bounds check and
        // panic on index). 4.3e9 > 2^32.
        let data = vec![200u8; 16 * 16];
        assert_eq!(sample_bilinear(&data, 16, 16, 4_300_000_000.0, 1.0), 0);
        assert_eq!(sample_bilinear(&data, 16, 16, 1.0, -4_300_000_000.0), 0);
        assert_eq!(sample_bilinear(&data, 16, 16, f64::INFINITY, 1.0), 0);
    }

    #[test]
    fn aligned_output_has_requested_dimensions() {
        let frame = IrFrame::new(220, 220, vec![40u8; 220 * 220]).unwrap();
        let lm = FaceLandmarks::new([
            (70.0, 90.0),
            (150.0, 90.0),
            (110.0, 130.0),
            (80.0, 170.0),
            (140.0, 170.0),
        ]);
        let out = align_face(&frame, &lm, ALIGNED_FACE_SIZE).unwrap();
        assert_eq!(out.dimensions(), (ALIGNED_FACE_SIZE, ALIGNED_FACE_SIZE));
    }
}
