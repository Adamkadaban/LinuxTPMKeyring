//! Identity-validation harness: prove the **shipped** `mug` pipeline (YuNet detect → 5-point align →
//! SFace embed → cosine distance + threshold) only matches when it should, on a labeled face-pairs
//! dataset (LFW), grayscale to emulate the single-channel IR input.
//!
//! Ignored by default and excluded from the model-free CI build (needs the `face-model` feature plus
//! user-supplied models and a prepared dataset), so it never runs in CI. This exercises the real
//! product code — no Python, no re-implementation.
//!
//! ## Prepare the dataset (one-off, host-side; not part of the validation)
//!
//! Convert LFW pairs to raw grayscale `.grey` frames + a `pairs.tsv` manifest. Any tool works; e.g.
//! with Python + scikit-learn (data marshaling only — the matching logic is this Rust file):
//!
//! ```text
//! LFW_DIR/
//!   pairs.tsv         # lines: "<a>.grey\t<b>.grey\t<1|0>"  (1 = same person)
//!   <name>_<n>.grey   # raw 8-bit grayscale, LFW_W x LFW_H (default 250x250)
//! ```
//!
//! ## Run
//!
//! ```sh
//! MUG_DETECTOR_MODEL=~/.local/share/tess/yunet.onnx \
//! MUG_MODEL_PATH=~/.local/share/tess/sface.onnx \
//! LFW_DIR=/path/to/prepared LFW_W=250 LFW_H=250 \
//! cargo test -p mug --features face-model --test lfw_validation -- --ignored --nocapture
//! ```
#![cfg(feature = "face-model")]

use mug::camera::read_grey_file;
use mug::{
    ALIGNED_FACE_SIZE, Embedding, EmbeddingExtractor, FaceDetector, MugError, PixelScale,
    TractExtractor, YuNetDetector, align_face, cosine_distance,
};
use std::env;

/// Pixel scaling matching the OpenCV-Zoo SFace contract: raw 0..255 (`(p/255 - 0)/(1/255) = p`).
/// The correct scale is model-specific; `MugConfig`'s model-agnostic default is `Symmetric`, so this
/// is the scale for the SFace model under test, not the out-of-the-box default.
const SCALE: PixelScale = PixelScale::Standardized {
    mean: 0.0,
    std: 1.0 / 255.0,
};
/// The cosine-distance match threshold **evaluated** for this SFace model (≈ cosine similarity 0.40).
/// Not the product default (`MugConfig::default().match_threshold == 0.34`, a model-agnostic
/// placeholder) — the right threshold is model/sensor-specific and is exactly what this harness
/// measures.
const MATCH_TH: f32 = 0.60;

/// Embed one image, or `Ok(None)` when **no face is detected** (a legitimate skip). Any other
/// failure (I/O, bad frame size, alignment degeneracy, model incompatibility) is an `Err` so it
/// fails the test rather than silently skewing the metrics.
fn embed_one(
    detector: &YuNetDetector,
    extractor: &TractExtractor,
    dir: &str,
    name: &str,
    w: u32,
    h: u32,
) -> mug::Result<Option<Embedding>> {
    let frame = read_grey_file(format!("{dir}/{name}"), w, h)?;
    match detector.detect(&frame) {
        Ok(det) => {
            let aligned = align_face(&frame, &det.landmarks, ALIGNED_FACE_SIZE)?;
            Ok(Some(extractor.extract(&aligned)?))
        }
        Err(MugError::NoFace) => Ok(None),
        Err(e) => Err(e),
    }
}

#[test]
#[ignore = "needs face-model + MUG_DETECTOR_MODEL + MUG_MODEL_PATH + a prepared LFW_DIR"]
fn lfw_pairs_separate_genuine_from_impostor() {
    let det_model = env::var("MUG_DETECTOR_MODEL").expect("set MUG_DETECTOR_MODEL");
    let emb_model = env::var("MUG_MODEL_PATH").expect("set MUG_MODEL_PATH");
    let dir = env::var("LFW_DIR").expect("set LFW_DIR (prepared dataset dir)");
    let w: u32 = env::var("LFW_W")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(250);
    let h: u32 = env::var("LFW_H")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(250);

    let detector = YuNetDetector::from_path(&det_model).expect("load YuNet");
    let extractor = TractExtractor::from_path(&emb_model, SCALE).expect("load SFace");

    let manifest = std::fs::read_to_string(format!("{dir}/pairs.tsv")).expect("read pairs.tsv");
    let (mut genuine, mut impostor) = (Vec::new(), Vec::new());
    let mut skipped = 0usize;
    for (i, line) in manifest.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Fail fast on a malformed manifest rather than silently skewing the metrics.
        let cols: Vec<&str> = line.split('\t').collect();
        assert!(
            cols.len() == 3,
            "pairs.tsv line {}: expected 3 tab-separated fields, got {}",
            i + 1,
            cols.len()
        );
        let (a, b) = (cols[0], cols[1]);
        let genuine_label = match cols[2].trim() {
            "1" => true,
            "0" => false,
            other => panic!(
                "pairs.tsv line {}: label must be 0 or 1, got {other:?}",
                i + 1
            ),
        };
        // A pair where a face isn't detected in one image is a legitimate skip (reported); any other
        // pipeline error fails the test.
        let ea = embed_one(&detector, &extractor, &dir, a, w, h)
            .unwrap_or_else(|e| panic!("pairs.tsv line {}: embed {a}: {e}", i + 1));
        let eb = embed_one(&detector, &extractor, &dir, b, w, h)
            .unwrap_or_else(|e| panic!("pairs.tsv line {}: embed {b}: {e}", i + 1));
        let (Some(ea), Some(eb)) = (ea, eb) else {
            skipped += 1;
            continue;
        };
        let d = cosine_distance(&ea, &eb).expect("cosine distance");
        if genuine_label {
            genuine.push(d);
        } else {
            impostor.push(d);
        }
    }

    assert!(
        genuine.len() >= 20 && impostor.len() >= 20,
        "too few usable pairs (genuine {}, impostor {}, skipped {}) — check the dataset",
        genuine.len(),
        impostor.len(),
        skipped
    );

    let mean = |v: &[f32]| v.iter().sum::<f32>() / v.len() as f32;
    let (gm, im) = (mean(&genuine), mean(&impostor));
    let ta = genuine.iter().filter(|&&d| d <= MATCH_TH).count() as f32 / genuine.len() as f32;
    let tr = impostor.iter().filter(|&&d| d > MATCH_TH).count() as f32 / impostor.len() as f32;

    // Best-accuracy threshold sweep + EER.
    let (mut best_acc, mut best_t) = (0.0f32, 0.0f32);
    let (mut eer, mut eer_gap) = (1.0f32, f32::INFINITY);
    let mut t = 0.10;
    while t <= 1.20 {
        let atr = impostor.iter().filter(|&&d| d > t).count() as f32 / impostor.len() as f32;
        let ata = genuine.iter().filter(|&&d| d <= t).count() as f32 / genuine.len() as f32;
        let acc = (ata + atr) / 2.0;
        if acc > best_acc {
            best_acc = acc;
            best_t = t;
        }
        let far = impostor.iter().filter(|&&d| d <= t).count() as f32 / impostor.len() as f32;
        let frr = genuine.iter().filter(|&&d| d > t).count() as f32 / genuine.len() as f32;
        if (far - frr).abs() < eer_gap {
            eer_gap = (far - frr).abs();
            eer = (far + frr) / 2.0;
        }
        t += 0.005;
    }

    eprintln!("=== LFW (grayscale) through the real mug pipeline ===");
    eprintln!(
        "genuine pairs {}  impostor pairs {}  skipped (no face) {}",
        genuine.len(),
        impostor.len(),
        skipped
    );
    eprintln!("genuine  cosine-distance mean {gm:.3}");
    eprintln!("impostor cosine-distance mean {im:.3}");
    eprintln!(
        "@ evaluated threshold {MATCH_TH:.2}: true-accept {:.1}%  true-reject {:.1}%  balanced-acc {:.1}%",
        ta * 100.0,
        tr * 100.0,
        (ta + tr) / 2.0 * 100.0
    );
    eprintln!(
        "best balanced-accuracy threshold {best_t:.3}: balanced-acc {:.1}%   EER ~ {:.1}%",
        best_acc * 100.0,
        eer * 100.0
    );

    // The pipeline must clearly separate same-person from different-person.
    assert!(
        gm < im,
        "genuine mean ({gm:.3}) must be below impostor mean ({im:.3})"
    );
    assert!(
        best_acc >= 0.80,
        "best-threshold balanced accuracy {:.1}% < 80% — the pipeline is not discriminating",
        best_acc * 100.0
    );
}
