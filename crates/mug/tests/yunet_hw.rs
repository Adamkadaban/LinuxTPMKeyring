//! Hardware/integration validation for the real YuNet detector path.
//!
//! Ignored by default and excluded from the model-free CI build (needs the `face-model` feature and
//! a user-supplied model + frame), so it never runs against real hardware in CI. Run locally with:
//!
//! ```sh
//! MUG_DETECTOR_MODEL=~/.local/share/tess/yunet.onnx \
//! MUG_TEST_FRAME=/path/to/frame_340x340.grey \
//! cargo test -p mug --features face-model --test yunet_hw -- --ignored --nocapture
//! ```
#![cfg(feature = "face-model")]

use mug::{ALIGNED_FACE_SIZE, FaceDetector, IrFrame, YuNetDetector, locate_and_align};
use std::env;

const W: u32 = 340;
const H: u32 = 340;

fn load_frame(path: &str) -> IrFrame {
    let data = std::fs::read(path).expect("read MUG_TEST_FRAME");
    assert_eq!(
        data.len(),
        (W * H) as usize,
        "frame must be {W}x{H} GREY ({} bytes)",
        W * H
    );
    IrFrame::new(W, H, data).unwrap()
}

#[test]
#[ignore = "needs MUG_DETECTOR_MODEL + MUG_TEST_FRAME and the face-model feature"]
fn yunet_detects_and_aligns_a_real_face() {
    let model = env::var("MUG_DETECTOR_MODEL").expect("set MUG_DETECTOR_MODEL");
    let frame_path = env::var("MUG_TEST_FRAME").expect("set MUG_TEST_FRAME");
    let frame = load_frame(&frame_path);

    let detector = YuNetDetector::from_path(&model).expect("YuNet must load in tract");
    let det = detector
        .detect(&frame)
        .expect("a face must be detected in the frame");
    eprintln!(
        "detection: score={:.3} bbox={:?} landmarks={:?}",
        det.score, det.bbox, det.landmarks.points
    );

    // Landmarks must land inside the frame.
    for (x, y) in det.landmarks.points {
        assert!(
            x >= 0.0 && x < W as f32 && y >= 0.0 && y < H as f32,
            "landmark ({x},{y}) outside the frame"
        );
    }
    // Eyes (indices 0,1) sit above the mouth corners (indices 3,4) for an upright face.
    let eye_y = (det.landmarks.points[0].1 + det.landmarks.points[1].1) / 2.0;
    let mouth_y = (det.landmarks.points[3].1 + det.landmarks.points[4].1) / 2.0;
    assert!(eye_y < mouth_y, "eyes ({eye_y}) should be above mouth ({mouth_y})");

    let aligned = locate_and_align(&detector, &frame, ALIGNED_FACE_SIZE).unwrap();
    assert_eq!(aligned.dimensions(), (ALIGNED_FACE_SIZE, ALIGNED_FACE_SIZE));
}
