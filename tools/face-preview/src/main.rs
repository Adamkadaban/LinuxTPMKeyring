//! Dev/eval-only live IR face-recognition viewer.
//!
//! Drives the **shipped** `mug` pipeline — `V4l2IrDevice` continuous capture → `YuNetDetector` →
//! `align_face` → `TractExtractor` → `cosine_distance` — and draws each stage in a window: the IR
//! feed, the detection box and landmarks, the aligned 112×112 crop SFace actually embeds, and the
//! live match verdict against a face you enroll with `E`. It touches neither the keyring nor the TPM.
//!
//! This is a standalone crate outside the tess workspace on purpose: its GUI dependency stack
//! (minifb → wayland/x11) stays out of the workspace lockfile and the cargo-vet / cargo-deny gates.
//! It path-depends on `mug`, so what you see is the exact code tess runs, not a re-implementation.
//!
//! Run (Brio auto-detected, or set `MUG_IR_NODE`):
//! ```sh
//! MUG_DETECTOR_MODEL=~/.local/share/tess/yunet.onnx \
//! MUG_MODEL_PATH=~/.local/share/tess/sface.onnx \
//!   cargo run --manifest-path tools/face-preview/Cargo.toml --release
//! ```

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use minifb::{Key, KeyRepeat, Scale, Window, WindowOptions};
use mug::{
    ALIGNED_FACE_SIZE, BRIO_IR_HEIGHT, BRIO_IR_WIDTH, Embedding, EmbeddingExtractor, FaceDetector,
    IrFrame, IrSource, MugConfig, MugError, TractExtractor, V4l2IrDevice, YuNetDetector,
    align_face, cosine_distance, find_brio_ir_node,
};

/// Required env var: path to the user-supplied YuNet ONNX detector.
const ENV_DETECTOR: &str = "MUG_DETECTOR_MODEL";
/// Required env var: path to the user-supplied SFace ONNX embedder.
const ENV_MODEL: &str = "MUG_MODEL_PATH";
/// Optional override for the IR capture node (else the Brio GREY node is auto-discovered).
const ENV_NODE: &str = "MUG_IR_NODE";
/// Optional cosine match threshold (else the SFace-calibrated default below).
const ENV_THRESHOLD: &str = "MUG_MATCH_THRESHOLD";
/// SFace cosine-distance match threshold validated on LFW (see NOTES.md); the `MugConfig::default`
/// 0.34 is a model-agnostic placeholder, so the viewer uses the evaluated SFace value by default.
const DEFAULT_THRESHOLD: f32 = 0.6;
/// Per-frame capture budget; a wedged camera yields a timeout and the loop just redraws.
const CAPTURE_DEADLINE_MS: u64 = 300;

fn env_str(var: &str) -> Result<String> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v),
        Ok(_) => Err(anyhow!("{var} is set but empty (path to the ONNX model)")),
        Err(std::env::VarError::NotPresent) => {
            Err(anyhow!("{var} is required (path to the ONNX model)"))
        }
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow!("{var} is not valid UTF-8")),
    }
}

fn main() -> Result<()> {
    let detector = YuNetDetector::from_path(&env_str(ENV_DETECTOR)?)
        .context("load the YuNet detector model")?;
    // Match the SFace pixel convention used everywhere else (raw 0–255 → ArcFace symmetric scale).
    let extractor =
        TractExtractor::from_path(&env_str(ENV_MODEL)?, MugConfig::default().pixel_scale)
            .context("load the SFace embedding model")?;
    let threshold = match std::env::var(ENV_THRESHOLD) {
        Ok(v) => v
            .parse::<f32>()
            .with_context(|| format!("{ENV_THRESHOLD}={v:?} is not a number"))?,
        Err(std::env::VarError::NotPresent) => DEFAULT_THRESHOLD,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(anyhow!("{ENV_THRESHOLD} is not UTF-8"));
        }
    };

    let node = match std::env::var_os(ENV_NODE) {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => find_brio_ir_node()
            .context("discover the Brio IR node (set MUG_IR_NODE to override)")?,
    };
    let mut device = V4l2IrDevice::open(&node, BRIO_IR_WIDTH, BRIO_IR_HEIGHT)
        .with_context(|| format!("open the IR node {}", node.display()))?;

    let (w, h) = (BRIO_IR_WIDTH as usize, BRIO_IR_HEIGHT as usize);
    let mut window = Window::new(
        "face-preview — E: enroll  Q: quit",
        w,
        h,
        WindowOptions {
            scale: Scale::X2,
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("open preview window: {e}"))?;
    window.set_target_fps(30);

    let mut buffer = vec![0u32; w * h];
    let mut enrolled: Option<Embedding> = None;
    let mut last_print = Instant::now();
    println!(
        "face-preview: streaming (the Brio IR emitter warms over ~1 s). Green box = face; press E to \
         enroll the current face, Q to quit. Threshold {threshold:.2}."
    );

    while window.is_open() && !window.is_key_down(Key::Q) {
        let frame = match device.capture(CAPTURE_DEADLINE_MS) {
            Ok(f) => f,
            Err(MugError::Timeout(_)) => {
                window.update();
                continue;
            }
            Err(e) => return Err(anyhow!("capture frame: {e}")),
        };

        for (px, &p) in buffer.iter_mut().zip(frame.as_bytes().iter()) {
            let v = u32::from(p);
            *px = (v << 16) | (v << 8) | v;
        }

        // Border: red = no face, yellow = face present, green = match, orange = no match.
        let mut status = 0x00c0_3030u32;
        let want_enroll = window.is_key_pressed(Key::E, KeyRepeat::No);
        if let Ok(det) = detector.detect(&frame) {
            draw_rect(&mut buffer, w, h, det.bbox, 0x0030_e030);
            for (lx, ly) in det.landmarks.points {
                draw_dot(&mut buffer, w, h, lx, ly, 0x00ff_a000);
            }
            status = 0x00e0_c030;
            if let Ok(aligned) = align_face(&frame, &det.landmarks, ALIGNED_FACE_SIZE) {
                blit_aligned(&mut buffer, w, h, &aligned);
                if let Ok(emb) = extractor.extract(&aligned) {
                    if want_enroll {
                        enrolled = Some(emb.clone());
                        println!("face-preview: enrolled the current face.");
                    }
                    if let Some(en) = &enrolled
                        && let Ok(dist) = cosine_distance(&emb, en)
                    {
                        let matched = dist <= threshold;
                        status = if matched { 0x0030_d030 } else { 0x00f0_8020 };
                        if last_print.elapsed().as_millis() > 300 {
                            println!(
                                "dist {dist:.3} (thr {threshold:.2}) -> {}",
                                if matched { "MATCH" } else { "NO MATCH" }
                            );
                            last_print = Instant::now();
                        }
                    }
                }
            }
        }

        draw_border(&mut buffer, w, h, status, 6);
        window
            .update_with_buffer(&buffer, w, h)
            .map_err(|e| anyhow!("update preview window: {e}"))?;
    }
    Ok(())
}

fn put_px(buf: &mut [u32], w: usize, h: usize, x: i64, y: i64, c: u32) {
    if x >= 0 && y >= 0 && (x as usize) < w && (y as usize) < h {
        buf[(y as usize) * w + (x as usize)] = c;
    }
}

fn draw_rect(buf: &mut [u32], w: usize, h: usize, bbox: (f32, f32, f32, f32), c: u32) {
    let (x0, y0) = (bbox.0 as i64, bbox.1 as i64);
    let (x1, y1) = ((bbox.0 + bbox.2) as i64, (bbox.1 + bbox.3) as i64);
    for xx in x0..=x1 {
        put_px(buf, w, h, xx, y0, c);
        put_px(buf, w, h, xx, y1, c);
    }
    for yy in y0..=y1 {
        put_px(buf, w, h, x0, yy, c);
        put_px(buf, w, h, x1, yy, c);
    }
}

fn draw_dot(buf: &mut [u32], w: usize, h: usize, x: f32, y: f32, c: u32) {
    let (cx, cy) = (x as i64, y as i64);
    for dy in -2..=2 {
        for dx in -2..=2 {
            put_px(buf, w, h, cx + dx, cy + dy, c);
        }
    }
}

fn draw_border(buf: &mut [u32], w: usize, h: usize, c: u32, t: usize) {
    for y in 0..h {
        for x in 0..w {
            if x < t || x >= w - t || y < t || y >= h - t {
                buf[y * w + x] = c;
            }
        }
    }
}

/// Inset the aligned crop at the top-right corner so the operator sees what SFace actually embeds.
fn blit_aligned(buf: &mut [u32], w: usize, h: usize, aligned: &IrFrame) {
    let (aw, ah) = (aligned.width() as usize, aligned.height() as usize);
    let bytes = aligned.as_bytes();
    let ox = w.saturating_sub(aw + 4);
    let oy = 4;
    for ay in 0..ah {
        for ax in 0..aw {
            let (px, py) = (ox + ax, oy + ay);
            if px < w && py < h {
                let v = u32::from(bytes[ay * aw + ax]);
                buf[py * w + px] = (v << 16) | (v << 8) | v;
            }
        }
    }
}
