//! Headless real-Brio liveness collector for #79 recalibration.
//!
//! Per sample it opens a **fresh** Brio IR device (so the emitter is cold), captures a liveness pair
//! via the shipped `capture_liveness_pair` (streaming warmup), then computes liveness features two
//! ways: on the **whole frame** (today's path) and on the **aligned face crop** (the #79 proposal,
//! detect → align both OFF/ON with the same landmarks → analyze the crop pair). Each row is appended
//! to a CSV. A cooldown between samples lets the emitter power back down so the next cold frame is
//! actually dark.
//!
//! It drives the exact shipped `mug` code (no re-implementation) and touches neither keyring nor TPM.
//!
//! ```sh
//! MUG_DETECTOR_MODEL=~/.local/share/tess/yunet.onnx \
//! FC_OUT=/tmp/fc.csv FC_LABEL=live FC_N=20 FC_COOLDOWN_MS=1500 \
//!   cargo run --manifest-path tools/face-collect/Cargo.toml --release
//! ```

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use mug::{
    ALIGNED_FACE_SIZE, BRIO_IR_HEIGHT, BRIO_IR_WIDTH, FaceDetector, FramePair, LivenessConfig,
    V4l2IrDevice, WarmingBrioDevice, YuNetDetector, align_face, analyze_liveness,
    capture_liveness_pair, find_brio_ir_node,
};

const CAPTURE_DEADLINE_MS: u64 = 2500;

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn main() -> Result<()> {
    let detector_path = env("MUG_DETECTOR_MODEL")
        .ok_or_else(|| anyhow!("MUG_DETECTOR_MODEL is required (path to the YuNet ONNX)"))?;
    let detector = YuNetDetector::from_path(&detector_path).context("load the YuNet detector")?;

    let out_path = PathBuf::from(env("FC_OUT").unwrap_or_else(|| "/tmp/face-collect.csv".into()));
    let label = env("FC_LABEL").unwrap_or_else(|| "unlabeled".into());
    let n: usize = env("FC_N").map_or(Ok(15), |v| v.parse()).context("FC_N")?;
    let cooldown = Duration::from_millis(
        env("FC_COOLDOWN_MS")
            .map_or(Ok(1500), |v| v.parse())
            .context("FC_COOLDOWN_MS")?,
    );

    let node = match env("MUG_IR_NODE") {
        Some(p) => PathBuf::from(p),
        None => find_brio_ir_node().context("discover the Brio IR node (set MUG_IR_NODE)")?,
    };

    // Write a header for a new file *or* an existing-but-empty one (e.g. pre-created by tooling, or
    // a previous run that crashed right after create).
    let needs_header = std::fs::metadata(&out_path)
        .map(|m| m.len() == 0)
        .unwrap_or(true);
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&out_path)
        .with_context(|| format!("open {}", out_path.display()))?;
    if needs_header {
        writeln!(out, "{}", csv_header())?;
    }

    let cfg = LivenessConfig::default();
    println!(
        "face-collect: label='{label}', {n} samples, cooldown {}ms, node {} -> {}",
        cooldown.as_millis(),
        node.display(),
        out_path.display()
    );
    println!("Hold the '{label}' subject in front of the camera for the whole run.");

    let (mut detected, mut faceless) = (0usize, 0usize);
    for idx in 0..n {
        if idx > 0 {
            std::thread::sleep(cooldown);
        }
        let pair = match capture_pair(&node) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[{idx}] capture failed: {e}");
                continue;
            }
        };

        let full =
            analyze_liveness(&pair, &cfg).map_err(|e| anyhow!("whole-frame liveness: {e}"))?;

        // Detect on the lit frame, then align BOTH frames with the same landmarks to get a crop pair.
        let crop = match detector.detect(&pair.emitter_on) {
            Ok(det) => {
                detected += 1;
                let off_c = align_face(&pair.emitter_off, &det.landmarks, ALIGNED_FACE_SIZE)
                    .context("align OFF crop")?;
                let on_c = align_face(&pair.emitter_on, &det.landmarks, ALIGNED_FACE_SIZE)
                    .context("align ON crop")?;
                let crop_pair = FramePair::new(off_c, on_c).context("build crop pair")?;
                Some(
                    analyze_liveness(&crop_pair, &cfg)
                        .map_err(|e| anyhow!("crop liveness: {e}"))?,
                )
            }
            Err(_) => {
                faceless += 1;
                None
            }
        };

        let detected_flag = crop.is_some();
        writeln!(
            out,
            "{}",
            csv_row(&label, idx, detected_flag, &full, crop.as_ref())
        )?;
        // Surface flush failures rather than silently losing calibration rows (e.g. disk full).
        out.flush().context("flush the CSV row to disk")?;
        print_progress(idx, detected_flag, &full, crop.as_ref());
    }

    println!(
        "face-collect: done — {detected} with a face, {faceless} faceless of {n}. Rows appended to {}.",
        out_path.display()
    );
    Ok(())
}

/// Open a fresh cold Brio device and capture one streaming-warmup liveness pair.
fn capture_pair(node: &std::path::Path) -> Result<FramePair> {
    let device = V4l2IrDevice::open(node, BRIO_IR_WIDTH, BRIO_IR_HEIGHT)
        .with_context(|| format!("open {}", node.display()))?;
    let (mut source, mut emitter) = WarmingBrioDevice::split(device, None);
    capture_liveness_pair(&mut source, &mut emitter, CAPTURE_DEADLINE_MS)
        .map_err(|e| anyhow!("capture liveness pair: {e}"))
    // `device` is moved into the split; both halves drop here → STREAMOFF/munmap, emitter cools.
}

fn csv_header() -> String {
    let mut s = String::from("label,idx,detected");
    for p in ["full", "crop"] {
        for f in [
            "mean_delta",
            "delta_std",
            "gradient",
            "specular",
            "saturated",
            "baseline",
            "score",
            "passed",
        ] {
            let _ = write!(s, ",{p}_{f}");
        }
    }
    s
}

fn feature_cols(s: &mut String, report: Option<&mug::LivenessReport>) {
    match report {
        Some(r) => {
            let f = &r.features;
            let _ = write!(
                s,
                ",{:.3},{:.3},{:.3},{:.5},{:.5},{:.3},{:.4},{}",
                f.mean_delta,
                f.delta_std,
                f.gradient_energy,
                f.specular_fraction,
                f.saturated_fraction,
                f.baseline_mean,
                f.score,
                r.passed as u8
            );
        }
        None => s.push_str(",,,,,,,,"),
    }
}

fn csv_row(
    label: &str,
    idx: usize,
    detected: bool,
    full: &mug::LivenessReport,
    crop: Option<&mug::LivenessReport>,
) -> String {
    let mut s = format!("{},{idx},{}", csv_escape(label), detected as u8);
    feature_cols(&mut s, Some(full));
    feature_cols(&mut s, crop);
    s
}

/// Escape a CSV field per RFC 4180: wrap in double quotes and double any embedded quote when the
/// field contains a comma, quote, CR, or LF. `FC_LABEL` is user-supplied, so an unescaped comma
/// would otherwise corrupt the row.
fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn print_progress(
    idx: usize,
    detected: bool,
    full: &mug::LivenessReport,
    crop: Option<&mug::LivenessReport>,
) {
    let ff = &full.features;
    let face = if detected { "face" } else { "NO-FACE" };
    let crop_str = match crop {
        Some(r) => format!(
            "crop[md {:.1} std {:.1} grad {:.2} base {:.1} score {:.2} {}]",
            r.features.mean_delta,
            r.features.delta_std,
            r.features.gradient_energy,
            r.features.baseline_mean,
            r.features.score,
            if r.passed { "PASS" } else { "rej" }
        ),
        None => "crop[-]".into(),
    };
    println!(
        "[{idx:02}] {face} full[md {:.1} std {:.1} grad {:.2} base {:.1} score {:.2} {}] {crop_str}",
        ff.mean_delta,
        ff.delta_std,
        ff.gradient_energy,
        ff.baseline_mean,
        ff.score,
        if full.passed { "PASS" } else { "rej" }
    );
}
