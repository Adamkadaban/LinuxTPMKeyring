//! Dev/eval-only live IR face-recognition viewer.
//!
//! Drives the **shipped** `mug` pipeline — `V4l2IrDevice` → `YuNetDetector` → `align_face` →
//! `TractExtractor` → `cosine_distance`, plus `analyze_liveness` on an aligned-crop pair — and draws
//! every stage: the live IR feed, the detection box and landmarks, the aligned 112×112 crop the
//! embedder sees, and a text HUD with FPS, detection state, the identity match verdict, and (on
//! demand) liveness. It touches neither the keyring nor the TPM.
//!
//! Inference (`tract`) runs on a **background thread** so the camera feed stays smooth even though a
//! pure-Rust runtime updates the detection a few times a second. The main thread only captures and
//! draws; the worker owns the detector/embedder.
//!
//! Standalone crate kept out of the tess workspace so its GUI stack never enters the workspace
//! lockfile or supply-chain gates; it path-depends on `mug`, so what you see is the shipped code.
//!
//! ```sh
//! MUG_DETECTOR_MODEL=~/.local/share/tess/yunet.onnx MUG_MODEL_PATH=~/.local/share/tess/sface.onnx \
//!   cargo run --manifest-path tools/face-preview/Cargo.toml --release
//! ```
//! Keys: `E` enroll the face in view · `L` take a liveness sample (emitter off→on) · `Q` quit.

#![forbid(unsafe_code)]
// Pixel-drawing helpers take buffer + geometry + colour; splitting them into structs would add noise
// to a dev-only viewer.
#![allow(clippy::too_many_arguments)]

use std::path::PathBuf;
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use font8x8::{BASIC_FONTS, UnicodeFonts};
use minifb::{Key, KeyRepeat, Scale, Window, WindowOptions};
use mug::{
    ALIGNED_FACE_SIZE, BRIO_IR_HEIGHT, BRIO_IR_WIDTH, Embedding, EmbeddingExtractor, FaceDetector,
    FramePair, IrFrame, IrSource, LivenessConfig, MugConfig, MugError, TractExtractor,
    V4l2IrDevice, WarmingBrioDevice, YuNetDetector, align_face, analyze_liveness,
    capture_liveness_pair, cosine_distance, find_brio_ir_node,
};

const ENV_DETECTOR: &str = "MUG_DETECTOR_MODEL";
const ENV_MODEL: &str = "MUG_MODEL_PATH";
const ENV_NODE: &str = "MUG_IR_NODE";
const ENV_THRESHOLD: &str = "MUG_MATCH_THRESHOLD";
/// SFace cosine-distance match threshold validated on LFW; the `MugConfig::default` 0.34 is a
/// model-agnostic placeholder, so the viewer uses the evaluated SFace value by default.
const DEFAULT_THRESHOLD: f32 = 0.6;
const CAPTURE_DEADLINE_MS: u64 = 300;
/// Cooldown before a liveness sample so the freshly-reopened device starts emitter-cold.
const LIVENESS_COOLDOWN: Duration = Duration::from_millis(1200);
/// How many recent inferences feed the rolling match verdict (previews multi-frame aggregation).
const MATCH_WINDOW: usize = 12;

// HUD colours (0x00RRGGBB).
const C_GOOD: u32 = 0x0030_e030;
const C_BAD: u32 = 0x00f0_6020;
const C_NEUTRAL: u32 = 0x00d0_d0d0;
const C_LANDMARK: u32 = 0x00ff_a000;

/// One frame's analysis, produced by the worker and drawn by the main thread.
#[derive(Clone, Default)]
struct Analysis {
    seq: u64,
    has_face: bool,
    bbox: (f32, f32, f32, f32),
    landmarks: [(f32, f32); 5],
    crop: Option<Vec<u8>>,
    distance: Option<f32>,
    enrolled: bool,
    infer_ms: f32,
}

/// A liveness sample (emitter off→on, analyzed on the aligned crop).
#[derive(Clone)]
struct LiveSample {
    has_face: bool,
    passed: bool,
    mean_delta: f32,
    gradient: f32,
    baseline: f32,
    score: f32,
    reason: Option<String>,
    at: Instant,
}

/// Work items sent to the inference thread.
enum Job {
    Frame(IrFrame),
    Liveness(FramePair),
}

/// A stable verdict aggregated over the last several inferences — a preview of the multi-frame
/// (trimmed-mean) decision the real `verify` should use, and what tames the per-frame flicker.
struct MatchWindow {
    total: usize,
    matches: usize,
    trimmed_mean: Option<f32>,
    verdict: Option<bool>,
}

impl MatchWindow {
    fn compute(window: &std::collections::VecDeque<f32>, threshold: f32) -> Self {
        let total = window.len();
        let matches = window.iter().filter(|&&d| d <= threshold).count();
        // Trimmed mean: drop the single worst (largest) distance, average the rest, threshold once.
        // Needs ≥3 samples so one transient frame can't carry the decision.
        let (trimmed_mean, verdict) = if total >= 3 {
            let mut v: Vec<f32> = window.iter().copied().collect();
            v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let kept = &v[..v.len() - 1];
            let mean = kept.iter().sum::<f32>() / kept.len() as f32;
            (Some(mean), Some(mean <= threshold))
        } else {
            (None, None)
        };
        Self {
            total,
            matches,
            trimmed_mean,
            verdict,
        }
    }
}

struct Shared {
    latest: Mutex<Analysis>,
    live: Mutex<Option<LiveSample>>,
    enroll: AtomicBool,
}

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
    let detector =
        YuNetDetector::from_path(&env_str(ENV_DETECTOR)?).context("load the YuNet detector")?;
    let extractor =
        TractExtractor::from_path(&env_str(ENV_MODEL)?, MugConfig::default().pixel_scale)
            .context("load the SFace embedder")?;
    let threshold = match std::env::var(ENV_THRESHOLD) {
        Ok(v) => v
            .parse()
            .with_context(|| format!("{ENV_THRESHOLD}={v:?}"))?,
        Err(std::env::VarError::NotPresent) => DEFAULT_THRESHOLD,
        Err(std::env::VarError::NotUnicode(_)) => return Err(anyhow!("{ENV_THRESHOLD} not UTF-8")),
    };
    let node = match std::env::var_os(ENV_NODE) {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => find_brio_ir_node().context("discover the Brio IR node (set MUG_IR_NODE)")?,
    };

    let shared = Arc::new(Shared {
        latest: Mutex::new(Analysis::default()),
        live: Mutex::new(None),
        enroll: AtomicBool::new(false),
    });

    // Inference thread: owns the models, processes the latest frame / liveness pair.
    let (tx, rx) = sync_channel::<Job>(1);
    let worker_shared = Arc::clone(&shared);
    let worker = std::thread::spawn(move || inference_loop(detector, extractor, worker_shared, rx));

    let (w, h) = (BRIO_IR_WIDTH as usize, BRIO_IR_HEIGHT as usize);
    let mut window = Window::new(
        "tess face-preview — E: enroll  L: liveness  Q: quit",
        w,
        h,
        WindowOptions {
            scale: Scale::X2,
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("open preview window: {e}"))?;
    window.set_target_fps(60);

    let mut buffer = vec![0u32; w * h];
    let mut device = open_stream(&node)?;
    let mut fps = FpsCounter::new();
    let mut dist_window: std::collections::VecDeque<f32> =
        std::collections::VecDeque::with_capacity(MATCH_WINDOW);
    let mut last_seq = 0u64;
    let mut last_face_seen: Option<Instant> = None;
    println!(
        "face-preview: streaming. E=enroll  L=liveness sample  Q=quit. Threshold {threshold:.2}."
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
        fps.tick();

        render_gray(&mut buffer, &frame);

        // Hand the worker the latest frame; drop it if the worker is still busy (keeps the feed smooth).
        match tx.try_send(Job::Frame(frame.clone())) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => return Err(anyhow!("inference thread died")),
        }

        if window.is_key_pressed(Key::E, KeyRepeat::No) {
            shared.enroll.store(true, Ordering::Relaxed);
        }
        if window.is_key_pressed(Key::L, KeyRepeat::No) {
            device = liveness_sample(device, &node, &tx, &mut buffer, &mut window, w, h)?;
        }

        let analysis = shared.latest.lock().unwrap().clone();
        let live = shared.live.lock().unwrap().clone();

        // Feed the rolling window once per *new* inference (the worker bumps `seq`), not per render
        // frame — otherwise a single slow inference would be counted many times.
        if analysis.seq != last_seq {
            last_seq = analysis.seq;
            if analysis.has_face {
                last_face_seen = Some(Instant::now());
                if let Some(d) = analysis.distance {
                    if dist_window.len() == MATCH_WINDOW {
                        dist_window.pop_front();
                    }
                    dist_window.push_back(d);
                }
            }
        }
        let match_window = MatchWindow::compute(&dist_window, threshold);
        let face_recent = last_face_seen.is_some_and(|t| t.elapsed() < Duration::from_millis(400));

        draw_overlay(
            &mut buffer,
            w,
            h,
            &analysis,
            &match_window,
            face_recent,
            live.as_ref(),
            fps.fps(),
        );

        window
            .update_with_buffer(&buffer, w, h)
            .map_err(|e| anyhow!("update window: {e}"))?;
    }

    drop(tx);
    let _ = worker.join();
    Ok(())
}

fn open_stream(node: &std::path::Path) -> Result<V4l2IrDevice> {
    // The IR node allows a single opener; right after a previous handle closes the kernel can still
    // report EBUSY for a moment. Retry briefly so reopening after a liveness sample is reliable.
    let mut last = None;
    for _ in 0..10 {
        match V4l2IrDevice::open(node, BRIO_IR_WIDTH, BRIO_IR_HEIGHT) {
            Ok(dev) => return Ok(dev),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(80));
            }
        }
    }
    Err(anyhow!(
        "open IR node {} after retries: {}",
        node.display(),
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Run a liveness sample: close the stream so the emitter cools, capture a cold off→on pair, hand it
/// to the worker, and reopen the stream. Consumes the streaming `device` (the node has a single
/// opener) and returns the fresh streaming device.
fn liveness_sample(
    device: V4l2IrDevice,
    node: &std::path::Path,
    tx: &SyncSender<Job>,
    buffer: &mut [u32],
    window: &mut Window,
    w: usize,
    h: usize,
) -> Result<V4l2IrDevice> {
    draw_text(
        buffer,
        w,
        h,
        6,
        h - 14,
        C_NEUTRAL,
        "liveness: sampling (hold still)...",
    );
    let _ = window.update_with_buffer(buffer, w, h);

    // Close the streaming device first (frees the node) so the emitter cools before a cold capture.
    drop(device);
    std::thread::sleep(LIVENESS_COOLDOWN);
    let dev = open_stream(node)?;
    let (mut source, mut emitter) = WarmingBrioDevice::split(dev, None);
    match capture_liveness_pair(&mut source, &mut emitter, 2500) {
        Ok(pair) => {
            let _ = tx.send(Job::Liveness(pair));
        }
        Err(e) => eprintln!("liveness capture failed: {e}"),
    }
    drop(source);
    drop(emitter);
    open_stream(node)
}

/// The inference thread body: blocks on jobs, updates the shared analysis/liveness state.
fn inference_loop(
    detector: YuNetDetector,
    extractor: TractExtractor,
    shared: Arc<Shared>,
    rx: std::sync::mpsc::Receiver<Job>,
) {
    let mut enrolled: Option<Embedding> = None;
    let cfg = LivenessConfig::default();
    let mut seq: u64 = 0;
    while let Ok(job) = rx.recv() {
        match job {
            Job::Frame(frame) => {
                let t0 = Instant::now();
                seq += 1;
                let mut a = Analysis {
                    seq,
                    enrolled: enrolled.is_some(),
                    ..Default::default()
                };
                if let Ok(det) = detector.detect(&frame) {
                    a.has_face = true;
                    a.bbox = det.bbox;
                    a.landmarks = det.landmarks.points;
                    if let Ok(aligned) = align_face(&frame, &det.landmarks, ALIGNED_FACE_SIZE) {
                        a.crop = Some(aligned.as_bytes().to_vec());
                        if let Ok(emb) = extractor.extract(&aligned) {
                            if shared.enroll.swap(false, Ordering::Relaxed) {
                                enrolled = Some(emb.clone());
                                println!("face-preview: enrolled the current face.");
                            }
                            a.enrolled = enrolled.is_some();
                            if let Some(en) = &enrolled {
                                a.distance = cosine_distance(&emb, en).ok();
                            }
                        }
                    }
                }
                a.infer_ms = t0.elapsed().as_secs_f32() * 1000.0;
                *shared.latest.lock().unwrap() = a;
            }
            Job::Liveness(pair) => {
                *shared.live.lock().unwrap() = Some(liveness_of(&detector, &pair, &cfg));
            }
        }
    }
}

/// Detect on the lit frame, align both frames with the same landmarks, and analyze the crop pair.
fn liveness_of(detector: &YuNetDetector, pair: &FramePair, cfg: &LivenessConfig) -> LiveSample {
    let mut s = LiveSample {
        has_face: false,
        passed: false,
        mean_delta: 0.0,
        gradient: 0.0,
        baseline: 0.0,
        score: 0.0,
        reason: None,
        at: Instant::now(),
    };
    let Ok(det) = detector.detect(&pair.emitter_on) else {
        s.reason = Some("no face detected".into());
        return s;
    };
    s.has_face = true;
    let (Ok(off_c), Ok(on_c)) = (
        align_face(&pair.emitter_off, &det.landmarks, ALIGNED_FACE_SIZE),
        align_face(&pair.emitter_on, &det.landmarks, ALIGNED_FACE_SIZE),
    ) else {
        s.reason = Some("alignment failed".into());
        return s;
    };
    let Ok(crop_pair) = FramePair::new(off_c, on_c) else {
        return s;
    };
    if let Ok(rep) = analyze_liveness(&crop_pair, cfg) {
        let f = &rep.features;
        s.passed = rep.passed;
        s.mean_delta = f.mean_delta;
        s.gradient = f.gradient_energy;
        s.baseline = f.baseline_mean;
        s.score = f.score;
        s.reason = rep.reason;
    }
    s
}

/// Frame-rate over a sliding ~1 s window.
struct FpsCounter {
    times: std::collections::VecDeque<Instant>,
}
impl FpsCounter {
    fn new() -> Self {
        Self {
            times: std::collections::VecDeque::with_capacity(64),
        }
    }
    fn tick(&mut self) {
        let now = Instant::now();
        self.times.push_back(now);
        while let Some(&front) = self.times.front() {
            if now.duration_since(front) > Duration::from_secs(1) {
                self.times.pop_front();
            } else {
                break;
            }
        }
    }
    fn fps(&self) -> f32 {
        self.times.len() as f32
    }
}

fn render_gray(buf: &mut [u32], frame: &IrFrame) {
    for (px, &p) in buf.iter_mut().zip(frame.as_bytes().iter()) {
        let v = u32::from(p);
        *px = (v << 16) | (v << 8) | v;
    }
}

fn draw_overlay(
    buf: &mut [u32],
    w: usize,
    h: usize,
    a: &Analysis,
    window: &MatchWindow,
    face_recent: bool,
    live: Option<&LiveSample>,
    fps: f32,
) {
    let mut border = C_BAD; // red-ish: no face
    if a.has_face {
        draw_rect(buf, w, h, a.bbox, C_GOOD);
        for (lx, ly) in a.landmarks {
            draw_dot(buf, w, h, lx, ly, C_LANDMARK);
        }
        border = 0x00e0_c030; // yellow: face, no verdict yet
        if let Some(crop) = &a.crop {
            blit_crop(buf, w, h, crop);
        }
    }
    // Border reflects the *stable* (windowed) verdict, not the jittery per-frame one.
    if let Some(v) = window.verdict {
        border = if v { C_GOOD } else { C_BAD };
    }
    draw_border(buf, w, h, border, 5);

    // HUD panel (top-left).
    fill_rect(buf, w, h, 0, 0, w, 28, 0x0010_1010);
    draw_text(
        buf,
        w,
        h,
        4,
        2,
        C_NEUTRAL,
        &format!("fps {fps:>2.0}  inf {:>3.0}ms", a.infer_ms),
    );
    // Debounced face presence so a one-frame detector miss doesn't flicker the label.
    let face_line = if face_recent {
        ("FACE", C_GOOD)
    } else {
        ("no face", C_BAD)
    };
    draw_text(buf, w, h, 4, 12, face_line.1, face_line.0);

    let (id_text, id_color) = if !a.enrolled {
        ("press E to enroll".to_string(), C_NEUTRAL)
    } else {
        match (window.verdict, window.trimmed_mean) {
            (Some(true), Some(m)) => (
                format!("MATCH  {}/{} avg {m:.3}", window.matches, window.total),
                C_GOOD,
            ),
            (Some(false), Some(m)) => (
                format!("NO MATCH  {}/{} avg {m:.3}", window.matches, window.total),
                C_BAD,
            ),
            _ => (
                format!("sampling… {}/{}", window.matches, window.total),
                C_NEUTRAL,
            ),
        }
    };
    draw_text(buf, w, h, 70, 12, id_color, &id_text);

    // Liveness line (bottom), shown for a few seconds after a sample.
    if let Some(ls) = live
        && ls.at.elapsed() < Duration::from_secs(6)
    {
        fill_rect(buf, w, h, 0, h - 12, w, 12, 0x0010_1010);
        let (txt, col) = liveness_line(ls);
        draw_text(buf, w, h, 4, h - 11, col, &txt);
    }
}

fn liveness_line(ls: &LiveSample) -> (String, u32) {
    if !ls.has_face {
        return (
            format!(
                "LIVENESS: no face in pair ({}) - a spoof would be rejected here",
                ls.reason.as_deref().unwrap_or("no detection")
            ),
            C_GOOD,
        );
    }
    if ls.passed {
        (
            format!(
                "LIVENESS PASS = real 3D face (grad {:.1} md {:.0} score {:.2})",
                ls.gradient, ls.mean_delta, ls.score
            ),
            C_GOOD,
        )
    } else {
        (
            format!(
                "LIVENESS REJECT = looks flat/spoof (grad {:.1} md {:.0} score {:.2})",
                ls.gradient, ls.mean_delta, ls.score
            ),
            C_BAD,
        )
    }
}

fn put_px(buf: &mut [u32], w: usize, h: usize, x: i64, y: i64, c: u32) {
    if x >= 0 && y >= 0 && (x as usize) < w && (y as usize) < h {
        buf[(y as usize) * w + (x as usize)] = c;
    }
}

fn fill_rect(
    buf: &mut [u32],
    w: usize,
    h: usize,
    x: usize,
    y: usize,
    rw: usize,
    rh: usize,
    c: u32,
) {
    for yy in y..(y + rh).min(h) {
        for xx in x..(x + rw).min(w) {
            buf[yy * w + xx] = c;
        }
    }
}

fn draw_rect(buf: &mut [u32], w: usize, h: usize, bbox: (f32, f32, f32, f32), c: u32) {
    let (x0, y0) = (bbox.0 as i64, bbox.1 as i64);
    let (x1, y1) = ((bbox.0 + bbox.2) as i64 - 1, (bbox.1 + bbox.3) as i64 - 1);
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
    for dy in -2..=2 {
        for dx in -2..=2 {
            put_px(buf, w, h, x as i64 + dx, y as i64 + dy, c);
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

/// Draw an 8×8 bitmap string (font8x8) into the buffer at `(x, y)`.
fn draw_text(buf: &mut [u32], w: usize, h: usize, x: usize, y: usize, c: u32, text: &str) {
    let mut cx = x;
    for ch in text.chars() {
        if let Some(glyph) = BASIC_FONTS.get(ch) {
            for (row, bits) in glyph.iter().enumerate() {
                for col in 0..8 {
                    if (bits >> col) & 1 != 0 {
                        put_px(buf, w, h, (cx + col) as i64, (y + row) as i64, c);
                    }
                }
            }
        }
        cx += 8;
    }
}

/// Inset the aligned crop at the top-right corner so the operator sees what SFace embeds.
fn blit_crop(buf: &mut [u32], w: usize, h: usize, crop: &[u8]) {
    let side = ALIGNED_FACE_SIZE as usize;
    if crop.len() != side * side {
        return;
    }
    let ox = w.saturating_sub(side + 4);
    let oy = 30;
    for ay in 0..side {
        for ax in 0..side {
            let (px, py) = (ox + ax, oy + ay);
            if px < w && py < h {
                let v = u32::from(crop[ay * side + ax]);
                buf[py * w + px] = (v << 16) | (v << 8) | v;
            }
        }
    }
}
