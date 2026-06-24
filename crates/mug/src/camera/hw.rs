//! The real Logitech Brio IR path: GREY-node selection, bounded frame capture, and the UVC
//! extension-unit IR-emitter enable. None of this is exercised in CI (no camera); the orchestrator
//! validates it against the physical Brio. It is plain safe Rust over the `sys` ioctl boundary.

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::camera::{BRIO_IR_HEIGHT, BRIO_IR_WIDTH, IrEmitter, IrFrame, IrSource};
use crate::error::{MugError, Result};
use crate::sys;

/// Directory of stable `by-id` device symlinks. Selecting the node here (rather than a bare
/// `/dev/video4`) keeps the choice stable across reboots and re-enumeration.
const V4L_BY_ID_DIR: &str = "/dev/v4l/by-id";

/// Default Brio IR-emitter UVC extension unit. The Brio exposes its IR-emitter control as a vendor
/// extension-unit `SET_CUR`; the concrete unit/selector/payload are device data confirmed on the
/// physical camera (cf. the `linux-enable-ir-emitter` Brio configuration), not security logic. A
/// wrong value fails safe: the emitter stays off, the liveness differential cannot pass, and the
/// face factor degrades to the PIN.
pub const BRIO_EMITTER_UNIT: u8 = 0x04;
/// Default Brio IR-emitter UVC selector (see [`BRIO_EMITTER_UNIT`]).
pub const BRIO_EMITTER_SELECTOR: u8 = 0x06;

/// Find a stable `by-id` path to the Brio IR (GREY) capture node.
///
/// Scans `/dev/v4l/by-id`, keeping symlinks that look like a Logitech Brio and whose target node
/// advertises the `GREY` pixelformat (the IR sensor) rather than the RGB node. Returns the first
/// match. Errors with [`MugError::NoIrNode`] when none is found — the caller fails safe to the PIN.
pub fn find_brio_ir_node() -> Result<PathBuf> {
    let entries = std::fs::read_dir(V4L_BY_ID_DIR)
        .map_err(|e| MugError::Camera(format!("read {V4L_BY_ID_DIR}: {e}")))?;

    let mut last_err: Option<MugError> = None;
    for entry in entries {
        let entry = entry.map_err(|e| MugError::Camera(format!("read dir entry: {e}")))?;
        let link = entry.path();
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();

        // by-id names encode vendor/product, e.g. "usb-046d_Logitech_BRIO_...-video-index1".
        let looks_like_brio = name.contains("brio") || name.contains("046d");
        if !looks_like_brio {
            continue;
        }

        // A Brio-looking node that can't be probed (permission denied, broken symlink, ioctl error)
        // is remembered, not silently skipped: if no GREY node is found, the real failure surfaces
        // instead of a misleading NoIrNode.
        match node_offers_grey(&link) {
            Ok(true) => return Ok(link),
            Ok(false) => {}
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(MugError::NoIrNode))
}

fn node_offers_grey(path: &Path) -> Result<bool> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| MugError::Camera(format!("open {}: {e}", path.display())))?;
    let formats = sys::enum_capture_pixelformats(file.as_raw_fd())
        .map_err(|e| MugError::Camera(format!("enum formats on {}: {e}", path.display())))?;
    Ok(formats.contains(&sys::V4L2_PIX_FMT_GREY))
}

/// A real Brio IR capture node, configured to GREY at the sensor's native geometry, streaming via
/// V4L2 MMAP I/O (the Brio IR node advertises streaming only — no `read()`).
pub struct V4l2IrDevice {
    // Declared before `file` so it drops first (STREAMOFF + munmap) while the capture fd is open.
    stream: sys::MmapStream,
    // Owns the capture fd the `stream` borrows by raw value; kept alive (and dropped last) purely so
    // the fd stays open for the stream's lifetime — never read directly after construction.
    #[allow(dead_code)]
    file: File,
    width: u32,
    height: u32,
}

impl V4l2IrDevice {
    /// Open `path`, force `width`x`height` GREY, and start MMAP streaming. Use
    /// [`V4l2IrDevice::open_brio`] for the discovered Brio node at its native 340x340.
    pub fn open(path: impl AsRef<Path>, width: u32, height: u32) -> Result<Self> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| MugError::Camera(format!("open {}: {e}", path.display())))?;

        let (gw, gh) = sys::set_grey_format(file.as_raw_fd(), width, height)
            .map_err(|e| MugError::Camera(format!("set GREY format on {}: {e}", path.display())))?;
        if (gw, gh) != (width, height) {
            return Err(MugError::Camera(format!(
                "driver granted {gw}x{gh}, expected {width}x{height}"
            )));
        }
        let stream = sys::MmapStream::start(file.as_raw_fd(), 4).map_err(|e| {
            MugError::Camera(format!("start MMAP streaming on {}: {e}", path.display()))
        })?;
        Ok(Self {
            stream,
            file,
            width,
            height,
        })
    }

    /// Open the discovered Brio IR node at its native 340x340 GREY geometry.
    pub fn open_brio() -> Result<Self> {
        let node = find_brio_ir_node()?;
        Self::open(node, BRIO_IR_WIDTH, BRIO_IR_HEIGHT)
    }
}

impl IrSource for V4l2IrDevice {
    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture(&mut self, deadline_ms: u64) -> Result<IrFrame> {
        let timeout = deadline_ms.min(i32::MAX as u64) as i32;
        let expected = (self.width as usize) * (self.height as usize);
        match self
            .stream
            .dequeue(timeout, expected)
            .map_err(|e| MugError::Camera(format!("dequeue frame: {e}")))?
        {
            Some(buf) => IrFrame::new(self.width, self.height, buf),
            None => Err(MugError::Timeout(deadline_ms)),
        }
    }
}

/// The Brio IR-emitter control over its UVC extension unit. `on_payload`/`off_payload` are the
/// device-confirmed SET_CUR data; supply them from configuration (see the module-level note on
/// fail-safe behaviour when they are wrong).
pub struct BrioEmitter {
    file: File,
    unit: u8,
    selector: u8,
    on_payload: Vec<u8>,
    off_payload: Vec<u8>,
}

impl BrioEmitter {
    /// Open `path` (any video node of the Brio works for the control transfer) and bind the
    /// extension-unit coordinates and payloads.
    pub fn new(
        path: impl AsRef<Path>,
        unit: u8,
        selector: u8,
        on_payload: Vec<u8>,
        off_payload: Vec<u8>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| MugError::Emitter(format!("open {}: {e}", path.display())))?;
        Ok(Self {
            file,
            unit,
            selector,
            on_payload,
            off_payload,
        })
    }
}

impl IrEmitter for BrioEmitter {
    fn set_enabled(&mut self, on: bool) -> Result<()> {
        let payload = if on {
            &self.on_payload
        } else {
            &self.off_payload
        };
        sys::uvc_set_cur(self.file.as_raw_fd(), self.unit, self.selector, payload)
            .map_err(|e| MugError::Emitter(format!("UVC SET_CUR (on={on}): {e}")))
    }
}

// Streaming warmup thresholds. On at least some Logitech Brios the IR emitter is *not* driven by a
// UVC `SET_CUR`; it auto-enables after ~1 s of continuous streaming and stays on while streaming,
// so the natural emitter-OFF/ON differential is "cold first frame" vs "a later, warmed frame". These
// decide when a streamed frame counts as warm (emitter on). The streaming-warmup technique is also
// what `linux-enable-ir-emitter` (GPL-3.0) relies on for detection; this is an independent
// implementation, no code shared.
/// Default absolute mean brightness (0..255) at/above which a streamed IR frame is emitter-on.
const WARM_MIN_MEAN: f32 = 24.0;
/// Default brightness a warm frame must clear over the cold baseline (guards a bright ambient scene).
const WARM_MIN_DELTA: f32 = 14.0;
/// Default per-frame poll slice (ms) while waiting for the emitter to warm, so the wait stays
/// responsive to the overall deadline.
const WARM_POLL_MS: u64 = 200;

/// Tunable thresholds for the streaming-warmup capture (defaults are the device-confirmed Brio
/// values). Operators tune these per sensor/lighting via the `warmup` block of the mug config — no
/// rebuild. The warm wait is always bounded by the capture deadline regardless of these values.
#[derive(Clone, Copy, Debug)]
pub struct WarmupConfig {
    /// Absolute mean brightness (0..255) at/above which a streamed frame counts as emitter-on.
    pub min_mean: f32,
    /// Brightness a warm frame must clear over the cold baseline.
    pub min_delta: f32,
    /// Per-frame poll slice (ms); clamped to at least 1 ms at use so a 0 can't busy-spin.
    pub poll_ms: u64,
}

impl Default for WarmupConfig {
    fn default() -> Self {
        Self {
            min_mean: WARM_MIN_MEAN,
            min_delta: WARM_MIN_DELTA,
            poll_ms: WARM_POLL_MS,
        }
    }
}

/// Phase of the warmup capture: the next frame is either the cold (emitter-off) baseline or a warmed
/// (emitter-on) frame to be streamed up to.
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Cold,
    Warm,
}

struct WarmingShared<S: IrSource, E: IrEmitter> {
    device: S,
    emitter: Option<E>,
    phase: Phase,
    cold_mean: f32,
    warmup: WarmupConfig,
}

/// An IR device whose emitter is driven by **streaming warmup** rather than a `SET_CUR` toggle. It
/// presents the standard [`IrSource`] / [`IrEmitter`] split (so
/// [`capture_liveness_pair`](crate::camera::capture_liveness_pair) and the gate use it unchanged):
/// `set_enabled(false)` then capture yields the cold/dark baseline; after `set_enabled(true)`,
/// capture streams frames until one brightens (the emitter has auto-warmed) or the deadline elapses.
/// An optional inner [`IrEmitter`] is still poked best-effort for devices that *do* need `SET_CUR` —
/// a failure there is non-fatal because streaming is the primary mechanism and a never-lit emitter is
/// caught downstream by liveness/timeout (→ PIN). Generic over the inner source/emitter so the
/// warmup logic is unit-tested with synthetic frames; [`WarmingBrioDevice`] is the concrete Brio
/// wiring.
pub struct WarmingDevice;

impl WarmingDevice {
    /// Split an inner capture device (and optional best-effort `SET_CUR` emitter) into warming
    /// source/emitter handles using the default warmup thresholds.
    pub fn split<S: IrSource, E: IrEmitter>(
        device: S,
        emitter: Option<E>,
    ) -> (WarmingSource<S, E>, WarmingEmitter<S, E>) {
        Self::split_with_config(device, emitter, WarmupConfig::default())
    }

    /// Split with explicit [`WarmupConfig`] thresholds (operator-tuned via the mug config).
    pub fn split_with_config<S: IrSource, E: IrEmitter>(
        device: S,
        emitter: Option<E>,
        warmup: WarmupConfig,
    ) -> (WarmingSource<S, E>, WarmingEmitter<S, E>) {
        let shared = Rc::new(RefCell::new(WarmingShared {
            device,
            emitter,
            phase: Phase::Cold,
            cold_mean: 0.0,
            warmup,
        }));
        (
            WarmingSource {
                shared: Rc::clone(&shared),
            },
            WarmingEmitter { shared },
        )
    }
}

/// The [`IrSource`] half of [`WarmingDevice`].
pub struct WarmingSource<S: IrSource, E: IrEmitter> {
    shared: Rc<RefCell<WarmingShared<S, E>>>,
}

impl<S: IrSource, E: IrEmitter> IrSource for WarmingSource<S, E> {
    fn dimensions(&self) -> (u32, u32) {
        self.shared.borrow().device.dimensions()
    }

    fn capture(&mut self, deadline_ms: u64) -> Result<IrFrame> {
        let mut s = self.shared.borrow_mut();
        match s.phase {
            // Cold: the first frame after a fresh open, before the emitter has warmed — the dark
            // emitter-OFF baseline for the liveness differential.
            Phase::Cold => {
                let frame = s.device.capture(deadline_ms)?;
                s.cold_mean = frame.mean();
                Ok(frame)
            }
            // Warm: stream frames until the emitter has auto-warmed (brightness rises) or the deadline
            // elapses, returning the warmed emitter-ON frame.
            Phase::Warm => {
                let deadline = Instant::now() + Duration::from_millis(deadline_ms);
                let baseline = s.cold_mean;
                let warmup = s.warmup;
                let mut brightest: Option<IrFrame> = None;
                loop {
                    let remaining = deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis() as u64;
                    if remaining == 0 {
                        break;
                    }
                    // Clamp the poll slice to ≥1 ms so a misconfigured `poll_ms == 0` can't busy-spin
                    // the warm loop.
                    let slice = remaining.min(warmup.poll_ms.max(1));
                    let frame = match s.device.capture(slice) {
                        Ok(f) => f,
                        // A poll slice with no frame: keep waiting within the overall deadline.
                        Err(MugError::Timeout(_)) => continue,
                        Err(e) => return Err(e),
                    };
                    let m = frame.mean();
                    if m >= warmup.min_mean && m >= baseline + warmup.min_delta {
                        return Ok(frame);
                    }
                    if brightest.as_ref().is_none_or(|b| m > b.mean()) {
                        brightest = Some(frame);
                    }
                }
                // Never warmed within the deadline: hand the brightest frame seen to liveness (a
                // still-dark frame is rejected → PIN), or time out if nothing was captured at all.
                brightest.ok_or(MugError::Timeout(deadline_ms))
            }
        }
    }
}

/// The [`IrEmitter`] half of [`WarmingDevice`]: selects the cold/warm phase the paired
/// [`WarmingSource`] captures, and best-effort pokes a real `SET_CUR` emitter if one was given.
pub struct WarmingEmitter<S: IrSource, E: IrEmitter> {
    shared: Rc<RefCell<WarmingShared<S, E>>>,
}

impl<S: IrSource, E: IrEmitter> IrEmitter for WarmingEmitter<S, E> {
    fn set_enabled(&mut self, on: bool) -> Result<()> {
        let mut s = self.shared.borrow_mut();
        s.phase = if on { Phase::Warm } else { Phase::Cold };
        if let Some(em) = s.emitter.as_mut()
            && let Err(e) = em.set_enabled(on)
        {
            eprintln!(
                "mug: note: IR-emitter SET_CUR (on={on}) failed; relying on streaming warmup: {e}"
            );
        }
        Ok(())
    }
}

/// Concrete [`IrSource`] half of [`WarmingBrioDevice`].
pub type WarmingBrioSource = WarmingSource<V4l2IrDevice, BrioEmitter>;
/// Concrete [`IrEmitter`] half of [`WarmingBrioDevice`].
pub type WarmingBrioEmitter = WarmingEmitter<V4l2IrDevice, BrioEmitter>;

/// The Brio wiring of [`WarmingDevice`]: a real [`V4l2IrDevice`] capture node plus an optional
/// best-effort [`BrioEmitter`] `SET_CUR`, driven by streaming warmup.
pub struct WarmingBrioDevice;

impl WarmingBrioDevice {
    /// Split a Brio capture node (and optional best-effort `SET_CUR` emitter) into the source/emitter
    /// handles [`capture_liveness_pair`](crate::camera::capture_liveness_pair) needs, with default
    /// warmup thresholds.
    pub fn split(
        device: V4l2IrDevice,
        emitter: Option<BrioEmitter>,
    ) -> (WarmingBrioSource, WarmingBrioEmitter) {
        WarmingDevice::split(device, emitter)
    }

    /// As [`WarmingBrioDevice::split`], with operator-tuned [`WarmupConfig`] thresholds.
    pub fn split_with_config(
        device: V4l2IrDevice,
        emitter: Option<BrioEmitter>,
        warmup: WarmupConfig,
    ) -> (WarmingBrioSource, WarmingBrioEmitter) {
        WarmingDevice::split_with_config(device, emitter, warmup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camera::{IrEmitter, IrSource, capture_liveness_pair};

    /// A synthetic source returning a fixed brightness per call, advancing through a ramp (last value
    /// repeats) — models the Brio's cold→warm streaming.
    struct RampSource {
        means: Vec<u8>,
        idx: usize,
        w: u32,
        h: u32,
    }
    impl IrSource for RampSource {
        fn dimensions(&self) -> (u32, u32) {
            (self.w, self.h)
        }
        fn capture(&mut self, _deadline_ms: u64) -> Result<IrFrame> {
            let v = self.means[self.idx.min(self.means.len() - 1)];
            self.idx += 1;
            IrFrame::new(self.w, self.h, vec![v; (self.w * self.h) as usize])
        }
    }
    struct NoEmitter;
    impl IrEmitter for NoEmitter {
        fn set_enabled(&mut self, _on: bool) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn cold_capture_is_the_first_dark_frame_then_warm_streams_to_bright() {
        // Dark for several frames, then a bright (warmed) frame.
        let src = RampSource {
            means: vec![2, 2, 2, 2, 2, 60],
            idx: 0,
            w: 8,
            h: 8,
        };
        let (mut s, mut e) = WarmingDevice::split(src, None::<NoEmitter>);
        e.set_enabled(false).unwrap();
        let off = s.capture(1000).unwrap();
        assert!(off.mean() < WARM_MIN_MEAN, "cold frame should be dark");
        e.set_enabled(true).unwrap();
        let on = s.capture(1000).unwrap();
        assert!(
            on.mean() >= WARM_MIN_MEAN,
            "warm capture must stream to a bright frame, got {}",
            on.mean()
        );
    }

    #[test]
    fn liveness_pair_through_warming_device_has_a_strong_differential() {
        let src = RampSource {
            means: vec![2, 2, 2, 80],
            idx: 0,
            w: 8,
            h: 8,
        };
        let (mut s, mut e) = WarmingDevice::split(src, None::<NoEmitter>);
        let pair = capture_liveness_pair(&mut s, &mut e, 1000).unwrap();
        assert!(pair.emitter_off.mean() < WARM_MIN_MEAN);
        assert!(pair.emitter_on.mean() >= WARM_MIN_MEAN);
    }

    #[test]
    fn never_warming_returns_the_dark_frame_for_liveness_to_reject() {
        // All frames stay dark: warm capture returns the brightest-seen (still dark), which liveness
        // then rejects → PIN. It must not hang or error spuriously.
        let src = RampSource {
            means: vec![3, 3, 3],
            idx: 0,
            w: 8,
            h: 8,
        };
        let (mut s, mut e) = WarmingDevice::split(src, None::<NoEmitter>);
        e.set_enabled(false).unwrap();
        let _ = s.capture(10).unwrap();
        e.set_enabled(true).unwrap();
        let on = s.capture(20).unwrap();
        assert!(
            on.mean() < WarmupConfig::default().min_mean,
            "a never-warming frame stays dark"
        );
    }

    /// A source whose every capture times out — models a camera that never delivers a frame. The warm
    /// loop must stay bounded by the deadline and surface `Timeout` (→ PIN), never stall login.
    struct StallSource {
        w: u32,
        h: u32,
    }
    impl IrSource for StallSource {
        fn dimensions(&self) -> (u32, u32) {
            (self.w, self.h)
        }
        fn capture(&mut self, deadline_ms: u64) -> Result<IrFrame> {
            // Honour the requested slice so the warm loop's wall-clock matches its deadline budget.
            std::thread::sleep(Duration::from_millis(deadline_ms.min(5)));
            Err(MugError::Timeout(deadline_ms))
        }
    }

    #[test]
    fn warm_phase_stays_bounded_and_times_out_when_no_frame_ever_arrives() {
        let (mut s, mut e) = WarmingDevice::split(StallSource { w: 8, h: 8 }, None::<NoEmitter>);
        e.set_enabled(true).unwrap();
        let deadline_ms = 60;
        let start = Instant::now();
        let result = s.capture(deadline_ms);
        let elapsed = start.elapsed();
        assert!(
            matches!(result, Err(MugError::Timeout(_))),
            "a camera that never delivers a frame must time out (→ PIN), got {result:?}"
        );
        // Bounded: the warm loop honours the deadline (generous slack for slice rounding + sleeps).
        assert!(
            elapsed < Duration::from_millis(deadline_ms * 4 + 200),
            "warm capture must not stall login; took {elapsed:?} for a {deadline_ms}ms deadline"
        );
    }

    #[test]
    fn warmup_config_thresholds_govern_when_a_frame_counts_as_warm() {
        // A frame at mean 30: warm under a low threshold, still-dark under a high one.
        let make = || RampSource {
            means: vec![2, 30],
            idx: 0,
            w: 8,
            h: 8,
        };
        let low = WarmupConfig {
            min_mean: 20.0,
            min_delta: 5.0,
            poll_ms: 50,
        };
        let (mut s, mut e) = WarmingDevice::split_with_config(make(), None::<NoEmitter>, low);
        e.set_enabled(false).unwrap();
        let _ = s.capture(50).unwrap();
        e.set_enabled(true).unwrap();
        assert!(
            s.capture(50).unwrap().mean() >= low.min_mean,
            "a low threshold accepts the mean-30 frame as warm"
        );

        let high = WarmupConfig {
            min_mean: 200.0,
            min_delta: 5.0,
            poll_ms: 50,
        };
        let (mut s, mut e) = WarmingDevice::split_with_config(make(), None::<NoEmitter>, high);
        e.set_enabled(false).unwrap();
        let _ = s.capture(50).unwrap();
        e.set_enabled(true).unwrap();
        assert!(
            s.capture(50).unwrap().mean() < high.min_mean,
            "a high threshold never treats the mean-30 frame as warm"
        );
    }
}
