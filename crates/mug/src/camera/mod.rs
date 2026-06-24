//! IR frame acquisition.
//!
//! Capture is abstracted behind [`IrSource`] (produces GREY frames) and [`IrEmitter`] (toggles the
//! active IR illuminator) so the security-critical liveness/matcher logic is driven by a synthetic
//! [`VirtualIrDevice`] in headless CI and by the real Logitech Brio on hardware — the same split
//! `tess-fprint` uses with libfprint's virtual driver. The orchestrator validates the real Brio
//! path against the physical camera; this crate's tests never open a real device.

mod hw;

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::error::{MugError, Result};

pub use hw::{
    BRIO_EMITTER_SELECTOR, BRIO_EMITTER_UNIT, BrioEmitter, V4l2IrDevice, WarmingBrioDevice,
    WarmingBrioEmitter, WarmingBrioSource, find_brio_ir_node,
};

/// Brio USB vendor id (Logitech).
pub const BRIO_VENDOR_ID: u16 = 0x046d;
/// Brio USB product id.
pub const BRIO_PRODUCT_ID: u16 = 0x085e;
/// The Brio IR sensor's single discrete GREY frame width.
pub const BRIO_IR_WIDTH: u32 = 340;
/// The Brio IR sensor's single discrete GREY frame height.
pub const BRIO_IR_HEIGHT: u32 = 340;

/// A single 8-bit greyscale IR frame.
#[derive(Clone, Debug)]
pub struct IrFrame {
    width: u32,
    height: u32,
    data: Vec<u8>,
}

impl IrFrame {
    /// Build a frame, validating that `data` is exactly `width * height` bytes.
    pub fn new(width: u32, height: u32, data: Vec<u8>) -> Result<Self> {
        let expected = (width as usize)
            .checked_mul(height as usize)
            .ok_or_else(|| MugError::InvalidFrame("dimension overflow".into()))?;
        if data.len() != expected {
            return Err(MugError::InvalidFrame(format!(
                "expected {expected} bytes for {width}x{height}, got {}",
                data.len()
            )));
        }
        Ok(Self {
            width,
            height,
            data,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Mean pixel value in `[0, 255]`. An empty-scene Brio IR frame with the emitter off reads near
    /// black (mean ~10); a real face under IR illumination is far brighter.
    pub fn mean(&self) -> f32 {
        if self.data.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.data.iter().map(|&p| p as u64).sum();
        sum as f32 / self.data.len() as f32
    }
}

/// An emitter-OFF / emitter-ON IR frame pair captured back-to-back for active-illumination liveness.
#[derive(Clone, Debug)]
pub struct FramePair {
    pub emitter_off: IrFrame,
    pub emitter_on: IrFrame,
}

impl FramePair {
    /// Pair two frames, requiring identical dimensions (the differential analysis is per-pixel).
    pub fn new(emitter_off: IrFrame, emitter_on: IrFrame) -> Result<Self> {
        if emitter_off.dimensions() != emitter_on.dimensions() {
            return Err(MugError::InvalidFrame(format!(
                "frame pair dimension mismatch: off {:?} vs on {:?}",
                emitter_off.dimensions(),
                emitter_on.dimensions()
            )));
        }
        Ok(Self {
            emitter_off,
            emitter_on,
        })
    }

    pub fn dimensions(&self) -> (u32, u32) {
        self.emitter_off.dimensions()
    }
}

/// A source of IR frames. The real hardware implementation must honour `deadline_ms` and never
/// block past it (a wedged camera must not freeze the unlock); in-memory/test sources that return a
/// frame immediately trivially satisfy this and may ignore the parameter.
pub trait IrSource {
    fn dimensions(&self) -> (u32, u32);
    /// Capture one frame, bounded by `deadline_ms`.
    fn capture(&mut self, deadline_ms: u64) -> Result<IrFrame>;
}

/// Controls the active IR illuminator. The real implementation drives the Brio's UVC extension-unit
/// control; the virtual one just records state.
pub trait IrEmitter {
    /// Turn the emitter on or off. Must be bounded and must surface failure (the gate fails safe on
    /// an emitter error rather than treating a dark frame as "live").
    fn set_enabled(&mut self, on: bool) -> Result<()>;
}

/// Capture a liveness frame pair: emitter OFF → capture, emitter ON → capture, then best-effort
/// restore OFF. The whole operation is bounded by `deadline_ms`: the first capture gets half the
/// budget and the second gets whatever remains, so two captures never exceed the caller's deadline.
pub fn capture_liveness_pair<S, E>(
    source: &mut S,
    emitter: &mut E,
    deadline_ms: u64,
) -> Result<FramePair>
where
    S: IrSource,
    E: IrEmitter,
{
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let first_budget = deadline_ms / 2;

    emitter.set_enabled(false)?;
    let off = source.capture(first_budget)?;

    emitter.set_enabled(true)?;
    // Whatever is left of the overall budget (saturating to 0), so the pair stays within deadline_ms
    // even for tiny/misconfigured values. The remaining span never exceeds deadline_ms, so it fits u64.
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_millis() as u64;
    let on = source.capture(remaining)?;

    // Restoring the emitter to off is best-effort cleanup: a failure here must not turn a captured
    // pair into an error (the emitter starts off again on the next pair regardless), but it is
    // logged rather than swallowed so an operator can spot a flaky emitter.
    if let Err(e) = emitter.set_enabled(false) {
        eprintln!("mug: warning: failed to restore IR emitter to off (best-effort): {e}");
    }

    FramePair::new(off, on)
}

/// File-backed synthetic IR device: the CI substrate. Reads two raw GREY blobs from a directory
/// (selected with [`VirtualIrDevice::ENV_DIR`]), returning the OFF blob while the emitter is off and
/// the ON blob while it is on. It implements both [`IrSource`] and [`IrEmitter`], so it stands in for
/// the whole Brio device in tests without any kernel, camera, or `unsafe` involvement.
pub struct VirtualIrDevice {
    dir: PathBuf,
    width: u32,
    height: u32,
    enabled: bool,
}

impl VirtualIrDevice {
    /// Environment variable naming the directory of synthetic GREY frames (mirrors
    /// `tess-fprint`'s `FP_VIRTUAL_DEVICE` env-selected substrate).
    pub const ENV_DIR: &'static str = "MUG_VIRTUAL_IR_DIR";
    /// Raw GREY frame served while the emitter is off.
    pub const OFF_FRAME: &'static str = "ir_off.grey";
    /// Raw GREY frame served while the emitter is on.
    pub const ON_FRAME: &'static str = "ir_on.grey";

    /// Construct from an explicit directory and frame dimensions.
    pub fn new(dir: impl Into<PathBuf>, width: u32, height: u32) -> Self {
        Self {
            dir: dir.into(),
            width,
            height,
            enabled: false,
        }
    }

    /// Construct from [`VirtualIrDevice::ENV_DIR`], defaulting to the Brio IR geometry.
    pub fn from_env() -> Result<Self> {
        let dir = std::env::var_os(Self::ENV_DIR)
            .ok_or_else(|| MugError::Camera(format!("{} is not set", Self::ENV_DIR)))?;
        Ok(Self::new(PathBuf::from(dir), BRIO_IR_WIDTH, BRIO_IR_HEIGHT))
    }

    fn load(&self, name: &str) -> Result<IrFrame> {
        load_synthetic(&self.dir, name, self.width, self.height)
    }

    /// Split the synthetic device into independent source and emitter handles that share emitter
    /// state through an `Rc<Cell<bool>>`. The combined [`VirtualIrDevice`] is both [`IrSource`] and
    /// [`IrEmitter`] but cannot be borrowed mutably as both at once, which
    /// [`capture_liveness_pair`] requires; this pair is the headless analogue of the real Brio's
    /// separate capture node and emitter control.
    pub fn split(
        dir: impl Into<PathBuf>,
        width: u32,
        height: u32,
    ) -> (VirtualIrSource, VirtualIrEmitter) {
        let state = Rc::new(Cell::new(false));
        let dir = dir.into();
        (
            VirtualIrSource {
                dir,
                width,
                height,
                state: Rc::clone(&state),
            },
            VirtualIrEmitter { state },
        )
    }

    /// Split from [`VirtualIrDevice::ENV_DIR`], defaulting to the Brio IR geometry.
    pub fn split_from_env() -> Result<(VirtualIrSource, VirtualIrEmitter)> {
        let dir = std::env::var_os(Self::ENV_DIR)
            .ok_or_else(|| MugError::Camera(format!("{} is not set", Self::ENV_DIR)))?;
        Ok(Self::split(
            PathBuf::from(dir),
            BRIO_IR_WIDTH,
            BRIO_IR_HEIGHT,
        ))
    }
}

fn load_synthetic(dir: &Path, name: &str, width: u32, height: u32) -> Result<IrFrame> {
    let path = dir.join(name);
    let data = fs::read(&path)
        .map_err(|e| MugError::Camera(format!("read synthetic frame {}: {e}", path.display())))?;
    IrFrame::new(width, height, data)
}

/// The [`IrSource`] half of [`VirtualIrDevice::split`]: serves the OFF/ON synthetic frame selected
/// by the shared emitter state.
pub struct VirtualIrSource {
    dir: PathBuf,
    width: u32,
    height: u32,
    state: Rc<Cell<bool>>,
}

impl IrSource for VirtualIrSource {
    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture(&mut self, _deadline_ms: u64) -> Result<IrFrame> {
        let name = if self.state.get() {
            VirtualIrDevice::ON_FRAME
        } else {
            VirtualIrDevice::OFF_FRAME
        };
        load_synthetic(&self.dir, name, self.width, self.height)
    }
}

/// The [`IrEmitter`] half of [`VirtualIrDevice::split`]: toggles the state the paired
/// [`VirtualIrSource`] reads.
pub struct VirtualIrEmitter {
    state: Rc<Cell<bool>>,
}

impl IrEmitter for VirtualIrEmitter {
    fn set_enabled(&mut self, on: bool) -> Result<()> {
        self.state.set(on);
        Ok(())
    }
}

impl IrSource for VirtualIrDevice {
    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture(&mut self, _deadline_ms: u64) -> Result<IrFrame> {
        let name = if self.enabled {
            Self::ON_FRAME
        } else {
            Self::OFF_FRAME
        };
        self.load(name)
    }
}

impl IrEmitter for VirtualIrDevice {
    fn set_enabled(&mut self, on: bool) -> Result<()> {
        self.enabled = on;
        Ok(())
    }
}

/// Read a raw GREY blob from `path` into an [`IrFrame`]. Convenience for callers wiring up synthetic
/// fixtures or `.grey` dumps captured elsewhere.
pub fn read_grey_file(path: impl AsRef<Path>, width: u32, height: u32) -> Result<IrFrame> {
    let path = path.as_ref();
    let data = fs::read(path).map_err(|e| MugError::Io(format!("read {}: {e}", path.display())))?;
    IrFrame::new(width, height, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A source whose returned frame depends on a shared emitter-state cell, so `capture_liveness_pair`
    /// can be driven end-to-end with independent source and emitter handles.
    struct SharedSource {
        off: IrFrame,
        on: IrFrame,
        state: Rc<RefCell<bool>>,
    }
    struct SharedEmitter {
        state: Rc<RefCell<bool>>,
    }
    impl IrSource for SharedSource {
        fn dimensions(&self) -> (u32, u32) {
            self.off.dimensions()
        }
        fn capture(&mut self, _deadline_ms: u64) -> Result<IrFrame> {
            Ok(if *self.state.borrow() {
                self.on.clone()
            } else {
                self.off.clone()
            })
        }
    }
    impl IrEmitter for SharedEmitter {
        fn set_enabled(&mut self, on: bool) -> Result<()> {
            *self.state.borrow_mut() = on;
            Ok(())
        }
    }

    #[test]
    fn capture_liveness_pair_drives_emitter_then_captures() {
        let state = Rc::new(RefCell::new(false));
        let mut src = SharedSource {
            off: IrFrame::new(2, 2, vec![5, 5, 5, 5]).unwrap(),
            on: IrFrame::new(2, 2, vec![200, 200, 200, 200]).unwrap(),
            state: Rc::clone(&state),
        };
        let mut emitter = SharedEmitter {
            state: Rc::clone(&state),
        };
        let pair = capture_liveness_pair(&mut src, &mut emitter, 200).unwrap();
        assert_eq!(pair.emitter_off.mean(), 5.0);
        assert_eq!(pair.emitter_on.mean(), 200.0);
        // Emitter restored to off after the pair.
        assert!(!*state.borrow());
    }

    #[test]
    fn frame_rejects_wrong_length() {
        let err = IrFrame::new(4, 4, vec![0u8; 15]).unwrap_err();
        assert!(matches!(err, MugError::InvalidFrame(_)));
    }

    #[test]
    fn frame_pair_rejects_dim_mismatch() {
        let a = IrFrame::new(2, 2, vec![0; 4]).unwrap();
        let b = IrFrame::new(2, 3, vec![0; 6]).unwrap();
        assert!(FramePair::new(a, b).is_err());
    }

    #[test]
    fn mean_is_average_pixel() {
        let f = IrFrame::new(2, 2, vec![0, 10, 20, 30]).unwrap();
        assert_eq!(f.mean(), 15.0);
    }

    #[test]
    fn virtual_device_serves_off_then_on() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(VirtualIrDevice::OFF_FRAME), vec![5u8; 16]).unwrap();
        std::fs::write(dir.path().join(VirtualIrDevice::ON_FRAME), vec![200u8; 16]).unwrap();
        let mut dev = VirtualIrDevice::new(dir.path(), 4, 4);

        dev.set_enabled(false).unwrap();
        assert_eq!(dev.capture(100).unwrap().mean(), 5.0);
        dev.set_enabled(true).unwrap();
        assert_eq!(dev.capture(100).unwrap().mean(), 200.0);
    }

    #[test]
    fn capture_pair_toggles_emitter_and_returns_both() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(VirtualIrDevice::OFF_FRAME), vec![5u8; 16]).unwrap();
        std::fs::write(dir.path().join(VirtualIrDevice::ON_FRAME), vec![200u8; 16]).unwrap();
        let mut dev = VirtualIrDevice::new(dir.path(), 4, 4);
        // VirtualIrDevice is both source and emitter; capture_liveness_pair needs two handles, so
        // exercise the toggle sequence manually here and the integrated path in the crate tests.
        dev.set_enabled(false).unwrap();
        let off = dev.capture(100).unwrap();
        dev.set_enabled(true).unwrap();
        let on = dev.capture(100).unwrap();
        let pair = FramePair::new(off, on).unwrap();
        assert_eq!(pair.emitter_off.mean(), 5.0);
        assert_eq!(pair.emitter_on.mean(), 200.0);
    }
}
