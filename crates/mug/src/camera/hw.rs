//! The real Logitech Brio IR path: GREY-node selection, bounded frame capture, and the UVC
//! extension-unit IR-emitter enable. None of this is exercised in CI (no camera); the orchestrator
//! validates it against the physical Brio. It is plain safe Rust over the `sys` ioctl boundary.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::camera::{IrEmitter, IrFrame, IrSource, BRIO_IR_HEIGHT, BRIO_IR_WIDTH};
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

/// A real Brio IR capture node, configured to GREY at the sensor's native geometry.
pub struct V4l2IrDevice {
    file: File,
    width: u32,
    height: u32,
}

impl V4l2IrDevice {
    /// Open `path` and force `width`x`height` GREY. Use [`V4l2IrDevice::open_brio`] for the discovered
    /// Brio node at its native 340x340.
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
        Ok(Self {
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
        let ready = sys::poll_readable(self.file.as_raw_fd(), timeout)
            .map_err(|e| MugError::Camera(format!("poll: {e}")))?;
        if !ready {
            return Err(MugError::Timeout(deadline_ms));
        }

        let expected = (self.width as usize) * (self.height as usize);
        let mut buf = vec![0u8; expected];
        // uvcvideo delivers one full GREY frame per read for uncompressed formats; a short read means
        // a truncated/torn frame, which we reject rather than analyse.
        let n = self
            .file
            .read(&mut buf)
            .map_err(|e| MugError::Camera(format!("read frame: {e}")))?;
        if n != expected {
            return Err(MugError::Camera(format!(
                "short frame read: got {n} bytes, expected {expected}"
            )));
        }
        IrFrame::new(self.width, self.height, buf)
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
