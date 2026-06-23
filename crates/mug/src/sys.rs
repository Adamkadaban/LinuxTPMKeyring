//! The single `unsafe` boundary in mug: raw V4L2 and UVC ioctls.
//!
//! The Logitech Brio's IR emitter is a vendor UVC *extension-unit* control with no representation in
//! the safe `v4l` ecosystem — enabling it requires `UVCIOC_CTRL_QUERY` (a uvcvideo-private ioctl),
//! and selecting / configuring the GREY IR node requires `VIDIOC_ENUM_FMT` / `VIDIOC_S_FMT`. None of
//! those have a safe Rust wrapper, so this module holds the raw `ioctl` calls and the kernel-ABI
//! structs behind small, checked, Result-returning functions. Everything else in the crate is
//! `deny(unsafe_code)`.
//!
//! ABI references: `linux/videodev2.h` (V4L2 structs / `VIDIOC_*` codes), `linux/uvcvideo.h`
//! (`uvc_xu_control_query`, `UVCIOC_CTRL_QUERY`), and the `linux-enable-ir-emitter` project, which
//! drives the Brio emitter through exactly this `UVC_SET_CUR` extension-unit path.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::io;
use std::os::unix::io::RawFd;

/// `V4L2_BUF_TYPE_VIDEO_CAPTURE`.
pub const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;

/// `V4L2_PIX_FMT_GREY` — 8-bit greyscale, the Brio IR node's only discrete format.
pub const V4L2_PIX_FMT_GREY: u32 = fourcc(b'G', b'R', b'E', b'Y');

/// UVC request codes (`linux/usb/video.h`).
pub const UVC_SET_CUR: u8 = 0x01;
pub const UVC_GET_CUR: u8 = 0x81;
pub const UVC_GET_LEN: u8 = 0x85;
pub const UVC_GET_INFO: u8 = 0x86;

/// Build a V4L2 fourcc the same way the `v4l2_fourcc` macro does.
pub const fn fourcc(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}

/// `struct v4l2_pix_format` (single-planar). Overlaid onto the `v4l2_format` union below.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct v4l2_pix_format {
    pub width: u32,
    pub height: u32,
    pub pixelformat: u32,
    pub field: u32,
    pub bytesperline: u32,
    pub sizeimage: u32,
    pub colorspace: u32,
    pub priv_: u32,
    pub flags: u32,
    pub ycbcr_enc: u32,
    pub quantization: u32,
    pub xfer_func: u32,
}

/// `struct v4l2_format`. The kernel `fmt` member is a union whose largest variants force 8-byte
/// alignment and a 200-byte payload; modelling it as `type_ + explicit pad + [u8; 200]` reproduces
/// the exact 208-byte size the `VIDIOC_S_FMT`/`G_FMT` ioctl numbers encode. `pix` is overlaid at the
/// start of `fmt`.
#[repr(C)]
pub struct v4l2_format {
    pub type_: u32,
    pub _pad: u32,
    pub fmt: [u8; 200],
}

impl v4l2_format {
    fn zeroed(type_: u32) -> Self {
        Self {
            type_,
            _pad: 0,
            fmt: [0u8; 200],
        }
    }
}

/// `struct v4l2_fmtdesc` — one entry of the format enumeration.
#[repr(C)]
#[derive(Default)]
pub struct v4l2_fmtdesc {
    pub index: u32,
    pub type_: u32,
    pub flags: u32,
    pub description: [u8; 32],
    pub pixelformat: u32,
    pub mbus_code: u32,
    pub reserved: [u32; 3],
}

/// `struct uvc_xu_control_query` (`linux/uvcvideo.h`).
#[repr(C)]
pub struct uvc_xu_control_query {
    pub unit: u8,
    pub selector: u8,
    pub query: u8,
    pub size: u16,
    pub data: *mut u8,
}

nix::ioctl_readwrite!(vidioc_g_fmt, b'V', 4, v4l2_format);
nix::ioctl_readwrite!(vidioc_s_fmt, b'V', 5, v4l2_format);
nix::ioctl_readwrite!(vidioc_enum_fmt, b'V', 2, v4l2_fmtdesc);
nix::ioctl_readwrite!(uvcioc_ctrl_query, b'u', 0x21, uvc_xu_control_query);

// The `_IOWR` request codes above bake `size_of::<T>()` into the ioctl number, so a struct whose
// layout drifts from the kernel ABI would silently issue the wrong ioctl. These compile-time checks
// pin the sizes the kernel `videodev2.h`/`uvcvideo.h` headers define. The first three are u32-only
// (target-independent); `uvc_xu_control_query` ends in a pointer, so its size is gated to the LP64
// x86_64 ABI this crate targets.
const _: () = assert!(core::mem::size_of::<v4l2_format>() == 208);
const _: () = assert!(core::mem::size_of::<v4l2_pix_format>() == 48);
const _: () = assert!(core::mem::size_of::<v4l2_fmtdesc>() == 64);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<uvc_xu_control_query>() == 16);

fn errno_io(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// Enumerate the capture pixelformats a node advertises, returned as fourcc words. Used to pick the
/// Brio node that offers `GREY` (the IR sensor) rather than the RGB node.
pub fn enum_capture_pixelformats(fd: RawFd) -> io::Result<Vec<u32>> {
    let mut formats = Vec::new();
    let mut index = 0u32;
    loop {
        let mut desc = v4l2_fmtdesc {
            index,
            type_: V4L2_BUF_TYPE_VIDEO_CAPTURE,
            ..Default::default()
        };
        // SAFETY: `desc` is a valid, fully-initialised `v4l2_fmtdesc`; the driver reads `index`/
        // `type` and writes the remaining fields in place. `EINVAL` is the documented terminator.
        let res = unsafe { vidioc_enum_fmt(fd, &mut desc) };
        match res {
            Ok(_) => {
                formats.push(desc.pixelformat);
                index += 1;
            }
            Err(nix::errno::Errno::EINVAL) => break,
            Err(e) => return Err(errno_io(e)),
        }
    }
    Ok(formats)
}

/// Force the node to `width`x`height` `GREY` and return the dimensions the driver actually granted.
pub fn set_grey_format(fd: RawFd, width: u32, height: u32) -> io::Result<(u32, u32)> {
    let mut fmt = v4l2_format::zeroed(V4L2_BUF_TYPE_VIDEO_CAPTURE);
    let pix = v4l2_pix_format {
        width,
        height,
        pixelformat: V4L2_PIX_FMT_GREY,
        field: 1, // V4L2_FIELD_NONE
        ..Default::default()
    };
    // SAFETY: `fmt.fmt` is 200 bytes; `v4l2_pix_format` is 48 bytes and is the first union member,
    // so writing it at offset 0 is in-bounds and matches the kernel layout. `fmt` outlives the call.
    unsafe {
        let dst = fmt.fmt.as_mut_ptr() as *mut v4l2_pix_format;
        dst.write_unaligned(pix);
    }
    // SAFETY: `fmt` is a valid, fully-initialised `v4l2_format` for the capture buffer type.
    unsafe { vidioc_s_fmt(fd, &mut fmt) }.map_err(errno_io)?;

    // SAFETY: union payload was just written by the driver; reading the pix overlay back is in-bounds.
    let granted = unsafe {
        let src = fmt.fmt.as_ptr() as *const v4l2_pix_format;
        src.read_unaligned()
    };
    // V4L2 S_FMT may silently substitute a different pixelformat. This is the "force GREY" boundary,
    // so reject anything else rather than let callers read non-GREY bytes as GREY.
    if granted.pixelformat != V4L2_PIX_FMT_GREY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "driver granted pixelformat {:#010x}, not GREY ({:#010x})",
                granted.pixelformat, V4L2_PIX_FMT_GREY
            ),
        ));
    }
    Ok((granted.width, granted.height))
}

/// Issue a UVC extension-unit `SET_CUR` to `unit`/`selector` with `data`. This is the mechanism
/// `linux-enable-ir-emitter` uses to switch the Brio IR emitter on; the exact unit/selector/payload
/// are device data supplied by the caller, not magic baked in here.
pub fn uvc_set_cur(fd: RawFd, unit: u8, selector: u8, data: &[u8]) -> io::Result<()> {
    // The kernel copies `size` bytes from `data`; a wrong length is a hard error, never silent.
    let size: u16 = data
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "UVC payload exceeds u16"))?;
    let mut buf = data.to_vec();
    let mut query = uvc_xu_control_query {
        unit,
        selector,
        query: UVC_SET_CUR,
        size,
        data: buf.as_mut_ptr(),
    };
    // SAFETY: `query` is fully initialised and `query.data` points at `buf`, which is `size` bytes
    // and outlives the ioctl. SET_CUR only reads from the buffer.
    unsafe { uvcioc_ctrl_query(fd, &mut query) }.map_err(errno_io)?;
    Ok(())
}

/// Wait up to `timeout_ms` for the fd to become readable (a frame is ready). Returns `Ok(false)` on
/// timeout so the caller can surface a bounded [`crate::MugError::Timeout`] instead of blocking
/// login on a wedged camera. A `poll(2)` interrupted by a signal (`EINTR`) is retried with the
/// remaining time so a stray signal never aborts a capture, while the overall deadline stays bounded.
pub fn poll_readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let deadline = (timeout_ms >= 0)
        .then(|| std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64));
    loop {
        let remaining = match deadline {
            Some(d) => {
                let left = d.saturating_duration_since(std::time::Instant::now());
                // When the deadline has passed (or `timeout_ms == 0`), this is 0 — a non-blocking
                // poll, so an already-readable fd still reports ready instead of a false timeout.
                left.as_millis().min(i32::MAX as u128) as i32
            }
            None => -1,
        };
        // SAFETY: a single valid `pollfd` is passed with count 1; libc::poll writes only `revents`.
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            return Ok(false); // genuine timeout
        }
        if pfd.revents & libc::POLLIN != 0 {
            return Ok(true);
        }
        // poll reported the fd ready for a reason other than readable — POLLERR/POLLHUP/POLLNVAL
        // (camera unplugged, fd invalid). Surface a real error, never a misclassified timeout.
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other(format!(
                "poll on camera fd reported revents {:#x} (device error/hangup)",
                pfd.revents
            )));
        }
        return Ok(false);
    }
}
