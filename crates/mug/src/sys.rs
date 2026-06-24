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
/// `V4L2_MEMORY_MMAP`.
pub const V4L2_MEMORY_MMAP: u32 = 1;

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

/// `struct v4l2_requestbuffers`.
#[repr(C)]
#[derive(Default)]
pub struct v4l2_requestbuffers {
    pub count: u32,
    pub type_: u32,
    pub memory: u32,
    pub capabilities: u32,
    pub flags: u8,
    pub reserved: [u8; 3],
}

/// `struct v4l2_timecode` (nested in `v4l2_buffer`).
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct v4l2_timecode {
    pub type_: u32,
    pub flags: u32,
    pub frames: u8,
    pub seconds: u8,
    pub minutes: u8,
    pub hours: u8,
    pub userbits: [u8; 4],
}

/// `struct v4l2_buffer` (single-planar, MMAP). The `timestamp` is modelled as two `i64`s (`timeval`
/// on LP64) and the `m` union as a `u64`; its MMAP `offset` member (`__u32`) is the first 4 bytes of
/// the union in memory and is read endian-safely in [`MmapStream::start`]. The size is pinned to the
/// kernel ABI below.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct v4l2_buffer {
    pub index: u32,
    pub type_: u32,
    pub bytesused: u32,
    pub flags: u32,
    pub field: u32,
    pub timestamp_sec: i64,
    pub timestamp_usec: i64,
    pub timecode: v4l2_timecode,
    pub sequence: u32,
    pub memory: u32,
    pub m: u64,
    pub length: u32,
    pub reserved2: u32,
    pub request_fd: u32,
}

impl v4l2_buffer {
    fn capture_mmap(index: u32) -> Self {
        Self {
            index,
            type_: V4L2_BUF_TYPE_VIDEO_CAPTURE,
            memory: V4L2_MEMORY_MMAP,
            ..Default::default()
        }
    }
}

nix::ioctl_readwrite!(vidioc_g_fmt, b'V', 4, v4l2_format);
nix::ioctl_readwrite!(vidioc_s_fmt, b'V', 5, v4l2_format);
nix::ioctl_readwrite!(vidioc_enum_fmt, b'V', 2, v4l2_fmtdesc);
nix::ioctl_readwrite!(uvcioc_ctrl_query, b'u', 0x21, uvc_xu_control_query);
nix::ioctl_readwrite!(vidioc_reqbufs, b'V', 8, v4l2_requestbuffers);
nix::ioctl_readwrite!(vidioc_querybuf, b'V', 9, v4l2_buffer);
nix::ioctl_readwrite!(vidioc_qbuf, b'V', 15, v4l2_buffer);
nix::ioctl_readwrite!(vidioc_dqbuf, b'V', 17, v4l2_buffer);
nix::ioctl_write_ptr!(vidioc_streamon, b'V', 18, i32);
nix::ioctl_write_ptr!(vidioc_streamoff, b'V', 19, i32);

// The `_IOWR` request codes above bake `size_of::<T>()` into the ioctl number, so a struct whose
// layout drifts from the kernel ABI would silently issue the wrong ioctl. These compile-time checks
// pin the sizes the kernel `videodev2.h`/`uvcvideo.h` headers define. The first three are u32-only
// (target-independent); `uvc_xu_control_query` ends in a pointer, so its size is gated to the LP64
// x86_64 ABI this crate targets.
const _: () = assert!(core::mem::size_of::<v4l2_format>() == 208);
const _: () = assert!(core::mem::size_of::<v4l2_pix_format>() == 48);
const _: () = assert!(core::mem::size_of::<v4l2_fmtdesc>() == 64);
const _: () = assert!(core::mem::size_of::<v4l2_requestbuffers>() == 20);
const _: () = assert!(core::mem::size_of::<v4l2_timecode>() == 16);
const _: () = assert!(core::mem::size_of::<v4l2_buffer>() == 88);
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

/// A V4L2 MMAP streaming session: request + memory-map a small ring of capture buffers, queue them,
/// and `STREAMON`. The Brio IR node only advertises streaming I/O (no `read()`), so this is the only
/// way to pull frames from it. Frames are dequeued, copied out, and the buffer is requeued. On drop
/// it `STREAMOFF`s and unmaps every buffer. Lives in the `unsafe` `sys` boundary; the rest of the
/// crate drives it through [`MmapStream::dequeue`].
pub struct MmapStream {
    fd: RawFd,
    buffers: Vec<(*mut u8, usize)>,
    streaming: bool,
}

impl MmapStream {
    /// Request `count` MMAP buffers on `fd`, map and queue them, and start streaming. `fd` must
    /// outlive the returned stream (the caller's `File` owns it; declare this field before the file
    /// so it drops first, while the fd is still open).
    pub fn start(fd: RawFd, count: u32) -> io::Result<Self> {
        let mut req = v4l2_requestbuffers {
            count,
            type_: V4L2_BUF_TYPE_VIDEO_CAPTURE,
            memory: V4L2_MEMORY_MMAP,
            ..Default::default()
        };
        // SAFETY: `req` is a valid, fully-initialised `v4l2_requestbuffers`; the driver reads
        // count/type/memory and writes the granted count back in place.
        unsafe { vidioc_reqbufs(fd, &mut req) }.map_err(errno_io)?;
        if req.count == 0 {
            return Err(io::Error::other("driver granted zero capture buffers"));
        }

        let mut stream = MmapStream {
            fd,
            buffers: Vec::with_capacity(req.count as usize),
            streaming: false,
        };

        for index in 0..req.count {
            let mut buf = v4l2_buffer::capture_mmap(index);
            // SAFETY: `buf` is a valid `v4l2_buffer` requesting MMAP buffer `index`; the driver fills
            // its `length` and `m.offset` in place. On error `stream`'s Drop unmaps any earlier maps.
            unsafe { vidioc_querybuf(fd, &mut buf) }.map_err(errno_io)?;
            let length = buf.length as usize;
            // The C `m` union's MMAP `offset` member (`__u32`) occupies the first 4 bytes of the
            // union in memory. Read those bytes in memory order so the value is correct regardless of
            // host endianness (on big-endian the offset is the high half of the `u64`, not `& low32`).
            let m_bytes = buf.m.to_ne_bytes();
            let offset =
                u32::from_ne_bytes([m_bytes[0], m_bytes[1], m_bytes[2], m_bytes[3]]) as libc::off_t;
            // SAFETY: map exactly the driver-reported buffer length at the driver-reported mmap
            // offset on the capture fd. The result is checked against MAP_FAILED before use and
            // unmapped in Drop with the same length.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    offset,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            stream.buffers.push((ptr.cast::<u8>(), length));

            let mut qbuf = v4l2_buffer::capture_mmap(index);
            // SAFETY: queue the just-mapped buffer `index` for capture; valid fully-init struct.
            unsafe { vidioc_qbuf(fd, &mut qbuf) }.map_err(errno_io)?;
        }

        let buf_type = V4L2_BUF_TYPE_VIDEO_CAPTURE as i32;
        // SAFETY: STREAMON takes a pointer to the buffer-type int; `buf_type` outlives the call.
        unsafe { vidioc_streamon(fd, &buf_type) }.map_err(errno_io)?;
        stream.streaming = true;
        Ok(stream)
    }

    /// Dequeue one full `expected_len`-byte frame, then requeue the buffer. Returns `Ok(None)` on a
    /// poll timeout within `timeout_ms` (the caller maps that to a bounded `Timeout`), so a wedged
    /// camera never blocks login.
    ///
    /// A size mismatch (`bytesused != expected_len`, or a buffer mapped shorter than the frame)
    /// **fails closed** with an error rather than zero-padding a short frame: padding the dark
    /// emitter-OFF baseline with zeros would inflate the liveness delta and risk a false accept. The
    /// buffer is requeued first so a single corrupt frame doesn't starve the stream.
    pub fn dequeue(&mut self, timeout_ms: i32, expected_len: usize) -> io::Result<Option<Vec<u8>>> {
        if !poll_readable(self.fd, timeout_ms)? {
            return Ok(None);
        }
        let mut buf = v4l2_buffer {
            type_: V4L2_BUF_TYPE_VIDEO_CAPTURE,
            memory: V4L2_MEMORY_MMAP,
            ..Default::default()
        };
        // SAFETY: DQBUF fills `buf` (index/bytesused/…) for the next ready buffer; valid struct.
        unsafe { vidioc_dqbuf(self.fd, &mut buf) }.map_err(errno_io)?;
        let idx = buf.index as usize;
        let &(ptr, len) = self
            .buffers
            .get(idx)
            .ok_or_else(|| io::Error::other(format!("DQBUF returned out-of-range index {idx}")))?;

        let bytesused = buf.bytesused as usize;
        // Copy the full frame out of the mapped buffer *before* requeueing it (the driver may reuse
        // the buffer the moment it is queued). Only a frame whose driver-reported length matches the
        // expected size and fits the mapping is accepted.
        let frame = if bytesused == expected_len && expected_len <= len {
            let mut out = vec![0u8; expected_len];
            // SAFETY: `ptr` maps `len` bytes; `expected_len <= len`, so the copy reads exactly
            // `expected_len` valid mapped bytes into `out` (which has `expected_len` bytes).
            unsafe {
                std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), expected_len);
            }
            Some(out)
        } else {
            None
        };

        let mut requeue = v4l2_buffer::capture_mmap(buf.index);
        // SAFETY: requeue the same buffer index for further capture; valid fully-init struct.
        unsafe { vidioc_qbuf(self.fd, &mut requeue) }.map_err(errno_io)?;

        match frame {
            Some(out) => Ok(Some(out)),
            None => Err(io::Error::other(format!(
                "V4L2 frame size mismatch: driver reported {bytesused} bytes for an \
                 {expected_len}-byte frame (mapped {len}); failing closed rather than padding"
            ))),
        }
    }
}

impl Drop for MmapStream {
    fn drop(&mut self) {
        if self.streaming {
            let buf_type = V4L2_BUF_TYPE_VIDEO_CAPTURE as i32;
            // SAFETY: STREAMOFF on the still-open capture fd; best-effort cleanup.
            unsafe {
                let _ = vidioc_streamoff(self.fd, &buf_type);
            }
        }
        for &(ptr, len) in &self.buffers {
            // SAFETY: each `(ptr, len)` came from a successful `mmap` with the same length and has
            // not been unmapped before; unmap exactly once here.
            unsafe {
                libc::munmap(ptr.cast::<libc::c_void>(), len);
            }
        }
    }
}
