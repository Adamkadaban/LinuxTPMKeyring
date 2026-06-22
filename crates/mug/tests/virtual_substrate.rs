//! End-to-end headless exercise of the synthetic IR substrate: write procedural GREY frames to a
//! [`MugConfig`]-independent temp dir, drive the file-backed [`VirtualIrDevice`] through a full
//! liveness pair, and prove the live pair passes while photo/screen spoofs are rejected — with no
//! camera, no model, and no `unsafe`.

use mug::camera::VirtualIrDevice;
use mug::liveness::{analyze, synth, LivenessConfig};
use mug::{FramePair, IrEmitter, IrSource};

const W: u32 = 96;
const H: u32 = 96;

fn write_pair(dir: &std::path::Path, pair: &FramePair) {
    std::fs::write(
        dir.join(VirtualIrDevice::OFF_FRAME),
        pair.emitter_off.as_bytes(),
    )
    .unwrap();
    std::fs::write(
        dir.join(VirtualIrDevice::ON_FRAME),
        pair.emitter_on.as_bytes(),
    )
    .unwrap();
}

/// Drive a file-backed virtual device through an emitter OFF→ON capture (the device is both source
/// and emitter, so the toggle is sequenced here rather than via `capture_liveness_pair`, which the
/// camera unit tests cover with independent handles).
fn capture_pair_from_dir(dir: &std::path::Path) -> FramePair {
    let mut dev = VirtualIrDevice::new(dir, W, H);
    dev.set_enabled(false).unwrap();
    let off = dev.capture(500).unwrap();
    dev.set_enabled(true).unwrap();
    let on = dev.capture(500).unwrap();
    FramePair::new(off, on).unwrap()
}

#[test]
fn virtual_substrate_live_pair_passes() {
    let dir = tempfile::tempdir().unwrap();
    write_pair(dir.path(), &synth::live_pair(W, H));

    let pair = capture_pair_from_dir(dir.path());
    let report = analyze(&pair, &LivenessConfig::default()).unwrap();
    assert!(report.passed, "live pair must pass: {:?}", report.features);
}

#[test]
fn virtual_substrate_spoofs_are_rejected() {
    let cfg = LivenessConfig::default();
    for (label, spoof) in [
        ("flat_photo", synth::flat_photo_pair(W, H)),
        ("glossy_photo", synth::glossy_photo_pair(W, H)),
        ("screen", synth::screen_pair(W, H)),
    ] {
        let dir = tempfile::tempdir().unwrap();
        write_pair(dir.path(), &spoof);

        let pair = capture_pair_from_dir(dir.path());
        let report = analyze(&pair, &cfg).unwrap();
        assert!(
            !report.passed,
            "{label} must be rejected, but passed: {:?}",
            report.features
        );
    }
}
