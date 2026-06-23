//! Mug — a secure IR face factor for tess.
//!
//! # What this is
//!
//! Mug is the face-recognition leg of tess's multi-factor unlock. Unlike Howdy — which runs RGB (or
//! raw IR) face *recognition* with **no liveness defense**, so a printed photo or a phone screen
//! held to the lens authenticates — Mug's first-class job is **anti-spoofing via active IR
//! reflectance**. It captures a pair of IR frames with the camera's IR emitter OFF then ON and
//! rejects anything whose differential response is flat or screen-like rather than a real,
//! 3-D, skin-reflectance surface (see [`liveness`]).
//!
//! # Security framing (read this before trusting it)
//!
//! Mug provides **face-or-PIN unlock** (Windows-Hello-style): a successful, liveness-gated face
//! match releases the keyring key with no PIN typed, and the **PIN remains an always-available
//! fallback**. This is a deliberate trade-off. With a typed PIN nothing that unlocks the key is ever
//! stored, so PIN login is self-protecting at rest. To unlock with just a face, the face gate must
//! hand the TPM the unlock credential, so that credential is stored on the device, protected by the
//! liveness-gated match plus filesystem permissions (and the device's disk encryption when present).
//! Commodity Linux has no VBS/TEE to anchor that, so face-unlock's powered-off-theft resistance is
//! weaker than PIN-only's. Mug raises the spoofing bar far above Howdy's (a photo or screen is
//! rejected), but it is **not** a guarantee against a determined attacker with a fabricated 3-D mask
//! matched to the enrolled face — out of scope, as is any root/kernel adversary on a live machine.
//! Treat a Mug pass as "probably the right live person in front of the camera." Users who want the
//! strongest at-rest posture use PIN login and leave face unenrolled.
//!
//! # Shape
//!
//! - [`camera`] — IR frame acquisition behind the [`camera::IrSource`] / [`camera::IrEmitter`]
//!   traits, so a synthetic source ([`camera::VirtualIrDevice`]) drives headless tests while the
//!   real Logitech Brio path ([`camera::V4l2IrDevice`] + [`camera::BrioEmitter`]) runs on hardware.
//! - [`liveness`] — the active-illumination differential analysis; deterministic and unit-tested.
//! - [`matcher`] — a pluggable IR-frame embedding matcher ([`matcher::EmbeddingExtractor`]) with
//!   cosine-distance verification. No model ships with tess; CI uses a deterministic mock.
//! - [`store`] — per-user enrollment (the IR embedding + liveness calibration, never a raw image),
//!   0600 under the XDG data dir, zeroized in memory.
//! - `sys` — the only place `unsafe` lives: raw V4L2 / UVC ioctls (the Brio IR-emitter is a vendor
//!   UVC extension-unit control with no safe wrapper).
//!
//! [`verify`] composes capture → liveness → match into one bounded operation, and [`FaceGate`] wraps
//! it behind [`tess_core::AuthGate`] so face slots into the same bounded `authorize(deadline_ms)`
//! interface as the fingerprint gate.

#![deny(unsafe_code)]

pub mod camera;
pub mod config;
pub mod liveness;
pub mod matcher;
pub mod store;

#[allow(unsafe_code)]
mod sys;

mod error;
mod gate;

pub use error::{MugError, Result};

pub use camera::{
    BRIO_EMITTER_SELECTOR, BRIO_EMITTER_UNIT, BRIO_IR_HEIGHT, BRIO_IR_WIDTH, BRIO_PRODUCT_ID,
    BRIO_VENDOR_ID, BrioEmitter, FramePair, IrEmitter, IrFrame, IrSource, V4l2IrDevice,
    VirtualIrDevice, VirtualIrEmitter, VirtualIrSource, capture_liveness_pair, find_brio_ir_node,
};
pub use config::MugConfig;
pub use gate::{FaceGate, verify};
pub use liveness::{LivenessConfig, LivenessFeatures, LivenessReport, analyze as analyze_liveness};
pub use matcher::{Embedding, EmbeddingExtractor, Matcher, PooledExtractor, cosine_distance};
pub use store::{EnrollStore, FaceEnrollment, LivenessCalibration};
