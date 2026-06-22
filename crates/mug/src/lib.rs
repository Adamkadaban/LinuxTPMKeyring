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
//! The face factor is **host-trusted convenience, never the sole gate**. The real authorization is
//! the TPM PIN authValue: a sealed key is only released after the PIN succeeds, and no liveness
//! pass or face match on its own ever releases key material. Mug raises the spoofing bar far above
//! Howdy's (a photo or screen is rejected), but it is **not** a guarantee against a determined
//! attacker with a fabricated 3-D mask matched to the enrolled face — that is out of scope, as is
//! any root/kernel adversary on a live machine. Treat a Mug pass as "probably the right live
//! person in front of the camera," layered on the PIN, not as proof.
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
//! Wave 2 wraps [`matcher`]/[`liveness`]/[`camera`] in a bounded, non-blocking `AuthGate`; the
//! module boundaries here are designed for that.

#![deny(unsafe_code)]

pub mod camera;
pub mod config;
pub mod liveness;
pub mod matcher;
pub mod store;

#[allow(unsafe_code)]
mod sys;

mod error;

pub use error::{MugError, Result};

pub use camera::{
    capture_liveness_pair, FramePair, IrEmitter, IrFrame, IrSource, VirtualIrDevice,
    BRIO_IR_HEIGHT, BRIO_IR_WIDTH, BRIO_PRODUCT_ID, BRIO_VENDOR_ID,
};
pub use config::MugConfig;
pub use liveness::{analyze as analyze_liveness, LivenessConfig, LivenessFeatures, LivenessReport};
pub use matcher::{cosine_distance, Embedding, EmbeddingExtractor, Matcher};
pub use store::{EnrollStore, FaceEnrollment, LivenessCalibration};
