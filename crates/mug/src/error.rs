//! Error type for the mug crate. Errors are never swallowed — a silently-dropped camera or liveness
//! error could let a spoof through or hang login, so every fallible path returns one of these and
//! the caller decides whether to fail safe (fall through to the PIN).

/// Errors surfaced by mug. Mapped to a `tess_core::Error` at the wave-2 `AuthGate` boundary via the
/// [`From`] impl below.
#[derive(Debug, thiserror::Error)]
pub enum MugError {
    /// A camera / V4L2 operation failed (open, ioctl, short read).
    #[error("camera error: {0}")]
    Camera(String),

    /// No Brio IR (GREY-format) node could be selected.
    #[error("no Brio IR (GREY) capture node found")]
    NoIrNode,

    /// The IR emitter could not be enabled. The gate must fail safe on this: no emitter means the
    /// liveness differential cannot be trusted, so the face factor degrades to the PIN.
    #[error("IR emitter enable failed: {0}")]
    Emitter(String),

    /// A bounded capture or analysis exceeded its deadline.
    #[error("operation timed out after {0}ms")]
    Timeout(u64),

    /// The active-illumination liveness check rejected the frame pair (likely a photo or screen).
    #[error("liveness rejected: {0}")]
    LivenessRejected(String),

    /// No embedding extractor is configured (no model), so the face factor is unavailable and must
    /// degrade to the PIN.
    #[error("face matcher unavailable: {0}")]
    MatcherUnavailable(String),

    /// A face was embedded but did not match the enrolled template within the threshold.
    #[error("no face match (distance {distance:.4} >= threshold {threshold:.4})")]
    NoMatch { distance: f32, threshold: f32 },

    /// Too few quality-gated frames (a face detected and aligned) were captured within the deadline
    /// to make a confident multi-frame match decision. The face factor degrades to the PIN rather
    /// than deciding identity from one or two noisy frames.
    #[error(
        "insufficient face frames for a confident match ({captured} captured, {required} required)"
    )]
    InsufficientFrames { captured: usize, required: usize },

    /// No enrollment exists for the user.
    #[error("user is not enrolled for the face factor")]
    NotEnrolled,

    /// No face was found in the frame (the detector returned nothing above threshold). The face
    /// factor degrades to the PIN; a frame with no face is rejected here rather than reaching the
    /// matcher, where it could otherwise false-match against the background.
    #[error("no face detected in frame")]
    NoFace,

    /// The enrollment store could not be read/written.
    #[error("enroll store error: {0}")]
    Store(String),

    /// A frame had unexpected dimensions or length.
    #[error("invalid frame: {0}")]
    InvalidFrame(String),

    /// Generic I/O failure with context.
    #[error("io error: {0}")]
    Io(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, MugError>;

impl From<MugError> for tess_core::Error {
    /// Collapse mug failures into the shared auth-gate error category. A face-factor failure is
    /// never fatal to login on its own — the PIN gate is authoritative — so every variant maps to
    /// the recoverable `Auth`/`Timeout` space rather than a hard error.
    fn from(e: MugError) -> Self {
        match e {
            MugError::Timeout(ms) => tess_core::Error::Timeout(ms),
            other => tess_core::Error::Auth(other.to_string()),
        }
    }
}
