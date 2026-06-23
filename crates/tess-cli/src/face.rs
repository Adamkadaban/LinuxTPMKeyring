//! CLI-facing face-factor plumbing: resolve the current user, build the mug enroll store, and
//! construct the IR capture pipeline (template capture at enroll, bounded verify at unlock) from the
//! environment. The only capture backend wired today is the virtual IR substrate + model-free mock
//! matcher, selected via `MUG_VIRTUAL_IR_DIR` (used by CI and to try the flow). Real Brio capture +
//! an ONNX matcher model are a tracked follow-up (issue #56); until then a non-virtual environment
//! reports the factor unavailable and the caller degrades to the PIN.

use anyhow::{anyhow, Context, Result};
use mug::{
    EnrollStore, FaceEnrollment, LivenessCalibration, LivenessConfig, Matcher, MugConfig,
    PooledExtractor, VirtualIrDevice,
};
use tess_core::SecretBytes;

use crate::enroll::sealer::KeySealer;
use crate::enroll::{recovery, FaceTemplateSource, Paths};

/// Embedding dimensionality for the model-free CI matcher. The real ONNX matcher's dimensionality
/// comes from the loaded network; this only governs the deterministic mock path.
const MOCK_DIM: usize = 64;

/// Resolve the current login user, used as the mug-store key. Reads `$USER`, then `$LOGNAME`.
pub fn current_username() -> Result<String> {
    for var in ["USER", "LOGNAME"] {
        if let Some(value) = std::env::var_os(var) {
            let name = value.to_string_lossy().into_owned();
            if !name.is_empty() {
                return Ok(name);
            }
        }
    }
    Err(anyhow!(
        "cannot resolve the current username (neither $USER nor $LOGNAME is set)"
    ))
}

/// The per-user mug enrollment store (the IR embedding + liveness calibration, never a raw image).
pub fn enroll_store() -> Result<EnrollStore> {
    EnrollStore::default_location().map_err(|e| anyhow!("resolve the mug enroll store: {e}"))
}

/// Whether the headless virtual IR substrate is selected (CI / sim runs).
fn virtual_substrate() -> bool {
    std::env::var_os(VirtualIrDevice::ENV_DIR).is_some()
}

/// A mug-backed [`FaceTemplateSource`]: capture a liveness-gated pair and embed the emitter-ON frame
/// into an enrollment template. Generic over the capture/embedding backends so the same logic serves
/// the virtual CI substrate and real hardware.
struct MugTemplateSource<S, E, X>
where
    S: mug::IrSource,
    E: mug::IrEmitter,
    X: mug::EmbeddingExtractor,
{
    source: S,
    emitter: E,
    matcher: Matcher<X>,
    liveness_cfg: LivenessConfig,
    match_threshold: f32,
    deadline_ms: u64,
}

impl<S, E, X> FaceTemplateSource for MugTemplateSource<S, E, X>
where
    S: mug::IrSource,
    E: mug::IrEmitter,
    X: mug::EmbeddingExtractor,
{
    fn capture_template(&mut self) -> Result<FaceEnrollment> {
        let pair =
            mug::capture_liveness_pair(&mut self.source, &mut self.emitter, self.deadline_ms)
                .map_err(|e| anyhow!("capture the IR frame pair: {e}"))?;
        let features = mug::analyze_liveness(&pair, &self.liveness_cfg)
            .map_err(|e| anyhow!("analyze liveness: {e}"))?
            .into_result()
            .map_err(|e| anyhow!("liveness check failed during enrollment: {e}"))?;
        let embedding = self
            .matcher
            .embed(&pair.emitter_on)
            .map_err(|e| anyhow!("embed the enrollment frame: {e}"))?;
        Ok(FaceEnrollment::new(
            embedding,
            self.match_threshold,
            LivenessCalibration {
                enrolled_score: features.score,
                score_threshold: self.liveness_cfg.score_threshold,
            },
        ))
    }
}

/// Build the face template source from the environment. Returns an owned trait object the enrollment
/// transaction drives once. Errors (no virtual substrate and no model) leave the PIN enrollment
/// untouched — the transaction rolls the whole thing back.
pub fn template_source_from_env() -> Result<Box<dyn FaceTemplateSource>> {
    let cfg = MugConfig::default();
    if virtual_substrate() {
        let (source, emitter) = VirtualIrDevice::split_from_env()
            .map_err(|e| anyhow!("open the virtual IR device: {e}"))?;
        let matcher = Matcher::new(
            PooledExtractor::new(MOCK_DIM).map_err(|e| anyhow!("build the mock matcher: {e}"))?,
            cfg.match_threshold,
        );
        Ok(Box::new(MugTemplateSource {
            source,
            emitter,
            matcher,
            liveness_cfg: cfg.liveness_config(),
            match_threshold: cfg.match_threshold,
            deadline_ms: cfg.capture_deadline_ms,
        }))
    } else {
        Err(anyhow!(
            "no face capture backend available: set {} for the virtual IR substrate (the only backend wired \
             today; real-camera capture + an IR matcher model are a follow-up, see issue #56)",
            VirtualIrDevice::ENV_DIR
        ))
    }
}

/// Run the bounded face verify against `enrolled`, building the capture pipeline from the
/// environment. `Ok(())` means a live, matching face; any error is the caller's cue to fall back to
/// the PIN.
pub fn verify_from_env(enrolled: &FaceEnrollment) -> Result<()> {
    let cfg = MugConfig::default();
    if virtual_substrate() {
        let (mut source, mut emitter) = VirtualIrDevice::split_from_env()
            .map_err(|e| anyhow!("open the virtual IR device: {e}"))?;
        let matcher = Matcher::new(
            PooledExtractor::new(MOCK_DIM).map_err(|e| anyhow!("build the mock matcher: {e}"))?,
            cfg.match_threshold,
        );
        mug::verify(
            &mut source,
            &mut emitter,
            &matcher,
            enrolled,
            &cfg.liveness_config(),
            cfg.capture_deadline_ms,
        )
        .map_err(|e| anyhow!("face verification failed: {e}"))
    } else {
        Err(anyhow!(
            "no face capture backend available: set {} for the virtual IR substrate (the only backend wired \
             today; real-camera capture + an IR matcher model are a follow-up, see issue #56)",
            VirtualIrDevice::ENV_DIR
        ))
    }
}

/// Load the current user's face enrollment, or `None` when not enrolled for the face factor.
pub fn load_enrollment() -> Result<Option<FaceEnrollment>> {
    let store = enroll_store()?;
    let username = current_username()?;
    store
        .load(&username)
        .map_err(|e| anyhow!("load the face enrollment for {username}: {e}"))
}

/// Whether the current user has a face template on disk, without creating/chmod-ing the store dir
/// (so read-only status probes never mutate the filesystem). `false` when the store/username can't
/// be resolved.
pub fn template_present() -> bool {
    match (enroll_store(), current_username()) {
        (Ok(store), Ok(username)) => store.is_enrolled(&username).unwrap_or(false),
        _ => false,
    }
}

/// Read the face authValue (`A_face`) from disk and unseal the keyring key from the face-sealed
/// metadata. Assumes the face gate already passed; the caller unlocks the keyring with the result.
pub fn unseal_with_face<S: KeySealer>(sealer: &mut S, paths: &Paths) -> Result<SecretBytes> {
    let a_face = recovery::read_secret_file(&paths.face_key)
        .with_context(|| format!("read the face authValue {}", paths.face_key.display()))?;
    let metadata = tess_tpm::persist::load(&paths.metadata_face)
        .with_context(|| format!("load the face metadata {}", paths.metadata_face.display()))?;
    let sealed = tess_tpm::persist::from_metadata(&metadata)
        .context("reconstruct the face-sealed object from metadata")?;
    sealer
        .unseal(&sealed, &a_face)
        .context("unseal the keyring key with the face authValue")
}
