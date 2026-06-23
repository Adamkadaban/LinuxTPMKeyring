//! CLI-facing face-factor plumbing: resolve the current user, build the mug enroll store, and
//! construct the IR capture pipeline (template capture at enroll, bounded verify at unlock) from the
//! environment.
//!
//! Two capture backends are wired, selected by [`select_backend`]:
//!
//! - the headless **virtual IR substrate** (`MUG_VIRTUAL_IR_DIR`), used by CI and to try the flow; and
//! - the real **Logitech Brio** IR path (the GREY IR node + the UVC-XU emitter), opt-in and validated
//!   only by a manual host smoke — never in CI.
//!
//! Both run the same liveness gate and, today, the same model-free mock matcher: tess ships no face
//! model, so identity matching stays a deterministic mock until an ONNX matcher backend lands. When
//! no backend is available (no substrate, no camera) the factor reports unavailable and the caller
//! degrades to the PIN.

use anyhow::{Context, Result, anyhow};
use mug::{
    EnrollStore, FaceEnrollment, IrEmitter, IrSource, LivenessCalibration, LivenessConfig, Matcher,
    MugConfig, PooledExtractor, VirtualIrDevice,
};
use tess_core::SecretBytes;

use crate::enroll::sealer::KeySealer;
use crate::enroll::{FaceTemplateSource, Paths, recovery};

/// Embedding dimensionality for the model-free CI matcher. A real ONNX matcher's dimensionality
/// comes from the loaded network; this only governs the deterministic mock path.
const MOCK_DIM: usize = 64;

/// Selects the IR capture backend (`auto` | `virtual` | `hardware`).
const ENV_BACKEND: &str = "MUG_IR_BACKEND";
/// Hex-encoded UVC SET_CUR payload that turns the Brio IR emitter on (overrides the default).
const ENV_EMITTER_ON: &str = "MUG_IR_EMITTER_ON_HEX";
/// Hex-encoded UVC SET_CUR payload that turns the Brio IR emitter off (overrides the default).
const ENV_EMITTER_OFF: &str = "MUG_IR_EMITTER_OFF_HEX";

/// Default Brio IR-emitter payloads. The exact bytes are device-confirmed during the manual smoke;
/// a wrong value fails safe (the emitter stays off, the liveness differential cannot pass, the face
/// factor degrades to the PIN), so these defaults are only a starting point, overridable via env.
const DEFAULT_EMITTER_ON: &[u8] = &[0x01];
const DEFAULT_EMITTER_OFF: &[u8] = &[0x00];

/// The selected IR capture backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureBackend {
    /// File-backed synthetic substrate (`MUG_VIRTUAL_IR_DIR`): CI and headless flow trials.
    Virtual,
    /// The real Logitech Brio IR capture node + UVC-XU emitter.
    Hardware,
}

/// Resolve the current login user, used as the mug-store key. Prefers `$TESS_FACE_USER` (the
/// authoritative PAM-plumbed user in the helper), then falls back to `$USER`, then `$LOGNAME`.
pub fn current_username() -> Result<String> {
    // Prefer the PAM-plumbed user: in the privileged PAM helper the inherited `$USER`/`$LOGNAME` are
    // untrusted, so the session gate passes the PAM-resolved login user in `TESS_FACE_USER`. Outside
    // PAM (the `tess enroll --face` CLI) that variable is unset and `$USER`/`$LOGNAME` is correct.
    for var in ["TESS_FACE_USER", "USER", "LOGNAME"] {
        if let Some(value) = std::env::var_os(var) {
            let name = value.to_string_lossy().into_owned();
            if !name.is_empty() {
                return Ok(name);
            }
        }
    }
    Err(anyhow!(
        "cannot resolve the current username (none of $TESS_FACE_USER, $USER, $LOGNAME are set)"
    ))
}

/// The per-user mug enrollment store (the IR embedding + liveness calibration, never a raw image).
pub fn enroll_store() -> Result<EnrollStore> {
    EnrollStore::default_location().map_err(|e| anyhow!("resolve the mug enroll store: {e}"))
}

/// Whether the headless virtual IR substrate is configured (CI / sim runs).
fn virtual_substrate() -> bool {
    std::env::var_os(VirtualIrDevice::ENV_DIR).is_some()
}

/// Choose the capture backend from the environment.
///
/// Precedence:
/// 1. `MUG_IR_BACKEND=hardware` forces the Brio path (explicit opt-in wins).
/// 2. `MUG_IR_BACKEND=virtual` selects the substrate, erroring if `MUG_VIRTUAL_IR_DIR` is unset.
/// 3. `auto`/unset: the substrate when `MUG_VIRTUAL_IR_DIR` is set (the CI/default path), otherwise
///    the Brio when a GREY IR node is discoverable, otherwise unavailable (degrade to the PIN).
fn select_backend() -> Result<CaptureBackend> {
    let requested = std::env::var(ENV_BACKEND).ok();
    resolve_backend(requested.as_deref(), virtual_substrate(), || {
        mug::find_brio_ir_node().is_ok()
    })
}

/// Pure backend-selection logic, factored out of [`select_backend`] so it is unit-testable without
/// touching the process environment or any real camera.
fn resolve_backend(
    requested: Option<&str>,
    virtual_set: bool,
    brio_present: impl FnOnce() -> bool,
) -> Result<CaptureBackend> {
    match requested.map(str::trim) {
        Some("hardware") => Ok(CaptureBackend::Hardware),
        Some("virtual") => {
            if virtual_set {
                Ok(CaptureBackend::Virtual)
            } else {
                Err(anyhow!(
                    "{ENV_BACKEND}=virtual but {} is not set (point it at a directory of synthetic GREY frames)",
                    VirtualIrDevice::ENV_DIR
                ))
            }
        }
        Some("auto") | Some("") | None => {
            if virtual_set {
                Ok(CaptureBackend::Virtual)
            } else if brio_present() {
                Ok(CaptureBackend::Hardware)
            } else {
                Err(anyhow!(
                    "no face capture backend available: set {} for the virtual IR substrate, or attach a \
                     Logitech Brio (GREY IR node) and set {ENV_BACKEND}=hardware — the face factor is \
                     unavailable and the caller degrades to the PIN",
                    VirtualIrDevice::ENV_DIR
                ))
            }
        }
        Some(other) => Err(anyhow!(
            "unknown {ENV_BACKEND}={other:?} (expected auto, virtual, or hardware)"
        )),
    }
}

/// Parse a hex-encoded emitter payload, tolerating `0x` prefixes and `:`/`,`/whitespace separators.
fn parse_hex_payload(raw: &str) -> std::result::Result<Vec<u8>, String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != ',')
        .collect();
    let hex = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if hex.is_empty() {
        return Err("empty payload".into());
    }
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd hex length {}", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex byte {:?}: {e}", &hex[i..i + 2]))
        })
        .collect()
}

/// Resolve a single emitter payload from `var`, falling back to `default`.
fn emitter_payload(var: &str, default: &[u8]) -> Result<Vec<u8>> {
    match std::env::var(var) {
        Ok(value) => parse_hex_payload(&value).map_err(|e| anyhow!("{var}: {e}")),
        Err(_) => Ok(default.to_vec()),
    }
}

/// Build the real Brio capture source + emitter, discovering the GREY IR node once and binding the
/// emitter control to the same node. Any failure (no camera, permission denied) surfaces as an error
/// the caller treats as "face unavailable → degrade to the PIN".
fn build_hardware_backend() -> Result<(mug::V4l2IrDevice, mug::BrioEmitter)> {
    let node = mug::find_brio_ir_node().map_err(|e| anyhow!("discover the Brio IR node: {e}"))?;
    let source = mug::V4l2IrDevice::open(&node, mug::BRIO_IR_WIDTH, mug::BRIO_IR_HEIGHT)
        .map_err(|e| anyhow!("open the Brio IR capture node {}: {e}", node.display()))?;
    let on_payload = emitter_payload(ENV_EMITTER_ON, DEFAULT_EMITTER_ON)?;
    let off_payload = emitter_payload(ENV_EMITTER_OFF, DEFAULT_EMITTER_OFF)?;
    let emitter = mug::BrioEmitter::new(
        &node,
        mug::BRIO_EMITTER_UNIT,
        mug::BRIO_EMITTER_SELECTOR,
        on_payload,
        off_payload,
    )
    .map_err(|e| anyhow!("open the Brio IR emitter control {}: {e}", node.display()))?;
    Ok((source, emitter))
}

/// Build the model-free CI/default matcher. The real ONNX matcher backend is a tracked follow-up; no
/// model ships, so identity matching is the deterministic mock today.
fn build_mock_matcher(cfg: &MugConfig) -> Result<Matcher<PooledExtractor>> {
    Ok(Matcher::new(
        PooledExtractor::new(MOCK_DIM).map_err(|e| anyhow!("build the mock matcher: {e}"))?,
        cfg.match_threshold,
    ))
}

/// A mug-backed [`FaceTemplateSource`]: capture a liveness-gated pair and embed the emitter-ON frame
/// into an enrollment template. Generic over the capture/embedding backends so the same logic serves
/// the virtual CI substrate and real hardware.
struct MugTemplateSource<S, E, X>
where
    S: IrSource,
    E: IrEmitter,
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
    S: IrSource,
    E: IrEmitter,
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

/// Assemble a [`MugTemplateSource`] for the given source/emitter with the model-free matcher.
fn mug_template_source<S, E>(
    source: S,
    emitter: E,
    cfg: &MugConfig,
) -> Result<MugTemplateSource<S, E, PooledExtractor>>
where
    S: IrSource,
    E: IrEmitter,
{
    Ok(MugTemplateSource {
        source,
        emitter,
        matcher: build_mock_matcher(cfg)?,
        liveness_cfg: cfg.liveness_config(),
        match_threshold: cfg.match_threshold,
        deadline_ms: cfg.capture_deadline_ms,
    })
}

/// Build the face template source from the environment. Returns an owned trait object the enrollment
/// transaction drives once. Errors (no backend selectable) leave the PIN enrollment untouched — the
/// transaction rolls the whole thing back.
pub fn template_source_from_env() -> Result<Box<dyn FaceTemplateSource>> {
    let cfg = MugConfig::default();
    match select_backend()? {
        CaptureBackend::Virtual => {
            let (source, emitter) = VirtualIrDevice::split_from_env()
                .map_err(|e| anyhow!("open the virtual IR device: {e}"))?;
            Ok(Box::new(mug_template_source(source, emitter, &cfg)?))
        }
        CaptureBackend::Hardware => {
            let (source, emitter) = build_hardware_backend()?;
            Ok(Box::new(mug_template_source(source, emitter, &cfg)?))
        }
    }
}

/// Run the bounded face verify against `enrolled` with the matcher and config.
fn run_verify<S, E>(
    source: &mut S,
    emitter: &mut E,
    enrolled: &FaceEnrollment,
    cfg: &MugConfig,
) -> Result<()>
where
    S: IrSource,
    E: IrEmitter,
{
    let matcher = build_mock_matcher(cfg)?;
    mug::verify(
        source,
        emitter,
        &matcher,
        enrolled,
        &cfg.liveness_config(),
        cfg.capture_deadline_ms,
    )
    .map_err(|e| anyhow!("face verification failed: {e}"))
}

/// Run the bounded face verify against `enrolled`, building the capture pipeline from the
/// environment. `Ok(())` means a live, matching face; any error is the caller's cue to fall back to
/// the PIN.
pub fn verify_from_env(enrolled: &FaceEnrollment) -> Result<()> {
    let cfg = MugConfig::default();
    match select_backend()? {
        CaptureBackend::Virtual => {
            let (mut source, mut emitter) = VirtualIrDevice::split_from_env()
                .map_err(|e| anyhow!("open the virtual IR device: {e}"))?;
            run_verify(&mut source, &mut emitter, enrolled, &cfg)
        }
        CaptureBackend::Hardware => {
            let (mut source, mut emitter) = build_hardware_backend()?;
            run_verify(&mut source, &mut emitter, enrolled, &cfg)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_dir_selects_virtual_when_auto() {
        assert_eq!(
            resolve_backend(None, true, || panic!(
                "must not probe when substrate is set"
            ))
            .unwrap(),
            CaptureBackend::Virtual
        );
        assert_eq!(
            resolve_backend(Some("auto"), true, || panic!("must not probe")).unwrap(),
            CaptureBackend::Virtual
        );
    }

    #[test]
    fn explicit_virtual_requires_substrate() {
        assert_eq!(
            resolve_backend(Some("virtual"), true, || false).unwrap(),
            CaptureBackend::Virtual
        );
        assert!(resolve_backend(Some("virtual"), false, || false).is_err());
    }

    #[test]
    fn explicit_hardware_always_selects_hardware() {
        // Selected even with no camera and no substrate; the build step then reports unavailable.
        assert_eq!(
            resolve_backend(Some("hardware"), false, || false).unwrap(),
            CaptureBackend::Hardware
        );
        // Explicit hardware wins even when a substrate happens to be configured.
        assert_eq!(
            resolve_backend(Some("hardware"), true, || false).unwrap(),
            CaptureBackend::Hardware
        );
    }

    #[test]
    fn auto_probes_hardware_without_substrate() {
        assert_eq!(
            resolve_backend(None, false, || true).unwrap(),
            CaptureBackend::Hardware
        );
    }

    #[test]
    fn auto_without_substrate_or_camera_is_unavailable() {
        let err = resolve_backend(None, false, || false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no face capture backend available"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn unknown_backend_is_rejected() {
        let err = resolve_backend(Some("bogus"), true, || true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown"), "unexpected message: {err}");
    }

    #[test]
    fn select_backend_reads_substrate_env() {
        // The Virtual branch never probes hardware, so this is deterministic regardless of whether
        // the host running the test happens to have a camera attached.
        let _lock = tess_testenv::env_lock();
        let _backend = tess_testenv::EnvGuard::remove(ENV_BACKEND);
        let _dir = tess_testenv::EnvGuard::set(VirtualIrDevice::ENV_DIR, "/nonexistent-ir-dir");
        assert_eq!(select_backend().unwrap(), CaptureBackend::Virtual);
        // Building the source only reads the env var, not the directory contents.
        assert!(template_source_from_env().is_ok());
    }

    #[test]
    fn parse_hex_payload_accepts_separators_and_prefix() {
        assert_eq!(parse_hex_payload("01ff").unwrap(), vec![0x01, 0xff]);
        assert_eq!(parse_hex_payload("0x0a:0b").unwrap(), vec![0x0a, 0x0b]);
        assert_eq!(
            parse_hex_payload("aa bb,cc").unwrap(),
            vec![0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    fn parse_hex_payload_rejects_malformed() {
        assert!(parse_hex_payload("").is_err());
        assert!(parse_hex_payload("0").is_err());
        assert!(parse_hex_payload("zz").is_err());
    }
}
