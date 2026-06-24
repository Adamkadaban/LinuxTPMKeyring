//! CLI-facing face-factor plumbing: resolve the current user, build the mug enroll store, and
//! construct the IR capture pipeline (template capture at enroll, bounded verify at unlock) from the
//! environment.
//!
//! Two capture backends are wired, selected by [`select_backend`]:
//!
//! - the headless **virtual IR substrate** (`MUG_VIRTUAL_IR_DIR`), used by CI and to try the flow; and
//! - the real **Logitech Brio** IR path (the GREY IR node + the UVC-XU emitter), opt-in and validated
//!   only by a manual smoke on a dedicated test machine (throwaway keyring/TPM) — never the daily-driver host, never in CI.
//!
//! Both run the same liveness gate. Identity matching requires the real `tract` ONNX matcher (the
//! `face-model` feature plus a runtime model path via `MUG_MODEL_PATH`/config); tess ships no model,
//! so you supply one (see the README for where to download a compatible network). Without a real
//! model the face factor **fails closed** — it refuses to enroll or unlock rather than fall back to
//! the model-free mock, which does no identity discrimination and would accept essentially any live
//! face. The mock is a hermetic test-only substrate, gated behind `TESS_ALLOW_MOCK_FACE`. When no
//! backend is available (no substrate, no camera) the factor reports unavailable and the caller
//! degrades to the PIN.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use mug::{
    EmbeddingExtractor, EnrollStore, FaceDetector, FaceEnrollment, IrEmitter, IrSource,
    LivenessCalibration, LivenessConfig, Matcher, MugConfig, PooledExtractor, VirtualIrDevice,
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
/// Brio IR-emitter UVC extension-unit id (hex u8, e.g. `0x04`) — overrides [`mug::BRIO_EMITTER_UNIT`].
const ENV_EMITTER_UNIT: &str = "MUG_IR_EMITTER_UNIT";
/// Brio IR-emitter UVC selector (hex u8, e.g. `0x06`) — overrides [`mug::BRIO_EMITTER_SELECTOR`].
const ENV_EMITTER_SELECTOR: &str = "MUG_IR_EMITTER_SELECTOR";
/// Video node the emitter SET_CUR targets (path) — defaults to the GREY capture node, but the
/// emitter extension unit may live on a different Brio node.
const ENV_EMITTER_NODE: &str = "MUG_IR_EMITTER_NODE";

/// Default Brio IR-emitter payloads. The exact bytes are device-confirmed during the manual smoke;
/// a wrong value fails safe (the emitter stays off, the liveness differential cannot pass, the face
/// factor degrades to the PIN), so these defaults are only a starting point, overridable via env.
const DEFAULT_EMITTER_ON: &[u8] = &[0x01];
const DEFAULT_EMITTER_OFF: &[u8] = &[0x00];

/// The selected IR capture backend.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CaptureBackend {
    /// File-backed synthetic substrate (`MUG_VIRTUAL_IR_DIR`): CI and headless flow trials.
    Virtual,
    /// The real Logitech Brio IR capture node + UVC-XU emitter. Carries the GREY IR node when it was
    /// already discovered during `auto` selection (reused so the auth path scans `/dev/v4l/by-id`
    /// once); `None` for an explicit `hardware` request, where the builder discovers it.
    Hardware(Option<PathBuf>),
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
    let requested = match std::env::var(ENV_BACKEND) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(anyhow!(
                "{ENV_BACKEND} is set but is not valid UTF-8 (expected auto, virtual, or hardware)"
            ));
        }
    };
    resolve_backend(
        requested.as_deref(),
        virtual_substrate(),
        mug::find_brio_ir_node,
    )
}

/// Pure backend-selection logic, factored out of [`select_backend`] so it is unit-testable without
/// touching the process environment or any real camera. `probe_brio` returns `Ok(node)` with the
/// discovered GREY node, `Err(MugError::NoIrNode)` when none is attached, or another error when the
/// probe itself failed (e.g. `/dev/v4l/by-id` unreadable, or a Brio-like node that can't be opened)
/// — the last is surfaced rather than collapsed into "no camera". A node discovered here is carried
/// in `Hardware(Some(..))` so the builder reuses it instead of re-scanning.
fn resolve_backend(
    requested: Option<&str>,
    virtual_set: bool,
    probe_brio: impl FnOnce() -> mug::Result<PathBuf>,
) -> Result<CaptureBackend> {
    match requested.map(str::trim) {
        Some("hardware") => Ok(CaptureBackend::Hardware(None)),
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
            } else {
                match probe_brio() {
                    Ok(node) => Ok(CaptureBackend::Hardware(Some(node))),
                    Err(mug::MugError::NoIrNode) => Err(anyhow!(
                        "no face capture backend available: set {} for the virtual IR substrate, or \
                         attach a Logitech Brio (GREY IR node) — auto-detected when present. The face \
                         factor is unavailable and the caller degrades to the PIN",
                        VirtualIrDevice::ENV_DIR
                    )),
                    Err(e) => Err(anyhow!(
                        "the Brio IR probe failed ({e}); fix it or set {} for the virtual IR \
                         substrate. The face factor is unavailable and the caller degrades to the PIN",
                        VirtualIrDevice::ENV_DIR
                    )),
                }
            }
        }
        Some(other) => Err(anyhow!(
            "unknown {ENV_BACKEND}={other:?} (expected auto, virtual, or hardware)"
        )),
    }
}

/// Parse a hex-encoded emitter payload, tolerating `0x` prefixes and `:`/`,`/whitespace separators.
fn parse_hex_payload(raw: &str) -> std::result::Result<Vec<u8>, String> {
    // Brio SET_CUR payloads are a handful of bytes; bound the input up front so a hostile env var
    // can't force a large allocation on the auth path.
    const MAX_INPUT_LEN: usize = 256;
    if raw.len() > MAX_INPUT_LEN {
        return Err(format!(
            "payload too long ({} bytes; max {MAX_INPUT_LEN})",
            raw.len()
        ));
    }
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
    // Guard before byte-slicing below: reject any non-ASCII-hex character (including multi-byte
    // UTF-8) up front, so `&hex[i..i + 2]` can never split a char boundary and panic.
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("non-hex characters in payload {raw:?}"));
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
        Err(std::env::VarError::NotPresent) => Ok(default.to_vec()),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow!(
            "{var} is set but is not valid UTF-8; expected hex bytes (e.g. 01ff) or unset it for the default"
        )),
    }
}

/// Parse a hex `u8` (with or without a `0x` prefix), e.g. `0x04` or `4`.
fn parse_hex_u8(raw: &str) -> std::result::Result<u8, String> {
    let s = raw.trim();
    // A generous DoS bound on a mispointed env var; a real u8 hex is short, but accept leading-zero
    // forms like `0x00000004`. `from_str_radix` below does the actual validity/overflow check.
    if s.len() > 64 {
        return Err("value too long for a hex u8".into());
    }
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() {
        return Err("empty value".into());
    }
    u8::from_str_radix(s, 16).map_err(|e| format!("invalid hex u8 {s:?}: {e}"))
}

/// Whether a resolved device file name is a V4L2 video node (`videoN`, N = digits).
fn is_v4l2_video_name(name: &str) -> bool {
    name.strip_prefix("video")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Validate that an env-provided device path is a V4L2 video node (`/dev/videoN`), so an untrusted
/// env var can't point the emitter `open()` at an arbitrary read+write path — not even another char
/// device under `/dev` like `/dev/mem` (the PAM/session context treats env as untrusted). The path is
/// canonicalized first (resolving `..` and symlinks, so `/dev/v4l/by-id/...` works but `/dev/../tmp/x`
/// is rejected); the *resolved* path must be a character device under `/dev` named `videoN`.
fn validate_device_node(var: &str, path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let resolved = std::fs::canonicalize(path)
        .map_err(|e| anyhow!("resolve {var} {}: {e}", path.display()))?;
    if !resolved.starts_with("/dev") {
        return Err(anyhow!(
            "{var} must resolve to a path under /dev, got {}",
            resolved.display()
        ));
    }
    let name = resolved.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !is_v4l2_video_name(name) {
        return Err(anyhow!(
            "{var} must resolve to a V4L2 video node (/dev/videoN), got {}",
            resolved.display()
        ));
    }
    let meta = std::fs::metadata(&resolved)
        .map_err(|e| anyhow!("stat {var} {}: {e}", resolved.display()))?;
    if !meta.file_type().is_char_device() {
        return Err(anyhow!(
            "{var} {} is not a character device",
            resolved.display()
        ));
    }
    Ok(())
}

/// Resolve a hex-`u8` emitter coordinate from `var`, falling back to `default`.
fn emitter_coord(var: &str, default: u8) -> Result<u8> {
    match std::env::var(var) {
        Ok(value) => parse_hex_u8(&value).map_err(|e| anyhow!("{var}: {e}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow!(
            "{var} is set but is not valid UTF-8; expected a hex u8 (e.g. 0x04)"
        )),
    }
}

/// Build the real Brio capture source + emitter, discovering the GREY IR node once. The emitter
/// SET_CUR targets the capture node by default, or `MUG_IR_EMITTER_NODE` when set (the emitter
/// extension unit may live on a different Brio node); its unit/selector default to the Brio values
/// and are overridable via `MUG_IR_EMITTER_UNIT`/`MUG_IR_EMITTER_SELECTOR`. Any failure (no camera,
/// permission denied) surfaces as an error the caller treats as "face unavailable → degrade to PIN".
fn build_hardware_backend(node: Option<PathBuf>) -> Result<(mug::V4l2IrDevice, mug::BrioEmitter)> {
    let node = match node {
        Some(node) => node,
        None => mug::find_brio_ir_node().map_err(|e| anyhow!("discover the Brio IR node: {e}"))?,
    };
    let source = mug::V4l2IrDevice::open(&node, mug::BRIO_IR_WIDTH, mug::BRIO_IR_HEIGHT)
        .map_err(|e| anyhow!("open the Brio IR capture node {}: {e}", node.display()))?;
    let on_payload = emitter_payload(ENV_EMITTER_ON, DEFAULT_EMITTER_ON)?;
    let off_payload = emitter_payload(ENV_EMITTER_OFF, DEFAULT_EMITTER_OFF)?;
    let unit = emitter_coord(ENV_EMITTER_UNIT, mug::BRIO_EMITTER_UNIT)?;
    let selector = emitter_coord(ENV_EMITTER_SELECTOR, mug::BRIO_EMITTER_SELECTOR)?;
    let emitter_node = match std::env::var_os(ENV_EMITTER_NODE) {
        Some(path) if path.is_empty() => {
            return Err(anyhow!(
                "{ENV_EMITTER_NODE} is set but empty; unset it to use the capture node"
            ));
        }
        Some(path) => {
            let path = PathBuf::from(path);
            validate_device_node(ENV_EMITTER_NODE, &path)?;
            path
        }
        None => node.clone(),
    };
    let emitter = mug::BrioEmitter::new(&emitter_node, unit, selector, on_payload, off_payload)
        .map_err(|e| {
            anyhow!(
                "open the Brio IR emitter control {}: {e}",
                emitter_node.display()
            )
        })?;
    Ok((source, emitter))
}

/// The env var pointing at a user-supplied ONNX face-embedding model. A configured `model_path`
/// takes precedence; the env var is consulted only when no path is configured, and even then it only
/// loads a model when mug is built with the `face-model` feature. A non-UTF-8 value errors. Without a
/// loadable model the matcher fails closed (an error) unless `TESS_ALLOW_MOCK_FACE` opts into the
/// test-only mock. No model ships with tess.
const ENV_MODEL_PATH: &str = "MUG_MODEL_PATH";

/// The env var pointing at a user-supplied ONNX face-detector (YuNet) model. A configured
/// `detector_model_path` takes precedence; the env var is consulted only when no path is configured,
/// and even then it only loads a model when mug is built with the `face-model` feature. Without a
/// loadable detector the real enroll/unlock path fails closed (an error) unless `TESS_ALLOW_MOCK_FACE`
/// opts into the detector-free path (whole-frame embedding, identity meaningless). No model ships.
const ENV_DETECTOR_MODEL: &str = "MUG_DETECTOR_MODEL";

/// The env var pointing at a JSON [`MugConfig`] file (thresholds, `pixel_scale`, `model_path`, …).
const ENV_CONFIG: &str = "MUG_CONFIG";

/// Load the mug config: parse the JSON file at `MUG_CONFIG` if that var is set, otherwise use the
/// secure defaults. A set-but-unreadable or malformed file is an error (never silently ignored) so a
/// misconfiguration surfaces rather than reverting to defaults behind the operator's back.
fn load_config() -> Result<MugConfig> {
    use std::io::Read;
    /// A `MugConfig` JSON is well under a kilobyte; cap the read so a mispointed `MUG_CONFIG`
    /// (e.g. `/dev/zero` or a huge file) fails fast instead of hanging/OOMing on the auth path.
    const MAX_CONFIG_BYTES: u64 = 64 * 1024;
    match std::env::var(ENV_CONFIG) {
        Ok(path) => {
            let file =
                std::fs::File::open(&path).with_context(|| format!("open mug config {path}"))?;
            let meta = file
                .metadata()
                .with_context(|| format!("stat mug config {path}"))?;
            if !meta.is_file() {
                return Err(anyhow!("mug config {path} is not a regular file"));
            }
            let mut data = String::new();
            file.take(MAX_CONFIG_BYTES + 1)
                .read_to_string(&mut data)
                .with_context(|| format!("read mug config {path}"))?;
            if data.len() as u64 > MAX_CONFIG_BYTES {
                return Err(anyhow!(
                    "mug config {path} exceeds the {MAX_CONFIG_BYTES}-byte cap"
                ));
            }
            serde_json::from_str(&data).with_context(|| format!("parse mug config {path}"))
        }
        Err(std::env::VarError::NotPresent) => Ok(MugConfig::default()),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(anyhow!("{ENV_CONFIG} is set but is not valid UTF-8"))
        }
    }
}

/// Test/CI-only opt-in (`TESS_ALLOW_MOCK_FACE=1`) allowing the model-free mock matcher to stand in
/// for a real model. The mock does **no** identity discrimination, so this must never be set in a
/// real deployment; the hermetic virtual-IR test substrate sets it so the pipeline is exercisable
/// without shipping a model.
pub const ENV_ALLOW_MOCK_FACE: &str = "TESS_ALLOW_MOCK_FACE";

/// Whether the model-free mock matcher may stand in for a real model (fail-closed by default).
fn mock_face_allowed() -> bool {
    std::env::var(ENV_ALLOW_MOCK_FACE)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Build the identity matcher: the real `tract` ONNX matcher when built with the `face-model` feature
/// and given a model path. Without a real model this **fails closed** (returns an error) unless the
/// mock is permitted — either by `TESS_ALLOW_MOCK_FACE` (the test substrate) or by `allow_mock`
/// (the read-only `face-test` diagnostic, which seals nothing). The mock does no identity
/// discrimination, so it must never gate a real enroll/unlock. Returns a boxed extractor so both
/// share one matcher type.
fn build_matcher(
    cfg: &MugConfig,
    allow_mock: bool,
) -> Result<Matcher<Box<dyn EmbeddingExtractor>>> {
    let model_path = match cfg.model_path.clone() {
        Some(path) => Some(path),
        None => match std::env::var(ENV_MODEL_PATH) {
            Ok(path) => Some(path),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(anyhow!("{ENV_MODEL_PATH} is set but is not valid UTF-8"));
            }
        },
    };

    #[cfg(feature = "face-model")]
    if let Some(path) = model_path.as_deref() {
        // `from_path` already includes the path and detailed context in its error; convert directly
        // rather than wrapping with redundant text.
        let extractor = mug::TractExtractor::from_path(path, cfg.pixel_scale)?;
        return Ok(Matcher::new(
            Box::new(extractor) as Box<dyn EmbeddingExtractor>,
            cfg.match_threshold,
        ));
    }

    // No real model is loaded. The only remaining matcher is the deterministic mock, which performs
    // NO identity discrimination — it would accept essentially any live face. Fail closed so it can
    // never silently gate a real enroll/unlock; allow it only for the hermetic test substrate or the
    // no-stakes face-test diagnostic.
    if !allow_mock && !mock_face_allowed() {
        let detail = if model_path.is_some() {
            "a model path is configured but this build lacks the `face-model` feature"
        } else {
            "no model is configured"
        };
        return Err(anyhow!(
            "face identity matching requires a model ({detail}). Build with \
             `cargo build -p tess-cli --features face-model` and point {ENV_MODEL_PATH} at a \
             fixed-shape NCHW ONNX face model (see the README for where to download one). Refusing \
             to use the model-free mock, which would accept any live face."
        ));
    }
    if allow_mock {
        if model_path.is_some() {
            eprintln!(
                "tess: note — a model path is configured but this build lacks the `face-model` \
                 feature, so identity matching uses the model-free mock and is meaningless (liveness \
                 is still real). Rebuild with `cargo build -p tess-cli --features face-model` for \
                 real identity."
            );
        } else {
            eprintln!(
                "tess: note — no model configured; identity matching uses the model-free mock and \
                 is meaningless (liveness is still real). Set {ENV_MODEL_PATH} to a real model for \
                 identity discrimination."
            );
        }
    } else {
        eprintln!(
            "tess: WARNING — {ENV_ALLOW_MOCK_FACE} is set; using the model-free mock matcher. \
             Identity matching is DISABLED (accepts essentially any live face) — unset it for \
             fail-closed behavior. For testing only."
        );
    }
    let mock =
        PooledExtractor::new(MOCK_DIM).map_err(|e| anyhow!("build the mock matcher: {e}"))?;
    Ok(Matcher::new(
        Box::new(mock) as Box<dyn EmbeddingExtractor>,
        cfg.match_threshold,
    ))
}

/// Build the face detector (YuNet via `tract`) when built with the `face-model` feature and given a
/// detector model path. Without one, the **real** enroll/unlock path fails closed; the detector-free
/// path (whole-frame embedding, no identity discrimination) is permitted only for the test substrate
/// (`TESS_ALLOW_MOCK_FACE`) or the `face-test` diagnostic (`allow_mock`), in which case `None` is
/// returned so callers align only when a detector is present.
fn build_detector(cfg: &MugConfig, allow_mock: bool) -> Result<Option<Box<dyn FaceDetector>>> {
    let detector_path = match cfg.detector_model_path.clone() {
        Some(path) => Some(path),
        None => match std::env::var(ENV_DETECTOR_MODEL) {
            Ok(path) => Some(path),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(anyhow!(
                    "{ENV_DETECTOR_MODEL} is set but is not valid UTF-8"
                ));
            }
        },
    };

    #[cfg(feature = "face-model")]
    if let Some(path) = detector_path.as_deref() {
        let detector = mug::YuNetDetector::from_path(path)?;
        return Ok(Some(Box::new(detector) as Box<dyn FaceDetector>));
    }

    // No detector is loaded. Identity matching would then embed the whole frame (with the real
    // embedder or the mock), which encodes the background and does not discriminate a face — fail
    // closed on the real path so it can never silently gate a real enroll/unlock; permit it only for
    // the test substrate or the diagnostic.
    if !allow_mock && !mock_face_allowed() {
        let detail = if detector_path.is_some() {
            "a detector path is configured but this build lacks the `face-model` feature"
        } else {
            "no detector is configured"
        };
        return Err(anyhow!(
            "face identity matching requires a face detector ({detail}). Build with \
             `cargo build -p tess-cli --features face-model` and point {ENV_DETECTOR_MODEL} at a \
             fixed-shape YuNet ONNX model (see the README). Refusing to embed the whole frame, which \
             does not discriminate a face."
        ));
    }
    let cause = if detector_path.is_some() {
        "a detector path is configured but this build lacks the `face-model` feature"
    } else {
        "no detector is configured"
    };
    if allow_mock {
        eprintln!(
            "tess: note — {cause}; identity matching embeds the WHOLE frame and does not \
             discriminate a face (liveness is still real). Set {ENV_DETECTOR_MODEL} to a YuNet model \
             (built with `--features face-model`) for real recognition."
        );
    } else {
        // Reached only because TESS_ALLOW_MOCK_FACE opted into the detector-free path on a real flow.
        eprintln!(
            "tess: WARNING — {ENV_ALLOW_MOCK_FACE} is set and {cause}; running WITHOUT a face \
             detector. Identity matching embeds the whole frame and does NOT discriminate a face — \
             unset it for fail-closed behavior. For testing only."
        );
    }
    Ok(None)
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
    detector: Option<Box<dyn FaceDetector>>,
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
        // Locate + align the face before embedding so the template describes the face, not the
        // whole scene. With no detector (test substrate) embed the frame by reference (no copy).
        let embedding = match &self.detector {
            Some(d) => {
                let face =
                    mug::locate_and_align(d.as_ref(), &pair.emitter_on, mug::ALIGNED_FACE_SIZE)
                        .map_err(|e| anyhow!("locate/align the enrollment face: {e}"))?;
                self.matcher.embed(&face)
            }
            None => self.matcher.embed(&pair.emitter_on),
        }
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

/// Assemble a [`MugTemplateSource`] for the given source/emitter with the configured matcher (the
/// real `tract` ONNX backend when built and configured; otherwise this fails closed unless the
/// test-only `TESS_ALLOW_MOCK_FACE` opt-in is set — see [`build_matcher`]).
fn mug_template_source<S, E>(
    source: S,
    emitter: E,
    cfg: &MugConfig,
) -> Result<MugTemplateSource<S, E, Box<dyn EmbeddingExtractor>>>
where
    S: IrSource,
    E: IrEmitter,
{
    Ok(MugTemplateSource {
        source,
        emitter,
        matcher: build_matcher(cfg, false)?,
        detector: build_detector(cfg, false)?,
        liveness_cfg: cfg.liveness_config(),
        match_threshold: cfg.match_threshold,
        deadline_ms: cfg.capture_deadline_ms,
    })
}

/// Build the face template source from the environment. Returns an owned trait object the enrollment
/// transaction drives once. Errors (no backend selectable) leave the PIN enrollment untouched — the
/// transaction rolls the whole thing back.
pub fn template_source_from_env() -> Result<Box<dyn FaceTemplateSource>> {
    let cfg = load_config()?;
    match select_backend()? {
        CaptureBackend::Virtual => {
            let (source, emitter) = VirtualIrDevice::split_from_env()
                .map_err(|e| anyhow!("open the virtual IR device: {e}"))?;
            Ok(Box::new(mug_template_source(source, emitter, &cfg)?))
        }
        CaptureBackend::Hardware(node) => {
            let (source, emitter) = build_hardware_backend(node)?;
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
    let matcher = build_matcher(cfg, false)?;
    let detector = build_detector(cfg, false)?;
    mug::verify(
        source,
        emitter,
        &matcher,
        detector.as_deref(),
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
    let cfg = load_config()?;
    match select_backend()? {
        CaptureBackend::Virtual => {
            let (mut source, mut emitter) = VirtualIrDevice::split_from_env()
                .map_err(|e| anyhow!("open the virtual IR device: {e}"))?;
            run_verify(&mut source, &mut emitter, enrolled, &cfg)
        }
        CaptureBackend::Hardware(node) => {
            let (mut source, mut emitter) = build_hardware_backend(node)?;
            run_verify(&mut source, &mut emitter, enrolled, &cfg)
        }
    }
}

/// Run the read-only `face-test` diagnostic from the environment: capture a reference and a probe
/// pair, print each liveness report, and (when both pass) the identity distance/verdict. Touches
/// neither the keyring nor the TPM — nothing is sealed, so the model-free mock is permitted when no
/// real model is configured (liveness stays real regardless).
pub fn face_test_from_env() -> Result<()> {
    let cfg = load_config()?;
    let matcher = build_matcher(&cfg, true)?;
    let detector = build_detector(&cfg, true)?;
    let pause = |msg: &str| {
        use std::io::Write as _;
        print!("{msg}, then press Enter… ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    };
    match select_backend()? {
        CaptureBackend::Virtual => {
            let (mut source, mut emitter) = VirtualIrDevice::split_from_env()
                .map_err(|e| anyhow!("open the virtual IR device: {e}"))?;
            let outcome = run_face_test(
                &mut source,
                &mut emitter,
                &matcher,
                detector.as_deref(),
                &cfg,
                &pause,
            )?;
            print_face_test_outcome(&outcome);
            Ok(())
        }
        CaptureBackend::Hardware(node) => {
            let (mut source, mut emitter) = build_hardware_backend(node)?;
            let outcome = run_face_test(
                &mut source,
                &mut emitter,
                &matcher,
                detector.as_deref(),
                &cfg,
                &pause,
            )?;
            print_face_test_outcome(&outcome);
            Ok(())
        }
    }
}

/// The result of a [`run_face_test`] run (each is a normal diagnostic outcome, never an error).
#[derive(Debug)]
enum FaceTestOutcome {
    /// The reference capture failed liveness, so no identity comparison was possible.
    ReferenceRejected,
    /// The probe capture failed liveness (e.g. a photo/screen) — the anti-spoof working.
    ProbeRejected,
    /// Both captures were live; the probe was compared to the reference.
    Compared {
        distance: f32,
        threshold: f32,
        matched: bool,
    },
}

fn print_face_test_outcome(outcome: &FaceTestOutcome) {
    println!();
    match outcome {
        FaceTestOutcome::ReferenceRejected => {
            println!("Reference rejected by liveness; cannot run the identity comparison.")
        }
        FaceTestOutcome::ProbeRejected => println!(
            "Probe REJECTED by liveness (e.g. a printed photo or a screen) → at unlock this falls \
             back to the PIN."
        ),
        FaceTestOutcome::Compared {
            distance,
            threshold,
            matched,
        } => println!(
            "Identity: cosine distance {distance:.4} (threshold {threshold:.4}) → {}",
            if *matched { "MATCH" } else { "NO MATCH" }
        ),
    }
}

/// Capture a reference then a probe pair, reporting liveness for each and (when both are live)
/// comparing the probe to the reference. `pause` is invoked before each capture (the CLI waits for
/// Enter; tests pass a no-op or a frame-swapping closure). A capture, embedding, or matching failure
/// is an `Err`; every well-formed diagnostic outcome (liveness rejection, match, or no-match) is an
/// `Ok(FaceTestOutcome)`.
fn run_face_test<S, E>(
    source: &mut S,
    emitter: &mut E,
    matcher: &Matcher<Box<dyn EmbeddingExtractor>>,
    detector: Option<&dyn FaceDetector>,
    cfg: &MugConfig,
    pause: &dyn Fn(&str),
) -> Result<FaceTestOutcome>
where
    S: IrSource,
    E: IrEmitter,
{
    let liveness_cfg = cfg.liveness_config();
    let deadline = cfg.capture_deadline_ms;

    pause("Get into position for the REFERENCE capture (your face)");
    let reference = match capture_and_report("reference", source, emitter, &liveness_cfg, deadline)?
    {
        Some(pair) => {
            let face = align_for_embed(detector, &pair.emitter_on)?;
            matcher
                .embed(&face)
                .map_err(|e| anyhow!("embed the reference frame: {e}"))?
        }
        None => return Ok(FaceTestOutcome::ReferenceRejected),
    };

    pause(
        "Get into position for the PROBE capture (your face again, a printed photo/screen, or another person)",
    );
    let probe = match capture_and_report("probe", source, emitter, &liveness_cfg, deadline)? {
        Some(pair) => pair,
        None => return Ok(FaceTestOutcome::ProbeRejected),
    };

    let probe_face = align_for_embed(detector, &probe.emitter_on)?;
    let distance = matcher
        .distance(&probe_face, &reference)
        .map_err(|e| anyhow!("match the probe against the reference: {e}"))?;
    Ok(FaceTestOutcome::Compared {
        distance,
        threshold: cfg.match_threshold,
        matched: distance <= cfg.match_threshold,
    })
}

/// Locate + align the face for embedding when a detector is present; otherwise pass the frame
/// through (the detector-free diagnostic path).
fn align_for_embed(
    detector: Option<&dyn FaceDetector>,
    frame: &mug::IrFrame,
) -> Result<mug::IrFrame> {
    match detector {
        Some(d) => mug::locate_and_align(d, frame, mug::ALIGNED_FACE_SIZE)
            .map_err(|e| anyhow!("locate/align the face: {e}")),
        None => Ok(frame.clone()),
    }
}

/// Capture one IR pair and print its liveness report. Returns `Some(pair)` when it passed liveness,
/// `None` when it was rejected — a normal diagnostic outcome, not an error.
fn capture_and_report<S, E>(
    label: &str,
    source: &mut S,
    emitter: &mut E,
    liveness_cfg: &LivenessConfig,
    deadline_ms: u64,
) -> Result<Option<mug::camera::FramePair>>
where
    S: IrSource,
    E: IrEmitter,
{
    let pair = mug::capture_liveness_pair(source, emitter, deadline_ms)
        .map_err(|e| anyhow!("capture the {label} IR pair: {e}"))?;
    let report = mug::analyze_liveness(&pair, liveness_cfg)
        .map_err(|e| anyhow!("analyze {label} liveness: {e}"))?;
    let f = &report.features;
    println!(
        "[{label}] liveness {}: score {:.3} (threshold {:.3}); mean_delta {:.2}, delta_std {:.2}, \
         gradient {:.2}, specular {:.3}, saturated {:.3}, baseline {:.2}",
        if report.passed { "PASS" } else { "REJECT" },
        f.score,
        liveness_cfg.score_threshold,
        f.mean_delta,
        f.delta_std,
        f.gradient_energy,
        f.specular_fraction,
        f.saturated_fraction,
        f.baseline_mean,
    );
    if let Some(reason) = &report.reason {
        println!("[{label}] reason: {reason}");
    }
    Ok(if report.passed { Some(pair) } else { None })
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
            resolve_backend(Some("virtual"), true, || Err(mug::MugError::NoIrNode)).unwrap(),
            CaptureBackend::Virtual
        );
        assert!(resolve_backend(Some("virtual"), false, || Err(mug::MugError::NoIrNode)).is_err());
    }

    #[test]
    fn explicit_hardware_always_selects_hardware() {
        // Selected even with no camera and no substrate; the build step then reports unavailable.
        assert_eq!(
            resolve_backend(Some("hardware"), false, || Err(mug::MugError::NoIrNode)).unwrap(),
            CaptureBackend::Hardware(None)
        );
        // Explicit hardware wins even when a substrate happens to be configured.
        assert_eq!(
            resolve_backend(Some("hardware"), true, || Err(mug::MugError::NoIrNode)).unwrap(),
            CaptureBackend::Hardware(None)
        );
    }

    #[test]
    fn auto_probes_hardware_without_substrate() {
        let node = std::path::PathBuf::from("/dev/v4l/by-id/usb-046d_Logitech_BRIO-video-index1");
        assert_eq!(
            resolve_backend(None, false, || Ok(node.clone())).unwrap(),
            CaptureBackend::Hardware(Some(node))
        );
    }

    #[test]
    fn auto_without_substrate_or_camera_is_unavailable() {
        let err = resolve_backend(None, false, || Err(mug::MugError::NoIrNode))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no face capture backend available"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn auto_surfaces_a_present_but_unusable_brio() {
        // A Brio-like node that can't be opened (e.g. permission denied) must surface the real
        // cause, not be flattened into "no camera".
        let err = resolve_backend(None, false, || {
            Err(mug::MugError::Camera(
                "open /dev/video4: permission denied".into(),
            ))
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("Brio IR probe failed") && err.contains("permission denied"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn unknown_backend_is_rejected() {
        let err = resolve_backend(Some("bogus"), true, || Ok(std::path::PathBuf::from("/x")))
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
        // No real model in tests: opt into the mock so building the matcher succeeds (production
        // fails closed without a model).
        let _mock = tess_testenv::EnvGuard::set(ENV_ALLOW_MOCK_FACE, "1");
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
        // Multi-byte UTF-8 must fail closed, not panic on a non-char-boundary byte slice.
        assert!(parse_hex_payload("€€").is_err());
        assert!(parse_hex_payload("0€").is_err());
        // Oversized input fails closed rather than allocating.
        assert!(parse_hex_payload(&"00".repeat(200)).is_err());
    }

    #[test]
    fn parse_hex_u8_accepts_prefix_and_bare() {
        assert_eq!(parse_hex_u8("0x04").unwrap(), 0x04);
        assert_eq!(parse_hex_u8("0X0e").unwrap(), 0x0e);
        assert_eq!(parse_hex_u8("6").unwrap(), 0x06);
        assert_eq!(parse_hex_u8(" ff ").unwrap(), 0xff);
        assert_eq!(parse_hex_u8("0x00000004").unwrap(), 0x04); // leading-zero form
    }

    #[test]
    fn parse_hex_u8_rejects_malformed_or_out_of_range() {
        assert!(parse_hex_u8("").is_err());
        assert!(parse_hex_u8("0x").is_err());
        assert!(parse_hex_u8("zz").is_err());
        assert!(parse_hex_u8("100").is_err()); // 0x100 overflows u8
        assert!(parse_hex_u8(&"0".repeat(100)).is_err()); // oversized input rejected without echo
    }

    #[test]
    fn is_v4l2_video_name_matches_only_video_n() {
        assert!(is_v4l2_video_name("video0"));
        assert!(is_v4l2_video_name("video12"));
        assert!(!is_v4l2_video_name("video"));
        assert!(!is_v4l2_video_name("video1a"));
        assert!(!is_v4l2_video_name("null"));
        assert!(!is_v4l2_video_name("mem"));
    }

    #[test]
    fn validate_device_node_rejects_non_video_nodes() {
        assert!(validate_device_node("X", std::path::Path::new("/tmp/not-a-node")).is_err());
        assert!(validate_device_node("X", std::path::Path::new("relative/path")).is_err());
        // A directory under /dev is not a video node.
        assert!(validate_device_node("X", std::path::Path::new("/dev")).is_err());
        // `..` traversal that resolves outside /dev is rejected (canonicalized first).
        assert!(validate_device_node("X", std::path::Path::new("/dev/../etc/hostname")).is_err());
        // A char device under /dev that isn't a video node (e.g. /dev/null) is rejected.
        assert!(validate_device_node("X", std::path::Path::new("/dev/null")).is_err());
    }

    #[test]
    fn build_matcher_fails_closed_without_a_model() {
        // No model and no opt-in: building the matcher must error rather than fall back to the mock,
        // so a real enroll/unlock can never silently accept any live face.
        let _lock = tess_testenv::env_lock();
        let _model = tess_testenv::EnvGuard::remove(ENV_MODEL_PATH);
        let _mock = tess_testenv::EnvGuard::remove(ENV_ALLOW_MOCK_FACE);
        let cfg = MugConfig::default();
        let err = match build_matcher(&cfg, false) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected a fail-closed error without a model"),
        };
        assert!(
            err.contains("requires a model"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn build_detector_fails_closed_without_a_detector() {
        // No detector and no opt-in: the real enroll/unlock path must error rather than silently
        // embed the whole frame (which does not discriminate a face).
        let _lock = tess_testenv::env_lock();
        let _det = tess_testenv::EnvGuard::remove(ENV_DETECTOR_MODEL);
        let _mock = tess_testenv::EnvGuard::remove(ENV_ALLOW_MOCK_FACE);
        let cfg = MugConfig::default();
        let err = match build_detector(&cfg, false) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected a fail-closed error without a detector"),
        };
        assert!(
            err.contains("requires a face detector"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn build_detector_allows_detector_free_path_for_diagnostic() {
        // The read-only diagnostic (allow_mock) may run detector-free: returns Ok(None) so callers
        // embed the whole frame (meaningless identity) without gating a real unlock.
        let _lock = tess_testenv::env_lock();
        let _det = tess_testenv::EnvGuard::remove(ENV_DETECTOR_MODEL);
        let _mock = tess_testenv::EnvGuard::remove(ENV_ALLOW_MOCK_FACE);
        let cfg = MugConfig::default();
        assert!(
            matches!(build_detector(&cfg, true), Ok(None)),
            "diagnostic path should permit a detector-free None"
        );
    }

    #[test]
    fn build_detector_allows_detector_free_path_with_mock_optin() {
        // The test-substrate opt-in permits the detector-free path even on the !allow_mock path.
        let _lock = tess_testenv::env_lock();
        let _det = tess_testenv::EnvGuard::remove(ENV_DETECTOR_MODEL);
        let _mock = tess_testenv::EnvGuard::set(ENV_ALLOW_MOCK_FACE, "1");
        let cfg = MugConfig::default();
        assert!(
            matches!(build_detector(&cfg, false), Ok(None)),
            "TESS_ALLOW_MOCK_FACE should permit a detector-free None"
        );
    }

    #[test]
    fn build_matcher_allows_mock_only_with_explicit_optin() {
        // The hermetic test substrate opts into the mock; only then does building succeed model-free.
        let _lock = tess_testenv::env_lock();
        let _model = tess_testenv::EnvGuard::remove(ENV_MODEL_PATH);
        let _mock = tess_testenv::EnvGuard::set(ENV_ALLOW_MOCK_FACE, "1");
        let cfg = MugConfig::default();
        assert!(build_matcher(&cfg, false).is_ok());
    }

    #[test]
    fn build_matcher_rejects_non_utf8_model_path_env() {
        use std::os::unix::ffi::OsStrExt;
        // A non-UTF-8 MUG_MODEL_PATH is an error regardless of the `face-model` feature (the check
        // runs before the feature gate), never a silent fallback or a panic.
        let _lock = tess_testenv::env_lock();
        let bad = std::ffi::OsStr::from_bytes(&[0x66, 0x6f, 0xff]);
        let _model = tess_testenv::EnvGuard::set_path(ENV_MODEL_PATH, std::path::Path::new(bad));
        let cfg = MugConfig::default();
        let err = match build_matcher(&cfg, false) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error for a non-UTF-8 model path"),
        };
        assert!(err.contains("not valid UTF-8"), "unexpected message: {err}");
    }

    #[test]
    fn load_config_defaults_without_env() {
        let _lock = tess_testenv::env_lock();
        let _cfg = tess_testenv::EnvGuard::remove(ENV_CONFIG);
        assert_eq!(
            load_config().unwrap().pixel_scale,
            mug::PixelScale::Symmetric
        );
    }

    #[test]
    fn load_config_reads_pixel_scale_from_file() {
        let _lock = tess_testenv::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mug.json");
        let cfg = MugConfig {
            pixel_scale: mug::PixelScale::Unit,
            ..MugConfig::default()
        };
        std::fs::write(&path, serde_json::to_string(&cfg).unwrap()).unwrap();
        let _cfg = tess_testenv::EnvGuard::set_path(ENV_CONFIG, &path);
        assert_eq!(load_config().unwrap().pixel_scale, mug::PixelScale::Unit);
    }

    #[test]
    fn load_config_malformed_file_errors() {
        let _lock = tess_testenv::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mug.json");
        std::fs::write(&path, "{ not json").unwrap();
        let _cfg = tess_testenv::EnvGuard::set_path(ENV_CONFIG, &path);
        assert!(load_config().is_err());
    }

    #[test]
    fn load_config_oversized_file_errors() {
        let _lock = tess_testenv::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mug.json");
        // A mispointed MUG_CONFIG (huge file) must fail fast, not be slurped on the auth path.
        std::fs::write(&path, vec![b' '; 128 * 1024]).unwrap();
        let _cfg = tess_testenv::EnvGuard::set_path(ENV_CONFIG, &path);
        let err = match load_config() {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected an error for an oversized config"),
        };
        assert!(err.contains("cap"), "unexpected message: {err}");
    }

    fn write_grey_pair(dir: &std::path::Path, pair: &mug::FramePair) {
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

    #[test]
    fn build_matcher_allows_mock_for_diagnostic_without_optin() {
        // face-test passes allow_mock=true: with no model and no env opt-in it still builds (the
        // mock), because the diagnostic seals nothing.
        let _lock = tess_testenv::env_lock();
        let _model = tess_testenv::EnvGuard::remove(ENV_MODEL_PATH);
        let _mock = tess_testenv::EnvGuard::remove(ENV_ALLOW_MOCK_FACE);
        let cfg = MugConfig::default();
        assert!(build_matcher(&cfg, true).is_ok());
    }

    #[test]
    fn face_test_compares_a_repeated_live_capture() {
        use mug::liveness::synth;
        let _lock = tess_testenv::env_lock();
        let dir = tempfile::tempdir().unwrap();
        write_grey_pair(dir.path(), &synth::live_pair(340, 340));
        let _ir = tess_testenv::EnvGuard::set_path(VirtualIrDevice::ENV_DIR, dir.path());
        let (mut s, mut e) = VirtualIrDevice::split_from_env().unwrap();
        let cfg = MugConfig::default();
        let matcher = build_matcher(&cfg, true).unwrap();
        // Same live frames for reference and probe → both live, compared (distance ~0 → matched).
        let outcome = run_face_test(&mut s, &mut e, &matcher, None, &cfg, &|_: &str| {}).unwrap();
        match outcome {
            FaceTestOutcome::Compared {
                distance, matched, ..
            } => assert!(
                matched,
                "identical live captures should match, distance {distance}"
            ),
            other => panic!("expected Compared, got {other:?}"),
        }
    }

    #[test]
    fn face_test_rejects_a_photo_probe() {
        use mug::liveness::synth;
        let _lock = tess_testenv::env_lock();
        let dir = tempfile::tempdir().unwrap();
        write_grey_pair(dir.path(), &synth::live_pair(340, 340)); // reference = live
        let _ir = tess_testenv::EnvGuard::set_path(VirtualIrDevice::ENV_DIR, dir.path());
        let (mut s, mut e) = VirtualIrDevice::split_from_env().unwrap();
        let cfg = MugConfig::default();
        let matcher = build_matcher(&cfg, true).unwrap();
        let dirp = dir.path().to_path_buf();
        // Swap in a flat-screen/photo pair before the PROBE capture → liveness must reject it.
        let pause = move |msg: &str| {
            if msg.contains("PROBE") {
                write_grey_pair(&dirp, &synth::screen_pair(340, 340));
            }
        };
        let outcome = run_face_test(&mut s, &mut e, &matcher, None, &cfg, &pause).unwrap();
        assert!(
            matches!(outcome, FaceTestOutcome::ProbeRejected),
            "a photo probe must be rejected by liveness, got {outcome:?}"
        );
    }
}
