//! The session unlock composition shared by the PAM helper and the (future) `tess unlock` command:
//! load the sealed object, unseal the random key with the PIN, and unlock the login keyring with it.
//!
//! This is the body the `tess-pam-helper` binary runs as a short-lived, watchdog'd child of the PAM
//! module. The PAM module never performs this work on its own thread — it hands the PIN to the
//! helper on stdin and supervises it under a hard deadline.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use tess_core::{Error as CoreError, KeyringBackend, SecretBytes};
use tess_fprint::FprintClient;
use tess_keyring::SecretServiceBackend;
use tess_tpm::{TctiConfig, persist};

use crate::enroll::Paths;
use crate::enroll::sealer::{KeySealer, TpmSealer};

/// Upper bound on the PIN read from stdin, so a misbehaving caller cannot make the helper read an
/// unbounded amount. A real PIN is far smaller; the TPM authValue layer rejects anything over its
/// own limit regardless.
const MAX_PIN_BYTES: u64 = 1024;

/// Wall-clock budget for the optional fingerprint front gate's fprintd verify, well inside the PAM
/// module's watchdog deadline so the TPM unseal still has headroom. Release builds always use this
/// value; debug/test builds may shorten it via `TESS_FPRINT_TIMEOUT_MS`.
const FINGERPRINT_VERIFY_DEADLINE_MS: u64 = 8_000;

/// Debug/test-only override pointing the helper's fprintd verify at a private mock bus instead of the
/// system bus. Release builds ignore the environment entirely and always use the system bus, so a
/// caller's environment cannot redirect the verify to an attacker-controlled D-Bus address in the
/// privileged PAM helper.
#[cfg(debug_assertions)]
const FPRINT_BUS_ADDRESS_ENV: &str = "TESS_FPRINT_BUS_ADDRESS";
/// The login user to claim the fprintd device for, set by the PAM module from `PAM_USER`. Empty (the
/// calling user, as `pam_fprintd` defaults) when unset. A production channel, honoured in all builds.
const FPRINT_USER_ENV: &str = "TESS_FPRINT_USER";
/// Debug/test-only override for the fprintd verify deadline (milliseconds). Release builds ignore it
/// and always use [`FINGERPRINT_VERIFY_DEADLINE_MS`], so a caller cannot push the helper into
/// watchdog-kill territory.
#[cfg(debug_assertions)]
const FPRINT_TIMEOUT_ENV: &str = "TESS_FPRINT_TIMEOUT_MS";

/// Select the TPM transport for the session helper. Delegates to the binary's shared selector so
/// the swtpm-vs-`/dev/tpmrm0` choice can't drift between subcommands.
pub fn tcti_from_env() -> TctiConfig {
    crate::tcti::from_env()
}

/// Load the sealed object at `metadata_path`, unseal the key under `pin` over `tcti`, and unlock the
/// login keyring via `keyring`. Any failure (not enrolled, wrong PIN, TPM fault, keyring error) is
/// surfaced with context — never swallowed; the caller decides how to degrade.
pub fn unseal_and_unlock(
    tcti: &TctiConfig,
    metadata_path: &Path,
    pin: &SecretBytes,
    keyring: &dyn KeyringBackend,
) -> Result<()> {
    let metadata = persist::load(metadata_path).with_context(|| {
        format!(
            "load sealed metadata from {} (is tess enrolled?)",
            metadata_path.display()
        )
    })?;
    let sealed = persist::from_metadata(&metadata).context("decode the sealed object")?;

    let mut sealer = TpmSealer::open(tcti).context("open the TPM")?;
    let key = sealer
        .unseal(&sealed, pin)
        .context("unseal the keyring key with the PIN")?;

    keyring
        .unlock(&key)
        .context("unlock the login keyring with the unsealed key")
}

/// Read the PIN from standard input (the channel the PAM module uses to hand it to the helper),
/// bounded to [`MAX_PIN_BYTES`]. The bytes are taken verbatim — no trailing-newline trimming — so
/// the PIN matches exactly what was sealed at enrollment. An empty or over-long PIN is a hard error
/// (not silently truncated), so malformed input is distinguishable from a genuine wrong-PIN failure.
fn read_pin_from_stdin() -> Result<SecretBytes> {
    let mut buf = Vec::new();
    // Read one byte past the limit so an over-long PIN is detected rather than silently truncated.
    std::io::stdin()
        .lock()
        .take(MAX_PIN_BYTES + 1)
        .read_to_end(&mut buf)
        .context("read PIN from stdin")?;
    ensure!(!buf.is_empty(), "no PIN supplied on stdin");
    ensure!(
        buf.len() as u64 <= MAX_PIN_BYTES,
        "PIN on stdin exceeds the {MAX_PIN_BYTES}-byte maximum"
    );
    Ok(SecretBytes::new(buf))
}

/// Entry point for the `tess-pam-helper` binary: optionally attempt the bounded face release path
/// and/or the fingerprint front gate, then read the PIN from stdin and run the session unlock
/// against the user's enrollment data, the environment-selected TPM, and the Secret Service login
/// keyring. Precedence: **face (model-B, releases the key with no PIN) → fingerprint (convenience)
/// → PIN (the real TPM gate) → password fallthrough**. The face leg is host-trusted convenience that
/// can release the key on its own, but any failure/timeout/not-enrolled degrades cleanly to the PIN;
/// the fingerprint leg never substitutes for the PIN. The PIN is read after the face attempt but
/// before the fingerprint verify, so an empty stdin short-circuits the pointless fingerprint verify;
/// it is still read after the (potentially multi-second) face capture, keeping its in-memory lifetime
/// near the unseal. Returns an error (mapped by the binary to a non-zero exit) only on failure of the
/// **PIN** path — the real gate.
pub fn run_pam_helper(fingerprint: bool, face: bool) -> Result<()> {
    let paths = Paths::for_user().context("resolve the tess data directory")?;
    let tcti = tcti_from_env();
    let keyring = SecretServiceBackend::connect().context("connect to the Secret Service")?;

    if face {
        // The bounded liveness-gated match can release the key with no PIN typed. On a clean unlock
        // there is nothing more to do; on any failure we report it and fall through to the PIN.
        match face_front_unlock(&tcti, &paths, &keyring) {
            FaceRelease::Unlocked => {
                eprintln!(
                    "tess-pam-helper: face verified (host-trusted convenience); keyring unlocked via the face authValue"
                );
                return Ok(());
            }
            FaceRelease::Fallback(reason) => {
                eprintln!("tess-pam-helper: face unavailable ({reason}) — falling back to the PIN");
            }
        }
    }
    // Read the PIN before the fingerprint front gate: when no PIN is on stdin (e.g. the face-only
    // path already fell back) this returns early, skipping the bounded — and pointless — fingerprint
    // verify, since fingerprint is only a convenience gate in front of the PIN unseal and can never
    // unlock without it. Avoids up to a full fingerprint deadline of needless login latency.
    let pin = read_pin_from_stdin()?;
    if fingerprint {
        // Convenience confirmation that the right user is present before the PIN unseal below; the
        // verify is bounded and its outcome only logged — the PIN is what unseals the key.
        report_fingerprint(fingerprint_front_gate());
    }
    unseal_and_unlock(&tcti, &paths.metadata, &pin, &keyring)
}

/// The outcome of the optional face release path. Every variant either unlocks outright or degrades
/// to the PIN — a face failure never aborts the helper, only the PIN path can.
enum FaceRelease {
    /// A live, matching face released the key and unlocked the keyring — no PIN needed.
    Unlocked,
    /// Face was unavailable (not enrolled, no capture backend, no match, liveness rejection, TPM or
    /// keyring fault); carries a secret-free reason for the journal. The caller falls back to the PIN.
    Fallback(String),
}

/// Attempt the bounded, liveness-gated face release: confirm face is fully enrolled, run the
/// match, and on success unseal the keyring key via the on-disk `A_face` authValue and unlock the
/// keyring. The TPM context is scoped to this function so it is dropped before the PIN fallback opens
/// its own (the swtpm transport used in tests is single-client). The IR capture is bounded by the
/// mug capture deadline; the subsequent TPM unseal and keyring unlock are not separately bounded, so
/// the PAM module's watchdog is the outer wall-clock backstop for the whole leg.
fn face_front_unlock(
    tcti: &TctiConfig,
    paths: &Paths,
    keyring: &dyn KeyringBackend,
) -> FaceRelease {
    if !crate::lifecycle::face_enrolled(paths) {
        return FaceRelease::Fallback("face not enrolled".to_string());
    }
    let enrollment = match crate::face::load_enrollment() {
        Ok(Some(enrollment)) => enrollment,
        Ok(None) => return FaceRelease::Fallback("no face enrollment on disk".to_string()),
        Err(e) => return FaceRelease::Fallback(format!("load face enrollment: {e:#}")),
    };
    if let Err(e) = crate::face::verify_from_env(&enrollment) {
        return FaceRelease::Fallback(format!("face verify: {e:#}"));
    }
    let mut sealer = match TpmSealer::open(tcti) {
        Ok(sealer) => sealer,
        Err(e) => return FaceRelease::Fallback(format!("open the TPM: {e:#}")),
    };
    match crate::lifecycle::unlock_with_face(&mut sealer, keyring, paths) {
        Ok(()) => FaceRelease::Unlocked,
        Err(e) => FaceRelease::Fallback(format!("face unseal/unlock: {e:#}")),
    }
}

/// The result of the optional fingerprint front gate. Every variant proceeds to the PIN unseal: a
/// match is convenience confirmation that the right user is present, never a substitute for the PIN,
/// and every failure mode degrades to the PIN rather than blocking login.
enum FingerprintGate {
    /// fprintd matched an enrolled finger (host-trusted convenience).
    Matched,
    /// A finger was read but matched no enrolled template (the explicit `NO_MATCH_REASON`).
    NoMatch,
    /// The bounded verify deadline elapsed first.
    TimedOut,
    /// fprintd was absent or unreachable, or reported any other terminal verification failure
    /// (no reader, no service, bus error, claim/start error, device disconnect, closed stream);
    /// carries the reason.
    Unavailable(String),
}

/// The fprintd verify deadline. Release builds always use [`FINGERPRINT_VERIFY_DEADLINE_MS`];
/// debug/test builds may shorten it via `TESS_FPRINT_TIMEOUT_MS` (a positive millisecond value).
fn fingerprint_deadline_ms() -> u64 {
    #[cfg(debug_assertions)]
    if let Some(ms) = std::env::var(FPRINT_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
    {
        return ms;
    }
    FINGERPRINT_VERIFY_DEADLINE_MS
}

/// Connect to fprintd for the verify. Production always uses the system bus; debug/test builds may
/// redirect to a private mock bus via `TESS_FPRINT_BUS_ADDRESS`. Release builds never consult the
/// environment, so a caller cannot point the privileged helper at an attacker-controlled bus.
fn connect_fprint(user: &str) -> tess_core::Result<FprintClient> {
    #[cfg(debug_assertions)]
    if let Ok(address) = std::env::var(FPRINT_BUS_ADDRESS_ENV)
        && !address.is_empty()
    {
        return FprintClient::connect_address(&address, user);
    }
    FprintClient::system(user)
}

/// Run one bounded fprintd verify and classify the outcome. Never returns an error: a fingerprint
/// failure must degrade to the PIN, never abort the session helper.
fn fingerprint_front_gate() -> FingerprintGate {
    let user = std::env::var(FPRINT_USER_ENV).unwrap_or_default();
    let client = match connect_fprint(&user) {
        Ok(client) => client,
        Err(e) => return FingerprintGate::Unavailable(e.to_string()),
    };
    match client.verify(fingerprint_deadline_ms()) {
        Ok(()) => FingerprintGate::Matched,
        Err(CoreError::Timeout(_)) => FingerprintGate::TimedOut,
        // `verify` reports both a clean no-match and other terminal failures (claim/start errors,
        // device disconnect, closed stream) as `Auth`; only the no-match sentinel is a real
        // no-match. Everything else is an unavailable reader, logged with its reason for diagnostics.
        Err(CoreError::Auth(reason)) if reason == tess_fprint::NO_MATCH_REASON => {
            FingerprintGate::NoMatch
        }
        Err(CoreError::Auth(reason)) => FingerprintGate::Unavailable(reason),
        Err(e) => FingerprintGate::Unavailable(e.to_string()),
    }
}

/// Write a secret-free line about the fingerprint outcome to stderr (the journal). No PIN, key, or
/// fingerprint data is ever logged — only the verdict and, for an unavailable reader, the reason.
fn report_fingerprint(gate: FingerprintGate) {
    match gate {
        FingerprintGate::Matched => eprintln!(
            "tess-pam-helper: fingerprint verified (host-trusted convenience); the PIN still unseals the key"
        ),
        FingerprintGate::NoMatch => {
            eprintln!("tess-pam-helper: fingerprint did not match — falling back to the PIN")
        }
        FingerprintGate::TimedOut => {
            eprintln!("tess-pam-helper: fingerprint verify timed out — falling back to the PIN")
        }
        FingerprintGate::Unavailable(reason) => eprintln!(
            "tess-pam-helper: fingerprint unavailable ({reason}) — falling back to the PIN"
        ),
    }
}
