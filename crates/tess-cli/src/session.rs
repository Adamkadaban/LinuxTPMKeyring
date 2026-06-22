//! The session unlock composition shared by the PAM helper and the (future) `tess unlock` command:
//! load the sealed object, unseal the random key with the PIN, and unlock the login keyring with it.
//!
//! This is the body the `tess-pam-helper` binary runs as a short-lived, watchdog'd child of the PAM
//! module. The PAM module never performs this work on its own thread — it hands the PIN to the
//! helper on stdin and supervises it under a hard deadline.

use std::io::Read;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use tess_core::{Error as CoreError, KeyringBackend, SecretBytes};
use tess_fprint::FprintClient;
use tess_keyring::SecretServiceBackend;
use tess_tpm::{persist, TctiConfig};

use crate::enroll::sealer::{KeySealer, TpmSealer};
use crate::enroll::Paths;

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

/// Entry point for the `tess-pam-helper` binary: read the PIN from stdin, optionally run the
/// fingerprint front gate, then run the session unlock against the user's enrollment data, the
/// environment-selected TPM, and the Secret Service login keyring. Returns an error (mapped by the
/// binary to a non-zero exit) on any failure of the **PIN** path — the real gate. The fingerprint
/// gate never produces such an error: it is host-trusted convenience layered on the PIN, so any
/// fingerprint result (match, no-match, timeout, unavailable) falls through to the PIN unseal, which
/// alone can release the sealed key.
pub fn run_pam_helper(fingerprint: bool) -> Result<()> {
    let paths = Paths::for_user().context("resolve the tess data directory")?;
    let tcti = tcti_from_env();
    if fingerprint {
        // Precedence: fingerprint (convenience) -> PIN (the real TPM gate) -> password fallthrough.
        // The verify is bounded and its outcome only logged; the PIN read below is what unseals the
        // key. Run the verify first so the PIN's in-memory lifetime spans only the unseal, not the
        // (potentially multi-second) fingerprint wait.
        report_fingerprint(fingerprint_front_gate());
    }
    let keyring = SecretServiceBackend::connect().context("connect to the Secret Service")?;
    let pin = read_pin_from_stdin()?;
    unseal_and_unlock(&tcti, &paths.metadata, &pin, &keyring)
}

/// The result of the optional fingerprint front gate. Every variant proceeds to the PIN unseal: a
/// match is convenience confirmation that the right user is present, never a substitute for the PIN,
/// and every failure mode degrades to the PIN rather than blocking login.
enum FingerprintGate {
    /// fprintd matched an enrolled finger (host-trusted convenience).
    Matched,
    /// A finger was read but did not match, or fprintd reported a terminal verification failure.
    NoMatch,
    /// The bounded verify deadline elapsed first.
    TimedOut,
    /// fprintd was absent or unreachable (no reader, no service, bus error); carries the reason.
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
    if let Ok(address) = std::env::var(FPRINT_BUS_ADDRESS_ENV) {
        if !address.is_empty() {
            return FprintClient::connect_address(&address, user);
        }
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
