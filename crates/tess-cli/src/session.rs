//! The session unlock composition shared by the PAM helper and the (future) `tess unlock` command:
//! load the sealed object, unseal the random key with the PIN, and unlock the login keyring with it.
//!
//! This is the body the `tess-pam-helper` binary runs as a short-lived, watchdog'd child of the PAM
//! module. The PAM module never performs this work on its own thread — it hands the PIN to the
//! helper on stdin and supervises it under a hard deadline.

use std::io::Read;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use tess_core::{KeyringBackend, SecretBytes};
use tess_keyring::SecretServiceBackend;
use tess_tpm::{persist, TctiConfig};

use crate::enroll::sealer::{KeySealer, TpmSealer};
use crate::enroll::Paths;

/// Upper bound on the PIN read from stdin, so a misbehaving caller cannot make the helper read an
/// unbounded amount. A real PIN is far smaller; the TPM authValue layer rejects anything over its
/// own limit regardless.
const MAX_PIN_BYTES: u64 = 1024;

/// Select the TPM transport: an swtpm when `TESS_SWTPM_HOST`/`TESS_SWTPM_PORT` are set (CI / Azure
/// smoke runs), otherwise the kernel resource manager at `/dev/tpmrm0`.
pub fn tcti_from_env() -> TctiConfig {
    if std::env::var_os("TESS_SWTPM_HOST").is_some()
        || std::env::var_os("TESS_SWTPM_PORT").is_some()
    {
        TctiConfig::swtpm_from_env()
    } else {
        TctiConfig::DeviceManager {
            path: "/dev/tpmrm0".to_string(),
        }
    }
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

/// Entry point for the `tess-pam-helper` binary: read the PIN from stdin, then run the session
/// unlock against the user's enrollment data, the environment-selected TPM, and the Secret Service
/// login keyring. Returns an error (mapped by the binary to a non-zero exit) on any failure.
pub fn run_pam_helper() -> Result<()> {
    let pin = read_pin_from_stdin()?;
    let paths = Paths::for_user().context("resolve the tess data directory")?;
    let tcti = tcti_from_env();
    let keyring = SecretServiceBackend::connect().context("connect to the Secret Service")?;
    unseal_and_unlock(&tcti, &paths.metadata, &pin, &keyring)
}
