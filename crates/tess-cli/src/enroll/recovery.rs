//! TPM-independent recovery backup for the keyring's wrapping key.
//!
//! Enrollment seals the keyring's fresh random key `K` in the TPM under the PIN (the normal unlock
//! path). That path dies if the TPM is cleared or the PIN is lost, so enrollment additionally backs
//! `K` up under a high-entropy **recovery secret** `R` that the user saves offline:
//!
//! 1. Generate `R` — 256 bits from the OS CSPRNG, shown to the user once as a transcription-friendly
//!    grouped-hex string.
//! 2. Derive a 256-bit key-encryption key `KEK = HKDF-SHA256(salt, R, info)` with a fresh random
//!    salt.
//! 3. AEAD-seal `K` under `KEK` with XChaCha20-Poly1305 and a fresh random 192-bit nonce.
//! 4. Persist only `{version, salt, nonce, ciphertext}` — never `K`, `R`, or any hash of either.
//!
//! The blob is recoverable **without the TPM** (decrypt with `KEK` re-derived from the
//! user-entered `R`) yet inert without `R`: the ciphertext is indistinguishable from random and the
//! Poly1305 tag rejects tampering or a wrong secret. `tess recover` (wave 2) decrypts it back to `K`
//! to re-unlock and re-seal. The recovery secret is at least as strong as the PIN, so this never
//! weakens the at-rest guarantee.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tess_core::SecretBytes;
use zeroize::Zeroizing;

const RECOVERY_SECRET_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEK_LEN: usize = 32;
/// The keyring key tess wraps is a fixed 32-byte TPM sealing key; XChaCha20-Poly1305 appends a
/// 16-byte Poly1305 tag, so a well-formed recovery ciphertext is always exactly this length.
const WRAPPED_KEY_LEN: usize = 32;
const AEAD_TAG_LEN: usize = 16;
const WRAPPED_CIPHERTEXT_LEN: usize = WRAPPED_KEY_LEN + AEAD_TAG_LEN;
const HKDF_INFO: &[u8] = b"tess recovery key-encryption key v1";
/// Domain-separation label for the lockout-hierarchy authValue sub-key. Distinct from [`HKDF_INFO`]
/// so the lockout authValue is never equal to the recovery key-encryption key; salt-less so it is
/// deterministic from the recovery secret alone (a hard-lockout reset has no stored salt to read).
const LOCKOUT_AUTH_INFO: &[u8] = b"tess-lockout-auth-v1";
/// Length of the derived lockout authValue: the SHA-256 digest size, the authValue cap the TPM
/// enforces on the lockout hierarchy.
const LOCKOUT_AUTH_LEN: usize = 32;

/// Schema version of the on-disk recovery blob, independent of the TPM metadata schema.
pub const RECOVERY_BLOB_VERSION: u32 = 1;

/// Process-local sequence so back-to-back `save_blob` calls get distinct temp names.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// The persisted recovery artifact: the AEAD-sealed keyring key plus the public parameters needed to
/// re-derive the key-encryption key. Holds no secret in the clear — useless without the recovery
/// secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBlob {
    pub version: u32,
    /// HKDF salt, base64.
    pub salt: String,
    /// XChaCha20-Poly1305 nonce, base64.
    pub nonce: String,
    /// XChaCha20-Poly1305 ciphertext of the keyring key (includes the Poly1305 tag), base64.
    pub ciphertext: String,
}

/// Generate a fresh 256-bit recovery secret from the OS CSPRNG.
pub fn generate_recovery_secret() -> Result<SecretBytes> {
    let mut bytes = Zeroizing::new(vec![0u8; RECOVERY_SECRET_LEN]);
    getrandom::fill(&mut bytes[..])
        .map_err(|e| anyhow!("draw recovery secret from CSPRNG: {e}"))?;
    Ok(SecretBytes::new(std::mem::take(&mut *bytes)))
}

/// Render a recovery secret as a transcription-friendly grouped-hex string (lowercase hex in
/// hyphen-separated 4-byte groups), e.g. `0a1b2c3d-...`. The grouping is cosmetic; [`decode`] ignores
/// hyphens and case.
pub fn encode(secret: &SecretBytes) -> String {
    secret
        .as_slice()
        .chunks(4)
        .map(|chunk| chunk.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// Parse a recovery secret printed by [`encode`], tolerating hyphens, whitespace, and either case.
/// Used by `tess recover` (wave 2) and the tests that prove the displayed string round-trips.
pub fn decode(display: &str) -> Result<SecretBytes> {
    let hex: String = display
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    ensure!(
        hex.len() == RECOVERY_SECRET_LEN * 2,
        "recovery secret must be {} hex digits, got {}",
        RECOVERY_SECRET_LEN * 2,
        hex.len()
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(RECOVERY_SECRET_LEN));
    let raw = hex.as_bytes();
    for pair in raw.chunks(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(SecretBytes::new(std::mem::take(&mut *bytes)))
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => Err(anyhow!(
            "invalid character '{}' in recovery secret",
            other as char
        )),
    }
}

/// Derive the 256-bit key-encryption key from the recovery secret and a salt via HKDF-SHA256. The
/// recovery secret is already high-entropy, so an extract/expand KDF (not a slow password hash)
/// suffices and keeps recovery instant.
fn derive_kek(recovery: &SecretBytes, salt: &[u8]) -> Result<Zeroizing<[u8; KEK_LEN]>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), recovery.as_slice());
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    hk.expand(HKDF_INFO, &mut *kek)
        .map_err(|e| anyhow!("derive recovery key-encryption key: {e}"))?;
    Ok(kek)
}

/// Derive the TPM lockout-hierarchy authValue from the recovery secret via HKDF-SHA256 with a
/// distinct `info` label and no salt. Deterministic (no stored salt to read at reset time),
/// domain-separated from the recovery key-encryption key, and never equal to the keyring-wrapping
/// key — so only the recovery-secret holder can authorize the privileged dictionary-attack reset.
pub fn derive_lockout_auth(recovery: &SecretBytes) -> Result<SecretBytes> {
    let hk = Hkdf::<Sha256>::new(None, recovery.as_slice());
    let mut auth = Zeroizing::new(vec![0u8; LOCKOUT_AUTH_LEN]);
    hk.expand(LOCKOUT_AUTH_INFO, &mut auth[..])
        .map_err(|e| anyhow!("derive lockout authValue: {e}"))?;
    Ok(SecretBytes::new(std::mem::take(&mut *auth)))
}

/// AEAD-seal `key` under a key-encryption key derived from `recovery`, returning the persistable
/// blob. Salt and nonce are fresh per call.
pub fn wrap_key(key: &SecretBytes, recovery: &SecretBytes) -> Result<RecoveryBlob> {
    // The recovery format is fixed-size; refuse a non-32-byte key up front so a misuse fails
    // immediately rather than persisting a `recovery.json` that `unwrap_key` would later reject.
    ensure!(
        key.len() == WRAPPED_KEY_LEN,
        "recovery wrap expects a {WRAPPED_KEY_LEN}-byte key, got {}",
        key.len()
    );
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| anyhow!("draw recovery salt: {e}"))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("draw recovery nonce: {e}"))?;

    let kek = derive_kek(recovery, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*kek)
        .map_err(|e| anyhow!("init recovery cipher: {e}"))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), key.as_slice())
        .map_err(|e| anyhow!("seal keyring key under recovery secret: {e}"))?;

    Ok(RecoveryBlob {
        version: RECOVERY_BLOB_VERSION,
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
}

/// Recover the keyring key from a blob using the recovery secret. A wrong secret or a tampered blob
/// fails the Poly1305 tag and surfaces an error rather than returning garbage.
pub fn unwrap_key(blob: &RecoveryBlob, recovery: &SecretBytes) -> Result<SecretBytes> {
    ensure!(
        blob.version == RECOVERY_BLOB_VERSION,
        "unsupported recovery blob version {} (expected {})",
        blob.version,
        RECOVERY_BLOB_VERSION
    );
    let salt = decode_exact(&blob.salt, SALT_LEN, "salt")?;
    let nonce = decode_exact(&blob.nonce, NONCE_LEN, "nonce")?;
    let ciphertext = decode_exact(&blob.ciphertext, WRAPPED_CIPHERTEXT_LEN, "ciphertext")?;

    let kek = derive_kek(recovery, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&*kek)
        .map_err(|e| anyhow!("init recovery cipher: {e}"))?;
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("recovery secret did not match (or the recovery blob is corrupt)"))?;
    Ok(SecretBytes::new(plaintext))
}

/// Base64-decode a fixed-size field, bounding the *encoded* length first so a maliciously edited
/// `recovery.json` can't force a large allocation, then asserting the decoded length is exact.
fn decode_exact(value: &str, expected: usize, field: &str) -> Result<Vec<u8>> {
    // base64 encodes 3 bytes as 4 chars; allow a few extra chars for padding before rejecting.
    let max_encoded = expected.div_ceil(3) * 4 + 4;
    ensure!(
        value.len() <= max_encoded,
        "recovery {field} is too long ({} chars; expected <= {max_encoded})",
        value.len()
    );
    let bytes = STANDARD
        .decode(value)
        .map_err(|e| anyhow!("decode recovery {field}: {e}"))?;
    ensure!(
        bytes.len() == expected,
        "recovery {field} must be {expected} bytes, got {}",
        bytes.len()
    );
    Ok(bytes)
}

/// Serialize a recovery blob to pretty JSON and write it to `path` atomically (temp sibling +
/// rename), mode `0600` on Unix. The blob holds no plaintext secret, but it is not world-business.
pub fn save_blob(blob: &RecoveryBlob, path: &Path) -> Result<()> {
    let json = serde_json::to_vec_pretty(blob).context("serialize recovery blob")?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = temp_sibling(path);
    write_private(&tmp, &json).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow!("rename {} -> {}: {e}", tmp.display(), path.display())
    })?;
    // fsync the parent directory so the renamed entry itself is durable; without this a crash after
    // rename can lose the recovery blob even though its data was synced.
    sync_parent_dir(path).with_context(|| format!("sync parent dir of {}", path.display()))?;
    Ok(())
}

/// Durably create an empty marker file at `path` (atomic temp-write + rename + parent-dir fsync,
/// mode 0600), so a crash right after enrollment can't lose it. The marker carries no data — only
/// its presence is meaningful — but it must survive power loss to stay consistent with the TPM
/// lockout authValue whose tess-ownership it records.
pub(crate) fn write_durable_marker(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = temp_sibling(path);
    write_private(&tmp, &[]).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow!("rename {} -> {}: {e}", tmp.display(), path.display())
    })?;
    sync_parent_dir(path).with_context(|| format!("sync parent dir of {}", path.display()))?;
    Ok(())
}

/// Durably write raw secret bytes to `path` (atomic temp-write + rename + parent-dir fsync, mode
/// 0600). The caller owns wiping the in-memory copy via [`SecretBytes`]. Used for the face-unlock
/// authValue (`A_face`): unlike the recovery blob it is the raw credential, so it never reaches disk
/// in any form other than this private file.
pub(crate) fn write_secret_file(path: &Path, secret: &SecretBytes) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = temp_sibling(path);
    write_private(&tmp, secret.as_slice()).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow!("rename {} -> {}: {e}", tmp.display(), path.display())
    })?;
    sync_parent_dir(path).with_context(|| format!("sync parent dir of {}", path.display()))?;
    Ok(())
}

/// Read raw secret bytes written by [`write_secret_file`] back into a zeroizing [`SecretBytes`]. The
/// `std::fs::read` buffer is moved straight into the secret container (no extra clear-text copy).
pub(crate) fn read_secret_file(path: &Path) -> Result<SecretBytes> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    // The face authValue's at-rest protection is its 0600 mode; refuse to use it if group/other
    // have any access (SSH-style), rather than silently proceeding with a widened, insecure file.
    let mode = meta.permissions().mode() & 0o777;
    ensure!(
        mode & 0o077 == 0,
        "{} has insecure permissions {:#o}; expected no group/other access (e.g. 0600). Fix with: chmod 600 {}",
        path.display(),
        mode,
        path.display()
    );
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(SecretBytes::new(bytes))
}

/// Read and parse a recovery blob from `path`.
pub fn load_blob(path: &Path) -> Result<RecoveryBlob> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let blob: RecoveryBlob =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        blob.version == RECOVERY_BLOB_VERSION,
        "unsupported recovery blob version {} in {}",
        blob.version,
        path.display()
    );
    Ok(blob)
}

fn temp_sibling(path: &Path) -> std::path::PathBuf {
    // A process-local monotonic sequence guarantees distinct temp names for back-to-back calls even
    // when the clock resolution is coarser than a nanosecond (mirrors `tess_tpm::persist`).
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{seq}.{nanos}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// fsync the directory containing `path` so a freshly renamed entry survives a crash. On Unix a
/// directory is fsync'd by opening it read-only and calling `sync_all` on the handle.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretBytes {
        SecretBytes::new(
            (0u8..32)
                .map(|i| i.wrapping_mul(11).wrapping_add(5))
                .collect(),
        )
    }

    #[test]
    fn wrap_unwrap_round_trips_the_key() {
        let k = key();
        let r = generate_recovery_secret().unwrap();
        let blob = wrap_key(&k, &r).unwrap();
        let back = unwrap_key(&blob, &r).unwrap();
        assert_eq!(back.as_slice(), k.as_slice());
    }

    #[test]
    fn lockout_auth_is_deterministic_per_secret() {
        let r = generate_recovery_secret().unwrap();
        let a = derive_lockout_auth(&r).unwrap();
        let b = derive_lockout_auth(&r).unwrap();
        assert_eq!(a.as_slice(), b.as_slice(), "same secret -> same authValue");
        assert_eq!(a.len(), LOCKOUT_AUTH_LEN);
    }

    #[test]
    fn lockout_auth_differs_per_secret() {
        let r1 = generate_recovery_secret().unwrap();
        let r2 = generate_recovery_secret().unwrap();
        assert_ne!(
            derive_lockout_auth(&r1).unwrap().as_slice(),
            derive_lockout_auth(&r2).unwrap().as_slice()
        );
    }

    #[test]
    fn lockout_auth_is_not_the_recovery_kek() {
        // Domain separation: the lockout authValue must not equal the recovery key-encryption key
        // derived from the same secret (distinct HKDF info labels).
        let r = generate_recovery_secret().unwrap();
        let auth = derive_lockout_auth(&r).unwrap();
        let kek = derive_kek(&r, &[0u8; SALT_LEN]).unwrap();
        assert_ne!(auth.as_slice(), &kek[..]);
    }

    #[test]
    fn blob_holds_no_plaintext_key() {
        let k = key();
        let r = generate_recovery_secret().unwrap();
        let blob = wrap_key(&k, &r).unwrap();
        let ct = STANDARD.decode(&blob.ciphertext).unwrap();
        // Ciphertext (16-byte Poly1305 tag appended) must differ from the plaintext key.
        assert_ne!(ct.get(..32), Some(k.as_slice()));
        assert_eq!(ct.len(), k.len() + 16);
    }

    #[test]
    fn wrong_recovery_secret_fails() {
        let k = key();
        let r = generate_recovery_secret().unwrap();
        let wrong = generate_recovery_secret().unwrap();
        let blob = wrap_key(&k, &r).unwrap();
        assert!(unwrap_key(&blob, &wrong).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let k = key();
        let r = generate_recovery_secret().unwrap();
        let mut blob = wrap_key(&k, &r).unwrap();
        let mut ct = STANDARD.decode(&blob.ciphertext).unwrap();
        ct[0] ^= 0xff;
        blob.ciphertext = STANDARD.encode(ct);
        assert!(unwrap_key(&blob, &r).is_err());
    }

    #[test]
    fn wrap_rejects_non_32_byte_key() {
        let r = generate_recovery_secret().unwrap();
        let err = wrap_key(&SecretBytes::new(vec![0u8; 16]), &r).unwrap_err();
        assert!(format!("{err:#}").contains("32-byte key"));
    }

    #[test]
    fn unwrap_rejects_oversized_encoded_field() {
        let k = key();
        let r = generate_recovery_secret().unwrap();
        let mut blob = wrap_key(&k, &r).unwrap();
        blob.ciphertext = STANDARD.encode(vec![0u8; 4096]);
        let err = unwrap_key(&blob, &r).unwrap_err();
        assert!(format!("{err:#}").contains("too long"));
    }

    #[test]
    fn unwrap_rejects_malformed_blob_sizes() {
        let k = key();
        let r = generate_recovery_secret().unwrap();

        let mut short_salt = wrap_key(&k, &r).unwrap();
        short_salt.salt = STANDARD.encode([0u8; SALT_LEN - 1]);
        let err = unwrap_key(&short_salt, &r).unwrap_err();
        assert!(format!("{err:#}").contains("salt"));

        let mut short_ct = wrap_key(&k, &r).unwrap();
        short_ct.ciphertext = STANDARD.encode([0u8; WRAPPED_CIPHERTEXT_LEN - 1]);
        let err = unwrap_key(&short_ct, &r).unwrap_err();
        assert!(format!("{err:#}").contains("ciphertext"));

        let mut short_nonce = wrap_key(&k, &r).unwrap();
        short_nonce.nonce = STANDARD.encode([0u8; NONCE_LEN - 1]);
        let err = unwrap_key(&short_nonce, &r).unwrap_err();
        assert!(format!("{err:#}").contains("nonce"));
    }

    #[test]
    fn encode_decode_round_trips() {
        let r = generate_recovery_secret().unwrap();
        let display = encode(&r);
        assert_eq!(display.len(), 32 * 2 + 7); // 64 hex digits + 7 group separators
        let back = decode(&display).unwrap();
        assert_eq!(back.as_slice(), r.as_slice());
    }

    #[test]
    fn decode_tolerates_uppercase_and_spacing() {
        let r = generate_recovery_secret().unwrap();
        let display = encode(&r).to_uppercase().replace('-', " ");
        let back = decode(&display).unwrap();
        assert_eq!(back.as_slice(), r.as_slice());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert!(decode("0a0b").is_err());
    }

    #[test]
    fn save_load_round_trips_blob() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.json");
        let blob = wrap_key(&key(), &generate_recovery_secret().unwrap()).unwrap();
        save_blob(&blob, &path).unwrap();
        let loaded = load_blob(&path).unwrap();
        assert_eq!(loaded.version, blob.version);
        assert_eq!(loaded.ciphertext, blob.ciphertext);
        assert_eq!(loaded.salt, blob.salt);
        assert_eq!(loaded.nonce, blob.nonce);
    }

    #[test]
    fn secret_file_round_trips_and_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("face-unlock.key");
        let secret = generate_recovery_secret().unwrap();
        write_secret_file(&path, &secret).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the face authValue file must be 0600");
        let read_back = read_secret_file(&path).unwrap();
        assert_eq!(read_back.as_slice(), secret.as_slice());
    }
}
