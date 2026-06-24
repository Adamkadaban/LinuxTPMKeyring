//! Shared types, on-disk metadata schema, secret hygiene, and core traits for tess.
//!
//! This crate is dependency-light on purpose: every other crate builds on these types and traits.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Current version of the on-disk [`Metadata`] schema. Bump on any incompatible change.
pub const METADATA_VERSION: u32 = 1;

/// Errors surfaced across tess crates. Libraries propagate these with context; the binary edge
/// (`tess-cli`, `tess-pam`) maps them to user-facing messages or PAM return codes. Errors are never
/// swallowed — a lost TPM/keyring error can silently lock a user out of their secrets.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TPM error: {0}")]
    Tpm(String),

    #[error("keyring error: {0}")]
    Keyring(String),

    #[error("authentication gate error: {0}")]
    Auth(String),

    #[error("TPM is in dictionary-attack lockout: {0}")]
    Lockout(String),

    #[error("metadata error: {0}")]
    Metadata(String),

    #[error("unsupported metadata version {found} (expected {expected})")]
    MetadataVersion { found: u32, expected: u32 },

    #[error("operation timed out after {0}ms")]
    Timeout(u64),

    #[error("not enrolled")]
    NotEnrolled,

    #[error("io error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A zeroizing, RAM-locked byte buffer for secret material (the sealed random key, the recovery
/// secret, a PIN). The backing buffer is `mlock`ed so the kernel can't page it to swap or
/// hibernation, and it is `zeroize`d then unlocked on drop. Never `Debug`-printed in the clear.
///
/// Locking is **best-effort**: if the OS refuses (e.g. a low `RLIMIT_MEMLOCK`) the secret is still
/// zeroized on drop and a one-line note is emitted — locking never fails construction or blocks an
/// auth path. The wipe-then-unlock-then-free ordering is enforced by field declaration order
/// (`_lock` before `data`).
pub struct SecretBytes {
    // Drops before `data` (declaration order): after `Drop::drop` zeroizes `data`, the guard
    // unlocks the pages while `data`'s buffer is still allocated, then `data` frees it.
    _lock: Option<region::LockGuard>,
    data: Vec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        let lock = lock_buffer(&bytes);
        Self {
            _lock: lock,
            data: bytes,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Whether this buffer's pages are currently `mlock`ed (test-only observability).
    #[cfg(test)]
    fn is_locked(&self) -> bool {
        self._lock.is_some()
    }
}

/// Best-effort `mlock` of `buf`'s backing pages. Returns `None` for an empty buffer or when the OS
/// refuses to lock (logged once, never fatal — the secret stays zeroize-on-drop regardless).
fn lock_buffer(buf: &[u8]) -> Option<region::LockGuard> {
    if buf.is_empty() {
        return None;
    }
    match region::lock(buf.as_ptr(), buf.len()) {
        Ok(guard) => Some(guard),
        Err(e) => {
            eprintln!(
                "tess: note: could not mlock a {}-byte secret buffer ({e}); it stays \
                 zeroize-on-drop but may be pageable. Raise RLIMIT_MEMLOCK to lock secrets in RAM.",
                buf.len()
            );
            None
        }
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        // A clone gets its own freshly-locked buffer (the lock guard binds to a specific allocation).
        Self::new(self.data.clone())
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

// Marker: the manual `Drop` below zeroizes the contents, so `SecretBytes` honors the
// `ZeroizeOnDrop` contract.
impl ZeroizeOnDrop for SecretBytes {}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Wipe while the pages are still locked; `_lock` then unlocks (field-drop order) before
        // `data` frees its buffer.
        self.data.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes({} bytes, redacted)", self.data.len())
    }
}

/// Describes how a sealed object is gated. The MVP uses [`Policy::PinAuthValue`]; PCR binding and
/// `PolicyOR(PIN | biometric)` are deferred extension points.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Policy {
    /// PIN as the TPM authValue; anti-hammering via TPM dictionary-attack lockout.
    PinAuthValue,
}

/// Versioned, serde-serialized enrollment metadata persisted alongside the sealed blobs. **Never
/// contains a secret or a hash of one** — only public material and policy descriptors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub version: u32,
    pub policy: Policy,
    /// TPM sealed object public blob (TPM2B_PUBLIC), base64. Populated by `tess-tpm`.
    pub sealed_public: String,
    /// TPM sealed object private blob (TPM2B_PRIVATE), base64. Populated by `tess-tpm`.
    pub sealed_private: String,
}

impl Metadata {
    pub fn new(policy: Policy, sealed_public: String, sealed_private: String) -> Self {
        Self {
            version: METADATA_VERSION,
            policy,
            sealed_public,
            sealed_private,
        }
    }

    /// Reject metadata written by an incompatible future version.
    pub fn validate_version(&self) -> Result<()> {
        if self.version != METADATA_VERSION {
            return Err(Error::MetadataVersion {
                found: self.version,
                expected: METADATA_VERSION,
            });
        }
        Ok(())
    }
}

/// A factor that authorizes a key release (PIN now; fingerprint and face later). Implementations
/// must be bounded by a deadline and must never block the PAM thread.
pub trait AuthGate {
    /// Returns `Ok(())` if the factor was satisfied within `deadline_ms`, else an [`Error`].
    fn authorize(&self, deadline_ms: u64) -> Result<()>;
}

/// Abstraction over a secret store implementing the freedesktop Secret Service API (GNOME reference
/// impl; KWallet via `apiEnabled`). Unstable private GNOME D-Bus calls stay behind this trait.
pub trait KeyringBackend {
    /// Rekey the login keyring in place from `old` to `new`, preserving every existing item.
    fn rekey(&self, old: &SecretBytes, new: &SecretBytes) -> Result<()>;
    /// Unlock the login keyring with `secret`.
    fn unlock(&self, secret: &SecretBytes) -> Result<()>;
    /// Whether the login collection is currently locked.
    fn is_locked(&self) -> Result<bool>;
}

/// Where the unsealed key is held between unseal and keyring handoff. Heap impl now; a `keyctl logon`
/// kernel-keyring impl is a deferred hardening extension point.
pub trait SecretStash {
    fn store(&mut self, secret: SecretBytes) -> Result<()>;
    fn take(&mut self) -> Result<SecretBytes>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_redacts_debug() {
        let s = SecretBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(format!("{s:?}"), "SecretBytes(4 bytes, redacted)");
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
    }

    /// Locked-page count (kB) for this process from `/proc/self/status` (`VmLck`).
    fn vmlck_kb() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").expect("read /proc/self/status");
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmLck:") {
                let kb = rest.split_whitespace().next().unwrap_or("0");
                return kb.parse().unwrap_or(0);
            }
        }
        0
    }

    #[test]
    fn empty_secret_is_not_locked() {
        // Nothing to lock; `region::lock` of a zero-length buffer is skipped.
        assert!(!SecretBytes::new(Vec::new()).is_locked());
    }

    #[test]
    fn secret_buffer_is_mlocked_and_unlocked_on_drop() {
        // 64 KiB spans multiple pages so the VmLck delta is unambiguous when locking is permitted.
        let before = vmlck_kb();
        let secret = SecretBytes::new(vec![0xAB; 64 * 1024]);
        let during = vmlck_kb();
        if secret.is_locked() {
            assert!(
                during > before,
                "VmLck should grow while a secret is locked ({before} -> {during} kB)"
            );
            drop(secret);
            let after = vmlck_kb();
            assert!(
                after <= during,
                "VmLck should not stay elevated after the secret is dropped/unlocked \
                 ({during} -> {after} kB)"
            );
        } else {
            // A constrained sandbox (e.g. RLIMIT_MEMLOCK=0) denies locking; the secret is still
            // zeroize-on-drop, just pageable. Don't fail — that's the documented best-effort path.
            eprintln!("note: mlock denied in this environment; skipping the VmLck assertion");
        }
    }

    #[test]
    fn clone_gets_its_own_lock() {
        let a = SecretBytes::new(vec![7u8; 4096]);
        let b = a.clone();
        assert_eq!(a.as_slice(), b.as_slice());
        // Both either locked (normal) or both denied (constrained env) — never one-sided, since each
        // owns a distinct allocation locked independently.
        assert_eq!(a.is_locked(), b.is_locked());
    }

    #[test]
    fn metadata_roundtrips_and_validates() {
        let m = Metadata::new(Policy::PinAuthValue, "pub".into(), "priv".into());
        let json = serde_json::to_string(&m).unwrap();
        let back: Metadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, METADATA_VERSION);
        assert_eq!(back.policy, Policy::PinAuthValue);
        back.validate_version().unwrap();
    }

    #[test]
    fn metadata_rejects_future_version() {
        let mut m = Metadata::new(Policy::PinAuthValue, "p".into(), "q".into());
        m.version = METADATA_VERSION + 1;
        assert!(matches!(
            m.validate_version(),
            Err(Error::MetadataVersion { .. })
        ));
    }
}
