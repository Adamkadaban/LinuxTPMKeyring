//! Durable, secret-free persistence of a [`SealedObject`]. The sealed object's TPM2B public and
//! private blobs are base64-encoded into the versioned [`tess_core::Metadata`] schema and written as
//! JSON. Only public material and a policy descriptor ever reach disk — never the sealed key, a PIN,
//! or any hash of either; the blobs are useless without the TPM that created the primary and the PIN
//! that gates the object.
//!
//! These functions return [`tess_core::Result`] (not `tess_tpm::Result`): their currency is the
//! `tess_core` metadata schema and on-disk files, and a version mismatch surfaces as
//! [`tess_core::Error::MetadataVersion`] untranslated. They live in this dedicated `persist` module
//! rather than re-exported at the crate root so that differing error type is explicit at the call
//! site (`tess_tpm::persist::save`).

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tess_core::{Error, Metadata, Policy, Result};
use tss_esapi::structures::{Private, Public};
use tss_esapi::traits::{Marshall, UnMarshall};

use crate::seal::SealedObject;

/// Process-local sequence so concurrent `save` calls in one process get distinct temp names.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Encode a sealed object into versioned metadata: the structured `TPMT_PUBLIC` is marshalled to its
/// canonical TPM wire form and the `TPM2B_PRIVATE` buffer is taken verbatim, each base64-encoded.
pub fn to_metadata(sealed: &SealedObject) -> Result<Metadata> {
    let public = sealed
        .public()
        .marshall()
        .map_err(|e| Error::Tpm(format!("marshalling sealed public area: {e}")))?;
    let private = sealed.private().value().to_vec();

    Ok(Metadata::new(
        Policy::PinAuthValue,
        STANDARD.encode(public),
        STANDARD.encode(private),
        STANDARD.encode(sealed.expected_primary_name()),
    ))
}

/// Reconstruct a sealed object from metadata: validate the schema version, base64-decode the public
/// and private blobs and the pinned primary Name, unmarshal the public area, and rebuild the private
/// buffer. The result is ready to hand to [`crate::unseal`] (which re-verifies that Name) under the
/// same TPM's primary.
pub fn from_metadata(metadata: &Metadata) -> Result<SealedObject> {
    metadata.validate_version()?;
    if metadata.policy != Policy::PinAuthValue {
        return Err(Error::Metadata(format!(
            "unsupported sealing policy {:?}; this build only reloads {:?}",
            metadata.policy,
            Policy::PinAuthValue
        )));
    }

    let public_bytes = decode(&metadata.sealed_public, "sealed_public")?;
    let private_bytes = decode(&metadata.sealed_private, "sealed_private")?;
    let primary_name = decode(&metadata.primary_name, "primary_name")?;
    // `primary_name` is required in v2 (it is `#[serde(default)]` only so a v1 file deserializes far
    // enough to hit the structured version error). A current-version file with an empty Name is
    // corrupt or hand-edited: reject it here with a clear metadata error, rather than letting it look
    // valid to `tess doctor`/`status` and then surface later as a misleading `PrimaryNameMismatch`.
    if primary_name.is_empty() {
        return Err(Error::Metadata(
            "metadata is missing the pinned primary Name (corrupt or hand-edited v2 metadata); \
             re-enroll to regenerate it"
                .to_string(),
        ));
    }

    let public = Public::unmarshall(&public_bytes)
        .map_err(|e| Error::Tpm(format!("unmarshalling sealed public area: {e}")))?;
    let private = Private::try_from(private_bytes)
        .map_err(|e| Error::Tpm(format!("rebuilding sealed private blob: {e}")))?;

    Ok(SealedObject::from_blobs(public, private, primary_name))
}

/// Serialize `metadata` to pretty JSON and write it to `path` atomically (write a fresh sibling temp
/// file, then rename) so a crash mid-write can never leave a truncated, unparseable metadata file.
/// Atomic replace-on-rename is a Unix guarantee; on non-Unix targets `std::fs::rename` may not
/// replace an existing destination. The temp file is created with `create_new` (never reusing a
/// stale file); on Unix it is mode `0600` (no `0600` guarantee on non-Unix targets) — it holds no
/// secret, but enrollment metadata is not world-business. After rename the parent directory is
/// fsync'd (Unix) so the entry is durable.
pub fn save(metadata: &Metadata, path: &Path) -> Result<()> {
    let json = serde_json::to_vec_pretty(metadata)
        .map_err(|e| Error::Metadata(format!("serializing metadata: {e}")))?;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Io(format!("creating {}: {e}", parent.display())))?;
    }

    // Create a brand-new temp file, retrying with a fresh unique name only on a name collision so a
    // pre-existing stale temp can never be silently reused (which would defeat the 0600 guarantee).
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..16 {
        let tmp = temp_sibling(path);
        match write_new_private(&tmp, &json) {
            Ok(()) => {
                std::fs::rename(&tmp, path).map_err(|e| {
                    let _ = std::fs::remove_file(&tmp);
                    Error::Io(format!(
                        "renaming {} -> {}: {e}",
                        tmp.display(),
                        path.display()
                    ))
                })?;
                // fsync the parent directory so the rename (the new directory entry) is itself
                // durable; without this a crash after rename can still lose the update.
                sync_parent_dir(path).map_err(|e| {
                    Error::Io(format!("syncing parent dir of {}: {e}", path.display()))
                })?;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(Error::Io(format!("writing {}: {e}", tmp.display()))),
        }
    }
    Err(Error::Io(format!(
        "could not create a unique temp file next to {}: {}",
        path.display(),
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    )))
}

/// Read and parse metadata from `path`, rejecting an incompatible schema version. The returned
/// [`Metadata`] still needs [`from_metadata`] to become a loadable sealed object.
pub fn load(path: &Path) -> Result<Metadata> {
    let bytes =
        std::fs::read(path).map_err(|e| Error::Io(format!("reading {}: {e}", path.display())))?;
    let metadata: Metadata = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Metadata(format!("parsing {}: {e}", path.display())))?;
    metadata.validate_version()?;
    Ok(metadata)
}

fn decode(value: &str, field: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|e| Error::Metadata(format!("decoding base64 {field}: {e}")))
}

fn temp_sibling(path: &Path) -> std::path::PathBuf {
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
fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// fsync the directory containing `path` so a freshly created/renamed entry survives a crash. On
/// Unix a directory is fsync'd by opening it read-only and calling `sync_all` on the handle.
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
    use tess_core::METADATA_VERSION;

    #[test]
    fn decode_rejects_invalid_base64() {
        let err = decode("not valid base64!!!", "sealed_public").expect_err("must reject");
        assert!(matches!(err, Error::Metadata(_)));
    }

    #[test]
    fn from_metadata_rejects_bumped_version() {
        let mut metadata = Metadata::new(
            Policy::PinAuthValue,
            "AAAA".into(),
            "AAAA".into(),
            "AAAA".into(),
        );
        metadata.version = METADATA_VERSION + 1;
        assert!(matches!(
            from_metadata(&metadata),
            Err(Error::MetadataVersion { .. })
        ));
    }

    #[test]
    fn from_metadata_rejects_empty_primary_name() {
        // A current-version file missing primary_name must be rejected here as corrupt metadata —
        // not deferred to a misleading PrimaryNameMismatch at unseal. The empty-Name check runs
        // before unmarshalling, so the placeholder blobs never need to be valid.
        let metadata = Metadata::new(
            Policy::PinAuthValue,
            "AA".into(),
            "AA".into(),
            String::new(),
        );
        let err = from_metadata(&metadata).expect_err("empty primary_name must be rejected");
        assert!(
            matches!(err, Error::Metadata(_)),
            "expected a structured metadata error, got {err:?}"
        );
    }

    #[test]
    fn save_load_round_trips_metadata_json() {
        let dir = std::env::temp_dir().join(format!("tess-persist-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("metadata.json");

        let metadata = Metadata::new(
            Policy::PinAuthValue,
            STANDARD.encode([1u8, 2, 3, 4]),
            STANDARD.encode([5u8, 6, 7, 8]),
            STANDARD.encode([9u8, 10, 11, 12]),
        );
        save(&metadata, &path).expect("save");
        let loaded = load(&path).expect("load");

        assert_eq!(loaded.version, metadata.version);
        assert_eq!(loaded.policy, metadata.policy);
        assert_eq!(loaded.sealed_public, metadata.sealed_public);
        assert_eq!(loaded.sealed_private, metadata.sealed_private);
        assert_eq!(loaded.primary_name, metadata.primary_name);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_rejects_bumped_version_on_disk() {
        let dir =
            std::env::temp_dir().join(format!("tess-persist-ver-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("metadata.json");

        let mut metadata = Metadata::new(
            Policy::PinAuthValue,
            "AAAA".into(),
            "AAAA".into(),
            "AAAA".into(),
        );
        metadata.version = METADATA_VERSION + 1;
        let json = serde_json::to_vec_pretty(&metadata).unwrap();
        std::fs::write(&path, json).unwrap();

        assert!(matches!(load(&path), Err(Error::MetadataVersion { .. })));

        std::fs::remove_dir_all(&dir).ok();
    }
}
