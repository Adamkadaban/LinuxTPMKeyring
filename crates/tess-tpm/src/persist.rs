//! Durable, secret-free persistence of a [`SealedObject`]. The sealed object's TPM2B public and
//! private blobs are base64-encoded into the versioned [`tess_core::Metadata`] schema and written as
//! JSON. Only public material and a policy descriptor ever reach disk — never the sealed key, a PIN,
//! or any hash of either; the blobs are useless without the TPM that created the primary and the PIN
//! that gates the object.

use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tess_core::{Error, Metadata, Policy, Result};
use tss_esapi::structures::{Private, Public};
use tss_esapi::traits::{Marshall, UnMarshall};

use crate::seal::SealedObject;

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
    ))
}

/// Reconstruct a sealed object from metadata: validate the schema version, base64-decode both blobs,
/// unmarshal the public area, and rebuild the private buffer. The result is ready to hand to
/// [`crate::unseal`] under the same TPM's primary.
pub fn from_metadata(metadata: &Metadata) -> Result<SealedObject> {
    metadata.validate_version()?;

    let public_bytes = decode(&metadata.sealed_public, "sealed_public")?;
    let private_bytes = decode(&metadata.sealed_private, "sealed_private")?;

    let public = Public::unmarshall(&public_bytes)
        .map_err(|e| Error::Tpm(format!("unmarshalling sealed public area: {e}")))?;
    let private = Private::try_from(private_bytes)
        .map_err(|e| Error::Tpm(format!("rebuilding sealed private blob: {e}")))?;

    Ok(SealedObject::from_blobs(public, private))
}

/// Serialize `metadata` to pretty JSON and write it to `path` atomically (write a sibling temp file,
/// then rename) so a crash mid-write can never leave a truncated, unparseable metadata file. The
/// file is created mode `0600`; it holds no secret, but enrollment metadata is not world-business.
pub fn save(metadata: &Metadata, path: &Path) -> Result<()> {
    let json = serde_json::to_vec_pretty(metadata)
        .map_err(|e| Error::Metadata(format!("serializing metadata: {e}")))?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Io(format!("creating {}: {e}", parent.display())))?;
        }
    }

    let tmp = temp_sibling(path);
    write_private(&tmp, &json).map_err(|e| Error::Io(format!("writing {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::Io(format!(
            "renaming {} -> {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(())
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
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
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
        let mut metadata = Metadata::new(Policy::PinAuthValue, "AAAA".into(), "AAAA".into());
        metadata.version = METADATA_VERSION + 1;
        assert!(matches!(
            from_metadata(&metadata),
            Err(Error::MetadataVersion { .. })
        ));
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
        );
        save(&metadata, &path).expect("save");
        let loaded = load(&path).expect("load");

        assert_eq!(loaded.version, metadata.version);
        assert_eq!(loaded.policy, metadata.policy);
        assert_eq!(loaded.sealed_public, metadata.sealed_public);
        assert_eq!(loaded.sealed_private, metadata.sealed_private);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_rejects_bumped_version_on_disk() {
        let dir =
            std::env::temp_dir().join(format!("tess-persist-ver-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("metadata.json");

        let mut metadata = Metadata::new(Policy::PinAuthValue, "AAAA".into(), "AAAA".into());
        metadata.version = METADATA_VERSION + 1;
        let json = serde_json::to_vec_pretty(&metadata).unwrap();
        std::fs::write(&path, json).unwrap();

        assert!(matches!(load(&path), Err(Error::MetadataVersion { .. })));

        std::fs::remove_dir_all(&dir).ok();
    }
}
