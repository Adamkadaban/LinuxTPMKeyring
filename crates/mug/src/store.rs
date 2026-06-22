//! Per-user face enrollment storage.
//!
//! Stores the IR **embedding** and liveness **calibration** — never a raw face image — under the
//! user's XDG data dir, file mode 0600, directory 0700. The in-memory representation is zeroized on
//! drop. Enrollment is non-destructive: saving a user's record replaces only that user's file and is
//! written atomically (temp + rename) so a crash mid-write can't corrupt an existing enrollment.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{MugError, Result};

/// On-disk schema version for a [`FaceEnrollment`].
pub const ENROLLMENT_VERSION: u32 = 1;

/// Liveness calibration captured at enroll time: the score the live enrollment produced and the
/// threshold to enforce at verify. Personalizing the threshold lets a user with a consistently lower
/// (but still clearly-live) score enroll without weakening the global floor for everyone.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct LivenessCalibration {
    /// Composite liveness score observed during enrollment.
    pub enrolled_score: f32,
    /// Score threshold to enforce at verify time (>= the global default).
    pub score_threshold: f32,
}

/// One user's face enrollment. The embedding is zeroized on drop; no raw image is ever persisted.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct FaceEnrollment {
    pub version: u32,
    /// Unix timestamp (seconds) of enrollment.
    pub created_unix: i64,
    /// L2-normalized IR face embedding.
    pub embedding: Vec<f32>,
    /// Maximum cosine distance accepted as a match.
    pub match_threshold: f32,
    /// Liveness calibration.
    pub liveness: LivenessCalibration,
}

impl FaceEnrollment {
    /// Build a fresh enrollment stamped with the current time and current schema version.
    pub fn new(embedding: Vec<f32>, match_threshold: f32, liveness: LivenessCalibration) -> Self {
        let created_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self {
            version: ENROLLMENT_VERSION,
            created_unix,
            embedding,
            match_threshold,
            liveness,
        }
    }

    fn validate_version(&self) -> Result<()> {
        if self.version != ENROLLMENT_VERSION {
            return Err(MugError::Store(format!(
                "unsupported enrollment version {} (expected {ENROLLMENT_VERSION})",
                self.version
            )));
        }
        Ok(())
    }
}

/// Filesystem-backed enrollment store, one JSON file per user under a 0700 directory.
pub struct EnrollStore {
    dir: PathBuf,
}

impl EnrollStore {
    /// Environment override for the store directory (used by tests; also lets an admin relocate it).
    pub const ENV_DIR: &'static str = "MUG_STORE_DIR";

    /// Store rooted at an explicit directory.
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Resolve the default store directory: [`EnrollStore::ENV_DIR`] if set, else
    /// `$XDG_DATA_HOME/mug` (falling back to `$HOME/.local/share/mug`).
    pub fn default_location() -> Result<Self> {
        if let Some(dir) = std::env::var_os(Self::ENV_DIR) {
            return Ok(Self::with_dir(PathBuf::from(dir)));
        }
        let base = if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            PathBuf::from(xdg)
        } else if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(".local").join("share")
        } else {
            return Err(MugError::Store(
                "cannot resolve store dir: neither MUG_STORE_DIR, XDG_DATA_HOME, nor HOME set"
                    .into(),
            ));
        };
        Ok(Self::with_dir(base.join("mug")))
    }

    fn user_path(&self, username: &str) -> Result<PathBuf> {
        // Defend the path join against separators / traversal in the username.
        if username.is_empty()
            || username.contains('/')
            || username.contains('\\')
            || username.contains("..")
        {
            return Err(MugError::Store(format!("invalid username: {username:?}")));
        }
        Ok(self.dir.join(format!("{username}.json")))
    }

    fn ensure_dir(&self) -> Result<()> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir)
                .map_err(|e| MugError::Store(format!("create {}: {e}", self.dir.display())))?;
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| MugError::Store(format!("chmod 700 {}: {e}", self.dir.display())))?;
        }
        Ok(())
    }

    /// Load a user's enrollment, or `None` if they are not enrolled.
    pub fn load(&self, username: &str) -> Result<Option<FaceEnrollment>> {
        let path = self.user_path(username)?;
        match fs::read(&path) {
            Ok(bytes) => {
                let enrollment: FaceEnrollment = serde_json::from_slice(&bytes)
                    .map_err(|e| MugError::Store(format!("parse {}: {e}", path.display())))?;
                enrollment.validate_version()?;
                Ok(Some(enrollment))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(MugError::Store(format!("read {}: {e}", path.display()))),
        }
    }

    /// Save a user's enrollment atomically with mode 0600. Replaces only this user's file.
    pub fn save(&self, username: &str, enrollment: &FaceEnrollment) -> Result<()> {
        enrollment.validate_version()?;
        self.ensure_dir()?;
        let path = self.user_path(username)?;
        let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));

        let mut json = serde_json::to_vec_pretty(enrollment)
            .map_err(|e| MugError::Store(format!("serialize enrollment: {e}")))?;

        let write_result = (|| -> std::io::Result<()> {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
            Ok(())
        })();
        // The serialized buffer held a copy of the embedding; wipe it regardless of outcome.
        json.zeroize();
        write_result.map_err(|e| MugError::Store(format!("write {}: {e}", tmp.display())))?;

        fs::rename(&tmp, &path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            MugError::Store(format!("rename into {}: {e}", path.display()))
        })?;
        Ok(())
    }

    /// Remove a user's enrollment. Returns `true` if a record existed.
    pub fn remove(&self, username: &str) -> Result<bool> {
        let path = self.user_path(username)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(MugError::Store(format!("remove {}: {e}", path.display()))),
        }
    }

    /// List enrolled usernames.
    pub fn list_users(&self) -> Result<Vec<String>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut users = Vec::new();
        let entries = fs::read_dir(&self.dir)
            .map_err(|e| MugError::Store(format!("read {}: {e}", self.dir.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| MugError::Store(format!("dir entry: {e}")))?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                if let Some(stem) = path.file_stem() {
                    users.push(stem.to_string_lossy().into_owned());
                }
            }
        }
        users.sort();
        Ok(users)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FaceEnrollment {
        FaceEnrollment::new(
            vec![0.5, 0.5, 0.5, 0.5],
            0.2,
            LivenessCalibration {
                enrolled_score: 0.7,
                score_threshold: 0.45,
            },
        )
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = EnrollStore::with_dir(dir.path());
        assert!(store.load("alice").unwrap().is_none());

        store.save("alice", &sample()).unwrap();
        let loaded = store.load("alice").unwrap().unwrap();
        assert_eq!(loaded.embedding, vec![0.5, 0.5, 0.5, 0.5]);
        assert_eq!(loaded.match_threshold, 0.2);
    }

    #[test]
    fn file_is_0600_and_dir_0700() {
        let dir = tempfile::tempdir().unwrap();
        let store = EnrollStore::with_dir(dir.path().join("mug"));
        store.save("bob", &sample()).unwrap();
        let file_mode = fs::metadata(store.dir().join("bob.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "enrollment file must be 0600");
        assert_eq!(dir_mode, 0o700, "store dir must be 0700");
    }

    #[test]
    fn save_is_non_destructive_to_other_users() {
        let dir = tempfile::tempdir().unwrap();
        let store = EnrollStore::with_dir(dir.path());
        store.save("alice", &sample()).unwrap();
        store.save("bob", &sample()).unwrap();
        // Re-saving bob must leave alice untouched.
        store.save("bob", &sample()).unwrap();
        assert!(store.load("alice").unwrap().is_some());
        let mut users = store.list_users().unwrap();
        users.sort();
        assert_eq!(users, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[test]
    fn remove_reports_existence() {
        let dir = tempfile::tempdir().unwrap();
        let store = EnrollStore::with_dir(dir.path());
        store.save("alice", &sample()).unwrap();
        assert!(store.remove("alice").unwrap());
        assert!(!store.remove("alice").unwrap());
    }

    #[test]
    fn rejects_path_traversal_username() {
        let dir = tempfile::tempdir().unwrap();
        let store = EnrollStore::with_dir(dir.path());
        assert!(store.save("../evil", &sample()).is_err());
        assert!(store.load("a/b").is_err());
    }

    #[test]
    fn default_location_honours_env() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY of test: set + read within this test only; value removed after.
        std::env::set_var(EnrollStore::ENV_DIR, dir.path());
        let store = EnrollStore::default_location().unwrap();
        assert_eq!(store.dir(), dir.path());
        std::env::remove_var(EnrollStore::ENV_DIR);
    }
}
