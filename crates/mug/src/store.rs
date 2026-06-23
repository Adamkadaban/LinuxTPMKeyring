//! Per-user face enrollment storage.
//!
//! Stores the IR **embedding** and liveness **calibration** — never a raw face image — under the
//! user's XDG data dir, file mode 0600, directory 0700. The in-memory representation is zeroized on
//! drop. Enrollment is non-destructive: saving a user's record replaces only that user's file and is
//! written atomically (temp + rename) so a crash mid-write can't corrupt an existing enrollment.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{MugError, Result};

/// Process-local sequence so back-to-back atomic writes get distinct temp names.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// On-disk schema version for a [`FaceEnrollment`].
pub const ENROLLMENT_VERSION: u32 = 1;

/// Liveness calibration captured at enroll time: the score the live enrollment produced and the
/// threshold to enforce at verify. Personalizing the threshold lets a user with a consistently lower
/// (but still clearly-live) score enroll without weakening the global floor for everyone.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub struct LivenessCalibration {
    /// Composite liveness score observed during enrollment.
    pub enrolled_score: f32,
    /// Score threshold to enforce at verify time. Read back verbatim from disk; range validation and
    /// clamping against the global floor is a wave-2 concern, so no invariant is asserted here.
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
        if let Some(dir) = std::env::var_os(Self::ENV_DIR)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            return Ok(Self::with_dir(dir));
        }
        // Ignore a relative/empty XDG_DATA_HOME (per the XDG spec) so enrollment never lands in a
        // surprising CWD-relative location; fall through to $HOME, then error.
        let base = if let Some(xdg) = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            xdg
        } else if let Some(home) = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            home.join(".local").join("share")
        } else {
            return Err(MugError::Store(
                "cannot resolve store dir: set MUG_STORE_DIR or an absolute XDG_DATA_HOME/HOME"
                    .into(),
            ));
        };
        Ok(Self::with_dir(base.join("mug")))
    }

    fn user_path(&self, username: &str) -> Result<PathBuf> {
        // Let the path parser validate the username instead of substring-matching: require it to be
        // exactly one *Normal* path component. That rejects separators, "", ".", "..", absolute
        // paths and OS prefixes, while accepting legitimate names like "a..b". The single-component
        // name then joins inside the store dir with no traversal.
        let mut components = Path::new(username).components();
        let single_normal = matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(c)), None) if c == std::ffi::OsStr::new(username)
        );
        if !single_normal {
            return Err(MugError::Store(format!("invalid username: {username:?}")));
        }
        Ok(self.dir.join(format!("{username}.json")))
    }

    fn ensure_dir(&self) -> Result<()> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir)
                .map_err(|e| MugError::Store(format!("create {}: {e}", self.dir.display())))?;
        }
        let meta = fs::metadata(&self.dir)
            .map_err(|e| MugError::Store(format!("stat {}: {e}", self.dir.display())))?;
        if !meta.is_dir() {
            return Err(MugError::Store(format!(
                "{} exists but is not a directory",
                self.dir.display()
            )));
        }
        // Enforce 0700 every time, not only on create: a pre-existing dir may carry loose perms.
        if meta.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| MugError::Store(format!("chmod 700 {}: {e}", self.dir.display())))?;
        }
        Ok(())
    }

    /// Whether `username` has an enrollment on disk, without creating or chmod-ing the store dir.
    /// For read-only probes (e.g. status) that must not mutate the filesystem; prefer [`load`] when
    /// the template contents are needed.
    pub fn is_enrolled(&self, username: &str) -> Result<bool> {
        Ok(self.user_path(username)?.is_file())
    }

    /// Load a user's enrollment, or `None` if they are not enrolled.
    pub fn load(&self, username: &str) -> Result<Option<FaceEnrollment>> {
        self.ensure_dir()?;
        let path = self.user_path(username)?;
        match fs::read(&path) {
            Ok(mut bytes) => {
                let parsed = serde_json::from_slice::<FaceEnrollment>(&bytes)
                    .map_err(|e| MugError::Store(format!("parse {}: {e}", path.display())));
                // The buffer holds the plaintext embedding/calibration — wipe it before returning
                // (on the parse-error path too), matching save's zeroize.
                bytes.zeroize();
                let enrollment = parsed?;
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
        let tmp = temp_sibling(&path);

        let mut json = serde_json::to_vec_pretty(enrollment)
            .map_err(|e| MugError::Store(format!("serialize enrollment: {e}")))?;

        // The serialized buffer holds a plaintext copy of the embedding. Write it durably, then wipe
        // it regardless of outcome; on any write/fsync/rename failure remove the temp so no partial
        // file containing the embedding is left behind.
        let write_result = write_private(&tmp, &json);
        json.zeroize();
        write_result.map_err(|e| {
            let _ = fs::remove_file(&tmp);
            MugError::Store(format!("write {}: {e}", tmp.display()))
        })?;

        fs::rename(&tmp, &path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            MugError::Store(format!("rename into {}: {e}", path.display()))
        })?;

        // fsync the parent dir so the renamed entry itself survives a crash, not just its contents.
        sync_parent_dir(&path)
            .map_err(|e| MugError::Store(format!("sync parent dir of {}: {e}", path.display())))?;
        Ok(())
    }

    /// Remove a user's enrollment. Returns `true` if a record existed.
    pub fn remove(&self, username: &str) -> Result<bool> {
        self.ensure_dir()?;
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
        self.ensure_dir()?;
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

/// Build a unique sibling temp path so back-to-back writes never collide and an attacker cannot
/// pre-create a predictable temp name (the `O_EXCL` open in [`write_private`] would reject a
/// pre-existing or symlinked path anyway).
fn temp_sibling(path: &Path) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{seq}.{nanos}", std::process::id()));
    path.with_file_name(name)
}

/// Create `path` with `O_EXCL` (mode 0600), write `bytes`, and fsync the file. `create_new` fails if
/// the path already exists or is a symlink, eliminating the clobber/symlink risk of a reused temp.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// fsync the directory containing `path` so a freshly renamed entry survives a crash. On Unix a
/// directory is fsync'd by opening it read-only and calling `sync_all` on the handle.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    fs::File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// Saves a process-global env var and restores its prior value (or unsets it) on drop, including
    /// on panic, so the override never leaks into other tests in the same process.
    struct EnvGuard {
        key: &'static str,
        prev: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &Path) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

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
    fn user_path_validation_accepts_normal_rejects_traversal() {
        let store = EnrollStore::with_dir("/tmp/mug-test");
        // Legitimate names, including embedded dots, are accepted.
        for ok in ["alice", "a..b", "a.b", "user_1", "café"] {
            assert!(store.user_path(ok).is_ok(), "{ok:?} should be valid");
        }
        // Separators, traversal, current/parent dir, empty, and absolute paths are rejected.
        for bad in ["", ".", "..", "a/b", "../etc", "/abs"] {
            assert!(store.user_path(bad).is_err(), "{bad:?} should be rejected");
        }
        // A valid name stays inside the store dir.
        assert_eq!(
            store.user_path("alice").unwrap(),
            Path::new("/tmp/mug-test/alice.json")
        );
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
        let _guard = EnvGuard::set(EnrollStore::ENV_DIR, dir.path());
        let store = EnrollStore::default_location().unwrap();
        assert_eq!(store.dir(), dir.path());
    }
}
