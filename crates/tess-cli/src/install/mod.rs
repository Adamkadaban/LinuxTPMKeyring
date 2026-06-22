//! Filesystem orchestration for `tess install` / `tess install --uninstall`.
//!
//! This wires `pam_tess.so` into a `pam.d` service stack and installs the module into the system
//! PAM module directory, idempotently and fail-safe. The string-only edit and validation logic lives
//! in [`config`]; this module adds the side effects: detect the module directory, back up the
//! original service file *before* editing, validate the candidate stack, write it atomically, and
//! copy the module. Uninstall reverses all of it and is safe to run when nothing is installed.
//!
//! Safety posture: the edit is only committed after [`config::validate_stack`] confirms the result
//! is well-formed and the tess line is fail-open. If validation fails the original file is left
//! untouched (it is never the partially-written temp), and a backup always exists to restore from.

pub mod cli;
pub mod config;

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

/// Default Debian 13 session stack tess wires into. Other login services include this file.
pub const DEFAULT_SERVICE_FILE: &str = "/etc/pam.d/common-session";

/// Suffix of the one-time backup tess writes before its first edit of a service file.
const BACKUP_SUFFIX: &str = ".tess-backup";

/// Roots searched for the PAM module directory, mirroring the CI smoke test's `find /lib /usr/lib`.
const PAM_SEARCH_ROOTS: [&str; 4] = ["/lib", "/usr/lib", "/lib64", "/usr/lib64"];

/// Bound on the module-directory search depth so a pathological symlink farm can't make detection
/// run unbounded.
const PAM_SEARCH_MAX_DEPTH: usize = 6;

/// Where the install acts: the service file to edit, the built module to install, and the PAM module
/// directory to install it into. Constructed explicitly so tests drive it entirely within a temp
/// directory and never touch the host's real `/etc/pam.d` or module directory.
#[derive(Debug, Clone)]
pub struct InstallPlan {
    pub service_file: PathBuf,
    pub module_src: PathBuf,
    pub module_dir: PathBuf,
}

impl InstallPlan {
    /// Path of the `pam_tess.so` once installed into the module directory.
    pub fn installed_module(&self) -> PathBuf {
        self.module_dir.join(config::MODULE_FILE)
    }

    /// Path of the one-time backup of the service file.
    pub fn backup_file(&self) -> PathBuf {
        backup_path(&self.service_file)
    }
}

/// What `install` did, for a clear user-facing summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub service_file: PathBuf,
    pub installed_module: PathBuf,
    pub backup_file: PathBuf,
    /// True if the stack already contained the tess block before this run (re-run / no-op edit).
    pub already_wired: bool,
}

/// What `uninstall` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallReport {
    pub service_file: PathBuf,
    pub removed_block: bool,
    pub removed_module: bool,
    pub removed_backup: bool,
}

/// Wire `pam_tess.so` into the service stack and install the module, idempotently.
///
/// Order: back up the original service file (once) → compute the edited stack → **validate it before
/// writing** → write atomically → install the module. Re-running is a no-op edit (the block is
/// refreshed in place, never duplicated) and refreshes the module.
pub fn install(plan: &InstallPlan) -> Result<InstallReport> {
    let original = fs::read_to_string(&plan.service_file).with_context(|| {
        format!(
            "read PAM service file {} (does it exist? run as root)",
            plan.service_file.display()
        )
    })?;

    let already_wired = config::has_block(&original);

    let backup = plan.backup_file();
    if !backup.exists() {
        fs::copy(&plan.service_file, &backup).with_context(|| {
            format!(
                "back up {} to {} before editing",
                plan.service_file.display(),
                backup.display()
            )
        })?;
    }

    let edited = config::add_block(&original);
    config::validate_stack(&edited).with_context(|| {
        format!(
            "refusing to write {}: candidate PAM stack failed the fail-open safety check",
            plan.service_file.display()
        )
    })?;

    atomic_write_preserving_mode(&plan.service_file, &edited)
        .with_context(|| format!("write edited PAM stack to {}", plan.service_file.display()))?;

    install_module(plan)?;

    Ok(InstallReport {
        service_file: plan.service_file.clone(),
        installed_module: plan.installed_module(),
        backup_file: backup,
        already_wired,
    })
}

/// Remove the tess block from the service stack, delete the installed module, and remove the backup.
///
/// Idempotent and safe when tess is not installed: a missing service file, an already-clean stack,
/// an absent module, and an absent backup are all no-ops. The stack edit is validated before being
/// written, exactly as on install.
pub fn uninstall(plan: &InstallPlan) -> Result<UninstallReport> {
    let mut removed_block = false;
    match fs::read_to_string(&plan.service_file) {
        Ok(original) => {
            if config::has_block(&original) {
                let restored = config::remove_block(&original);
                config::validate_stack(&restored).with_context(|| {
                    format!(
                        "refusing to write {}: stack after removing the tess block failed validation",
                        plan.service_file.display()
                    )
                })?;
                atomic_write_preserving_mode(&plan.service_file, &restored).with_context(|| {
                    format!("restore PAM stack in {}", plan.service_file.display())
                })?;
                removed_block = true;
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e)
                .with_context(|| format!("read PAM service file {}", plan.service_file.display()));
        }
    }

    let installed = plan.installed_module();
    let removed_module = remove_if_exists(&installed)
        .with_context(|| format!("remove installed module {}", installed.display()))?;

    let backup = plan.backup_file();
    let removed_backup =
        remove_if_exists(&backup).with_context(|| format!("remove backup {}", backup.display()))?;

    Ok(UninstallReport {
        service_file: plan.service_file.clone(),
        removed_block,
        removed_module,
        removed_backup,
    })
}

/// Copy the built module into the PAM module directory as `pam_tess.so` with mode 0644.
fn install_module(plan: &InstallPlan) -> Result<()> {
    if !plan.module_src.is_file() {
        bail!(
            "PAM module source {} not found; build it (`cargo build -p tess-pam`) or pass --module",
            plan.module_src.display()
        );
    }
    if !plan.module_dir.is_dir() {
        bail!(
            "PAM module directory {} does not exist",
            plan.module_dir.display()
        );
    }
    let dst = plan.installed_module();
    fs::copy(&plan.module_src, &dst).with_context(|| {
        format!(
            "install module {} -> {}",
            plan.module_src.display(),
            dst.display()
        )
    })?;
    fs::set_permissions(&dst, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("set mode on {}", dst.display()))?;
    Ok(())
}

/// Backup path for a service file: the file with [`BACKUP_SUFFIX`] appended.
fn backup_path(service_file: &Path) -> PathBuf {
    let mut name = service_file.as_os_str().to_os_string();
    name.push(BACKUP_SUFFIX);
    PathBuf::from(name)
}

/// Remove `path` if present, returning whether it existed. A missing file is not an error.
fn remove_if_exists(path: &Path) -> io::Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Write `content` to `path` atomically (temp file in the same directory, then rename), preserving
/// the existing file's permission bits. The rename is atomic on the same filesystem, so a crash
/// mid-write never leaves a truncated PAM stack — readers see either the old or the new file whole.
fn atomic_write_preserving_mode(path: &Path, content: &str) -> Result<()> {
    // Guard against a path with no parent (e.g. a bare root); the temp sibling below relies on one.
    path.parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    let mode = fs::metadata(path).map(|m| m.permissions().mode()).ok();

    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tess-tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);

    let write_result = (|| -> Result<()> {
        fs::write(&tmp, content)?;
        if let Some(mode) = mode {
            fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

/// Detect the system PAM module directory by locating a stock module (`pam_permit.so`) under the
/// well-known library roots and taking its parent — the same approach as the CI smoke test, so it
/// works across multiarch layouts. Errors if no module directory is found.
pub fn detect_module_dir() -> Result<PathBuf> {
    for root in PAM_SEARCH_ROOTS {
        let root = Path::new(root);
        if !root.is_dir() {
            continue;
        }
        if let Some(dir) = find_module_dir(root, "pam_permit.so", PAM_SEARCH_MAX_DEPTH) {
            return Ok(dir);
        }
    }
    Err(anyhow!(
        "could not locate the PAM module directory (no pam_permit.so under {})",
        PAM_SEARCH_ROOTS.join(", ")
    ))
}

/// Bounded breadth-first search for a file named `needle` beneath `root`, returning its parent
/// directory. Does not follow into symlinked directories, so a symlink loop can't trap the walk.
fn find_module_dir(root: &Path, needle: &str, max_depth: usize) -> Option<PathBuf> {
    let mut frontier = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = frontier.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_file() && entry.file_name() == needle {
                return Some(dir);
            }
            if file_type.is_dir() && depth < max_depth {
                frontier.push((path, depth + 1));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `InstallPlan` wholly inside `root` (a tempdir): a fixture service file, a dummy
    /// module source, and a module directory. Nothing here touches the host's real PAM paths.
    fn plan_in(root: &Path, service_contents: &str) -> InstallPlan {
        let service_file = root.join("common-session");
        fs::write(&service_file, service_contents).unwrap();
        let module_src = root.join("libpam_tess.so");
        fs::write(&module_src, b"\x7fELF-not-really").unwrap();
        let module_dir = root.join("security");
        fs::create_dir_all(&module_dir).unwrap();
        InstallPlan {
            service_file,
            module_src,
            module_dir,
        }
    }

    const FIXTURE: &str = "\
session [default=1] pam_permit.so
session required     pam_unix.so
session optional     pam_gnome_keyring.so auto_start
";

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tess-install-test-{}-{}",
            std::process::id(),
            // A monotonic-ish discriminator so parallel tests don't collide.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn install_then_uninstall_restores_byte_for_byte() {
        let root = tempdir();
        let plan = plan_in(&root, FIXTURE);

        let report = install(&plan).unwrap();
        assert!(!report.already_wired);
        let after_install = fs::read_to_string(&plan.service_file).unwrap();
        assert!(after_install.contains(config::SNIPPET_LINE));
        assert!(plan.installed_module().is_file());
        assert!(plan.backup_file().is_file());
        // The backup is the true original.
        assert_eq!(fs::read_to_string(plan.backup_file()).unwrap(), FIXTURE);

        let un = uninstall(&plan).unwrap();
        assert!(un.removed_block && un.removed_module && un.removed_backup);
        // The service file is restored to the exact original bytes.
        assert_eq!(fs::read_to_string(&plan.service_file).unwrap(), FIXTURE);
        assert!(!plan.installed_module().exists());
        assert!(!plan.backup_file().exists());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn install_is_idempotent() {
        let root = tempdir();
        let plan = plan_in(&root, FIXTURE);

        install(&plan).unwrap();
        let once = fs::read_to_string(&plan.service_file).unwrap();
        let second = install(&plan).unwrap();
        let twice = fs::read_to_string(&plan.service_file).unwrap();

        assert!(
            second.already_wired,
            "second run sees the block already present"
        );
        assert_eq!(once, twice, "re-running install must not change the file");
        assert_eq!(twice.matches(config::BEGIN_MARKER).count(), 1);
        assert_eq!(twice.matches(config::SNIPPET_LINE).count(), 1);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn backup_preserves_true_original_across_reinstall() {
        let root = tempdir();
        let plan = plan_in(&root, FIXTURE);

        install(&plan).unwrap();
        // A second install must not overwrite the backup with the already-edited file.
        install(&plan).unwrap();
        assert_eq!(fs::read_to_string(plan.backup_file()).unwrap(), FIXTURE);

        uninstall(&plan).unwrap();
        assert_eq!(fs::read_to_string(&plan.service_file).unwrap(), FIXTURE);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn uninstall_is_safe_when_not_installed() {
        let root = tempdir();
        let plan = plan_in(&root, FIXTURE);

        let report = uninstall(&plan).unwrap();
        assert!(!report.removed_block && !report.removed_module && !report.removed_backup);
        // The file is untouched.
        assert_eq!(fs::read_to_string(&plan.service_file).unwrap(), FIXTURE);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn uninstall_missing_service_file_is_ok() {
        let root = tempdir();
        let plan = plan_in(&root, FIXTURE);
        fs::remove_file(&plan.service_file).unwrap();

        let report = uninstall(&plan).unwrap();
        assert!(!report.removed_block);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn install_preserves_file_mode() {
        let root = tempdir();
        let plan = plan_in(&root, FIXTURE);
        fs::set_permissions(&plan.service_file, fs::Permissions::from_mode(0o600)).unwrap();

        install(&plan).unwrap();
        let mode = fs::metadata(&plan.service_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "atomic write must preserve the original mode");

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn install_aborts_and_preserves_file_when_module_src_missing() {
        let root = tempdir();
        let plan = plan_in(&root, FIXTURE);
        fs::remove_file(&plan.module_src).unwrap();

        // The stack edit + validation succeed, but installing the module fails; the edit has been
        // written (it is safe and fail-open) yet no module exists, so a later session is a no-op.
        let err = install(&plan).unwrap_err();
        assert!(err.to_string().contains("module source"));
        assert!(!plan.installed_module().exists());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn find_module_dir_locates_needle() {
        let root = tempdir();
        let nested = root.join("x86_64-linux-gnu").join("security");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("pam_permit.so"), b"x").unwrap();

        let found = find_module_dir(&root, "pam_permit.so", PAM_SEARCH_MAX_DEPTH).unwrap();
        assert_eq!(found, nested);
        assert!(find_module_dir(&root, "pam_absent.so", PAM_SEARCH_MAX_DEPTH).is_none());

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn backup_path_appends_suffix() {
        assert_eq!(
            backup_path(Path::new("/etc/pam.d/common-session")),
            PathBuf::from("/etc/pam.d/common-session.tess-backup")
        );
    }
}
