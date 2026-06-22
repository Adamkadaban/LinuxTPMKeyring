//! Wiring for `tess install` / `tess install --uninstall`: resolve the service file, the PAM module
//! directory, and the built module, then run the idempotent install/uninstall and print a summary.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

use super::{config, detect_module_dir, install, uninstall, InstallPlan, DEFAULT_SERVICE_FILE};

/// Parsed `install` subcommand options.
#[derive(Debug, Clone, Default)]
pub struct InstallArgs {
    /// Remove the tess wiring instead of adding it.
    pub uninstall: bool,
    /// `pam.d` service file to edit (default: the Debian session stack).
    pub service: Option<PathBuf>,
    /// Built `pam_tess.so` to install (default: resolved next to the `tess` binary).
    pub module: Option<PathBuf>,
    /// PAM module directory (default: auto-detected via `pam_permit.so`).
    pub module_dir: Option<PathBuf>,
}

/// Run the `install` subcommand.
pub fn run(args: InstallArgs) -> Result<()> {
    let service_file = args
        .service
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SERVICE_FILE));

    if args.uninstall {
        // Unwiring the stack and removing the backup do not require the module directory; detect it
        // best-effort so a detection failure in a restricted environment still unwires the stack
        // (the lockout-relevant part). An empty module dir tells `uninstall` to skip module removal.
        let module_dir = match resolve_module_dir(args.module_dir) {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!(
                    "warning: could not detect the PAM module directory ({e}); the session stack \
                     will still be unwired, but an installed pam_tess.so (if any) is left in place."
                );
                PathBuf::new()
            }
        };
        let plan = InstallPlan {
            service_file,
            module_src: PathBuf::new(),
            module_dir,
        };
        let report = uninstall(&plan)?;
        println!("tess uninstall:");
        println!(
            "  service stack {}: {}",
            report.service_file.display(),
            if report.removed_block {
                "tess block removed (original restored)"
            } else {
                "no tess block present"
            }
        );
        if plan.module_dir.as_os_str().is_empty() {
            println!("  module: not removed (module directory undetected)");
        } else {
            println!(
                "  module {}: {}",
                plan.installed_module().display(),
                if report.removed_module {
                    "removed"
                } else {
                    "absent"
                }
            );
        }
        let backup = plan.backup_file();
        let backup_status = if report.removed_backup {
            "removed"
        } else if backup.exists() {
            "kept (no tess block was removed, so the rollback backup is preserved)"
        } else {
            "absent"
        };
        println!("  backup {}: {}", backup.display(), backup_status);
        return Ok(());
    }

    let module_dir = resolve_module_dir(args.module_dir)?;
    let module_src = match args.module {
        Some(p) => p,
        None => default_module_src()?,
    };
    let plan = InstallPlan {
        service_file,
        module_src,
        module_dir,
    };
    let report = install(&plan)?;
    println!("tess install:");
    println!("  module installed: {}", report.installed_module.display());
    println!(
        "  session stack {}: {}",
        report.service_file.display(),
        if report.already_wired {
            "already wired (refreshed, no duplicate)"
        } else {
            "tess block added (fail-open: session optional)"
        }
    );
    println!("  backup: {}", report.backup_file.display());
    println!();
    println!(
        "The login keyring will be unlocked at session open once `tess enroll` has sealed a key. \
         The `{}` line is optional/fail-open — a tess failure never blocks login.",
        config::SNIPPET_LINE
    );
    Ok(())
}

/// Resolve the PAM module directory: an explicit override, else auto-detect.
fn resolve_module_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    match explicit {
        Some(dir) => Ok(dir),
        None => detect_module_dir(),
    }
}

/// Locate the built `pam_tess.so` next to the running `tess` binary, trying both the cdylib's
/// on-disk name (`libpam_tess.so`) and the installed name (`pam_tess.so`).
fn default_module_src() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("locate the running tess binary")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("the tess binary has no parent directory"))?;
    for candidate in ["libpam_tess.so", config::MODULE_FILE] {
        let path = dir.join(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(anyhow!(
        "could not find libpam_tess.so or {} next to {}; build it (`cargo build -p tess-pam`) and \
         pass --module <path>",
        config::MODULE_FILE,
        dir.display()
    ))
}
