//! The `tess` CLI: enrollment plus the post-enrollment lifecycle subcommands.

use clap::{Parser, Subcommand};

use std::path::PathBuf;

use tess_cli::{doctor, enroll, install, lifecycle};

/// tess — Windows-Hello-style unlocking for the Linux keyring.
#[derive(Parser)]
#[command(name = "tess", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll: seal a random key under a PIN and rekey the keyring in place (transactional).
    Enroll {
        /// PIN that gates the TPM-sealed key. Prompted without echo when omitted; prefer that —
        /// a PIN passed here is visible in the process list and may land in shell history.
        #[arg(long)]
        pin: Option<String>,
    },
    /// Re-unlock using the recovery secret; with `--reseal`, also re-seal under a new PIN.
    Recover {
        /// After restoring access, re-seal the keyring key under a new PIN against the current TPM
        /// (use after a TPM clear to restore the normal PIN-unlock path).
        #[arg(long)]
        reseal: bool,
        /// New PIN for `--reseal`. Prompted without echo when omitted; prefer that — a PIN passed
        /// here is visible in the process list and may land in shell history.
        #[arg(long, requires = "reseal")]
        pin: Option<String>,
    },
    /// Restore the password-based keyring (items preserved) and remove sealed blobs.
    Unenroll {
        /// PIN that gates the TPM-sealed key. Prompted without echo when omitted; prefer that —
        /// a PIN passed here is visible in the process list and may land in shell history.
        #[arg(long)]
        pin: Option<String>,
    },
    /// Show enrollment, keyring, and TPM state.
    Status,
    /// One-shot manual unlock.
    Unlock {
        /// PIN that gates the TPM-sealed key. Prompted without echo when omitted; prefer that —
        /// a PIN passed here is visible in the process list and may land in shell history.
        #[arg(long)]
        pin: Option<String>,
    },
    /// Dry-run the session unlock path (no changes) and report what would happen.
    Test,
    /// Check TPM / keyring / fprintd / enrollment readiness. Exits non-zero when not ready.
    Doctor {
        /// Post-install verification: also require a Secret Service daemon and a completed
        /// `tess enroll` (sealed metadata present and parseable), not just the TPM.
        #[arg(long)]
        post_install: bool,
    },
    /// Wire (or unwire) the PAM module into the system stack.
    Install {
        /// Remove the tess PAM wiring and module instead of installing them.
        #[arg(long)]
        uninstall: bool,
        /// `pam.d` service file to edit (default: the Debian session stack `/etc/pam.d/common-session`).
        #[arg(long)]
        service: Option<PathBuf>,
        /// Built `pam_tess.so` to install (default: resolved next to the `tess` binary).
        #[arg(long)]
        module: Option<PathBuf>,
        /// PAM module directory (default: auto-detected via `pam_permit.so`).
        #[arg(long)]
        module_dir: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Enroll { pin } => enroll::cli::run(pin)?,
        Command::Recover { reseal, pin } => lifecycle::cli::run_recover(reseal, pin)?,
        Command::Unenroll { pin } => lifecycle::cli::run_unenroll(pin)?,
        Command::Status => lifecycle::cli::run_status()?,
        Command::Unlock { pin } => lifecycle::cli::run_unlock(pin)?,
        Command::Test => lifecycle::cli::run_test()?,
        Command::Doctor { post_install } => {
            if !doctor::run(post_install) {
                // read-only probes have already dropped any TPM context; nothing live to unwind.
                std::process::exit(1);
            }
        }
        Command::Install {
            uninstall,
            service,
            module,
            module_dir,
        } => install::cli::run(install::cli::InstallArgs {
            uninstall,
            service,
            module,
            module_dir,
        })?,
    }
    Ok(())
}
