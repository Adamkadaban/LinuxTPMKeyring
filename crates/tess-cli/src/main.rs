//! The `tess` CLI. Enrollment is implemented; the remaining lifecycle subcommands land in a later
//! phase.

use clap::{Parser, Subcommand};

use std::path::PathBuf;

use tess_cli::{doctor, enroll, install};

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
    /// Re-unlock / re-enroll using the recovery secret.
    Recover,
    /// Restore the password-based keyring (items preserved) and remove sealed blobs.
    Unenroll,
    /// Show enrollment, keyring, and TPM state.
    Status,
    /// One-shot manual unlock.
    Unlock,
    /// Dry-run the session unlock path.
    Test,
    /// Check TPM / keyring / fprintd readiness.
    Doctor,
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
        Command::Doctor => doctor::run(),
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
        Command::Status => println!("tess status: not yet implemented"),
        Command::Recover | Command::Unenroll | Command::Unlock | Command::Test => {
            println!("not yet implemented");
        }
    }
    Ok(())
}
