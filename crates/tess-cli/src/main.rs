//! The `tess` CLI. Enrollment is implemented; the remaining lifecycle subcommands are Phase 3
//! wave 2 (see `PLAN.md` §5).

use clap::{Parser, Subcommand};

use tess_cli::{doctor, enroll};

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
        /// PIN that gates the TPM-sealed key. Prompted without echo when omitted.
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
    Install,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Enroll { pin } => enroll::cli::run(pin)?,
        Command::Doctor => doctor::run(),
        Command::Status => println!("tess status: not yet implemented (Phase 3 wave 2)"),
        Command::Recover
        | Command::Unenroll
        | Command::Unlock
        | Command::Test
        | Command::Install => {
            println!("not yet implemented — see PLAN.md");
        }
    }
    Ok(())
}
