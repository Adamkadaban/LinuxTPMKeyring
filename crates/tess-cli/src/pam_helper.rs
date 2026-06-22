//! `tess-pam-helper` — the short-lived process the tess PAM module spawns (under a watchdog and a
//! hard deadline) to do the heavy session work off the PAM thread: read the PIN from stdin,
//! optionally run a bounded fingerprint front gate (`--fingerprint`), unseal the TPM-sealed key, and
//! unlock the login keyring. Exit `0` on a successful unlock, non-zero on any failure. The PIN and
//! the unsealed key never appear in argv, the environment, on disk, or in the output — only
//! secret-free error context is written to stderr for the journal.

use std::process::ExitCode;

fn main() -> ExitCode {
    // The PAM module appends `--fingerprint` when its `fingerprint=yes` argument enables the front
    // gate. Absent it, the helper runs the PIN-only path.
    let fingerprint = std::env::args().skip(1).any(|arg| arg == "--fingerprint");
    match tess_cli::session::run_pam_helper(fingerprint) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tess-pam-helper: {e:#}");
            ExitCode::FAILURE
        }
    }
}
