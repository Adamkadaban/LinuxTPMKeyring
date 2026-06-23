//! `tess-pam-helper` — the short-lived process the tess PAM module spawns (under a watchdog and a
//! hard deadline) to do the heavy session work off the PAM thread: optionally attempt a bounded face
//! release (`--face`) and/or fingerprint front gate (`--fingerprint`), read the PIN from stdin,
//! unseal the TPM-sealed key, and unlock the login keyring. Exit `0` on a successful unlock, non-zero
//! on any failure. The PIN and the unsealed key never appear in argv, the environment, on disk, or in
//! the output — only secret-free error context is written to stderr for the journal.

use std::process::ExitCode;

fn main() -> ExitCode {
    // The PAM module appends `--fingerprint` / `--face` when its `fingerprint=yes` / `face=yes`
    // arguments enable those legs. Absent both, the helper runs the PIN-only path. Scan argv once
    // rather than allocating a Vec — this is the login-time path.
    let mut fingerprint = false;
    let mut face = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--fingerprint" => fingerprint = true,
            "--face" => face = true,
            _ => {}
        }
    }
    match tess_cli::session::run_pam_helper(fingerprint, face) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tess-pam-helper: {e:#}");
            ExitCode::FAILURE
        }
    }
}
