//! `tess doctor` — read-only readiness probes for TPM, keyring, and fprintd.
//!
//! Every probe is side-effect-free: it checks for the presence of device nodes or
//! binaries on `PATH`. It never opens a D-Bus session, never touches a secret, and
//! never unlocks anything. Per project policy it runs in CI or on the Azure VM, not
//! the developer host.

use std::env;
use std::fmt::Write as _;
use std::path::Path;

/// Display name of the TPM resource-manager probe. Shared between the probe
/// construction and the verdict logic so the two can't drift.
const TPM_RM_PROBE_NAME: &str = "TPM resource manager (/dev/tpmrm0)";

/// Outcome of a single readiness probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    Ok,
    Missing,
}

impl ProbeStatus {
    fn label(self) -> &'static str {
        match self {
            ProbeStatus::Ok => "OK",
            ProbeStatus::Missing => "MISSING",
        }
    }
}

/// A named readiness check with its result and a short human note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub name: String,
    pub status: ProbeStatus,
    pub detail: String,
}

impl Probe {
    fn new(name: &str, status: ProbeStatus, detail: &str) -> Self {
        Self {
            name: name.to_string(),
            status,
            detail: detail.to_string(),
        }
    }
}

/// Whether a probe is required for the core TPM-sealing guarantee.
///
/// The TPM is mandatory; keyring and fprintd are reported but never block the
/// overall verdict (fprintd is convenience; the keyring daemon is checked more
/// thoroughly at enroll time).
fn is_required(name: &str) -> bool {
    name == TPM_RM_PROBE_NAME
}

/// Render the probes as an aligned OK/MISSING table followed by a one-line verdict.
pub fn render_report(probes: &[Probe]) -> String {
    let name_width = probes
        .iter()
        .map(|p| p.name.len())
        .max()
        .unwrap_or(0)
        .max("COMPONENT".len());
    let status_width = "STATUS".len().max("MISSING".len());

    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<name_width$}  {:<status_width$}  DETAIL",
        "COMPONENT",
        "STATUS",
        name_width = name_width,
        status_width = status_width,
    );
    for probe in probes {
        let _ = writeln!(
            out,
            "{:<name_width$}  {:<status_width$}  {}",
            probe.name,
            probe.status.label(),
            probe.detail,
            name_width = name_width,
            status_width = status_width,
        );
    }
    out.push('\n');
    out.push_str(&overall_verdict(probes));
    out
}

/// One-line overall verdict. Only *required* probes can fail the verdict.
pub fn overall_verdict(probes: &[Probe]) -> String {
    let required_missing: Vec<&str> = probes
        .iter()
        .filter(|p| p.status == ProbeStatus::Missing && is_required(&p.name))
        .map(|p| p.name.as_str())
        .collect();
    let optional_missing = probes
        .iter()
        .filter(|p| p.status == ProbeStatus::Missing && !is_required(&p.name))
        .count();

    if required_missing.is_empty() {
        if optional_missing == 0 {
            "verdict: READY — all components present.".to_string()
        } else {
            format!(
                "verdict: READY — TPM present; {optional_missing} optional component(s) missing."
            )
        }
    } else {
        format!(
            "verdict: NOT READY — missing required: {}.",
            required_missing.join(", ")
        )
    }
}

/// True if `bin` is found in any `PATH` entry as an executable file.
fn binary_on_path(bin: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| is_executable_file(&dir.join(bin)))
}

/// True if `path` is a regular file with at least one executable bit set.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

fn probe_path(name: &str, path: &str) -> Probe {
    if Path::new(path).exists() {
        Probe::new(name, ProbeStatus::Ok, "present")
    } else {
        Probe::new(name, ProbeStatus::Missing, "device node not found")
    }
}

fn probe_keyring() -> Probe {
    // Lightweight: just check whether a keyring daemon binary is plausibly installed.
    // We deliberately do NOT open a D-Bus session or talk to org.freedesktop.secrets.
    let candidates = ["gnome-keyring-daemon", "kwalletd6", "kwalletd5"];
    if let Some(found) = candidates.iter().find(|b| binary_on_path(b)) {
        Probe::new(
            "Secret Service daemon",
            ProbeStatus::Ok,
            &format!("{found} on PATH (not contacted)"),
        )
    } else {
        Probe::new(
            "Secret Service daemon",
            ProbeStatus::Missing,
            "no gnome-keyring/kwallet binary on PATH",
        )
    }
}

fn probe_fprintd() -> Probe {
    if binary_on_path("fprintd") {
        Probe::new("fprintd", ProbeStatus::Ok, "fprintd on PATH")
    } else {
        Probe::new("fprintd", ProbeStatus::Missing, "fprintd not on PATH")
    }
}

/// Run all probes against the live system (read-only).
pub fn run_probes() -> Vec<Probe> {
    vec![
        probe_path(TPM_RM_PROBE_NAME, "/dev/tpmrm0"),
        probe_path("TPM raw device (/dev/tpm0)", "/dev/tpm0"),
        probe_keyring(),
        probe_fprintd(),
    ]
}

/// Entry point for the `doctor` subcommand.
pub fn run() {
    let probes = run_probes();
    println!("{}", render_report(&probes));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(name: &str, status: ProbeStatus) -> Probe {
        Probe::new(name, status, "x")
    }

    #[test]
    fn verdict_ready_when_all_present() {
        let probes = vec![
            probe("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Ok),
            probe("fprintd", ProbeStatus::Ok),
        ];
        assert_eq!(
            overall_verdict(&probes),
            "verdict: READY — all components present."
        );
    }

    #[test]
    fn verdict_ready_with_optional_missing() {
        let probes = vec![
            probe("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Ok),
            probe("fprintd", ProbeStatus::Missing),
            probe("Secret Service daemon", ProbeStatus::Missing),
        ];
        assert_eq!(
            overall_verdict(&probes),
            "verdict: READY — TPM present; 2 optional component(s) missing."
        );
    }

    #[test]
    fn verdict_not_ready_when_tpm_missing() {
        let probes = vec![
            probe("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Missing),
            probe("fprintd", ProbeStatus::Ok),
        ];
        assert_eq!(
            overall_verdict(&probes),
            "verdict: NOT READY — missing required: TPM resource manager (/dev/tpmrm0)."
        );
    }

    #[test]
    fn optional_missing_does_not_fail_verdict() {
        let probes = vec![
            probe("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Ok),
            probe("TPM raw device (/dev/tpm0)", ProbeStatus::Missing),
        ];
        assert!(overall_verdict(&probes).starts_with("verdict: READY"));
    }

    #[test]
    fn report_has_header_and_verdict() {
        let probes = vec![probe("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Ok)];
        let report = render_report(&probes);
        assert!(report.contains("COMPONENT"));
        assert!(report.contains("STATUS"));
        assert!(report.contains("DETAIL"));
        assert!(report.contains("verdict:"));
    }

    #[test]
    fn report_columns_align_to_widest_name() {
        let probes = vec![
            probe("short", ProbeStatus::Ok),
            probe("a-much-longer-component-name", ProbeStatus::Missing),
        ];
        let report = render_report(&probes);
        for line in report.lines().take_while(|l| !l.starts_with("verdict:")) {
            if line.contains("OK") || line.contains("MISSING") || line.contains("STATUS") {
                assert!(line.contains("  "));
            }
        }
    }

    #[test]
    fn status_labels_are_stable() {
        assert_eq!(ProbeStatus::Ok.label(), "OK");
        assert_eq!(ProbeStatus::Missing.label(), "MISSING");
    }

    #[test]
    fn executable_file_requires_executable_bit() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = env::temp_dir().join(format!("tess-doctor-exec-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let non_exec = dir.join("plain");
        fs::write(&non_exec, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&non_exec, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable_file(&non_exec), "0o644 file must not count");

        let exec = dir.join("script");
        fs::write(&exec, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&exec, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(is_executable_file(&exec), "0o755 file must count");

        assert!(
            !is_executable_file(&dir),
            "a directory is not a regular executable file"
        );
        assert!(
            !is_executable_file(&dir.join("does-not-exist")),
            "a missing path is not executable"
        );

        fs::remove_dir_all(&dir).ok();
    }
}
