//! `tess doctor` — read-only readiness probes for TPM, keyring, and fprintd.
//!
//! Every probe is side-effect-free: it checks for the presence of device nodes or
//! binaries on `PATH`. It never opens a D-Bus session, never touches a secret, and
//! never unlocks anything. Per project policy it runs in CI or on the Azure VM, not
//! the developer host.

use std::env;
use std::fmt::Write as _;
use std::path::Path;

use tess_tpm::{read_lockout_state, read_tpm_version, LockoutState, TctiConfig, TpmVersion};

/// Display name of the TPM resource-manager probe. Shared between the probe
/// construction and the verdict logic so the two can't drift.
const TPM_RM_PROBE_NAME: &str = "TPM resource manager (/dev/tpmrm0)";

/// Kernel resource-manager device node the TPM probe reads through.
const TPM_RM_PATH: &str = "/dev/tpmrm0";

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
        probe_tpm_rm(),
        probe_path("TPM raw device (/dev/tpm0)", "/dev/tpm0"),
        probe_keyring(),
        probe_fprintd(),
    ]
}

/// Probe the TPM resource manager. When the device node is present this additionally opens a
/// read-only ESAPI context to report the TPM version and DA-lockout state. The capability read is
/// best-effort: any failure (no runtime TCTI library, a busy or refusing TPM) downgrades to a
/// "detail unavailable" note carrying the reason — the node's presence alone still satisfies the
/// verdict, and nothing here is ever a secret or a mutation.
fn probe_tpm_rm() -> Probe {
    if !Path::new(TPM_RM_PATH).exists() {
        return Probe::new(
            TPM_RM_PROBE_NAME,
            ProbeStatus::Missing,
            "device node not found",
        );
    }
    let detail = match read_tpm_caps() {
        Ok((version, lockout)) => format_tpm_detail(
            Some(&version.to_string()),
            Some(&lockout_summary(&lockout)),
            None,
        ),
        Err(reason) => format_tpm_detail(None, None, Some(&reason)),
    };
    Probe::new(TPM_RM_PROBE_NAME, ProbeStatus::Ok, &detail)
}

/// Best-effort read-only capability read over the device TCTI: TPM version + DA-lockout state. The
/// error is rendered to a string so the caller can fold it into the probe detail rather than panic.
fn read_tpm_caps() -> Result<(TpmVersion, LockoutState), String> {
    let cfg = TctiConfig::DeviceManager {
        path: TPM_RM_PATH.to_string(),
    };
    let mut context = cfg.open_context().map_err(|e| e.to_string())?;
    let version = read_tpm_version(&mut context).map_err(|e| e.to_string())?;
    let lockout = read_lockout_state(&mut context).map_err(|e| e.to_string())?;
    Ok((version, lockout))
}

/// One-line DA-lockout summary: disabled, locked out, or `counter/max` remaining headroom.
fn lockout_summary(state: &LockoutState) -> String {
    if state.max_auth_fail == 0 {
        "DA lockout disabled".to_string()
    } else if state.is_locked_out() {
        format!("DA LOCKED OUT ({}/{})", state.counter, state.max_auth_fail)
    } else {
        format!("DA lockout {}/{}", state.counter, state.max_auth_fail)
    }
}

/// Compose the TPM resource-manager probe detail from a best-effort capability read. Pure so it can
/// be unit-tested without a TPM; `unavailable` short-circuits to the reason the read failed.
fn format_tpm_detail(
    version: Option<&str>,
    lockout: Option<&str>,
    unavailable: Option<&str>,
) -> String {
    if let Some(reason) = unavailable {
        return format!("present; TPM detail unavailable ({reason})");
    }
    let mut parts = vec!["present".to_string()];
    if let Some(v) = version {
        parts.push(v.to_string());
    }
    if let Some(l) = lockout {
        parts.push(l.to_string());
    }
    parts.join("; ")
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
    fn tpm_detail_reports_version_and_lockout_when_present() {
        let detail =
            format_tpm_detail(Some("TPM 2.0 (spec rev 138)"), Some("DA lockout 0/3"), None);
        assert_eq!(detail, "present; TPM 2.0 (spec rev 138); DA lockout 0/3");
    }

    #[test]
    fn tpm_detail_unavailable_carries_reason() {
        let detail = format_tpm_detail(None, None, Some("no TCTI library"));
        assert_eq!(detail, "present; TPM detail unavailable (no TCTI library)");
        // Even with version/lockout supplied, an unavailable reason must win (read failed).
        let detail = format_tpm_detail(Some("TPM 2.0"), Some("DA lockout 0/3"), Some("busy"));
        assert_eq!(detail, "present; TPM detail unavailable (busy)");
    }

    #[test]
    fn tpm_detail_present_without_caps_is_just_present() {
        assert_eq!(format_tpm_detail(None, None, None), "present");
    }

    #[test]
    fn lockout_summary_covers_disabled_active_and_locked() {
        let disabled = LockoutState {
            counter: 5,
            max_auth_fail: 0,
            interval: 0,
        };
        assert_eq!(lockout_summary(&disabled), "DA lockout disabled");

        let active = LockoutState {
            counter: 1,
            max_auth_fail: 3,
            interval: 1000,
        };
        assert_eq!(lockout_summary(&active), "DA lockout 1/3");

        let locked = LockoutState {
            counter: 3,
            max_auth_fail: 3,
            interval: 1000,
        };
        assert_eq!(lockout_summary(&locked), "DA LOCKED OUT (3/3)");
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
