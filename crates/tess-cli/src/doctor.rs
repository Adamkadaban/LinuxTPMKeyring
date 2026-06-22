//! `tess doctor` — read-only readiness probes for TPM, keyring, and fprintd.
//!
//! Every probe is side-effect-free: it checks for the presence of device nodes or
//! binaries on `PATH`. It never opens a D-Bus session, never touches a secret, and
//! never unlocks anything. Per project policy it runs in CI or on the Azure VM, not
//! the developer host.

use std::env;
use std::fmt::Write as _;
use std::path::Path;

use tess_tpm::{
    persist, read_lockout_state, read_tpm_version, LockoutState, TctiConfig, TpmVersion,
};

use crate::enroll;

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
///
/// `required` probes fail the overall verdict (and the process exit code) when missing; optional
/// ones are reported but never block. `hint` carries a one-line remediation surfaced in the verdict
/// when a required probe is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub name: String,
    pub status: ProbeStatus,
    pub detail: String,
    pub required: bool,
    pub hint: Option<String>,
}

impl Probe {
    fn new(name: &str, status: ProbeStatus, detail: &str) -> Self {
        Self {
            name: name.to_string(),
            status,
            detail: detail.to_string(),
            required: false,
            hint: None,
        }
    }

    /// Mark this probe as required for the overall verdict.
    fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Mark this probe required only when `yes` — used by probes that are informational by default
    /// but mandatory in post-install verification mode.
    fn required_if(mut self, yes: bool) -> Self {
        self.required = yes;
        self
    }

    /// Attach a one-line remediation hint, surfaced when a required probe is missing.
    fn with_hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.to_string());
        self
    }
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

/// True when no *required* probe is missing — the machine-readable readiness signal behind the
/// process exit code.
pub fn is_ready(probes: &[Probe]) -> bool {
    !probes
        .iter()
        .any(|p| p.status == ProbeStatus::Missing && p.required)
}

/// One-line overall verdict (plus per-component remediation hints when not ready). Only *required*
/// probes can fail the verdict.
pub fn overall_verdict(probes: &[Probe]) -> String {
    let required_missing: Vec<&Probe> = probes
        .iter()
        .filter(|p| p.status == ProbeStatus::Missing && p.required)
        .collect();
    let optional_missing = probes
        .iter()
        .filter(|p| p.status == ProbeStatus::Missing && !p.required)
        .count();

    if required_missing.is_empty() {
        if optional_missing == 0 {
            "verdict: READY — all components present.".to_string()
        } else {
            format!("verdict: READY — {optional_missing} optional component(s) missing.")
        }
    } else {
        let names: Vec<&str> = required_missing.iter().map(|p| p.name.as_str()).collect();
        let mut out = format!(
            "verdict: NOT READY — missing required: {}.",
            names.join(", ")
        );
        for probe in &required_missing {
            if let Some(hint) = &probe.hint {
                let _ = write!(out, "\n  → {}: {hint}", probe.name);
            }
        }
        out
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

fn probe_keyring(required: bool) -> Probe {
    // Lightweight: just check whether a keyring daemon binary is plausibly installed.
    // We deliberately do NOT open a D-Bus session or talk to org.freedesktop.secrets.
    let candidates = ["gnome-keyring-daemon", "kwalletd6", "kwalletd5"];
    if let Some(found) = candidates.iter().find(|b| binary_on_path(b)) {
        Probe::new(
            "Secret Service daemon",
            ProbeStatus::Ok,
            &format!("{found} on PATH (not contacted)"),
        )
        .required_if(required)
    } else {
        Probe::new(
            "Secret Service daemon",
            ProbeStatus::Missing,
            "no gnome-keyring/kwallet binary on PATH",
        )
        .required_if(required)
        .with_hint("install a Secret Service provider, e.g. `apt install gnome-keyring`")
    }
}

/// Probe whether `tess enroll` has completed: the sealed metadata must be present *and* parseable
/// (a truncated/corrupt blob is treated as missing). Informational by default; promoted to required
/// in post-install verification. Read-only — it loads metadata but never unseals or touches a
/// secret, so it consumes no DA attempt.
fn probe_enrollment(required: bool) -> Probe {
    const NAME: &str = "tess enrollment";
    let paths = match enroll::Paths::for_user() {
        Ok(paths) => paths,
        Err(reason) => {
            return Probe::new(
                NAME,
                ProbeStatus::Missing,
                &format!("cannot resolve data directory: {reason}"),
            )
            .required_if(required)
            .with_hint("set HOME (or XDG_DATA_HOME) so tess can locate its sealed metadata");
        }
    };
    if !paths.metadata.exists() {
        return Probe::new(
            NAME,
            ProbeStatus::Missing,
            "not enrolled (no sealed metadata)",
        )
        .required_if(required)
        .with_hint("run `tess enroll`");
    }
    match persist::load(&paths.metadata) {
        Ok(_) => {
            let recovery = if paths.recovery.exists() {
                "recovery blob present"
            } else {
                "no recovery blob"
            };
            Probe::new(NAME, ProbeStatus::Ok, &format!("enrolled; {recovery}"))
        }
        Err(reason) => Probe::new(
            NAME,
            ProbeStatus::Missing,
            &format!("sealed metadata unreadable: {reason}"),
        )
        .required_if(required)
        .with_hint("re-run `tess enroll`, or `tess recover` if the TPM state changed"),
    }
}

fn probe_fprintd() -> Probe {
    if binary_on_path("fprintd") {
        Probe::new("fprintd", ProbeStatus::Ok, "fprintd on PATH")
    } else {
        Probe::new("fprintd", ProbeStatus::Missing, "fprintd not on PATH")
    }
}

/// Run all probes against the live system (read-only). When `post_install` is set, the keyring
/// daemon and a completed `tess` enrollment are promoted to *required* — the post-install
/// verification mode the acceptance harness runs after `tess enroll`.
pub fn run_probes(post_install: bool) -> Vec<Probe> {
    vec![
        probe_tpm_rm(),
        probe_path("TPM raw device (/dev/tpm0)", "/dev/tpm0"),
        probe_keyring(post_install),
        probe_fprintd(),
        probe_enrollment(post_install),
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
        )
        .required()
        .with_hint("no TPM 2.0 resource manager — this host has no usable TPM, or the kernel TPM driver is not loaded");
    }
    let detail = match read_tpm_caps() {
        Ok((version, lockout)) => format_tpm_detail(
            Some(&version.to_string()),
            Some(&lockout_summary(&lockout)),
            None,
        ),
        Err(reason) => format_tpm_detail(None, None, Some(&reason)),
    };
    Probe::new(TPM_RM_PROBE_NAME, ProbeStatus::Ok, &detail).required()
}

/// Best-effort read-only capability read over the device TCTI: TPM version + DA-lockout state. The
/// error is rendered to a string so the caller can fold it into the probe detail rather than panic.
fn read_tpm_caps() -> Result<(TpmVersion, LockoutState), String> {
    read_caps(&TctiConfig::DeviceManager {
        path: TPM_RM_PATH.to_string(),
    })
}

/// Open a read-only ESAPI context against `tcti` and read the TPM version and DA-lockout state. No
/// authorization, no session, no mutation — shared by `doctor` and `status`/`test`. Errors are
/// stringified so callers can surface the reason in their report instead of failing hard.
pub(crate) fn read_caps(tcti: &TctiConfig) -> Result<(TpmVersion, LockoutState), String> {
    let mut context = tcti.open_context().map_err(|e| e.to_string())?;
    let version = read_tpm_version(&mut context).map_err(|e| e.to_string())?;
    let lockout = read_lockout_state(&mut context).map_err(|e| e.to_string())?;
    Ok((version, lockout))
}

/// One-line DA-lockout summary: disabled, locked out, or `counter/max` remaining headroom.
pub(crate) fn lockout_summary(state: &LockoutState) -> String {
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

/// Entry point for the `doctor` subcommand. Prints the readiness report and returns whether the
/// system is ready (no required component missing) so the caller can set the process exit code.
/// When `post_install` is set, the keyring daemon and a completed enrollment are required.
pub fn run(post_install: bool) -> bool {
    let probes = run_probes(post_install);
    println!("{}", render_report(&probes));
    is_ready(&probes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(name: &str, status: ProbeStatus) -> Probe {
        Probe::new(name, status, "x")
    }

    /// A required probe, for verdict tests that exercise the required/optional split.
    fn req(name: &str, status: ProbeStatus) -> Probe {
        Probe::new(name, status, "x").required()
    }

    #[test]
    fn verdict_ready_when_all_present() {
        let probes = vec![
            req("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Ok),
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
            req("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Ok),
            probe("fprintd", ProbeStatus::Missing),
            probe("Secret Service daemon", ProbeStatus::Missing),
        ];
        assert_eq!(
            overall_verdict(&probes),
            "verdict: READY — 2 optional component(s) missing."
        );
    }

    #[test]
    fn verdict_not_ready_when_tpm_missing() {
        let probes = vec![
            req("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Missing),
            probe("fprintd", ProbeStatus::Ok),
        ];
        assert!(overall_verdict(&probes).starts_with(
            "verdict: NOT READY — missing required: TPM resource manager (/dev/tpmrm0)."
        ));
    }

    #[test]
    fn verdict_surfaces_remediation_hints_for_required_missing() {
        let probes = vec![
            Probe::new("tess enrollment", ProbeStatus::Missing, "not enrolled")
                .required()
                .with_hint("run `tess enroll`"),
        ];
        let verdict = overall_verdict(&probes);
        assert!(verdict.contains("NOT READY"));
        assert!(verdict.contains("→ tess enrollment: run `tess enroll`"));
    }

    #[test]
    fn is_ready_tracks_required_probes_only() {
        assert!(is_ready(&[
            req("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Ok),
            probe("fprintd", ProbeStatus::Missing),
        ]));
        assert!(!is_ready(&[req(
            "TPM resource manager (/dev/tpmrm0)",
            ProbeStatus::Missing
        )]));
    }

    #[test]
    fn optional_missing_does_not_fail_verdict() {
        let probes = vec![
            req("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Ok),
            probe("TPM raw device (/dev/tpm0)", ProbeStatus::Missing),
        ];
        assert!(overall_verdict(&probes).starts_with("verdict: READY"));
    }

    #[test]
    fn report_has_header_and_verdict() {
        let probes = vec![req("TPM resource manager (/dev/tpmrm0)", ProbeStatus::Ok)];
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
