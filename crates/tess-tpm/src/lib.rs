//! TPM2 seal/unseal of a random key, gated by a PIN `PolicyAuthValue`, with mandatory HMAC +
//! parameter-encryption sessions. Provides an ESAPI context, the ECC storage primary, the salted
//! encrypted session, and `seal`/`unseal` of a random key under a PIN over that session.

use std::str::FromStr;

use tss_esapi::Context;
use tss_esapi::tcti_ldr::{DeviceConfig, NetworkTPMConfig, TctiNameConf};

mod caps;
mod esapi;
mod lockout;
pub mod persist;
mod seal;

pub use caps::{TpmVersion, read_tpm_version};
pub use esapi::{
    Error, Result, create_primary, ecc_storage_primary_template, start_salted_hmac_session,
};
pub use lockout::{
    LockoutState, lockout_auth_is_set, pin_holder_recover, read_lockout_state, reset_lockout,
    set_lockout_auth,
};
pub use seal::{SealedObject, generate_sealing_key, seal, unseal};

/// Selects the TPM transport: a software TPM (swtpm) for dev and CI, or the kernel resource
/// manager (`/dev/tpmrm0`) for a real / virtual hardware TPM.
#[derive(Debug, Clone)]
pub enum TctiConfig {
    /// swtpm via the swtpm TCTI (host:port).
    Swtpm { host: String, port: u16 },
    /// Kernel resource manager device, e.g. `/dev/tpmrm0`.
    DeviceManager { path: String },
}

impl TctiConfig {
    /// Conventional host/command-port for a local swtpm.
    pub const DEFAULT_SWTPM_HOST: &'static str = "127.0.0.1";
    pub const DEFAULT_SWTPM_PORT: u16 = 2321;

    /// Default for automated tests: a local swtpm on the conventional command port.
    pub fn swtpm_default() -> Self {
        Self::Swtpm {
            host: Self::DEFAULT_SWTPM_HOST.to_string(),
            port: Self::DEFAULT_SWTPM_PORT,
        }
    }

    /// Resolve a swtpm address from the environment, falling back to the conventional
    /// `127.0.0.1:2321`. Reads `TESS_SWTPM_HOST` and `TESS_SWTPM_PORT`; an unparseable port falls
    /// back to the default. This mirrors the env contract of `testing/swtpm/run.sh`.
    pub fn swtpm_from_env() -> Self {
        Self::resolve_swtpm(
            std::env::var("TESS_SWTPM_HOST").ok(),
            std::env::var("TESS_SWTPM_PORT").ok(),
        )
    }

    /// Pure env-defaulting logic, separated from the process-global `std::env` read so it can be
    /// tested deterministically. An absent, empty, or unparseable value falls back to the default.
    fn resolve_swtpm(host: Option<String>, port: Option<String>) -> Self {
        let host = host
            .filter(|h| !h.trim().is_empty())
            .unwrap_or_else(|| Self::DEFAULT_SWTPM_HOST.to_string());
        let port = port
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(Self::DEFAULT_SWTPM_PORT);
        Self::Swtpm { host, port }
    }

    /// The `host:port` the swtpm command channel listens on, if this is a swtpm transport. IPv6
    /// literals are bracketed so the result parses as a `SocketAddr`.
    pub fn swtpm_socket_addr(&self) -> Option<String> {
        match self {
            Self::Swtpm { host, port } => {
                if host.contains(':') && !host.starts_with('[') {
                    Some(format!("[{host}]:{port}"))
                } else {
                    Some(format!("{host}:{port}"))
                }
            }
            Self::DeviceManager { .. } => None,
        }
    }

    /// Build the `tss-esapi` TCTI descriptor for this transport: the swtpm TCTI for the software
    /// emulator (its control channel speaks swtpm's own protocol, not the IBM mssim one — the
    /// mssim TCTI's platform commands fail against swtpm), or a device-node config for the kernel
    /// resource manager. The swtpm path backs the `sim` test feature; the device path backs the
    /// `hw` feature, validated on the Azure vTPM rather than the dev host.
    pub fn tcti_name_conf(&self) -> Result<TctiNameConf> {
        match self {
            Self::Swtpm { host, port } => {
                let conf = NetworkTPMConfig::from_str(&format!("host={host},port={port}"))
                    .map_err(|e| Error::Tcti(e.to_string()))?;
                Ok(TctiNameConf::Swtpm(conf))
            }
            Self::DeviceManager { path } => {
                let conf = DeviceConfig::from_str(path).map_err(|e| Error::Tcti(e.to_string()))?;
                Ok(TctiNameConf::Device(conf))
            }
        }
    }

    /// Open a live ESAPI [`Context`] against this transport.
    pub fn open_context(&self) -> Result<Context> {
        Context::new(self.tcti_name_conf()?).map_err(|e| Error::Context(e.to_string()))
    }

    /// The `TPM2TOOLS_TCTI` string that points tpm2-tools at the *same* TPM tess uses: the `swtpm`
    /// TCTI for the software emulator (matching the command/control port pair), or the `device` TCTI
    /// for the kernel resource manager. Used by the privileged DA-lockout reset, which shells out to
    /// `tpm2_dictionarylockout` (the pinned `tss-esapi` exposes no safe wrapper for that command).
    pub fn tpm2_tools_tcti(&self) -> String {
        match self {
            Self::Swtpm { host, port } => format!("swtpm:host={host},port={port}"),
            Self::DeviceManager { path } => format!("device:{path}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swtpm_default_targets_mssim_port() {
        match TctiConfig::swtpm_default() {
            TctiConfig::Swtpm { port, .. } => assert_eq!(port, 2321),
            _ => panic!("expected swtpm config"),
        }
    }

    #[test]
    fn resolve_swtpm_uses_defaults_when_absent() {
        match TctiConfig::resolve_swtpm(None, None) {
            TctiConfig::Swtpm { host, port } => {
                assert_eq!(host, TctiConfig::DEFAULT_SWTPM_HOST);
                assert_eq!(port, TctiConfig::DEFAULT_SWTPM_PORT);
            }
            _ => panic!("expected swtpm config"),
        }
    }

    #[test]
    fn resolve_swtpm_honors_explicit_values() {
        match TctiConfig::resolve_swtpm(Some("10.0.0.5".to_string()), Some("12345".to_string())) {
            TctiConfig::Swtpm { host, port } => {
                assert_eq!(host, "10.0.0.5");
                assert_eq!(port, 12345);
            }
            _ => panic!("expected swtpm config"),
        }
    }

    #[test]
    fn resolve_swtpm_falls_back_on_unparseable_port() {
        match TctiConfig::resolve_swtpm(None, Some("not-a-port".to_string())) {
            TctiConfig::Swtpm { port, .. } => assert_eq!(port, TctiConfig::DEFAULT_SWTPM_PORT),
            _ => panic!("expected swtpm config"),
        }
    }

    #[test]
    fn resolve_swtpm_treats_empty_host_as_absent() {
        match TctiConfig::resolve_swtpm(Some("   ".to_string()), None) {
            TctiConfig::Swtpm { host, .. } => assert_eq!(host, TctiConfig::DEFAULT_SWTPM_HOST),
            _ => panic!("expected swtpm config"),
        }
    }

    #[test]
    fn swtpm_socket_addr_brackets_ipv6() {
        let cfg = TctiConfig::Swtpm {
            host: "::1".to_string(),
            port: 2321,
        };
        let addr = cfg.swtpm_socket_addr().expect("swtpm transport");
        assert_eq!(addr, "[::1]:2321");
        assert!(addr.parse::<std::net::SocketAddr>().is_ok());
    }

    #[test]
    fn device_manager_has_no_socket_addr() {
        let cfg = TctiConfig::DeviceManager {
            path: "/dev/tpmrm0".to_string(),
        };
        assert!(cfg.swtpm_socket_addr().is_none());
    }

    #[test]
    fn tpm2_tools_tcti_matches_transport() {
        let swtpm = TctiConfig::Swtpm {
            host: "127.0.0.1".to_string(),
            port: 2321,
        };
        assert_eq!(swtpm.tpm2_tools_tcti(), "swtpm:host=127.0.0.1,port=2321");

        let device = TctiConfig::DeviceManager {
            path: "/dev/tpmrm0".to_string(),
        };
        assert_eq!(device.tpm2_tools_tcti(), "device:/dev/tpmrm0");
    }

    /// Phase 0 reachability smoke test: bring up swtpm via `testing/swtpm/run.sh`, confirm the
    /// mssim command port accepts a TCP connection, then tear it down. A real TPM property read
    /// lands in Phase 1 once `tss-esapi` is wired in. Skips cleanly when swtpm is not installed so
    /// the default `cargo test --workspace` stays green on hardware-free hosts.
    #[cfg(feature = "sim")]
    #[test]
    fn swtpm_mssim_port_accepts_connection() {
        use std::net::TcpStream;
        use std::path::PathBuf;
        use std::process::Command;
        use std::time::Duration;

        // Skip only when swtpm is genuinely absent (ENOENT); any other failure to execute it
        // (present but not executable, missing runtime deps) is a real error and must fail the
        // test rather than silently passing the CI substrate step.
        match Command::new("swtpm").arg("--version").output() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping swtpm_mssim_port_accepts_connection: swtpm not found on PATH");
                return;
            }
            Err(e) => panic!("failed to execute swtpm: {e}"),
            Ok(_) => {}
        }

        // testing/swtpm/run.sh lives two levels up from this crate's manifest dir.
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testing/swtpm/run.sh")
            .canonicalize()
            .expect("locate testing/swtpm/run.sh");

        // Isolated, ephemeral ports + state dir so the test never collides with a developer-run
        // swtpm or another concurrent test, and leaves no shared state behind. Bind both probe
        // listeners simultaneously so the two ports are guaranteed distinct before we drop them.
        let host = "127.0.0.1";
        let (port, ctrl_port) = {
            use std::net::TcpListener;
            let l1 = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            let l2 = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
            let p1 = l1.local_addr().expect("local addr").port().to_string();
            let p2 = l2.local_addr().expect("local addr").port().to_string();
            (p1, p2)
        };
        let port = port.as_str();
        let ctrl_port = ctrl_port.as_str();
        let state_dir =
            std::env::temp_dir().join(format!("tess-swtpm-test-{}", std::process::id()));

        // RAII guard: stop swtpm and remove its state dir even if an assertion below panics.
        struct SwtpmGuard {
            script: PathBuf,
            state_dir: PathBuf,
            host: String,
            port: String,
            ctrl_port: String,
        }
        impl SwtpmGuard {
            fn run(&self, action: &str) -> std::process::Output {
                Command::new("bash")
                    .arg(&self.script)
                    .arg(action)
                    .env("TESS_SWTPM_HOST", &self.host)
                    .env("TESS_SWTPM_PORT", &self.port)
                    .env("TESS_SWTPM_CTRL_PORT", &self.ctrl_port)
                    .env("TESS_SWTPM_STATE_DIR", &self.state_dir)
                    .output()
                    .expect("invoke testing/swtpm/run.sh")
            }
        }
        impl Drop for SwtpmGuard {
            fn drop(&mut self) {
                let _ = self.run("stop");
                let _ = std::fs::remove_dir_all(&self.state_dir);
            }
        }

        let guard = SwtpmGuard {
            script,
            state_dir,
            host: host.to_string(),
            port: port.to_string(),
            ctrl_port: ctrl_port.to_string(),
        };

        let start = guard.run("start");
        assert!(
            start.status.success(),
            "run.sh start failed: {}",
            String::from_utf8_lossy(&start.stderr)
        );

        let cfg = TctiConfig::Swtpm {
            host: host.to_string(),
            port: port.parse().expect("port parses"),
        };
        let addr = cfg.swtpm_socket_addr().expect("swtpm transport");
        let sock = addr.parse().expect("addr parses to SocketAddr");

        // The script already waits for the port, but retry briefly to be robust.
        let mut connected = false;
        for _ in 0..25 {
            if TcpStream::connect_timeout(&sock, Duration::from_millis(500)).is_ok() {
                connected = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(connected, "could not connect to swtpm mssim port at {addr}");
    }
}
