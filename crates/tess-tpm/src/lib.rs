//! TPM2 seal/unseal of a random key, gated by a PIN `PolicyAuthValue`, with mandatory HMAC +
//! parameter-encryption sessions. Skeleton — implemented in Phase 1 (see `PLAN.md` §5, `docs/adr/0001`).

/// Selects the TPM transport: a software TPM (swtpm/mssim) for dev and CI, or the kernel resource
/// manager (`/dev/tpmrm0`) for a real / virtual hardware TPM.
#[derive(Debug, Clone)]
pub enum TctiConfig {
    /// swtpm via the mssim TCTI (host:port).
    Swtpm { host: String, port: u16 },
    /// Kernel resource manager device, e.g. `/dev/tpmrm0`.
    DeviceManager { path: String },
}

impl TctiConfig {
    /// Conventional mssim host/command-port for a local swtpm.
    pub const DEFAULT_SWTPM_HOST: &'static str = "127.0.0.1";
    pub const DEFAULT_SWTPM_PORT: u16 = 2321;

    /// Default for automated tests: a local swtpm on the conventional mssim port.
    pub fn swtpm_default() -> Self {
        Self::Swtpm {
            host: Self::DEFAULT_SWTPM_HOST.to_string(),
            port: Self::DEFAULT_SWTPM_PORT,
        }
    }

    /// Resolve a swtpm mssim address from the environment, falling back to the conventional
    /// `127.0.0.1:2321`. Reads `TESS_SWTPM_HOST` and `TESS_SWTPM_PORT`; an unparseable port falls
    /// back to the default. This mirrors the env contract of `testing/swtpm/run.sh`.
    pub fn swtpm_from_env() -> Self {
        Self::resolve_swtpm(
            std::env::var("TESS_SWTPM_HOST").ok(),
            std::env::var("TESS_SWTPM_PORT").ok(),
        )
    }

    /// Pure env-defaulting logic, separated from the process-global `std::env` read so it can be
    /// tested deterministically. An absent or unparseable value falls back to the default.
    fn resolve_swtpm(host: Option<String>, port: Option<String>) -> Self {
        let host = host.unwrap_or_else(|| Self::DEFAULT_SWTPM_HOST.to_string());
        let port = port
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(Self::DEFAULT_SWTPM_PORT);
        Self::Swtpm { host, port }
    }

    /// The `host:port` the mssim command channel listens on, if this is an swtpm transport.
    pub fn swtpm_socket_addr(&self) -> Option<String> {
        match self {
            Self::Swtpm { host, port } => Some(format!("{host}:{port}")),
            Self::DeviceManager { .. } => None,
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
    fn device_manager_has_no_socket_addr() {
        let cfg = TctiConfig::DeviceManager {
            path: "/dev/tpmrm0".to_string(),
        };
        assert!(cfg.swtpm_socket_addr().is_none());
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

        if Command::new("swtpm").arg("--version").output().is_err() {
            eprintln!("skipping swtpm_mssim_port_accepts_connection: swtpm not found on PATH");
            return;
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
