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
    /// Default for automated tests: a local swtpm on the conventional mssim port.
    pub fn swtpm_default() -> Self {
        Self::Swtpm {
            host: "127.0.0.1".to_string(),
            port: 2321,
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
}
