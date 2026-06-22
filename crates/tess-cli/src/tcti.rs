//! Shared selection of the TPM transport for the binary's TPM-touching subcommands.

use tess_tpm::TctiConfig;

/// Select the TPM transport: an swtpm when either `TESS_SWTPM_HOST` or `TESS_SWTPM_PORT` is set (CI
/// and local sim runs; `swtpm_from_env` fills any unset value with the conventional `127.0.0.1:2321`),
/// otherwise the kernel resource manager at `/dev/tpmrm0` (real hardware / the Azure vTPM, which is
/// reached through the device node, not swtpm).
pub(crate) fn from_env() -> TctiConfig {
    if std::env::var_os("TESS_SWTPM_HOST").is_some()
        || std::env::var_os("TESS_SWTPM_PORT").is_some()
    {
        TctiConfig::swtpm_from_env()
    } else {
        TctiConfig::DeviceManager {
            path: "/dev/tpmrm0".to_string(),
        }
    }
}
