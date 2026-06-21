//! `fprintd` client over the `net.reactivated.Fprint` D-Bus API — consumed unmodified, exactly as
//! `pam_fprintd` does. Tests drive the libfprint virtual driver + `python-dbusmock` (no real reader).
//! The biometric is host-trusted convenience, never the sole gate. Skeleton — implemented in Phase 2.

/// The fprintd D-Bus service name.
pub const FPRINT_BUS_NAME: &str = "net.reactivated.Fprint";

/// Environment variable libfprint reads to select the non-image virtual driver (test substrate).
pub const VIRTUAL_DEVICE_ENV: &str = "FP_VIRTUAL_DEVICE";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_name_is_fprint() {
        assert_eq!(FPRINT_BUS_NAME, "net.reactivated.Fprint");
    }
}
