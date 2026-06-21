//! `KeyringBackend` implementation over the freedesktop Secret Service API (`org.freedesktop.secrets`).
//! GNOME is the reference impl; KWallet is reachable via `apiEnabled`. Unstable private GNOME D-Bus
//! calls stay isolated here. Skeleton — implemented in Phase 2 (see `PLAN.md` §5, `docs/adr/0005`).

/// The well-known D-Bus name every supported backend implements.
pub const SECRET_SERVICE_BUS_NAME: &str = "org.freedesktop.secrets";

/// Object path of the GNOME login collection.
pub const LOGIN_COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/login";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_name_is_freedesktop_secrets() {
        assert_eq!(SECRET_SERVICE_BUS_NAME, "org.freedesktop.secrets");
    }
}
