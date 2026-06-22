//! `KeyringBackend` over the freedesktop Secret Service API (`org.freedesktop.secrets`).
//!
//! GNOME's gnome-keyring is the reference implementation. KWallet (with `apiEnabled=true`) and
//! KeePassXC expose the same API and are reachable through the same backend. Any dependency on
//! GNOME's unstable private D-Bus interface is isolated inside [`SecretServiceBackend`].

mod backend;

pub use backend::SecretServiceBackend;

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

    #[test]
    fn login_collection_path_is_well_known() {
        assert_eq!(
            LOGIN_COLLECTION_PATH,
            "/org/freedesktop/secrets/collection/login"
        );
    }
}
