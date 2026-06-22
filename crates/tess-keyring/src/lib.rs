//! `KeyringBackend` over the freedesktop Secret Service API (`org.freedesktop.secrets`).
//!
//! GNOME's gnome-keyring is the reference implementation, and the headless `unlock`/`rekey` here
//! target its private D-Bus interface (isolated inside [`SecretServiceBackend`]). KWallet (with
//! `apiEnabled=true`) and KeePassXC expose the same Secret Service API, so reading lock state works
//! against them; headless unlock/rekey on non-GNOME daemons (via the stable `Unlock`/`Prompt` path)
//! is future work.

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
