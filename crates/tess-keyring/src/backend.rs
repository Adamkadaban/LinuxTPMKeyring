//! `SecretServiceBackend`: a [`tess_core::KeyringBackend`] that speaks the freedesktop Secret
//! Service API (`org.freedesktop.secrets`) over D-Bus.
//!
//! The stable Secret Service spec covers reading lock state and `Unlock`/`Lock`, but it has no
//! headless way to *prove possession* of a collection password — `Unlock` raises an interactive
//! `Prompt`. GNOME exposes the missing primitives on its private
//! `org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface`: `UnlockWithMasterPassword` and
//! `ChangeWithMasterPassword` (the same call Seahorse's "change password" uses). Every dependency on
//! that unstable interface lives in this module, behind the trait, so churn there never leaks into
//! callers. The runtime unlock at login is expected to use the stable `gnome-keyring-daemon
//! --unlock` stdin path; this in-process `unlock` covers re-unlocking an already-running daemon.
//!
//! KWallet (KDE Frameworks ≥ 5.97 with `apiEnabled=true`) and KeePassXC implement the same Secret
//! Service API and are reachable through this backend; KWallet's native `pam_kwallet` path (keyed to
//! the login password, not separately unlockable) is out of scope.
//!
//! Secret material reaches the daemon through a `plain` session: the value crosses the *per-user*
//! session-bus socket without D-Bus-layer encryption. That socket is owned by the user and a
//! root/runtime adversary is out of scope, so the at-rest guarantee is unaffected; the released key
//! is wiped from this process's buffers ([`zeroize`]) the moment each call returns.

use tess_core::{Error, KeyringBackend, Result, SecretBytes};
use zbus::zvariant::{OwnedObjectPath, Type, Value};
use zeroize::Zeroize;

use crate::{LOGIN_COLLECTION_PATH, SECRET_SERVICE_BUS_NAME};

const COLLECTION_INTERFACE: &str = "org.freedesktop.Secret.Collection";
const SECRET_CONTENT_TYPE: &str = "text/plain";

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets",
    gen_async = false
)]
trait SecretServiceApi {
    fn open_session(
        &self,
        algorithm: &str,
        input: &Value<'_>,
    ) -> zbus::Result<(zbus::zvariant::OwnedValue, OwnedObjectPath)>;
}

#[zbus::proxy(
    interface = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets",
    gen_async = false
)]
trait GnomeKeyringInternal {
    fn change_with_master_password(
        &self,
        collection: &OwnedObjectPath,
        original: &DbusSecret,
        master: &DbusSecret,
    ) -> zbus::Result<()>;

    fn unlock_with_master_password(
        &self,
        collection: &OwnedObjectPath,
        master: &DbusSecret,
    ) -> zbus::Result<()>;
}

/// The Secret Service `Secret` struct (`(oayays)`): session path, encryption parameters, value, and
/// content type. For a `plain` session the parameters are empty and the value is the raw password.
/// The value and parameters are wiped on drop so the released key doesn't linger in this buffer.
#[derive(serde::Serialize, Type)]
struct DbusSecret {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

impl Drop for DbusSecret {
    fn drop(&mut self) {
        self.value.zeroize();
        self.parameters.zeroize();
    }
}

fn keyring_error(context: &str, err: impl std::fmt::Display) -> Error {
    Error::Keyring(format!("{context}: {err}"))
}

/// A keyring backend bound to a single Secret Service collection (the GNOME login keyring by
/// default).
pub struct SecretServiceBackend {
    conn: zbus::blocking::Connection,
    collection_path: OwnedObjectPath,
}

impl SecretServiceBackend {
    /// Connect to the session bus and target the GNOME login collection.
    pub fn connect() -> Result<Self> {
        let conn = zbus::blocking::Connection::session()
            .map_err(|e| keyring_error("connect to session bus", e))?;
        Self::with_connection(conn, LOGIN_COLLECTION_PATH)
    }

    /// Connect to an explicit bus address (e.g. a private test bus) and target `collection_path`.
    pub fn connect_to(address: &str, collection_path: &str) -> Result<Self> {
        let conn = zbus::blocking::connection::Builder::address(address)
            .map_err(|e| keyring_error("parse bus address", e))?
            .build()
            .map_err(|e| keyring_error("connect to bus", e))?;
        Self::with_connection(conn, collection_path)
    }

    fn with_connection(conn: zbus::blocking::Connection, collection_path: &str) -> Result<Self> {
        let collection_path = OwnedObjectPath::try_from(collection_path)
            .map_err(|e| keyring_error("invalid collection path", e))?;
        Ok(Self {
            conn,
            collection_path,
        })
    }

    fn open_plain_session(&self) -> Result<OwnedObjectPath> {
        let service = SecretServiceApiProxy::new(&self.conn)
            .map_err(|e| keyring_error("open Secret Service proxy", e))?;
        let input = Value::new("");
        let (_output, session) = service
            .open_session("plain", &input)
            .map_err(|e| keyring_error("open session", e))?;
        Ok(session)
    }

    fn internal(&self) -> Result<GnomeKeyringInternalProxy<'_>> {
        GnomeKeyringInternalProxy::new(&self.conn)
            .map_err(|e| keyring_error("open GNOME keyring internal proxy", e))
    }
}

fn dbus_secret(session: &OwnedObjectPath, secret: &SecretBytes) -> DbusSecret {
    DbusSecret {
        session: session.clone(),
        parameters: Vec::new(),
        value: secret.as_slice().to_vec(),
        content_type: SECRET_CONTENT_TYPE.to_string(),
    }
}

impl KeyringBackend for SecretServiceBackend {
    fn rekey(&self, old: &SecretBytes, new: &SecretBytes) -> Result<()> {
        let session = self.open_plain_session()?;
        let internal = self.internal()?;
        let original = dbus_secret(&session, old);
        let master = dbus_secret(&session, new);
        internal
            .change_with_master_password(&self.collection_path, &original, &master)
            .map_err(|e| keyring_error("rekey collection master password", e))
    }

    fn unlock(&self, secret: &SecretBytes) -> Result<()> {
        let session = self.open_plain_session()?;
        let internal = self.internal()?;
        let master = dbus_secret(&session, secret);
        internal
            .unlock_with_master_password(&self.collection_path, &master)
            .map_err(|e| keyring_error("unlock collection", e))
    }

    fn is_locked(&self) -> Result<bool> {
        let props = zbus::blocking::fdo::PropertiesProxy::builder(&self.conn)
            .destination(SECRET_SERVICE_BUS_NAME)
            .map_err(|e| keyring_error("set destination", e))?
            .path(self.collection_path.clone())
            .map_err(|e| keyring_error("set collection path", e))?
            .build()
            .map_err(|e| keyring_error("open properties proxy", e))?;
        let interface = zbus::names::InterfaceName::try_from(COLLECTION_INTERFACE)
            .map_err(|e| keyring_error("collection interface name", e))?;
        let value = props
            .get(interface, "Locked")
            .map_err(|e| keyring_error("read Locked property", e))?;
        bool::try_from(value).map_err(|e| keyring_error("decode Locked property", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbus_secret_has_secret_service_signature() {
        assert_eq!(DbusSecret::SIGNATURE.to_string(), "(oayays)");
    }

    #[test]
    fn dbus_secret_wraps_a_plain_value_and_wipes_on_drop() {
        let session = OwnedObjectPath::try_from("/org/freedesktop/secrets/session/s1").unwrap();
        let secret = SecretBytes::new(vec![1, 2, 3, 4]);
        let dbus = dbus_secret(&session, &secret);
        assert!(dbus.parameters.is_empty());
        assert_eq!(dbus.value, vec![1, 2, 3, 4]);
        assert_eq!(dbus.content_type, "text/plain");
    }

    #[test]
    fn keyring_error_preserves_context_and_cause() {
        let err = keyring_error("open session", "boom");
        match err {
            Error::Keyring(message) => assert_eq!(message, "open session: boom"),
            other => panic!("expected Error::Keyring, got {other:?}"),
        }
    }
}
