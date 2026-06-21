//! Seal a freshly generated random key into the TPM as a keyedhash data object gated by a PIN
//! `PolicyAuthValue`, and unseal it back, both running under the salted HMAC + parameter-encryption
//! session so the PIN authValue and the recovered key are encrypted on the TPM bus.

use getrandom::getrandom;
use tess_core::SecretBytes;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::{SessionType, Tss2ResponseCodeKind};
use tss_esapi::handles::{KeyHandle, ObjectHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Auth, Digest, KeyedHashScheme, Private, Public, PublicBuilder, PublicKeyedHashParameters,
    SensitiveData, SymmetricDefinition,
};
use tss_esapi::Context;

use crate::esapi::{start_salted_hmac_session, Error, Result};

/// Bytes of the random sealing key and the SHA-256 name hash that bounds the PIN authValue length.
const SEALED_KEY_LEN: usize = 32;
const MAX_PIN_LEN: usize = 32;

/// In-memory representation of a sealed object: the public and private TPM2B blobs returned by
/// `TPM2_Create`. Persistence to disk is out of scope here; this is the typed handoff that the
/// persistence layer marshals and stores.
#[derive(Debug, Clone)]
pub struct SealedObject {
    public: Public,
    private: Private,
}

impl SealedObject {
    /// Reconstruct a sealed object from previously persisted blobs (used by the persistence layer
    /// on reload before [`unseal`]).
    pub fn from_blobs(public: Public, private: Private) -> Self {
        Self { public, private }
    }

    pub fn public(&self) -> &Public {
        &self.public
    }

    pub fn private(&self) -> &Private {
        &self.private
    }
}

/// Generate a 256-bit sealing key by XOR-mixing OS randomness ([`getrandom`]) with the TPM's
/// `GetRandom`, so the key is unpredictable unless *both* sources are subverted — never a TPM-born
/// asymmetric key (ROCA) and never trusting the TPM RNG alone.
pub fn generate_sealing_key(context: &mut Context) -> Result<SecretBytes> {
    let mut key = vec![0u8; SEALED_KEY_LEN];
    getrandom(&mut key).map_err(|e| Error::Rng(e.to_string()))?;

    let tpm_random: Digest = context
        .get_random(SEALED_KEY_LEN)
        .map_err(|e| Error::Rng(e.to_string()))?;
    if tpm_random.value().len() != SEALED_KEY_LEN {
        return Err(Error::Rng(format!(
            "TPM returned {} random bytes, expected {SEALED_KEY_LEN}",
            tpm_random.value().len()
        )));
    }

    for (k, t) in key.iter_mut().zip(tpm_random.value()) {
        *k ^= t;
    }

    Ok(SecretBytes::new(key))
}

/// Seal `secret` under `primary` as a keyedhash data object whose `userWithAuth` authValue is `pin`
/// and whose authPolicy is the `PolicyAuthValue` digest, created under the salted HMAC +
/// parameter-encryption session. The object is dictionary-attack protected (anti-hammering).
pub fn seal(
    context: &mut Context,
    primary: KeyHandle,
    pin: &SecretBytes,
    secret: &SecretBytes,
) -> Result<SealedObject> {
    let auth = pin_to_auth(pin)?;
    let policy_digest = policy_auth_value_digest(context)?;
    let public = sealed_object_template(policy_digest)?;
    let sensitive = SensitiveData::try_from(secret.as_slice().to_vec())
        .map_err(|e| Error::Seal(e.to_string()))?;

    let session = start_salted_hmac_session(context, primary)?;
    let created = context.execute_with_session(Some(session), |ctx| {
        ctx.create(primary, public, Some(auth), Some(sensitive), None, None)
    });
    flush(context, SessionHandle::from(session).into());

    let created = created.map_err(|e| Error::Seal(e.to_string()))?;
    Ok(SealedObject {
        public: created.out_public,
        private: created.out_private,
    })
}

/// Unseal `sealed` under `primary` by loading it, starting a policy session that satisfies
/// `PolicyAuthValue` with `pin` as the object's authValue, and unsealing under that session (salted
/// and encrypting, so the recovered key is encrypted on the bus). A wrong PIN maps to
/// [`Error::WrongPin`]; transient handles are always flushed.
pub fn unseal(
    context: &mut Context,
    primary: KeyHandle,
    sealed: &SealedObject,
    pin: &SecretBytes,
) -> Result<SecretBytes> {
    let auth = pin_to_auth(pin)?;

    let load_session = start_salted_hmac_session(context, primary)?;
    let loaded = context.execute_with_session(Some(load_session), |ctx| {
        ctx.load(primary, sealed.private.clone(), sealed.public.clone())
    });
    flush(context, SessionHandle::from(load_session).into());
    let object: ObjectHandle = loaded.map_err(|e| Error::Load(e.to_string()))?.into();

    let result = unseal_with_policy(context, object, auth);

    flush(context, object);
    result
}

/// Run the policy session and unseal, isolated so the caller can flush the loaded object regardless
/// of outcome. Sets the PIN as the object's authValue, plays `PolicyAuthValue`, and unseals under
/// the salted/encrypting policy session.
fn unseal_with_policy(
    context: &mut Context,
    object: ObjectHandle,
    auth: Auth,
) -> Result<SecretBytes> {
    context
        .tr_set_auth(object, auth)
        .map_err(|e| Error::Unseal(e.to_string()))?;

    let policy = start_policy_session(context)?;
    let result = (|| -> std::result::Result<SensitiveData, tss_esapi::Error> {
        context.policy_auth_value(PolicySession::try_from(policy)?)?;
        context.execute_with_session(Some(policy), |ctx| ctx.unseal(object))
    })();
    flush(context, SessionHandle::from(policy).into());

    let sensitive = result.map_err(map_unseal_error)?;
    Ok(SecretBytes::new(sensitive.value().to_vec()))
}

/// Compute the `PolicyAuthValue` policy digest via a trial session: the digest a sealed object must
/// carry as its authPolicy so that unsealing requires proving knowledge of the PIN authValue.
fn policy_auth_value_digest(context: &mut Context) -> Result<Digest> {
    let trial = context
        .execute_without_session(|ctx| {
            ctx.start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
        })
        .map_err(|e| Error::Policy(e.to_string()))?
        .ok_or(Error::NoSession)?;

    let digest = (|| -> std::result::Result<Digest, tss_esapi::Error> {
        let session = PolicySession::try_from(trial)?;
        context.policy_auth_value(session)?;
        context.policy_get_digest(session)
    })();
    flush(context, SessionHandle::from(trial).into());

    digest.map_err(|e| Error::Policy(e.to_string()))
}

/// Start the real policy session that authorizes the unseal: salted by the storage primary and
/// encrypting, so the unsealed key is parameter-encrypted on the bus like the seal path.
fn start_policy_session(context: &mut Context) -> Result<AuthSession> {
    use tss_esapi::attributes::SessionAttributesBuilder;

    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| Error::Policy(e.to_string()))?
        .ok_or(Error::NoSession)?;

    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context
        .tr_sess_set_attributes(session, attributes, mask)
        .map_err(|e| Error::Policy(e.to_string()))?;

    Ok(session)
}

/// Keyedhash (sealed data) template bound to `policy_digest`: `userWithAuth` so the PIN authValue
/// gates use, `fixedTpm`/`fixedParent` so it lives only under this TPM's primary, and **no**
/// `noDA` so wrong PINs count toward dictionary-attack lockout.
fn sealed_object_template(policy_digest: Digest) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()
        .map_err(|e| Error::Template(e.to_string()))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_auth_policy(policy_digest)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|e| Error::Template(e.to_string()))
}

/// Convert a PIN into a TPM `Auth` value, rejecting PINs longer than the object's SHA-256 name hash
/// (the TPM caps an object's authValue at its name-algorithm digest size).
fn pin_to_auth(pin: &SecretBytes) -> Result<Auth> {
    if pin.len() > MAX_PIN_LEN {
        return Err(Error::PinTooLong {
            len: pin.len(),
            max: MAX_PIN_LEN,
        });
    }
    Auth::try_from(pin.as_slice().to_vec()).map_err(|e| Error::Seal(e.to_string()))
}

/// Map an unseal error: a TPM authorization-HMAC failure (wrong PIN) becomes [`Error::WrongPin`] so
/// callers can distinguish it from genuine TPM faults; everything else stays an [`Error::Unseal`].
fn map_unseal_error(e: tss_esapi::Error) -> Error {
    if is_auth_failure(&e) {
        Error::WrongPin
    } else {
        Error::Unseal(e.to_string())
    }
}

fn is_auth_failure(e: &tss_esapi::Error) -> bool {
    if let tss_esapi::Error::Tss2Error(rc) = e {
        matches!(
            rc.kind(),
            Some(Tss2ResponseCodeKind::AuthFail) | Some(Tss2ResponseCodeKind::BadAuth)
        )
    } else {
        false
    }
}

/// Best-effort flush of a transient TPM handle; a failed flush must not mask the operation's result.
fn flush(context: &mut Context, handle: ObjectHandle) {
    let _ = context.flush_context(handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_too_long_is_rejected() {
        let pin = SecretBytes::new(vec![0u8; MAX_PIN_LEN + 1]);
        assert!(matches!(pin_to_auth(&pin), Err(Error::PinTooLong { .. })));
    }

    #[test]
    fn pin_at_limit_converts() {
        let pin = SecretBytes::new(vec![0u8; MAX_PIN_LEN]);
        assert!(pin_to_auth(&pin).is_ok());
    }

    #[test]
    fn sealed_object_template_is_keyedhash_dictionary_protected() {
        let public = sealed_object_template(Digest::default()).expect("template builds");
        let Public::KeyedHash {
            object_attributes, ..
        } = public
        else {
            panic!("expected a keyedhash public area");
        };
        assert!(
            object_attributes.user_with_auth(),
            "PIN authValue gates use"
        );
        assert!(object_attributes.fixed_tpm());
        assert!(object_attributes.fixed_parent());
        assert!(
            !object_attributes.no_da(),
            "wrong PINs must count toward DA lockout"
        );
        assert!(
            !object_attributes.sign_encrypt(),
            "a sealed data object neither signs nor decrypts"
        );
        assert!(!object_attributes.decrypt());
    }
}
