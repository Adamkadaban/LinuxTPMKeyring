//! ESAPI plumbing shared by every later seal/unseal: the ECC storage primary template, primary
//! creation under the owner hierarchy, and the salted HMAC + parameter-encryption session that
//! protects the PIN authValue and unsealed key against TPM bus interposers.

use tss_esapi::Context;
use tss_esapi::attributes::session::{SessionAttributes, SessionAttributesMask};
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    CreatePrimaryKeyResult, EccPoint, Public, PublicBuilder, PublicEccParametersBuilder,
    SymmetricDefinition, SymmetricDefinitionObject,
};

/// Errors from the `tess-tpm` ESAPI layer. Wrap the underlying `tss-esapi` error as a string so the
/// detail is preserved without leaking the crate's types across the public boundary. At the crate
/// edge the auth-related variants (`WrongPin`/`PinTooLong`/`PinEmpty`) map to
/// [`tess_core::Error::Auth`]; everything else maps to [`tess_core::Error::Tpm`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid TCTI configuration: {0}")]
    Tcti(String),

    #[error("failed to open ESAPI context: {0}")]
    Context(String),

    #[error("failed to build TPM object template: {0}")]
    Template(String),

    #[error("failed to create ECC primary: {0}")]
    Primary(String),

    #[error("failed to start salted HMAC session: {0}")]
    Session(String),

    #[error("TPM returned no session handle")]
    NoSession,

    #[error("failed to compute or run the PIN policy: {0}")]
    Policy(String),

    #[error("failed to generate the sealing key: {0}")]
    Rng(String),

    #[error("PIN is {len} bytes, exceeds the {max}-byte authValue limit")]
    PinTooLong { len: usize, max: usize },

    #[error("PIN must not be empty")]
    PinEmpty,

    #[error("failed to seal the key: {0}")]
    Seal(String),

    #[error("failed to load the sealed object: {0}")]
    Load(String),

    #[error("failed to unseal the key: {0}")]
    Unseal(String),

    #[error("failed to read a TPM capability: {0}")]
    Capability(String),

    #[error("TPM is in dictionary-attack lockout")]
    Lockout,

    #[error("failed to set the TPM lockout-hierarchy authValue: {0}")]
    LockoutAuth(String),

    #[error("failed to reset the TPM dictionary-attack lockout: {0}")]
    LockoutReset(String),

    #[error("failed to flush a transient TPM handle: {0}")]
    Flush(String),

    #[error("wrong PIN")]
    WrongPin,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for tess_core::Error {
    fn from(e: Error) -> Self {
        match e {
            // A wrong PIN is an authentication failure, not a TPM fault — keep it distinguishable so
            // the enrollment/recovery layers can react (retry, count toward lockout) rather than
            // treating it as a hardware error. PinTooLong is likewise local input validation, not a
            // TPM fault.
            Error::WrongPin | Error::PinTooLong { .. } | Error::PinEmpty => {
                tess_core::Error::Auth(e.to_string())
            }
            // DA lockout is neither a wrong PIN nor a hardware fault: surface it distinctly so the
            // enrollment/recovery layers can prompt for a lockout reset or recovery secret rather
            // than retrying a PIN that will be rejected regardless.
            Error::Lockout => tess_core::Error::Lockout(
                "too many failed PIN attempts; locked out until the lockout interval elapses"
                    .to_string(),
            ),
            other => tess_core::Error::Tpm(other.to_string()),
        }
    }
}

/// Deterministic template for the storage primary: an ECC NIST-P256 **restricted decryption**
/// (storage) key under the owner hierarchy, AES-128-CFB as the child-protection symmetric, SHA-256
/// name hash. Fixed-TPM/fixed-parent/sensitive-data-origin so the key is reproducible from the seed
/// and never leaves the TPM. No TPM is required to build this, so it is unit-testable on any host.
pub fn ecc_storage_primary_template() -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .map_err(|e| Error::Template(e.to_string()))?;

    let ecc_parameters = PublicEccParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        EccCurve::NistP256,
    )
    .build()
    .map_err(|e| Error::Template(e.to_string()))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| Error::Template(e.to_string()))
}

/// Create the ECC storage primary under [`Hierarchy::Owner`] from [`ecc_storage_primary_template`].
/// The primary itself carries no authValue — the PIN binds the *sealed object*, not the storage
/// root. Owner-hierarchy authorization uses a transient null-auth HMAC session that the ESAPI helper
/// sets up, encrypts, and flushes automatically.
pub fn create_primary(context: &mut Context) -> Result<CreatePrimaryKeyResult> {
    let public = ecc_storage_primary_template()?;
    context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .map_err(|e: tss_esapi::Error| Error::Primary(e.to_string()))
}

/// Start the salted HMAC + parameter-encryption auth session every later seal/unseal runs under.
///
/// Salting with the storage `primary` (passed as the session's tpmKey) and enabling **decrypt +
/// encrypt** parameter encryption with an AES-128-CFB / SHA-256 session means the PIN authValue and
/// the unsealed blob are encrypted and integrity-protected on the TPM bus — defeating an interposer
/// that sniffs PCR-only-sealed secrets off the wire. `continue_session` keeps the session alive
/// across the multiple commands a seal/unseal performs.
pub fn start_salted_hmac_session(context: &mut Context, primary: KeyHandle) -> Result<AuthSession> {
    let session = context
        .start_auth_session(
            Some(primary),
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| Error::Session(e.to_string()))?
        .ok_or(Error::NoSession)?;

    let (attributes, mask) = encrypted_session_attributes();

    context
        .tr_sess_set_attributes(session, attributes, mask)
        .map_err(|e| Error::Session(e.to_string()))?;

    Ok(session)
}

/// The session attributes every seal/unseal session carries: **decrypt + encrypt** parameter
/// encryption (so the PIN authValue travelling to the TPM and the unsealed key travelling back are
/// both encrypted on the bus) plus `continue_session` (so the session survives the several commands
/// one seal/unseal issues). Shared by the HMAC session here and the policy session in `seal`, and
/// asserted by tests so a regression that drops parameter encryption fails the build. ESAPI offers
/// no getter for a live session's attributes, so the attribute set is factored out here and tested
/// at its source rather than read back off the started session.
pub(crate) fn encrypted_session_attributes() -> (SessionAttributes, SessionAttributesMask) {
    SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .with_continue_session(true)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_template_is_ecc_p256_restricted_storage_key() {
        let public = ecc_storage_primary_template().expect("template builds without a TPM");

        let Public::Ecc {
            object_attributes,
            parameters,
            unique,
            ..
        } = public
        else {
            panic!("expected an ECC public area");
        };

        assert!(object_attributes.restricted(), "must be a restricted key");
        assert!(object_attributes.decrypt(), "storage keys decrypt");
        assert!(
            !object_attributes.sign_encrypt(),
            "storage keys do not sign"
        );
        assert!(object_attributes.fixed_tpm(), "primary must be fixed-tpm");
        assert!(
            object_attributes.fixed_parent(),
            "primary must be fixed-parent"
        );
        assert!(object_attributes.sensitive_data_origin());
        assert!(object_attributes.user_with_auth());

        assert_eq!(parameters.ecc_curve(), EccCurve::NistP256);
        assert_eq!(
            parameters.symmetric_definition_object(),
            SymmetricDefinitionObject::AES_128_CFB,
            "children are wrapped with AES-128-CFB"
        );

        assert_eq!(
            unique,
            EccPoint::default(),
            "deterministic template seeds an empty unique point"
        );
    }

    #[test]
    fn seal_unseal_sessions_enable_parameter_encryption() {
        // Security invariant: every seal/unseal session must be parameter-encrypted in both
        // directions, so neither the PIN authValue nor the unsealed key crosses the TPM bus in the
        // clear. Dropping `with_decrypt`/`with_encrypt` from the shared attributes must fail here.
        let (attributes, mask) = encrypted_session_attributes();

        assert!(
            attributes.decrypt(),
            "command-parameter decrypt must be set so the PIN authValue is encrypted to the TPM"
        );
        assert!(
            attributes.encrypt(),
            "response-parameter encrypt must be set so the unsealed key is encrypted from the TPM"
        );
        assert!(
            attributes.continue_session(),
            "the session must persist across the multiple commands of a seal/unseal"
        );

        // The mask must actually cover the bits we set, otherwise `tr_sess_set_attributes` would
        // silently leave them unchanged on the live session.
        const CONTINUE_BIT: u8 = 1 << 0;
        const DECRYPT_BIT: u8 = 1 << 5;
        const ENCRYPT_BIT: u8 = 1 << 6;
        let raw_mask = u8::from(mask);
        assert_eq!(
            raw_mask & (CONTINUE_BIT | DECRYPT_BIT | ENCRYPT_BIT),
            CONTINUE_BIT | DECRYPT_BIT | ENCRYPT_BIT,
            "the attribute mask must apply the continue_session, decrypt, and encrypt bits"
        );
    }
}
