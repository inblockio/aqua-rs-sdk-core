use crate::primitives::{HashType, Method, RevisionLink};
use crate::schema::{PreSignature, Signature, SignatureValue};

/// Error type for signing operations.
#[derive(thiserror::Error, Debug)]
pub enum SignError {
    #[error("Key error: {0}")]
    Key(String),
    #[error("Signing failed: {0}")]
    Sign(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
}

/// Error type for signature verification operations.
#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Verification failed: {0}")]
    Failed(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
}

/// Trait for pluggable signers.
///
/// Implementations perform the full V4 signing flow for a target revision:
/// derive signer DID, create PreSignature, canonical JSON, sign, finalize.
///
/// Per spec-implementation.md Section 8.3, the `Signer` trait allows consumers
/// to add custom signers (hardware wallets, HSMs) without forking.
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// Perform the full V4 signing flow for a target revision.
    async fn sign_revision(
        &self,
        target_revision: &RevisionLink,
        method: Method,
        hash_type: HashType,
    ) -> Result<Signature, SignError>;
}

/// Common signing flow for signers that know their DID upfront.
///
/// Used by Ed25519Signer and P256KeySigner. MetaMask implements its own
/// two-phase flow because the signer DID isn't known until the wallet connects.
pub(crate) fn sign_with_presignature(
    target: &RevisionLink,
    method: Method,
    hash_type: HashType,
    signer_did: &str,
    signature_type: &str,
    sign_fn: impl FnOnce(&[u8]) -> Result<SignatureValue, SignError>,
) -> Result<Signature, SignError> {
    let pre_sig = PreSignature::new(target.clone(), method, hash_type, signer_did.to_string());
    let canonical_json = pre_sig.canonical_json(signature_type);
    let sig_value = sign_fn(&canonical_json)?;
    Ok(pre_sig.finalize(sig_value))
}
