use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::error::Error;

/// Result of Ed25519 signing: raw signature bytes + public key bytes.
pub struct Ed25519SignResult {
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}

/// Ed25519 verification error type.
#[derive(thiserror::Error, Debug)]
pub enum VerificationError {
    #[error("Invalid key length: expected 32 bytes")]
    InvalidKeyLength,
    #[error("Invalid signature length: expected 64 bytes")]
    InvalidSignatureLength,
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(ed25519_dalek::SignatureError),
}

/// Generate a fresh Ed25519 signing key and its `did:key:z6Mk...` identity.
///
/// Returns `(secret_key, did)`:
///
/// - `secret_key` is the 32-byte Ed25519 seed, ready to hand to
///   [`SigningCredentials::Did`](crate::schema::SigningCredentials::Did) as
///   `did_key: secret_key.to_vec()`,
/// - `did` is the `did:key:z6Mk...` string that the resulting signatures
///   carry, derived from the matching public key.
///
/// Key material comes from the operating system CSPRNG (`OsRng`) through the
/// same `ed25519-dalek` version this crate signs and verifies with, which is
/// the point: consumers were hand-rolling generation against a possibly
/// different `ed25519-dalek`, where a version skew silently produces keys that
/// do not round-trip.
///
/// Handle the secret like a secret: it is the whole identity. Nothing in this
/// crate persists it.
///
/// ```rust
/// use aqua_rs_sdk_core::generate_ed25519;
/// use aqua_rs_sdk_core::schema::SigningCredentials;
///
/// let (secret, did) = generate_ed25519();
/// assert!(did.starts_with("did:key:z6Mk"));
/// let credentials = SigningCredentials::Did { did_key: secret.to_vec() };
/// let _ = credentials;
/// ```
pub fn generate_ed25519() -> ([u8; 32], String) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let did = crate::primitives::did_key::encode_ed25519(signing_key.verifying_key().as_bytes());
    (signing_key.to_bytes(), did)
}

/// Handles Ed25519 signing operations using `did:key:z6Mk...` identity.
pub struct DIDSigner;

impl DIDSigner {
    pub fn new() -> Self {
        DIDSigner
    }

    /// Derives `did:key:z6Mk...` from a 32-byte Ed25519 private key.
    pub fn derive_did(&self, private_key: &[u8]) -> Result<String, Box<dyn Error>> {
        let signing_key = SigningKey::from_bytes(
            private_key
                .try_into()
                .map_err(|_| "Private key must be exactly 32 bytes")?,
        );
        let verifying_key = signing_key.verifying_key();
        Ok(crate::primitives::did_key::encode_ed25519(
            verifying_key.as_bytes(),
        ))
    }

    /// Signs canonical JSON bytes using Ed25519.
    ///
    /// Returns raw 64-byte signature + 32-byte public key.
    /// The signing input is the raw canonical JSON bytes (no JWS wrapping).
    pub fn sign_canonical(
        &self,
        canonical_json: &[u8],
        private_key: &[u8],
    ) -> Result<Ed25519SignResult, Box<dyn Error>> {
        let signing_key = SigningKey::from_bytes(
            private_key
                .try_into()
                .map_err(|_| "Private key must be exactly 32 bytes")?,
        );
        let verifying_key = signing_key.verifying_key();
        let sig = signing_key.sign(canonical_json);

        Ok(Ed25519SignResult {
            signature: sig.to_bytes(),
            public_key: verifying_key.to_bytes(),
        })
    }

    /// Verifies an Ed25519 signature against canonical JSON bytes.
    pub fn verify_canonical(
        &self,
        signature: &[u8; 64],
        public_key: &[u8; 32],
        expected_canonical_json: &[u8],
    ) -> Result<(), VerificationError> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(VerificationError::SignatureVerificationFailed)?;
        let sig = Signature::from_bytes(signature);
        verifying_key
            .verify_strict(expected_canonical_json, &sig)
            .map_err(VerificationError::SignatureVerificationFailed)
    }
}

impl Default for DIDSigner {
    fn default() -> Self {
        Self::new()
    }
}

/// Ed25519 signer implementing the `Signer` trait.
///
/// Wraps `DIDSigner` for crypto operations and holds the private key material.
pub struct Ed25519Signer {
    private_key: Vec<u8>,
}

impl Ed25519Signer {
    pub fn new(private_key: Vec<u8>) -> Self {
        Self { private_key }
    }
}

#[async_trait::async_trait]
impl super::traits::Signer for Ed25519Signer {
    async fn sign_revision(
        &self,
        target_revision: &crate::primitives::RevisionLink,
        method: crate::primitives::Method,
        hash_type: crate::primitives::HashType,
    ) -> Result<crate::schema::Signature, super::traits::SignError> {
        let did_signer = DIDSigner;

        let signer_did = did_signer
            .derive_did(&self.private_key)
            .map_err(|e| super::traits::SignError::Key(e.to_string()))?;

        let private_key = self.private_key.clone();
        super::traits::sign_with_presignature(
            target_revision,
            method,
            hash_type,
            &signer_did,
            "ed25519",
            |canonical_json| {
                let result = did_signer
                    .sign_canonical(canonical_json, &private_key)
                    .map_err(|e| super::traits::SignError::Sign(e.to_string()))?;
                Ok(crate::schema::SignatureValue::Ed25519 {
                    signature: result.signature,
                    signature_public_identifier: result.public_key,
                })
            },
        )
    }
}

#[cfg(test)]
mod generate_tests {
    use super::*;

    #[test]
    fn generated_key_derives_the_returned_did() {
        let (secret, did) = generate_ed25519();
        assert_eq!(
            DIDSigner.derive_did(&secret).unwrap(),
            did,
            "the returned DID must be the one this crate derives from the key"
        );
        assert!(
            did.starts_with("did:key:z6Mk"),
            "unexpected DID form: {did}"
        );
    }

    #[test]
    fn generated_keys_are_distinct() {
        let (a, did_a) = generate_ed25519();
        let (b, did_b) = generate_ed25519();
        assert_ne!(a, b, "two generations returned the same secret");
        assert_ne!(did_a, did_b);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn generated_key_signs_a_tree_that_verifies() {
        use crate::schema::{AquaTreeWrapper, SigningCredentials};
        use crate::{primitives::RevisionLink, schema::template::BuiltInTemplate};

        let (secret, did) = generate_ed25519();
        let aquafier = crate::Aquafier::new();
        let tree = aquafier
            .create_object(
                RevisionLink::from_bytes(
                    crate::schema::templates::AuditUserTurnMarker::TEMPLATE_LINK,
                ),
                None,
                serde_json::json!({
                    "signer_did": did,
                    "session_id": "generated-key-session",
                    "turn_index": 0,
                    "opens_at": 1754500000u64,
                }),
                None,
            )
            .unwrap();
        let signed = aquafier
            .sign_aqua_tree(
                AquaTreeWrapper::new(tree, None, None),
                &SigningCredentials::Did {
                    did_key: secret.to_vec(),
                },
                None,
                None,
            )
            .await
            .unwrap();
        let result = aquafier
            .verify_aqua_tree(AquaTreeWrapper::new(signed.aqua_tree, None, None), vec![])
            .await
            .unwrap();
        assert!(
            result.is_verified(),
            "a tree signed with a generated key must verify: {:?}",
            result.logs
        );
    }
}
