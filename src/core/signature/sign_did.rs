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
