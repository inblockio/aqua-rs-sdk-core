use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use std::error::Error;

/// Result of P-256 signing: raw 64-byte signature (r || s) + 33-byte compressed public key.
pub struct P256SignResult {
    pub signature: [u8; 64],
    pub public_key: [u8; 33],
}

/// P-256 verification error type.
#[derive(thiserror::Error, Debug)]
pub enum P256VerificationError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(p256::ecdsa::Error),
}

/// Handles ECDSA P-256 signing operations using `did:key:zDn...` identity.
pub struct P256Signer;

impl P256Signer {
    pub fn new() -> Self {
        P256Signer
    }

    /// Derives `did:key:zDn...` from a 32-byte P-256 private key scalar.
    pub fn derive_did(&self, private_key: &[u8]) -> Result<String, Box<dyn Error>> {
        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| format!("Invalid P-256 private key: {e}"))?;
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        let compressed_bytes: [u8; 33] = compressed
            .as_bytes()
            .try_into()
            .map_err(|_| "Compressed P-256 public key must be exactly 33 bytes")?;
        Ok(crate::primitives::did_key::encode_p256(&compressed_bytes))
    }

    /// Signs canonical JSON bytes using ECDSA P-256 (with SHA-256, per RFC 6979).
    ///
    /// Returns raw 64-byte signature (r || s) + 33-byte compressed SEC1 public key.
    pub fn sign_canonical(
        &self,
        canonical_json: &[u8],
        private_key: &[u8],
    ) -> Result<P256SignResult, Box<dyn Error>> {
        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| format!("Invalid P-256 private key: {e}"))?;
        let verifying_key = signing_key.verifying_key();
        let sig: Signature = signing_key.sign(canonical_json);
        let compressed = verifying_key.to_encoded_point(true);

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig.to_bytes());

        let mut pubkey_array = [0u8; 33];
        pubkey_array.copy_from_slice(compressed.as_bytes());

        Ok(P256SignResult {
            signature: sig_array,
            public_key: pubkey_array,
        })
    }

    /// Verifies an ECDSA P-256 signature against canonical JSON bytes.
    pub fn verify_canonical(
        &self,
        signature: &[u8; 64],
        public_key: &[u8; 33],
        expected_canonical_json: &[u8],
    ) -> Result<(), P256VerificationError> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| P256VerificationError::InvalidPublicKey(e.to_string()))?;
        let sig = Signature::from_slice(signature)
            .map_err(|e| P256VerificationError::InvalidSignature(e.to_string()))?;
        verifying_key
            .verify(expected_canonical_json, &sig)
            .map_err(P256VerificationError::SignatureVerificationFailed)
    }
}

impl Default for P256Signer {
    fn default() -> Self {
        Self::new()
    }
}

/// P-256 signer implementing the `Signer` trait.
///
/// Named `P256KeySigner` (not `P256Signer`) to avoid conflicting with the
/// existing `P256Signer` crypto helper used in ~13 test sites.
pub struct P256KeySigner {
    private_key: Vec<u8>,
}

impl P256KeySigner {
    pub fn new(private_key: Vec<u8>) -> Self {
        Self { private_key }
    }
}

#[async_trait::async_trait]
impl super::traits::Signer for P256KeySigner {
    async fn sign_revision(
        &self,
        target_revision: &crate::primitives::RevisionLink,
        method: crate::primitives::Method,
        hash_type: crate::primitives::HashType,
    ) -> Result<crate::schema::Signature, super::traits::SignError> {
        let p256_signer = P256Signer;

        let signer_did = p256_signer
            .derive_did(&self.private_key)
            .map_err(|e| super::traits::SignError::Key(e.to_string()))?;

        let private_key = self.private_key.clone();
        super::traits::sign_with_presignature(
            target_revision,
            method,
            hash_type,
            &signer_did,
            "ecdsa:p256",
            |canonical_json| {
                let result = p256_signer
                    .sign_canonical(canonical_json, &private_key)
                    .map_err(|e| super::traits::SignError::Sign(e.to_string()))?;
                Ok(crate::schema::SignatureValue::P256 {
                    signature: result.signature,
                    signature_public_identifier: result.public_key,
                })
            },
        )
    }
}
