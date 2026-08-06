use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// WebAuthn P-256 verification error type.
#[derive(thiserror::Error, Debug)]
pub enum WebAuthnVerificationError {
    #[error("authenticator_data must be at least 37 bytes, got {0}")]
    AuthDataTooShort(usize),
    #[error("UP (User Present) flag not set in authenticator_data")]
    UserNotPresent,
    #[error("clientDataJSON is not valid JSON: {0}")]
    InvalidClientDataJson(String),
    #[error("clientDataJSON type must be \"webauthn.get\", got \"{0}\"")]
    WrongType(String),
    #[error("clientDataJSON challenge field missing or invalid base64url")]
    InvalidChallenge,
    #[error("challenge mismatch: expected {expected}, got {actual}")]
    ChallengeMismatch { expected: String, actual: String },
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("P-256 signature verification failed: {0}")]
    SignatureVerificationFailed(p256::ecdsa::Error),
}

/// Verifies a WebAuthn assertion signature (P-256).
///
/// The signed payload in WebAuthn is: `authenticator_data || SHA-256(client_data_json)`.
/// The `expected_challenge` is the SHA-256 of the pre-signature canonical JSON,
/// which the relying party embedded in the client data at assertion time.
pub fn verify_webauthn_signature(
    signature: &[u8; 64],
    public_key: &[u8; 33],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    expected_challenge: &[u8; 32],
) -> Result<(), WebAuthnVerificationError> {
    // 1. Check authenticator_data length (rpIdHash:32 + flags:1 + signCount:4 = 37 minimum)
    if authenticator_data.len() < 37 {
        return Err(WebAuthnVerificationError::AuthDataTooShort(
            authenticator_data.len(),
        ));
    }

    // 2. Check UP (User Present) flag: bit 0 of flags byte (index 32)
    if authenticator_data[32] & 0x01 == 0 {
        return Err(WebAuthnVerificationError::UserNotPresent);
    }

    // 3. Parse clientDataJSON
    let client_data: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| WebAuthnVerificationError::InvalidClientDataJson(e.to_string()))?;

    // 4. Verify type == "webauthn.get"
    let cdj_type = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if cdj_type != "webauthn.get" {
        return Err(WebAuthnVerificationError::WrongType(cdj_type.to_string()));
    }

    // 5. base64url-decode the challenge field, compare to expected_challenge
    let challenge_b64 = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or(WebAuthnVerificationError::InvalidChallenge)?;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(challenge_b64)
        .map_err(|_| WebAuthnVerificationError::InvalidChallenge)?;

    if challenge_bytes.as_slice() != expected_challenge.as_slice() {
        return Err(WebAuthnVerificationError::ChallengeMismatch {
            expected: hex::encode(expected_challenge),
            actual: hex::encode(&challenge_bytes),
        });
    }

    // 6. Compute signed_payload = authenticator_data || SHA-256(client_data_json)
    let client_data_hash = Sha256::digest(client_data_json);
    let mut signed_payload = Vec::with_capacity(authenticator_data.len() + 32);
    signed_payload.extend_from_slice(authenticator_data);
    signed_payload.extend_from_slice(&client_data_hash);

    // 7. Verify P-256 signature over signed_payload
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| WebAuthnVerificationError::InvalidPublicKey(e.to_string()))?;
    let sig = Signature::from_slice(signature)
        .map_err(|e| WebAuthnVerificationError::InvalidSignature(e.to_string()))?;
    verifying_key
        .verify(&signed_payload, &sig)
        .map_err(WebAuthnVerificationError::SignatureVerificationFailed)
}

/// Result of a WebAuthn assertion (returned by the bridge).
pub struct WebAuthnAssertionResult {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: [u8; 64],
}

/// Bridge trait for obtaining WebAuthn assertions from a platform authenticator.
///
/// Implementations might call into the browser WebAuthn API, a CTAP2 device,
/// or a synthetic test bridge.
#[async_trait::async_trait]
pub trait WebAuthnBridge: Send + Sync {
    async fn get_assertion(
        &self,
        challenge: &[u8; 32],
        credential_id: &[u8],
        rp_id: &str,
    ) -> Result<WebAuthnAssertionResult, super::traits::SignError>;
}

/// WebAuthn signer implementing the `Signer` trait.
///
/// Delegates to a [`WebAuthnBridge`] for the platform-specific assertion ceremony,
/// then assembles the resulting `SignatureValue::WebAuthn`.
pub struct WebAuthnKeySigner<B: WebAuthnBridge> {
    bridge: B,
    credential_id: Vec<u8>,
    rp_id: String,
    public_key: [u8; 33],
}

impl<B: WebAuthnBridge> WebAuthnKeySigner<B> {
    pub fn new(bridge: B, credential_id: Vec<u8>, rp_id: String, public_key: [u8; 33]) -> Self {
        Self {
            bridge,
            credential_id,
            rp_id,
            public_key,
        }
    }
}

#[async_trait::async_trait]
impl<B: WebAuthnBridge> super::traits::Signer for WebAuthnKeySigner<B> {
    async fn sign_revision(
        &self,
        target_revision: &crate::primitives::RevisionLink,
        method: crate::primitives::Method,
        hash_type: crate::primitives::HashType,
    ) -> Result<crate::schema::Signature, super::traits::SignError> {
        // Derive DID from compressed public key
        let signer_did = crate::primitives::did_key::encode_p256(&self.public_key);

        // Create PreSignature
        let pre_sig = crate::schema::PreSignature::new(
            target_revision.clone(),
            method,
            hash_type,
            signer_did,
        );

        // Compute canonical JSON and challenge
        let canonical_json = pre_sig.canonical_json("webauthn:p256");
        let challenge: [u8; 32] = Sha256::digest(&canonical_json).into();

        // Perform assertion via bridge
        let assertion = self
            .bridge
            .get_assertion(&challenge, &self.credential_id, &self.rp_id)
            .await?;

        // Assemble signature value
        let sig_value = crate::schema::SignatureValue::WebAuthn {
            signature: assertion.signature,
            signature_public_identifier: self.public_key,
            authenticator_data: assertion.authenticator_data,
            client_data_json: assertion.client_data_json,
        };

        Ok(pre_sig.finalize(sig_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer as _, SigningKey};
    use sha2::{Digest, Sha256};

    /// Build synthetic authenticatorData with a given rpIdHash and UP flag set.
    fn build_authenticator_data(rp_id: &str, up_flag: bool) -> Vec<u8> {
        let rp_id_hash = Sha256::digest(rp_id.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_id_hash); // 32 bytes rpIdHash
        let flags: u8 = if up_flag { 0x01 } else { 0x00 };
        auth_data.push(flags); // 1 byte flags
        auth_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 4 bytes signCount
        auth_data
    }

    /// Build synthetic clientDataJSON with the given challenge.
    fn build_client_data_json(challenge: &[u8; 32], cdj_type: &str) -> Vec<u8> {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
        let json = format!(
            r#"{{"type":"{}","challenge":"{}","origin":"https://example.com","crossOrigin":false}}"#,
            cdj_type, challenge_b64
        );
        json.into_bytes()
    }

    /// Sign the WebAuthn payload: authenticator_data || SHA-256(client_data_json)
    fn sign_webauthn_payload(
        signing_key: &SigningKey,
        authenticator_data: &[u8],
        client_data_json: &[u8],
    ) -> [u8; 64] {
        let client_data_hash = Sha256::digest(client_data_json);
        let mut payload = Vec::with_capacity(authenticator_data.len() + 32);
        payload.extend_from_slice(authenticator_data);
        payload.extend_from_slice(&client_data_hash);

        let sig: p256::ecdsa::Signature = signing_key.sign(&payload);
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig.to_bytes());
        sig_array
    }

    fn test_keypair() -> (SigningKey, [u8; 33]) {
        let private_key_bytes: [u8; 32] = [
            42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
        ];
        let signing_key = SigningKey::from_slice(&private_key_bytes).unwrap();
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(compressed.as_bytes());
        (signing_key, pubkey)
    }

    #[test]
    fn verify_valid_assertion() {
        let (signing_key, pubkey) = test_keypair();
        let challenge: [u8; 32] = Sha256::digest(b"test canonical json").into();

        let auth_data = build_authenticator_data("example.com", true);
        let client_data = build_client_data_json(&challenge, "webauthn.get");
        let sig = sign_webauthn_payload(&signing_key, &auth_data, &client_data);

        let result = verify_webauthn_signature(&sig, &pubkey, &auth_data, &client_data, &challenge);
        assert!(result.is_ok(), "Valid assertion should verify: {result:?}");
    }

    #[test]
    fn reject_wrong_challenge() {
        let (signing_key, pubkey) = test_keypair();
        let challenge: [u8; 32] = Sha256::digest(b"correct challenge").into();
        let wrong_challenge: [u8; 32] = Sha256::digest(b"wrong challenge").into();

        let auth_data = build_authenticator_data("example.com", true);
        let client_data = build_client_data_json(&challenge, "webauthn.get");
        let sig = sign_webauthn_payload(&signing_key, &auth_data, &client_data);

        let result =
            verify_webauthn_signature(&sig, &pubkey, &auth_data, &client_data, &wrong_challenge);
        assert!(result.is_err(), "Wrong challenge should be rejected");
        assert!(
            matches!(
                result,
                Err(WebAuthnVerificationError::ChallengeMismatch { .. })
            ),
            "Should be a ChallengeMismatch error"
        );
    }

    #[test]
    fn reject_tampered_auth_data() {
        let (signing_key, pubkey) = test_keypair();
        let challenge: [u8; 32] = Sha256::digest(b"test challenge").into();

        let auth_data = build_authenticator_data("example.com", true);
        let client_data = build_client_data_json(&challenge, "webauthn.get");
        let sig = sign_webauthn_payload(&signing_key, &auth_data, &client_data);

        // Tamper with auth_data after signing
        let mut tampered_auth_data = auth_data.clone();
        tampered_auth_data[0] ^= 0xFF;

        let result =
            verify_webauthn_signature(&sig, &pubkey, &tampered_auth_data, &client_data, &challenge);
        assert!(
            result.is_err(),
            "Tampered auth data should fail verification"
        );
        assert!(
            matches!(
                result,
                Err(WebAuthnVerificationError::SignatureVerificationFailed(_))
            ),
            "Should be a SignatureVerificationFailed error"
        );
    }

    #[test]
    fn reject_up_flag_not_set() {
        let (signing_key, pubkey) = test_keypair();
        let challenge: [u8; 32] = Sha256::digest(b"test challenge").into();

        let auth_data = build_authenticator_data("example.com", false); // UP not set
        let client_data = build_client_data_json(&challenge, "webauthn.get");
        let sig = sign_webauthn_payload(&signing_key, &auth_data, &client_data);

        let result = verify_webauthn_signature(&sig, &pubkey, &auth_data, &client_data, &challenge);
        assert!(result.is_err(), "Missing UP flag should be rejected");
        assert!(
            matches!(result, Err(WebAuthnVerificationError::UserNotPresent)),
            "Should be a UserNotPresent error"
        );
    }

    #[test]
    fn reject_wrong_type() {
        let (signing_key, pubkey) = test_keypair();
        let challenge: [u8; 32] = Sha256::digest(b"test challenge").into();

        let auth_data = build_authenticator_data("example.com", true);
        // Use "webauthn.create" instead of "webauthn.get"
        let client_data = build_client_data_json(&challenge, "webauthn.create");
        let sig = sign_webauthn_payload(&signing_key, &auth_data, &client_data);

        let result = verify_webauthn_signature(&sig, &pubkey, &auth_data, &client_data, &challenge);
        assert!(result.is_err(), "Wrong type should be rejected");
        assert!(
            matches!(result, Err(WebAuthnVerificationError::WrongType(ref t)) if t == "webauthn.create"),
            "Should be a WrongType error, got: {result:?}"
        );
    }

    #[test]
    fn reject_short_auth_data() {
        let (_, pubkey) = test_keypair();
        let challenge: [u8; 32] = [0u8; 32];
        let short_auth_data = vec![0u8; 36]; // Less than 37 bytes
        let client_data = build_client_data_json(&challenge, "webauthn.get");
        let sig = [0u8; 64];

        let result =
            verify_webauthn_signature(&sig, &pubkey, &short_auth_data, &client_data, &challenge);
        assert!(result.is_err(), "Short auth data should be rejected");
        assert!(
            matches!(result, Err(WebAuthnVerificationError::AuthDataTooShort(36))),
            "Should be AuthDataTooShort(36), got: {result:?}"
        );
    }

    // ── Integration test: WebAuthnKeySigner roundtrip via SyntheticBridge ──

    /// A synthetic WebAuthn bridge for testing that performs the assertion
    /// ceremony entirely in software with a known P-256 key.
    struct SyntheticBridge {
        signing_key: SigningKey,
    }

    #[async_trait::async_trait]
    impl WebAuthnBridge for SyntheticBridge {
        async fn get_assertion(
            &self,
            challenge: &[u8; 32],
            _credential_id: &[u8],
            rp_id: &str,
        ) -> Result<WebAuthnAssertionResult, super::super::traits::SignError> {
            let auth_data = build_authenticator_data(rp_id, true);
            let client_data = build_client_data_json(challenge, "webauthn.get");
            let sig = sign_webauthn_payload(&self.signing_key, &auth_data, &client_data);

            Ok(WebAuthnAssertionResult {
                authenticator_data: auth_data,
                client_data_json: client_data,
                signature: sig,
            })
        }
    }

    #[tokio::test]
    async fn webauthn_signer_roundtrip_verify() {
        use crate::core::genesis::create_genesis_revision;
        use crate::core::signature::verify_signature_sync;
        use crate::primitives::{HashType, Method};
        use crate::schema::{AnyRevision, FileData};
        use crate::verification::Linkable;
        use std::path::PathBuf;

        let (signing_key, pubkey) = test_keypair();

        let bridge = SyntheticBridge { signing_key };
        let signer = WebAuthnKeySigner::new(
            bridge,
            b"test-credential-id".to_vec(),
            "example.com".to_string(),
            pubkey,
        );

        // Create a genesis tree
        let file_data = FileData::new(
            "test.txt".to_string(),
            b"hello webauthn".to_vec(),
            PathBuf::from("test.txt"),
        );
        let tree = create_genesis_revision(file_data, Method::Scalar).unwrap();
        let genesis_hash = tree.get_latest_revision_link().unwrap();

        // Sign via the Signer trait
        use super::super::traits::Signer;
        let signature_revision = signer
            .sign_revision(&genesis_hash, Method::Scalar, HashType::Sha3_256)
            .await
            .expect("WebAuthn signing should succeed");

        // Verify the signature type
        assert_eq!(
            signature_revision.signature().signature_type(),
            "webauthn:p256"
        );

        // Compute the revision link
        let sig_link = signature_revision
            .calculate_link(HashType::Sha3_256)
            .unwrap();

        // Verify through verify_signature_sync
        let any_rev = AnyRevision::Signature(signature_revision);
        let (ok, logs) = verify_signature_sync(&any_rev, &sig_link.to_string(), None);
        assert!(
            ok,
            "WebAuthn signature verification should succeed. Logs: {logs:?}"
        );
    }
}
