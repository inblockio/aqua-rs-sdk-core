use crate::{
    core::signature::{sign_did::DIDSigner, sign_p256::P256Signer},
    primitives::{
        log::{LogData, LogType},
        HashType, Method, MethodError, RevisionLink,
    },
    schema::{
        credentials::SigningCredentials, tree::Tree, AnyRevision, AquaOperationData,
        AquaTreeWrapper, Signature, SignatureValue,
    },
    verification::Linkable,
};
pub mod sign_did;
pub mod sign_eth;
pub mod sign_p256;
pub mod sign_webauthn;
pub mod traits;

/// Signs an Aqua Tree revision using a `Signer` trait object.
///
/// This is the trait-based dispatch entry point. All signing flows go through here.
pub async fn sign_aqua_tree_with_signer(
    aqua_tree_wrapper: &AquaTreeWrapper,
    signer: &dyn traits::Signer,
    canonicalization_method: Method,
    ident_character: Option<String>,
) -> Result<AquaOperationData, MethodError> {
    let mut aqua_tree = aqua_tree_wrapper.aqua_tree.clone();
    let mut logs: Vec<LogData> = Vec::new();
    let ident = ident_character.unwrap_or_default();

    let target_revision_hash = if let Some(rev) = aqua_tree_wrapper.revision.as_ref() {
        rev.clone()
    } else {
        aqua_tree.get_latest_revision_link().ok_or_else(|| {
            MethodError::WithLogs(vec![LogData {
                log: "No revisions found".to_string(),
                log_type: LogType::Error,
                ident: Some(ident.clone()),
            }])
        })?
    };

    // A signature commits to its target's algorithm, recovered from the target's
    // addressing multihash code (PCA-0015 §3.5/§3.10).
    let hash_type = target_revision_hash
        .hash_type()
        .unwrap_or(HashType::Sha3_256);

    let signature_revision = signer
        .sign_revision(&target_revision_hash, canonicalization_method, hash_type)
        .await
        .map_err(|e| {
            logs.push(LogData {
                log: format!("Signing failed: {e}"),
                log_type: LogType::Error,
                ident: Some(ident.clone()),
            });
            MethodError::WithLogs(logs.clone())
        })?;

    let verification_hash = signature_revision.calculate_link(hash_type).map_err(|e| {
        logs.push(LogData {
            log: format!("Failed to calculate verification hash: {e}"),
            log_type: LogType::Error,
            ident: Some(ident.clone()),
        });
        MethodError::WithLogs(logs.clone())
    })?;

    aqua_tree.revisions.insert(
        verification_hash,
        AnyRevision::Signature(signature_revision),
    );

    logs.push(LogData {
        log: "AquaTree signed successfully".to_string(),
        log_type: LogType::Success,
        ident: Some(ident.clone()),
    });

    Ok(AquaOperationData {
        aqua_tree,
        aqua_trees: vec![],
        log_data: logs,
    })
}

/// Signs an Aqua Tree revision using V4 spec protocol.
///
/// Thin wrapper over `sign_aqua_tree_with_signer` — converts `SigningCredentials`
/// into a `Signer` trait object and delegates.
pub async fn sign_aqua_tree_util(
    aqua_tree_wrapper: &AquaTreeWrapper,
    credentials: &SigningCredentials,
    canonicalization_method: Method,
    ident_character: Option<String>,
) -> Result<AquaOperationData, MethodError> {
    let ident = ident_character.clone().unwrap_or_default();
    let signer = credentials.into_signer().map_err(|e| {
        MethodError::WithLogs(vec![LogData {
            log: format!("Failed to create signer: {e}"),
            log_type: LogType::Error,
            ident: Some(ident.clone()),
        }])
    })?;
    sign_aqua_tree_with_signer(
        aqua_tree_wrapper,
        signer.as_ref(),
        canonicalization_method,
        ident_character,
    )
    .await
}

/// Recovers the Ethereum wallet address from an EIP-191 personal_sign signature.
pub fn recover_wallet_address(
    message: &str,
    signature: &[u8; 65],
) -> Result<[u8; 20], Box<dyn std::error::Error>> {
    // Decompose [u8; 65] into r+s (64 bytes) and v (1 byte)
    let v = signature[64];
    let recovery_id = k256::ecdsa::RecoveryId::try_from(if v >= 27 { v - 27 } else { v })
        .map_err(|e| format!("Invalid recovery id: {e}"))?;
    let sig = k256::ecdsa::Signature::from_slice(&signature[..64])
        .map_err(|e| format!("Invalid signature: {e}"))?;

    // EIP-191 message prefix
    let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
    let msg_hash = sign_eth::sha3_keccak256(prefixed.as_bytes());

    let recovered_key =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&msg_hash, &sig, recovery_id)
            .map_err(|e| format!("Recovery failed: {e}"))?;

    Ok(sign_eth::pubkey_to_address(&recovered_key))
}

/// Verify a [`SignatureValue`] against pre-signature canonical JSON bytes.
///
/// This is the single dispatch point for all signature algorithms. Adding a
/// new algorithm means adding one arm here (and the corresponding
/// `SignatureValue` variant).
pub fn verify_signature_value(
    sig: &SignatureValue,
    canonical_json: &[u8],
) -> Result<(), traits::VerifyError> {
    match sig {
        SignatureValue::Eip191 {
            signature,
            signature_public_identifier,
        } => {
            let canonical_str = String::from_utf8(canonical_json.to_vec())
                .map_err(|e| traits::VerifyError::Failed(format!("invalid UTF-8: {e}")))?;
            let recovered = recover_wallet_address(&canonical_str, signature)
                .map_err(|e| traits::VerifyError::Failed(format!("recovery error: {e}")))?;
            if &recovered == signature_public_identifier {
                Ok(())
            } else {
                Err(traits::VerifyError::Failed(format!(
                    "address mismatch: expected {:?}, got {:?}",
                    signature_public_identifier, recovered
                )))
            }
        }
        SignatureValue::Ed25519 {
            signature,
            signature_public_identifier,
        } => DIDSigner
            .verify_canonical(signature, signature_public_identifier, canonical_json)
            .map_err(|e| traits::VerifyError::Failed(e.to_string())),
        SignatureValue::P256 {
            signature,
            signature_public_identifier,
        } => P256Signer
            .verify_canonical(signature, signature_public_identifier, canonical_json)
            .map_err(|e| traits::VerifyError::Failed(e.to_string())),
        SignatureValue::WebAuthn {
            signature,
            signature_public_identifier,
            authenticator_data,
            client_data_json,
        } => {
            use sha2::{Digest, Sha256};
            let expected_challenge: [u8; 32] = Sha256::digest(canonical_json).into();
            sign_webauthn::verify_webauthn_signature(
                signature,
                signature_public_identifier,
                authenticator_data,
                client_data_json,
                &expected_challenge,
            )
            .map_err(|e| traits::VerifyError::Failed(e.to_string()))
        }
    }
}

/// The identity a signature attributes itself to, canonicalized to raw key
/// material so the two wire forms of one key compare equal.
///
/// Comparison is on key bytes, never on DID strings: one physical Ed25519 key
/// has both a `did:key:z6Mk…` form (SDK) and a `did:pkh:ed25519:0x…` form
/// (aqua-auth), and both must be recognized as the same identity (issue #65).
#[derive(Debug, PartialEq, Eq)]
enum SignerIdentity {
    /// EIP-191 / `did:pkh:eip155`: 20-byte Ethereum address.
    Eip155([u8; 20]),
    /// Ed25519 / `did:key:z6Mk…` / `did:pkh:ed25519`: 32-byte public key.
    Ed25519([u8; 32]),
    /// P-256 / WebAuthn / `did:key:zDn…`: 33-byte compressed public key.
    P256([u8; 33]),
}

impl SignerIdentity {
    /// The identity actually proven by the (already crypto-verified) signature:
    /// the embedded `signature_public_identifier`.
    fn from_signature(sig: &SignatureValue) -> Self {
        match sig {
            SignatureValue::Eip191 {
                signature_public_identifier,
                ..
            } => SignerIdentity::Eip155(*signature_public_identifier),
            SignatureValue::Ed25519 {
                signature_public_identifier,
                ..
            } => SignerIdentity::Ed25519(*signature_public_identifier),
            SignatureValue::P256 {
                signature_public_identifier,
                ..
            }
            | SignatureValue::WebAuthn {
                signature_public_identifier,
                ..
            } => SignerIdentity::P256(*signature_public_identifier),
        }
    }

    /// The identity a `signer` DID commits to, recovered from the DID's own
    /// bytes. Fail-closed: any method we cannot resolve to key material is an
    /// error, never a silent pass.
    fn from_did(did: &str) -> Result<Self, traits::VerifyError> {
        use crate::primitives::did_key::{self, KeyAlgorithm};

        let fail = |msg: String| traits::VerifyError::Failed(msg);

        if did_key::is_did_key(did) {
            let (alg, bytes) = did_key::decode(did)
                .map_err(|e| fail(format!("invalid did:key signer {did:?}: {e}")))?;
            return match alg {
                KeyAlgorithm::Ed25519 => bytes
                    .try_into()
                    .map(SignerIdentity::Ed25519)
                    .map_err(|_| fail(format!("did:key ed25519 signer {did:?} not 32 bytes"))),
                KeyAlgorithm::P256 => bytes
                    .try_into()
                    .map(SignerIdentity::P256)
                    .map_err(|_| fail(format!("did:key p256 signer {did:?} not 33 bytes"))),
            };
        }

        // did:pkh:eip155:<chain>:0x<20-byte address> (CAIP-10). The address is
        // the final colon-separated segment; compared as raw bytes, so EIP-55
        // mixed-case checksums match a lowercase form of the same address.
        if did.starts_with("did:pkh:eip155:") {
            let addr_hex = did
                .rsplit(':')
                .next()
                .and_then(|s| s.strip_prefix("0x"))
                .ok_or_else(|| fail(format!("did:pkh:eip155 signer {did:?} missing 0x address")))?;
            let bytes = hex::decode(addr_hex)
                .map_err(|e| fail(format!("did:pkh:eip155 signer {did:?} bad hex: {e}")))?;
            return bytes.try_into().map(SignerIdentity::Eip155).map_err(|_| {
                fail(format!(
                    "did:pkh:eip155 signer {did:?} not a 20-byte address"
                ))
            });
        }

        // did:pkh:ed25519:0x<32-byte public key> (aqua-auth dual form).
        if let Some(rest) = did.strip_prefix("did:pkh:ed25519:") {
            let pk_hex = rest
                .strip_prefix("0x")
                .ok_or_else(|| fail(format!("did:pkh:ed25519 signer {did:?} missing 0x key")))?;
            let bytes = hex::decode(pk_hex)
                .map_err(|e| fail(format!("did:pkh:ed25519 signer {did:?} bad hex: {e}")))?;
            return bytes
                .try_into()
                .map(SignerIdentity::Ed25519)
                .map_err(|_| fail(format!("did:pkh:ed25519 signer {did:?} not a 32-byte key")));
        }

        Err(fail(format!("unrecognized signer DID method: {did:?}")))
    }
}

/// Bind the verified signing key to the claimed `signer` DID (issue #65).
///
/// [`verify_signature_value`] proves the signature matches the embedded
/// `signature_public_identifier`; this proves that identifier is the identity
/// named by `signer`. Both are required. Without this check an attacker signs
/// with their own key while declaring a victim's DID as `signer` (which is in
/// the signed pre-image, so it is self-consistent) and passes verification,
/// forging attribution to the victim.
fn verify_signer_binding(sig: &SignatureValue, signer: &str) -> Result<(), traits::VerifyError> {
    let claimed = SignerIdentity::from_did(signer)?;
    let actual = SignerIdentity::from_signature(sig);
    if claimed == actual {
        Ok(())
    } else {
        Err(traits::VerifyError::Failed(format!(
            "signer {signer:?} does not match the signing key"
        )))
    }
}

/// Shared sync implementation for signature verification.
///
/// Per V4 spec, verification reconstructs the pre-signature inner object:
/// 1. Extract `signature_type` from the `signature` object
/// 2. Remove `signature` field, add `signature_type` as top-level field
/// 3. Serialize to RFC 8785 canonical JSON
/// 4. Verify the signature against those canonical bytes
fn verify_signature_inner(
    data: &AnyRevision,
    verification_hash: &str,
    ident_character: Option<String>,
) -> (bool, Vec<LogData>) {
    let mut logs: Vec<LogData> = Vec::new();
    let ident = ident_character.unwrap_or_default();
    let mut signature_ok = false;

    if verification_hash.is_empty() {
        logs.push(LogData {
            log: "The verificationHash MUST NOT be empty".to_string(),
            log_type: LogType::Error,
            ident: Some(ident.clone()),
        });
        return (signature_ok, logs);
    }

    // Extract signature data from AnyRevision
    let signature_data = match data {
        AnyRevision::Signature(sig) => sig,
        _ => {
            logs.push(LogData {
                log: "Revision is not a Signature type".to_string(),
                log_type: LogType::Error,
                ident: Some(ident.clone()),
            });
            return (signature_ok, logs);
        }
    };

    // Recover the revision-hash algorithm from the addressing multihash code
    // (PCA-0015 §3.10): the signing input's `hash_codec` is derived from it, so
    // the signature is bound to its algorithm. The identity check (recompute ==
    // declared link) is performed by `verify_revision_hash` in the pipeline.
    let hash_type = match verification_hash
        .parse::<RevisionLink>()
        .ok()
        .and_then(|link| link.hash_type().ok())
    {
        Some(ht) => ht,
        None => {
            logs.push(LogData {
                log: "Signature verification hash is not a valid multihash".to_string(),
                log_type: LogType::Error,
                ident: Some(ident.clone()),
            });
            return (signature_ok, logs);
        }
    };

    // Reconstruct the pre-signature canonical JSON (the verification input)
    let canonical_json = signature_data.pre_signature_canonical_json(hash_type);

    let sig_type = signature_data.signature().signature_type();
    logs.push(LogData {
        log: format!("Verifying {sig_type} signature"),
        log_type: LogType::Signature,
        ident: Some(ident.clone()),
    });

    match verify_signature_value(signature_data.signature(), &canonical_json) {
        Ok(()) => {
            // Crypto is valid against the embedded key; now bind that key to the
            // claimed `signer` DID so a valid signature cannot forge attribution
            // to another identity (issue #65).
            match verify_signer_binding(signature_data.signature(), signature_data.signer()) {
                Ok(()) => {
                    signature_ok = true;
                    logs.push(LogData {
                        log: format!("{sig_type} signature verification successful"),
                        log_type: LogType::Success,
                        ident: Some(ident.clone()),
                    });
                }
                Err(e) => {
                    logs.push(LogData {
                        log: format!("{sig_type} signature verification failed: {e}"),
                        log_type: LogType::Error,
                        ident: Some(ident.clone()),
                    });
                }
            }
        }
        Err(e) => {
            logs.push(LogData {
                log: format!("{sig_type} signature verification failed: {e}"),
                log_type: LogType::Error,
                ident: Some(ident.clone()),
            });
        }
    }

    (signature_ok, logs)
}

/// Verifies a signature on an Aqua Tree revision (async entry point).
///
/// Delegates to [`verify_signature_inner`]. The async wrapper exists for API
/// compatibility; the actual verification is fully synchronous.
pub async fn verify_signature(
    data: &AnyRevision,
    verification_hash: &str,
    ident_character: Option<String>,
) -> (bool, Vec<LogData>) {
    verify_signature_inner(data, verification_hash, ident_character)
}

/// Verifies a signature on an Aqua Tree revision (sync entry point).
///
/// Identical to [`verify_signature`] but callable without an async runtime.
pub fn verify_signature_sync(
    data: &AnyRevision,
    verification_hash: &str,
    ident_character: Option<String>,
) -> (bool, Vec<LogData>) {
    verify_signature_inner(data, verification_hash, ident_character)
}

/// Util function to add a pre-computed external signature to a tree
pub fn add_external_signature_util(
    aqua_tree: &mut Tree,
    target_revision_hash: &RevisionLink,
    signature: SignatureValue,
    signer: String,
    canonicalization_method: Method,
    logs: &mut Vec<LogData>,
) -> Result<(), MethodError> {
    // Inherit the target's algorithm from its addressing multihash (§3.5/§3.10).
    let hash_type = target_revision_hash
        .hash_type()
        .unwrap_or(HashType::Sha3_256);

    let signature_revision = Signature::new(
        target_revision_hash.clone(),
        canonicalization_method,
        signer,
        signature,
    );

    let verification_hash = signature_revision.calculate_link(hash_type).map_err(|e| {
        logs.push(LogData {
            log: format!("Failed to calculate verification hash: {e}"),
            log_type: LogType::Error,
            ident: None,
        });
        MethodError::WithLogs(logs.clone())
    })?;

    // Add to revisions
    aqua_tree.revisions.insert(
        verification_hash,
        AnyRevision::Signature(signature_revision),
    );

    logs.push(LogData {
        log: "External signature added successfully".to_string(),
        log_type: LogType::Success,
        ident: None,
    });

    Ok(())
}

#[cfg(test)]
mod signer_binding_tests {
    //! Issue #65: the `signer` DID must be bound to the verified signing key.
    //!
    //! Each `*_forged_signer_rejected` test signs a pre-image with key A while
    //! declaring `signer = <key B's DID>`. The signature is cryptographically
    //! valid for the embedded identifier (A), so the pre-#65 verifier accepts it;
    //! a bound verifier must reject it. The `*_honest_*` tests are the regression
    //! guard: a signer DID legitimately derived from the signing key still passes.

    use super::*;
    use crate::core::signature::{sign_eth, sign_p256::P256Signer};
    use crate::primitives::{HashType, Method, RevisionLink};
    use crate::schema::{PreSignature, SignatureValue};

    const KEY_A: [u8; 32] = [0x11; 32];
    const KEY_B: [u8; 32] = [0x22; 32];

    fn dummy_prev() -> RevisionLink {
        RevisionLink::from_bytes([0x07; 32])
    }

    /// Build an Ed25519 signature over a pre-image whose `signer` field is
    /// `claimed_signer`, physically signed by `priv_key`. Returns the revision
    /// and its addressing link (the verification hash passed to the verifier).
    fn ed25519_signed(priv_key: &[u8; 32], claimed_signer: String) -> (AnyRevision, String) {
        let ht = HashType::Sha3_256;
        let pre = PreSignature::new(dummy_prev(), Method::Scalar, ht, claimed_signer);
        let canonical = pre.canonical_json("ed25519");
        let res = DIDSigner::new()
            .sign_canonical(&canonical, priv_key)
            .expect("ed25519 sign");
        let sig = SignatureValue::Ed25519 {
            signature: res.signature,
            signature_public_identifier: res.public_key,
        };
        let signature = pre.finalize(sig);
        let link = signature.calculate_link(ht).expect("link");
        (AnyRevision::Signature(signature), link.to_string())
    }

    fn p256_signed(priv_key: &[u8; 32], claimed_signer: String) -> (AnyRevision, String) {
        let ht = HashType::Sha3_256;
        let pre = PreSignature::new(dummy_prev(), Method::Scalar, ht, claimed_signer);
        let canonical = pre.canonical_json("ecdsa:p256");
        let res = P256Signer::new()
            .sign_canonical(&canonical, priv_key)
            .expect("p256 sign");
        let sig = SignatureValue::P256 {
            signature: res.signature,
            signature_public_identifier: res.public_key,
        };
        let signature = pre.finalize(sig);
        let link = signature.calculate_link(ht).expect("link");
        (AnyRevision::Signature(signature), link.to_string())
    }

    fn eip191_signed(priv_key: &[u8; 32], claimed_signer: String) -> (AnyRevision, String) {
        let ht = HashType::Sha3_256;
        let pre = PreSignature::new(dummy_prev(), Method::Scalar, ht, claimed_signer);
        let canonical = pre.canonical_json("ethereum:eip-191");
        let canonical_str = String::from_utf8(canonical).expect("utf8");
        let signing_key = k256::ecdsa::SigningKey::from_slice(priv_key).expect("k256 key");
        let address = sign_eth::pubkey_to_address(signing_key.verifying_key());
        let prefixed = format!(
            "\x19Ethereum Signed Message:\n{}{}",
            canonical_str.len(),
            canonical_str
        );
        let msg_hash = sign_eth::sha3_keccak256(prefixed.as_bytes());
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&msg_hash)
            .expect("eip191 sign");
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte() + 27;
        let sig = SignatureValue::Eip191 {
            signature: sig_bytes,
            signature_public_identifier: address,
        };
        let signature = pre.finalize(sig);
        let link = signature.calculate_link(ht).expect("link");
        (AnyRevision::Signature(signature), link.to_string())
    }

    fn ed25519_did_key(priv_key: &[u8; 32]) -> String {
        DIDSigner::new().derive_did(priv_key).expect("ed25519 did")
    }

    fn ed25519_pubkey(priv_key: &[u8; 32]) -> [u8; 32] {
        DIDSigner::new()
            .sign_canonical(b"x", priv_key)
            .expect("sign")
            .public_key
    }

    fn p256_did_key(priv_key: &[u8; 32]) -> String {
        P256Signer::new().derive_did(priv_key).expect("p256 did")
    }

    fn eip191_did_pkh(priv_key: &[u8; 32]) -> String {
        sign_eth::Secp256k1Signer::new(priv_key.to_vec())
            .derive_did_pkh()
            .expect("eip191 did")
            .0
    }

    fn verify(rev: &AnyRevision, link: &str) -> bool {
        verify_signature_sync(rev, link, None).0
    }

    // ── H2: honest signers still verify (regression guard) ──────────────

    #[test]
    fn ed25519_honest_signer_accepted() {
        let (rev, link) = ed25519_signed(&KEY_A, ed25519_did_key(&KEY_A));
        assert!(verify(&rev, &link), "honest ed25519 signature must verify");
    }

    #[test]
    fn p256_honest_signer_accepted() {
        let (rev, link) = p256_signed(&KEY_A, p256_did_key(&KEY_A));
        assert!(verify(&rev, &link), "honest p256 signature must verify");
    }

    #[test]
    fn eip191_honest_signer_accepted() {
        let (rev, link) = eip191_signed(&KEY_A, eip191_did_pkh(&KEY_A));
        assert!(verify(&rev, &link), "honest eip191 signature must verify");
    }

    // ── H1: ab-initio signer substitution is rejected ───────────────────

    #[test]
    fn ed25519_forged_signer_rejected() {
        // Signed by A, but declares B's DID as `signer`.
        let (rev, link) = ed25519_signed(&KEY_A, ed25519_did_key(&KEY_B));
        assert!(
            !verify(&rev, &link),
            "forged ed25519 signer must be rejected"
        );
    }

    #[test]
    fn p256_forged_signer_rejected() {
        let (rev, link) = p256_signed(&KEY_A, p256_did_key(&KEY_B));
        assert!(!verify(&rev, &link), "forged p256 signer must be rejected");
    }

    #[test]
    fn eip191_forged_signer_rejected() {
        let (rev, link) = eip191_signed(&KEY_A, eip191_did_pkh(&KEY_B));
        assert!(
            !verify(&rev, &link),
            "forged eip191 signer must be rejected"
        );
    }

    // ── H3: did:key vs did:pkh:ed25519 dual form is NOT false-rejected ───

    #[test]
    fn ed25519_did_pkh_dual_form_accepted() {
        // aqua-auth presents one Ed25519 key as did:pkh:ed25519:0x<hex(pubkey)>.
        // It commits to the same 32 key-bytes as the did:key form, so it must pass.
        let signer = format!("did:pkh:ed25519:0x{}", hex::encode(ed25519_pubkey(&KEY_A)));
        let (rev, link) = ed25519_signed(&KEY_A, signer);
        assert!(verify(&rev, &link), "did:pkh:ed25519 dual form must verify");
    }

    // ── H4: cross-algorithm signer DID is rejected (type confusion) ─────

    #[test]
    fn eip191_signature_with_did_key_signer_rejected() {
        // eip191 signature (20-byte address) but signer is a did:key ed25519.
        let (rev, link) = eip191_signed(&KEY_A, ed25519_did_key(&KEY_A));
        assert!(
            !verify(&rev, &link),
            "cross-algorithm signer must be rejected"
        );
    }

    #[test]
    fn ed25519_signature_with_did_pkh_eip155_signer_rejected() {
        let (rev, link) = ed25519_signed(&KEY_A, eip191_did_pkh(&KEY_A));
        assert!(
            !verify(&rev, &link),
            "cross-algorithm signer must be rejected"
        );
    }

    // ── H6: async and sync pipelines agree (parity) ─────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn forged_signer_verdict_is_pipeline_identical() {
        let (rev, link) = ed25519_signed(&KEY_A, ed25519_did_key(&KEY_B));
        let sync_ok = verify_signature_sync(&rev, &link, None).0;
        let async_ok = verify_signature(&rev, &link, None).await.0;
        assert_eq!(sync_ok, async_ok, "pipelines must agree on the verdict");
        assert!(!sync_ok, "both pipelines must reject the forgery");
    }

    // ── Malformed / empty signer DID fails closed ───────────────────────

    #[test]
    fn empty_signer_rejected() {
        let (rev, link) = ed25519_signed(&KEY_A, String::new());
        assert!(!verify(&rev, &link), "empty signer must be rejected");
    }
}
