use crate::schema::{PreSignature, SignatureValue};

/// EIP-55 mixed-case checksum encoding for an Ethereum address.
pub(crate) fn eip55_checksum(addr: &[u8; 20]) -> String {
    let hex_addr = hex::encode(addr);
    let hash = sha3_keccak256(hex_addr.as_bytes());
    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if nibble >= 8 {
                checksummed.push(c.to_ascii_uppercase());
            } else {
                checksummed.push(c);
            }
        } else {
            checksummed.push(c);
        }
    }
    checksummed
}

/// Keccak-256 hash (Ethereum's "SHA3").
pub(crate) fn sha3_keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Derive the 20-byte Ethereum address from a secp256k1 public key.
pub(crate) fn pubkey_to_address(pubkey: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let uncompressed = pubkey.to_encoded_point(false);
    // Skip the 0x04 prefix byte, hash the 64-byte x||y
    let hash = sha3_keccak256(&uncompressed.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Handles signing operations using a raw secp256k1 private key (EIP-191 / Ethereum).
///
/// Unlike [`CliSigner`](super::sign_cli::CliSigner) which derives a secp256k1 key
/// from a BIP-39 mnemonic, this signer takes the 32-byte private key scalar directly.
/// This is useful for server-side signing where the key is stored as raw bytes
/// (e.g. loaded from a key store or HSM) rather than a seed phrase.
///
/// Produces `SignatureValue::Eip191` revisions using EIP-191 personal_sign over
/// the Aqua V4 canonical JSON.
pub struct Secp256k1Signer {
    private_key: Vec<u8>,
}

impl Secp256k1Signer {
    /// Create a new `Secp256k1Signer` from a 32-byte secp256k1 private key scalar.
    pub fn new(private_key: Vec<u8>) -> Self {
        Self { private_key }
    }

    /// Derive `did:pkh:eip155:1:0x{EIP-55 checksum address}` from the private key.
    ///
    /// Returns `(did_string, address_bytes)` on success.
    pub fn derive_did_pkh(&self) -> Result<(String, [u8; 20]), Box<dyn std::error::Error>> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&self.private_key)
            .map_err(|e| format!("Invalid secp256k1 private key: {e}"))?;
        let address = pubkey_to_address(signing_key.verifying_key());
        let did = format!("did:pkh:eip155:1:{}", eip55_checksum(&address));
        Ok((did, address))
    }
}

#[async_trait::async_trait]
impl super::traits::Signer for Secp256k1Signer {
    async fn sign_revision(
        &self,
        target_revision: &crate::primitives::RevisionLink,
        method: crate::primitives::Method,
        hash_type: crate::primitives::HashType,
    ) -> Result<crate::schema::Signature, super::traits::SignError> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&self.private_key)
            .map_err(|e| super::traits::SignError::Key(e.to_string()))?;
        let address = pubkey_to_address(signing_key.verifying_key());
        let signer_did = format!("did:pkh:eip155:1:{}", eip55_checksum(&address));

        let pre_sig = PreSignature::new(target_revision.clone(), method, hash_type, signer_did);
        let canonical_json = pre_sig.canonical_json("ethereum:eip-191");
        let canonical_str = String::from_utf8(canonical_json)
            .map_err(|e| super::traits::SignError::Sign(e.to_string()))?;

        // EIP-191 personal_sign: prefix + keccak256 + sign
        let prefixed = format!(
            "\x19Ethereum Signed Message:\n{}{}",
            canonical_str.len(),
            canonical_str
        );
        let msg_hash = sha3_keccak256(prefixed.as_bytes());

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&msg_hash)
            .map_err(|e| super::traits::SignError::Sign(e.to_string()))?;

        // r || s || v (v = recovery_id + 27, per EIP-191 convention)
        let sig_bytes: [u8; 65] = {
            let mut bytes = [0u8; 65];
            bytes[..64].copy_from_slice(&signature.to_bytes());
            bytes[64] = recovery_id.to_byte() + 27;
            bytes
        };

        Ok(pre_sig.finalize(SignatureValue::Eip191 {
            signature: sig_bytes,
            signature_public_identifier: address,
        }))
    }
}
