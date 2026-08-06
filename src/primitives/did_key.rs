//! did:key encoding and decoding (W3C DID method).
//!
//! Format: `did:key:` + multibase_base58btc(varint_codec_bytes + raw_public_key_bytes)
//!
//! Supported algorithms:
//! - Ed25519: multicodec prefix [0xed, 0x01], 32-byte public key
//! - P-256 (secp256r1): multicodec prefix [0x80, 0x24], 33-byte compressed public key

use multibase::Base;

// Multicodec varint prefixes
const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
const P256_CODEC: [u8; 2] = [0x80, 0x24];

const DID_KEY_PREFIX: &str = "did:key:";

/// The cryptographic algorithm identified by a did:key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Ed25519,
    P256,
}

/// Errors that can occur when decoding a did:key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidKeyError {
    #[error("not a did:key URI")]
    NotDidKey,
    #[error("multibase decode failed: {0}")]
    MultibaseDecode(String),
    #[error("unknown multicodec prefix")]
    UnknownCodec,
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
}

/// Encode an Ed25519 public key (32 bytes) as a did:key string.
///
/// The result starts with `did:key:z6Mk...`.
pub fn encode_ed25519(pubkey: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(2 + 32);
    data.extend_from_slice(&ED25519_CODEC);
    data.extend_from_slice(pubkey);
    let encoded = multibase::encode(Base::Base58Btc, &data);
    format!("{DID_KEY_PREFIX}{encoded}")
}

/// Encode a P-256 compressed public key (33 bytes) as a did:key string.
///
/// The result starts with `did:key:zDn...`.
pub fn encode_p256(pubkey: &[u8; 33]) -> String {
    let mut data = Vec::with_capacity(2 + 33);
    data.extend_from_slice(&P256_CODEC);
    data.extend_from_slice(pubkey);
    let encoded = multibase::encode(Base::Base58Btc, &data);
    format!("{DID_KEY_PREFIX}{encoded}")
}

/// Decode a did:key string, returning the algorithm and raw public key bytes.
pub fn decode(did: &str) -> Result<(KeyAlgorithm, Vec<u8>), DidKeyError> {
    let multibase_str = did
        .strip_prefix(DID_KEY_PREFIX)
        .ok_or(DidKeyError::NotDidKey)?;

    let (_base, bytes) = multibase::decode(multibase_str)
        .map_err(|e| DidKeyError::MultibaseDecode(e.to_string()))?;

    if bytes.len() < 2 {
        return Err(DidKeyError::UnknownCodec);
    }

    let codec = [bytes[0], bytes[1]];
    let key_bytes = &bytes[2..];

    match codec {
        ED25519_CODEC => {
            if key_bytes.len() != 32 {
                return Err(DidKeyError::InvalidKeyLength {
                    expected: 32,
                    actual: key_bytes.len(),
                });
            }
            Ok((KeyAlgorithm::Ed25519, key_bytes.to_vec()))
        }
        P256_CODEC => {
            if key_bytes.len() != 33 {
                return Err(DidKeyError::InvalidKeyLength {
                    expected: 33,
                    actual: key_bytes.len(),
                });
            }
            Ok((KeyAlgorithm::P256, key_bytes.to_vec()))
        }
        _ => Err(DidKeyError::UnknownCodec),
    }
}

/// Returns true if the string is a did:key URI.
pub fn is_did_key(did: &str) -> bool {
    did.starts_with(DID_KEY_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ed25519() {
        let pubkey: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let did = encode_ed25519(&pubkey);
        assert!(did.starts_with("did:key:z6Mk"));

        let (algo, decoded_bytes) = decode(&did).unwrap();
        assert_eq!(algo, KeyAlgorithm::Ed25519);
        assert_eq!(decoded_bytes, pubkey.to_vec());
    }

    #[test]
    fn roundtrip_p256() {
        // Compressed P-256 key (33 bytes, starts with 0x02 or 0x03)
        let pubkey: [u8; 33] = [
            0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let did = encode_p256(&pubkey);
        assert!(did.starts_with("did:key:zDn"));

        let (algo, decoded_bytes) = decode(&did).unwrap();
        assert_eq!(algo, KeyAlgorithm::P256);
        assert_eq!(decoded_bytes, pubkey.to_vec());
    }

    #[test]
    fn ed25519_prefix_is_z6mk() {
        let pubkey = [0xab; 32];
        let did = encode_ed25519(&pubkey);
        // After "did:key:" the multibase character is 'z' (base58btc),
        // followed by "6Mk" for Ed25519
        let multibase_part = did.strip_prefix("did:key:").unwrap();
        assert!(multibase_part.starts_with("z6Mk"), "got: {multibase_part}");
    }

    #[test]
    fn p256_prefix_is_zdn() {
        let pubkey = [0xab; 33];
        let did = encode_p256(&pubkey);
        let multibase_part = did.strip_prefix("did:key:").unwrap();
        assert!(multibase_part.starts_with("zDn"), "got: {multibase_part}");
    }

    #[test]
    fn is_did_key_positive() {
        assert!(is_did_key(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ));
    }

    #[test]
    fn is_did_key_negative() {
        assert!(!is_did_key("did:pkh:eip155:1:0x1234"));
        assert!(!is_did_key("not a did"));
        assert!(!is_did_key(""));
    }

    #[test]
    fn reject_non_did_key() {
        let result = decode("did:pkh:eip155:1:0x1234");
        assert_eq!(result, Err(DidKeyError::NotDidKey));
    }

    #[test]
    fn reject_unknown_codec() {
        // Encode with a bogus codec prefix
        let mut data = vec![0xff, 0xff];
        data.extend_from_slice(&[0u8; 32]);
        let encoded = multibase::encode(Base::Base58Btc, &data);
        let did = format!("did:key:{encoded}");
        let result = decode(&did);
        assert_eq!(result, Err(DidKeyError::UnknownCodec));
    }

    #[test]
    fn reject_invalid_ed25519_length() {
        // Ed25519 codec but only 16 bytes of key
        let mut data = Vec::new();
        data.extend_from_slice(&ED25519_CODEC);
        data.extend_from_slice(&[0u8; 16]);
        let encoded = multibase::encode(Base::Base58Btc, &data);
        let did = format!("did:key:{encoded}");
        let result = decode(&did);
        assert_eq!(
            result,
            Err(DidKeyError::InvalidKeyLength {
                expected: 32,
                actual: 16
            })
        );
    }

    #[test]
    fn reject_invalid_p256_length() {
        // P-256 codec but 32 bytes instead of 33
        let mut data = Vec::new();
        data.extend_from_slice(&P256_CODEC);
        data.extend_from_slice(&[0u8; 32]);
        let encoded = multibase::encode(Base::Base58Btc, &data);
        let did = format!("did:key:{encoded}");
        let result = decode(&did);
        assert_eq!(
            result,
            Err(DidKeyError::InvalidKeyLength {
                expected: 33,
                actual: 32
            })
        );
    }

    #[test]
    fn deterministic_encoding() {
        let pubkey = [0x42; 32];
        let did1 = encode_ed25519(&pubkey);
        let did2 = encode_ed25519(&pubkey);
        assert_eq!(did1, did2);
    }

    #[test]
    fn decode_known_vector() {
        // Well-known test vector from W3C did:key spec
        // did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp
        // corresponds to Ed25519 pubkey bytes
        let did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
        let (algo, key_bytes) = decode(did).unwrap();
        assert_eq!(algo, KeyAlgorithm::Ed25519);
        assert_eq!(key_bytes.len(), 32);
        // Re-encode should produce same DID
        let reencoded = encode_ed25519(key_bytes.as_slice().try_into().unwrap());
        assert_eq!(reencoded, did);
    }
}
