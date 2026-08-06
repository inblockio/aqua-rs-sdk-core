use serde_with::{DeserializeFromStr, SerializeDisplay};
use sha3::{digest::Update, Digest};
use std::{fmt::Display, str::FromStr};

/// Hash algorithm used for revision hashes and Merkle tree construction.
///
/// SHA3-256 is the default. BLAKE3-256 must be explicitly requested via
/// [`AquafierBuilder::hash_type()`](crate::AquafierBuilder::hash_type).
/// Batch timestamps and HKDF salt derivation always use SHA3-256 regardless.
///
/// Serialized as `"FIPS_202-SHA3-256"` or `"BLAKE3-256"`.
#[derive(SerializeDisplay, DeserializeFromStr, PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum HashType {
    /// NIST FIPS 202 SHA3-256 (default).
    Sha3_256,
    /// BLAKE3-256 (must be explicitly requested).
    Blake3_256,
}

impl Default for HashType {
    fn default() -> Self {
        Self::Sha3_256
    }
}

impl HashType {
    /// Hash the given bytes using this algorithm. Returns a 32-byte digest.
    pub fn hash(&self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha3_256 => sha3::Sha3_256::new().chain(bytes).finalize().to_vec(),
            Self::Blake3_256 => blake3::hash(bytes).as_bytes().to_vec(),
        }
    }

    /// Returns the registry digest length in bytes for this algorithm
    /// (the **Aqua profile** length, 32 for both `0x16` and `0x1e`). This is
    /// normative: a multihash whose declared length differs from this MUST be
    /// rejected (PCA-0015 §3.1.2).
    pub fn output_len(&self) -> usize {
        match self {
            Self::Sha3_256 | Self::Blake3_256 => 32,
        }
    }

    /// The multicodec integer naming this hash function (PCA-0015 §3.1).
    ///
    /// `0x16` = `sha3-256`, `0x1e` = `blake3`.
    pub fn multicodec(&self) -> u8 {
        match self {
            Self::Sha3_256 => 0x16,
            Self::Blake3_256 => 0x1e,
        }
    }

    /// Resolve a multicodec integer to a registered [`HashType`]. Any code not
    /// in the Aqua registry is rejected (no default-algorithm fallback,
    /// PCA-0015 §3.1.3).
    pub fn from_multicodec(code: u64) -> Result<Self, MultihashError> {
        match code {
            0x16 => Ok(Self::Sha3_256),
            0x1e => Ok(Self::Blake3_256),
            other => Err(MultihashError::UnknownCode(other)),
        }
    }
}

/// Errors from decoding an Aqua-profile multihash (PCA-0015 §3.1, §3.2, §3.11).
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum MultihashError {
    /// Ran out of bytes while decoding a varint or the digest.
    #[error("truncated multihash")]
    Truncated,
    /// A varint was not the minimal encoding of its value (PCA-0015 §3.2.1).
    #[error("non-minimal varint")]
    NonMinimalVarint,
    /// A varint encodes a value outside the single-byte registry range
    /// (PCA-0015 §3.2.2).
    #[error("varint out of registry range")]
    VarintOutOfRange,
    /// The multicodec code is not in the Aqua registry (PCA-0015 §3.1.3).
    #[error("unknown multicodec code: {0:#x}")]
    UnknownCode(u64),
    /// The declared digest length disagrees with the registry length for the
    /// code (PCA-0015 §3.1.2).
    #[error("declared length {declared} != registry length {registry} for code {code:#x}")]
    RegistryLengthMismatch {
        /// The length declared in the multihash.
        declared: usize,
        /// The Aqua-profile length for the code.
        registry: usize,
        /// The multicodec code.
        code: u64,
    },
    /// Bytes remain after a complete multihash (PCA-0015 §3.1.4).
    #[error("trailing bytes after multihash")]
    TrailingBytes,
}

/// Encode `digest` as an Aqua-profile multihash for `hash_type`:
/// `varint(code) || varint(len) || digest` (PCA-0015 §3.1, §3.5). For the
/// current registry both varints are single bytes.
pub fn multihash_encode(hash_type: HashType, digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + digest.len());
    encode_varint(hash_type.multicodec() as u64, &mut out);
    encode_varint(digest.len() as u64, &mut out);
    out.extend_from_slice(digest);
    out
}

/// Decode an Aqua-profile multihash into its algorithm and bare digest,
/// enforcing every rule of PCA-0015 §3.1/§3.2/§3.11 **explicitly**: minimal
/// varints, a registry code, the declared length equal to both the registry
/// length and the actual digest length, and no trailing bytes.
pub fn multihash_decode(bytes: &[u8]) -> Result<(HashType, Vec<u8>), MultihashError> {
    let (code, rest) = decode_varint(bytes)?;
    let (declared_len, rest) = decode_varint(rest)?;
    let hash_type = HashType::from_multicodec(code)?;
    let declared_len = declared_len as usize;
    let registry_len = hash_type.output_len();
    if declared_len != registry_len {
        return Err(MultihashError::RegistryLengthMismatch {
            declared: declared_len,
            registry: registry_len,
            code,
        });
    }
    // The declared length MUST equal the actual remaining byte count exactly:
    // fewer bytes is a truncated multihash, more bytes is a trailing-byte
    // attack (PCA-0015 §3.1.4). Either way the whole field must be consumed.
    match rest.len().cmp(&declared_len) {
        std::cmp::Ordering::Less => Err(MultihashError::Truncated),
        std::cmp::Ordering::Greater => Err(MultihashError::TrailingBytes),
        std::cmp::Ordering::Equal => Ok((hash_type, rest.to_vec())),
    }
}

/// Encode an unsigned-varint (multiformats `unsigned-varint`): 7 value bits per
/// byte, little-endian by group, high bit set on all but the last byte.
fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode a minimal unsigned-varint, returning the value and the unconsumed
/// tail. Rejects non-minimal encodings (by re-encoding and byte-comparing, per
/// PCA-0015 §3.2.1) and any value outside the single-byte registry range
/// (PCA-0015 §3.2.2).
fn decode_varint(bytes: &[u8]) -> Result<(u64, &[u8]), MultihashError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut consumed: usize = 0;
    loop {
        let byte = *bytes.get(consumed).ok_or(MultihashError::Truncated)?;
        if shift >= 64 {
            return Err(MultihashError::VarintOutOfRange);
        }
        value |= ((byte & 0x7f) as u64) << shift;
        consumed += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    // Minimality: re-encode the decoded value and require byte-identity with
    // the consumed bytes. This rejects e.g. a trailing `0x00` continuation
    // group (PCA-0015 §3.2.1).
    let mut canon = Vec::new();
    encode_varint(value, &mut canon);
    if canon.as_slice() != &bytes[..consumed] {
        return Err(MultihashError::NonMinimalVarint);
    }
    // The current registry uses only single-byte (`< 0x80`) codes and lengths
    // (PCA-0015 §3.2.2).
    if value >= 0x80 {
        return Err(MultihashError::VarintOutOfRange);
    }
    Ok((value, &bytes[consumed..]))
}

impl Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Sha3_256 => "FIPS_202-SHA3-256",
                Self::Blake3_256 => "BLAKE3-256",
            }
        )
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Invalid Hash Type")]
pub struct ParseError;

impl FromStr for HashType {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "FIPS_202-SHA3-256" => Ok(Self::Sha3_256),
            "BLAKE3-256" => Ok(Self::Blake3_256),
            _ => Err(ParseError),
        }
    }
}

/// Trait for revision types that carry a nonce for HKDF salt derivation.
///
/// Under PCA-0015 a revision no longer carries its own `hash_type` field: the
/// algorithm is supplied explicitly at creation and read from the addressing
/// multihash at verification, never from the struct.
pub trait Hashable {
    /// The random nonce used for HKDF salt derivation in Tree-method hashing.
    fn nonce(&self) -> &super::Nonce;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_display_and_parse() {
        let ht = HashType::Sha3_256;
        assert_eq!(ht.to_string(), "FIPS_202-SHA3-256");
        assert_eq!(HashType::from_str("FIPS_202-SHA3-256").unwrap(), ht);
    }

    #[test]
    fn test_blake3_256_display_and_parse() {
        let ht = HashType::Blake3_256;
        assert_eq!(ht.to_string(), "BLAKE3-256");
        assert_eq!(HashType::from_str("BLAKE3-256").unwrap(), ht);
    }

    #[test]
    fn test_serde_roundtrip() {
        let json = serde_json::to_string(&HashType::Blake3_256).unwrap();
        assert_eq!(json, "\"BLAKE3-256\"");
        let parsed: HashType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, HashType::Blake3_256);
    }

    #[test]
    fn test_unknown_hash_type_fails() {
        assert!(HashType::from_str("SHA-256").is_err());
        assert!(HashType::from_str("BLAKE2b-256").is_err());
    }

    #[test]
    fn test_default_is_sha3() {
        assert_eq!(HashType::default(), HashType::Sha3_256);
    }

    #[test]
    fn test_output_len() {
        assert_eq!(HashType::Sha3_256.output_len(), 32);
        assert_eq!(HashType::Blake3_256.output_len(), 32);
    }

    // ── PCA-0015 §6 worked multihash vectors (pinned bit-for-bit) ──────────

    /// §6 positive SHA3-256 vector: `multihash("aqua")` and its decode roundtrip.
    #[test]
    fn pca0015_sha3_256_aqua_multihash_vector() {
        let digest = HashType::Sha3_256.hash(b"aqua");
        assert_eq!(
            hex::encode(&digest),
            "0e45033cba286c7dc85255b5d9dfe4ebde65bc6d477a6250d1784f5c0d5c1aa4"
        );
        let mh = multihash_encode(HashType::Sha3_256, &digest);
        assert_eq!(
            hex::encode(&mh),
            "16200e45033cba286c7dc85255b5d9dfe4ebde65bc6d477a6250d1784f5c0d5c1aa4"
        );
        // Roundtrip: decode recovers algorithm + bare digest.
        let (ht, decoded) = multihash_decode(&mh).unwrap();
        assert_eq!(ht, HashType::Sha3_256);
        assert_eq!(decoded, digest);
    }

    /// §6 BLAKE3-256 vector: `1e20 || BLAKE3-256("aqua")`, default (unkeyed)
    /// 32-byte mode. The literal is transcribed from the `blake3` v1 crate
    /// (the PCA left it unpinned because the review env could not run BLAKE3).
    #[test]
    fn pca0015_blake3_256_aqua_multihash_vector() {
        let mh = multihash_encode(HashType::Blake3_256, &HashType::Blake3_256.hash(b"aqua"));
        assert_eq!(
            hex::encode(&mh),
            "1e204a037f9e6c19d69462ead0049b51237a5da0c861e9edd7c0610e626ac093ddd5"
        );
        let (ht, _) = multihash_decode(&mh).unwrap();
        assert_eq!(ht, HashType::Blake3_256);
    }

    /// §6 negative vectors: every malformed encoding the decoder MUST reject,
    /// each mapped to its specific [`MultihashError`].
    #[test]
    fn pca0015_negative_multihash_vectors() {
        // 0x1740... — unknown code 0x17 (rejected before any length check).
        let mut unknown_code = vec![0x17u8, 0x40];
        unknown_code.extend_from_slice(&[0u8; 64]);
        assert_eq!(
            multihash_decode(&unknown_code),
            Err(MultihashError::UnknownCode(0x17))
        );

        // 0x161f<31 bytes> — declared length 0x1f (31) != registry length 32.
        let mut short_len = vec![0x16u8, 0x1f];
        short_len.extend_from_slice(&[0u8; 31]);
        assert_eq!(
            multihash_decode(&short_len),
            Err(MultihashError::RegistryLengthMismatch {
                declared: 31,
                registry: 32,
                code: 0x16,
            })
        );

        // 0x1e40<64 bytes> — code 0x1e (BLAKE3) with out-of-profile length 0x40 (64).
        let mut blake3_overlong = vec![0x1eu8, 0x40];
        blake3_overlong.extend_from_slice(&[0u8; 64]);
        assert_eq!(
            multihash_decode(&blake3_overlong),
            Err(MultihashError::RegistryLengthMismatch {
                declared: 64,
                registry: 32,
                code: 0x1e,
            })
        );

        // 0x9600<32 bytes> — non-minimal CODE varint (96 00 decodes to 0x16).
        let mut nonminimal_code = vec![0x96u8, 0x00, 0x20];
        nonminimal_code.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            multihash_decode(&nonminimal_code),
            Err(MultihashError::NonMinimalVarint)
        );

        // 0x16a000<32 bytes> — non-minimal LENGTH varint (a0 00 decodes to 0x20).
        let mut nonminimal_len = vec![0x16u8, 0xa0, 0x00];
        nonminimal_len.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            multihash_decode(&nonminimal_len),
            Err(MultihashError::NonMinimalVarint)
        );

        // Valid multihash + one trailing byte — trailing-byte attack.
        let mut trailing =
            hex::decode("16200e45033cba286c7dc85255b5d9dfe4ebde65bc6d477a6250d1784f5c0d5c1aa4")
                .unwrap();
        trailing.push(0xff);
        assert_eq!(
            multihash_decode(&trailing),
            Err(MultihashError::TrailingBytes)
        );

        // Truncated: declared 32 but only 31 digest bytes present.
        let mut truncated = vec![0x16u8, 0x20];
        truncated.extend_from_slice(&[0u8; 31]);
        assert_eq!(multihash_decode(&truncated), Err(MultihashError::Truncated));
    }
}
