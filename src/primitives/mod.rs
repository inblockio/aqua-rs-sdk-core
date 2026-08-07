use hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

mod hash_type;
mod method;
mod timestamp;
mod version;

pub mod did;
pub mod did_key;
pub mod log;
pub mod merkle;
pub mod revision_kind;
pub mod unsupported;

pub use did::{Did, DidError};
pub use did_key::{DidKeyError, KeyAlgorithm};
pub use hash_type::{multihash_decode, multihash_encode, HashType, Hashable, MultihashError};
pub use method::{Canonicalizable, Method, MethodError};
pub use revision_kind::{
    genesis_type_link, resolve_revision_kind, template_id_multihash, RevisionKind,
    ANCHOR_TEMPLATE_HEX, GENESIS_TYPE_HASH, TEMPLATE_META_HEX, TEMPLATE_META_REVISION_TYPE,
};
pub use timestamp::Timestamp;
pub use version::{ParseError as VersionParseError, Version};

/// A 16-byte random nonce used for HKDF salt derivation in Tree-method revisions.
pub type Nonce = HexString<[u8; 16]>;

/// A cryptographic hash that identifies a revision within an Aqua tree.
///
/// Serialized as a `0x`-prefixed lowercase hex string (e.g., `"0xabcd..."`).
/// Typically 32 bytes (SHA3-256 or BLAKE3-256). Implements `Display`, `FromStr`,
/// `Serialize`, and `Deserialize` via the hex encoding.
pub type RevisionLink = HexString<Vec<u8>>;

/// Identifies an EVM-compatible chain for timestamping and signing.
///
/// Well-known chains have named variants; any other EVM-compatible chain
/// can be specified via `Custom` using its chain ID and an optional name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EvmChain {
    Mainnet,
    Sepolia,
    Holesky,
    /// Any EVM-compatible chain not covered by the named variants.
    Custom {
        chain_id: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
}

impl EvmChain {
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::Mainnet => 1,
            Self::Sepolia => 11155111,
            Self::Holesky => 17000,
            Self::Custom { chain_id, .. } => *chain_id,
        }
    }

    /// Hex-encoded chain ID, used for MetaMask `wallet_switchEthereumChain`.
    pub fn chain_id_hex(&self) -> String {
        format!("0x{:x}", self.chain_id())
    }
}

impl std::fmt::Display for EvmChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Sepolia => write!(f, "sepolia"),
            Self::Holesky => write!(f, "holesky"),
            Self::Custom { name: Some(n), .. } => write!(f, "{n}"),
            Self::Custom {
                name: None,
                chain_id,
            } => write!(f, "evm:{chain_id}"),
        }
    }
}

impl Default for EvmChain {
    fn default() -> Self {
        EvmChain::Sepolia
    }
}

impl Nonce {
    pub fn random() -> Self {
        Self(rand::random())
    }
}

impl RevisionLink {
    pub(crate) fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// Construct a `RevisionLink` by wrapping a bare 32-byte SHA3-256 digest as a
    /// multihash (`0x1620 || digest`). All callers pass template-id digests, which are
    /// always SHA3-256 (PCA-0015 §3.9).
    pub fn from_bytes(hash: [u8; 32]) -> Self {
        Self(hash_type::multihash_encode(HashType::Sha3_256, &hash))
    }

    /// The zero link (`0x0000...0000`). Used for headless/unresolvable anchors.
    pub fn zero() -> Self {
        Self(vec![0u8; 32])
    }

    /// Decode this addressing link's multihash to recover the revision-hash
    /// algorithm it commits to (PCA-0015 §3.5). Used by the verification
    /// pipeline to learn the algorithm without a stored `hash_type` field; the
    /// recovered code drives recomputation and the signature `hash_codec`
    /// (§3.10). Errors if the link is not a well-formed Aqua-profile multihash.
    pub fn hash_type(&self) -> Result<HashType, MultihashError> {
        hash_type::multihash_decode(&self.0).map(|(ht, _)| ht)
    }

    /// The bare 32-byte digest this link names, stripped of its multihash
    /// prefix.
    ///
    /// The protocol writes hashes two ways and the split is a known footgun:
    /// links on the wire (`revision_type`, `derives_from`, `ancestry`, anchor
    /// `structural_links`) are **full multihashes** (`0x1620...`, 34 bytes),
    /// while `TEMPLATE_LINK` constants, the ledger in
    /// `tests/audit_template_hashes.txt`, and template `..._hash` fields are
    /// **bare 64-hex digests**. This is the conversion between them.
    ///
    /// Accepts either form, mirroring how template resolution normalizes keys:
    ///
    /// - a bare 32-byte digest is returned as is (no algorithm is asserted,
    ///   because a bare digest does not carry one),
    /// - a well-formed Aqua-profile multihash is decoded and its digest
    ///   returned; the algorithm is recoverable separately via
    ///   [`hash_type`](RevisionLink::hash_type).
    ///
    /// Returns `None` (never panics) for anything else: a malformed multihash,
    /// an unregistered multicodec, or a wrong-length digest.
    ///
    /// Note for template links specifically: template ids are always SHA3-256
    /// (PCA-0015 §3.9), so a template link whose multihash names another
    /// algorithm is not a valid template id even though `bare_digest` will
    /// decode it. Template indexing enforces that separately; this accessor
    /// stays algorithm-agnostic because revision links legitimately use
    /// BLAKE3-256 as well.
    ///
    /// ```rust
    /// use aqua_rs_sdk_core::primitives::RevisionLink;
    ///
    /// let digest = [0xABu8; 32];
    /// let link = RevisionLink::from_bytes(digest); // 0x1620 || digest
    /// assert_eq!(link.bare_digest(), Some(digest));
    /// ```
    pub fn bare_digest(&self) -> Option<[u8; 32]> {
        if self.0.len() == 32 {
            return self.0.as_slice().try_into().ok();
        }
        match hash_type::multihash_decode(&self.0) {
            Ok((_, digest)) if digest.len() == 32 => digest.try_into().ok(),
            _ => None,
        }
    }

    /// [`bare_digest`](RevisionLink::bare_digest) rendered the way ledgers and
    /// template `..._hash` payload fields write it: `0x` plus 64 lowercase hex
    /// characters, with no multihash prefix.
    ///
    /// Returns `None` on the same inputs `bare_digest` rejects.
    pub fn bare_digest_hex(&self) -> Option<String> {
        self.bare_digest().map(|d| format!("0x{}", hex::encode(d)))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HexParseError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error("Missing 0x prefix")]
    Missing0x,
    #[error("Not lower case")]
    InvalidCase,
}

/// A byte sequence that serializes as a `0x`-prefixed lowercase hex string.
///
/// Used for [`RevisionLink`] (`HexString<Vec<u8>>`) and [`Nonce`] (`HexString<[u8; 16]>`).
/// Parsing enforces lowercase hex and a `0x` prefix.
#[derive(
    SerializeDisplay, DeserializeFromStr, PartialEq, Eq, Hash, Clone, Debug, PartialOrd, Ord,
)]
pub struct HexString<T>(pub(crate) T);

impl<T: AsRef<[u8]>> AsRef<[u8]> for HexString<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T> std::fmt::Display for HexString<T>
where
    T: ToHex,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", self.0.encode_hex::<String>())
    }
}

impl<T> std::str::FromStr for HexString<T>
where
    T: FromHex,
    HexParseError: From<<T as FromHex>::Error>,
{
    type Err = HexParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let p = <T>::from_hex(s.strip_prefix("0x").ok_or(Self::Err::Missing0x)?)?;
        // ensure lowercase hex
        if s.contains(|c| ('A'..='F').contains(&c)) {
            Err(Self::Err::InvalidCase)
        } else {
            Ok(HexString(p))
        }
    }
}

impl<T> From<HexString<T>> for String
where
    T: ToHex,
{
    fn from(h: HexString<T>) -> String {
        h.to_string()
    }
}

// ── Hex utilities ─────────────────────────────────────────────────────────────

/// Decode a hex string (with or without `0x` prefix) into raw bytes.
///
/// Returns an error if the string has odd length or contains non-hex characters.
pub(crate) fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if hex_str.is_empty() {
        return Ok(vec![]);
    }
    if hex_str.len() % 2 != 0 {
        return Err(format!("odd-length hex string ({} chars)", hex_str.len()));
    }
    let mut out = Vec::with_capacity(hex_str.len() / 2);
    for i in (0..hex_str.len()).step_by(2) {
        let byte_str = &hex_str[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| format!("invalid hex byte: {byte_str:?}"))?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod revision_link_tests {
    use super::*;
    use crate::schema::template::BuiltInTemplate;
    use crate::schema::templates::AuditUserTurnMarker;

    #[test]
    fn bare_digest_round_trips_from_bytes() {
        let digest = AuditUserTurnMarker::TEMPLATE_LINK;
        let link = RevisionLink::from_bytes(digest);
        assert_eq!(
            link.as_ref().len(),
            34,
            "from_bytes yields a full multihash"
        );
        assert_eq!(link.bare_digest(), Some(digest));
        assert_eq!(
            link.bare_digest_hex(),
            Some(format!("0x{}", hex::encode(digest)))
        );
    }

    #[test]
    fn bare_digest_passes_through_a_bare_digest() {
        // The internal built-in template trees key revisions by the bare
        // digest, so both forms have to answer.
        let digest = [0x5Au8; 32];
        let link = RevisionLink::new(digest.to_vec());
        assert_eq!(link.bare_digest(), Some(digest));
    }

    #[test]
    fn bare_digest_matches_the_template_index_key() {
        // The template index normalizes links with the same rule for the
        // SHA3-256 template ids it accepts; the two must never disagree.
        for digest in crate::core::builtin_templates().keys() {
            let link = RevisionLink::from_bytes(*digest);
            assert_eq!(link.bare_digest(), Some(*digest));
            assert_eq!(
                RevisionLink::new(digest.to_vec()).bare_digest(),
                Some(*digest)
            );
        }
    }

    #[test]
    fn bare_digest_rejects_malformed_links() {
        // Too short, too long, and a well-formed-looking prefix with a
        // wrong-length digest all answer None rather than panicking.
        for bytes in [vec![], vec![0x11], vec![0xAA; 31], vec![0xAA; 33], {
            let mut v = vec![0x16, 0x20];
            v.extend_from_slice(&[0xBB; 31]);
            v
        }] {
            assert_eq!(
                RevisionLink::new(bytes.clone()).bare_digest(),
                None,
                "malformed link must not decode: {bytes:?}"
            );
            assert_eq!(RevisionLink::new(bytes).bare_digest_hex(), None);
        }
    }

    #[test]
    fn bare_digest_is_algorithm_agnostic() {
        // A BLAKE3 revision link is a legitimate link; its digest is readable
        // even though it would not be a valid template id.
        let digest = [0x77u8; 32];
        let link = RevisionLink::new(hash_type::multihash_encode(HashType::Blake3_256, &digest));
        assert_eq!(link.bare_digest(), Some(digest));
        assert_eq!(link.hash_type().unwrap(), HashType::Blake3_256);
    }
}
