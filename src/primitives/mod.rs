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
    ANCHOR_TEMPLATE_HEX, GENESIS_TYPE_HASH, TEMPLATE_META_HEX,
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
