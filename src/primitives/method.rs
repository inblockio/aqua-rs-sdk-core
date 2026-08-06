use crate::primitives::log::LogData;

use super::hash_type::multihash_encode;
use super::{HashType, Hashable};
use serde::Serialize;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{fmt::Display, str::FromStr};

/// Canonicalization method for computing revision hashes.
///
/// - **Scalar** — flatten to sorted JSON Pointer paths, serialize to canonical JSON, hash the bytes.
///   Compact but does not support selective disclosure.
/// - **Tree** — flatten to sorted JSON Pointer paths, compute per-field Merkle leaf hashes with
///   HKDF-derived salts, build an RFC 9162 Merkle tree, return the root. Supports selective
///   disclosure (individual fields can be redacted while preserving the root hash).
///
/// Serialized as `"scalar"` or `"tree"`.
#[derive(SerializeDisplay, DeserializeFromStr, PartialEq, Eq, Hash, Clone, Debug, Copy)]
pub enum Method {
    /// JSON canonical hash — compact, no selective disclosure.
    Scalar,
    /// Merkle tree hash — supports selective disclosure via field-level redaction.
    Tree,
}

/// Error type for SDK operations involving revision methods.
#[derive(thiserror::Error, Debug)]
pub enum MethodError {
    /// JSON serialization/deserialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::error::Error),
    /// Operation failed with diagnostic log entries.
    #[error("Operation failed with the following log entries")]
    WithLogs(Vec<LogData>),
    /// Simple string error message.
    #[error("{0}")]
    Simple(String),
}

impl Method {
    /// Compute the revision hash bytes using the algorithm specified by this method.
    ///
    /// - **Scalar**: Flatten to JSON Pointer paths (RFC 6901), sort lexicographically,
    ///   serialize to canonical JSON (no whitespace), hash the UTF-8 bytes.
    /// - **Tree**: Flatten to JSON Pointer paths, sort, derive per-field HKDF salts
    ///   from the revision nonce, compute domain-separated leaf hashes
    ///   (`HASH(0x00 || salt || key || ":" || JSON_value)` per RFC 6962),
    ///   build a Merkle tree using `HASH(0x01 || left || right)` for internal nodes,
    ///   return root.
    /// The returned bytes are the **full multihash** of the revision
    /// (`varint(code) || varint(len) || digest`, PCA-0015 §3.5): the algorithm
    /// is supplied explicitly by the caller (the builder at creation, or the
    /// addressing multihash's code at verification), never read from the
    /// revision struct.
    pub fn compute_revision_hash<T: Serialize + Hashable>(
        &self,
        t: &T,
        hash_type: HashType,
    ) -> Result<Vec<u8>, MethodError> {
        let bare = match self {
            Self::Scalar => {
                let mut pointers = jsonpointer_flatten::from(t)?;
                pointers.sort_all_objects();
                let canonical_bytes = serde_json::to_vec(&pointers)?;
                hash_type.hash(&canonical_bytes)
            }
            Self::Tree => {
                let leaves = Self::leaves(t, hash_type)?;
                if leaves.is_empty() {
                    return Err(MethodError::Simple(
                        "Revision produced an empty leaf set".to_string(),
                    ));
                }
                super::merkle::merkle_root(&leaves, &hash_type)
            }
        };
        Ok(multihash_encode(hash_type, &bare))
    }

    /// Compute the **bare** leaf hashes for the tree method.
    ///
    /// Flattens the value to JSON Pointer paths, sorts lexicographically,
    /// derives per-field HKDF salts from the revision nonce, then computes
    /// domain-separated leaf hashes (RFC 6962 `0x00` prefix). Leaves are
    /// interior values and stay bare digests of `hash_type` (PCA-0015 §3.7).
    pub fn leaves<T: Serialize + Hashable>(
        t: &T,
        hash_type: HashType,
    ) -> Result<Vec<Vec<u8>>, MethodError> {
        let nonce_bytes = t.nonce().as_ref();
        let prk = super::merkle::derive_prk(nonce_bytes);

        let mut pointers = jsonpointer_flatten::from(t)?;
        pointers.sort_all_objects();

        Ok(if let serde_json::Value::Object(p) = pointers {
            p.into_iter()
                .filter(|(k, _)| !k.starts_with("/leaves"))
                .map(|(k, v)| {
                    let salt = super::merkle::derive_field_salt(&prk, &k);
                    super::merkle::leaf_hash(&hash_type, &salt, &k, &format!("{v}"))
                })
                .collect()
        } else {
            Vec::new()
        })
    }
}

impl Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Scalar => "scalar",
                Self::Tree => "tree",
            }
        )
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Invalid Method")]
pub struct ParseError;

impl FromStr for Method {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "scalar" => Ok(Self::Scalar),
            "tree" => Ok(Self::Tree),
            _ => Err(ParseError),
        }
    }
}

pub trait Canonicalizable {
    fn method(&self) -> &Method;
}
