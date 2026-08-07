use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditRoundAnchor` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditRoundAnchorError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("session_id must not be empty")]
    EmptySessionId,
    #[error("turn_id must be a 0x-prefixed registry multihash (70-char hex: 0x16/0x1e + 0x20 + 64 hex digits)")]
    InvalidTurnId,
    #[error("leaf_hashes must not be empty")]
    EmptyLeafHashes,
    #[error("merkle_root must start with '0x' and be 66 characters")]
    InvalidMerkleRoot,
    #[error("artifact_count must equal the number of leaf_hashes")]
    MismatchedArtifactCount,
}

/// TC2 — round-close anchor. Server-signed commitment closing a turn.
///
/// Spec: TC2 is the final artifact of every turn. Its Merkle root commits to
/// all artifacts (T2-T8) emitted during the turn, providing a tamper-evident
/// summary. The `turn_id` back-references the T1 turn marker that opened the
/// same turn.
///
/// `leaf_hashes` contains the ordered revision hashes of every artifact in
/// the turn. `merkle_root` is the SHA3-256 Merkle root over those leaves.
/// `artifact_count` MUST equal `leaf_hashes.len()`.
///
/// Ancestry: `audit_round_anchor -> audit_artifact -> identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditRoundAnchor {
    pub signer_did: String,
    pub session_id: String,
    pub turn_id: String,
    pub turn_index: u64,
    pub artifact_count: u64,
    pub leaf_hashes: Vec<String>,
    pub merkle_root: String,
    pub closed_at: u64,
}

impl AuditRoundAnchor {
    pub fn validate(&self) -> Result<(), AuditRoundAnchorError> {
        if self.signer_did.is_empty() {
            return Err(AuditRoundAnchorError::EmptySignerDid);
        }
        if self.session_id.is_empty() {
            return Err(AuditRoundAnchorError::EmptySessionId);
        }
        // `turn_id` references the T1 turn marker's revision hash — a §3.3
        // naming value, so it MUST be the full registry multihash form.
        if !is_multihash_hex(&self.turn_id) {
            return Err(AuditRoundAnchorError::InvalidTurnId);
        }
        if self.leaf_hashes.is_empty() {
            return Err(AuditRoundAnchorError::EmptyLeafHashes);
        }
        // `merkle_root` is the root of an app-defined Merkle structure over the
        // leaves (PCA-0015 §3.3 / out-of-scope), not an SDK-recomputed domain;
        // it stays a bare SHA3-256 digest (0x + 64 hex = 66 chars).
        if !self.merkle_root.starts_with("0x") || self.merkle_root.len() != 66 {
            return Err(AuditRoundAnchorError::InvalidMerkleRoot);
        }
        if self.artifact_count as usize != self.leaf_hashes.len() {
            return Err(AuditRoundAnchorError::MismatchedArtifactCount);
        }
        Ok(())
    }
}

/// Returns true if `value` is the lowercase `0x`-prefixed hex of a PCA-0015
/// registry multihash: code `0x16` (SHA3-256) or `0x1e` (BLAKE3-256), length
/// `0x20`, then a 32-byte digest — i.e. it matches `^0x(16|1e)20[0-9a-f]{64}$`.
fn is_multihash_hex(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    if hex.len() != 68 {
        return false;
    }
    if !hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    let code = &hex[0..2];
    &hex[2..4] == "20" && (code == "16" || code == "1e")
}

impl BuiltInTemplate for AuditRoundAnchor {
    const TEMPLATE_JSON: &'static str = include_str!("audit_round_anchor.json");
    /// Placeholder hash, populated by `verify-templates --fix` (cascade-aware).
    const TEMPLATE_LINK: [u8; 32] = [
        0xf1, 0x74, 0xf2, 0xf6, 0x69, 0xd1, 0x02, 0xd3, 0xd7, 0x4e, 0xfb, 0x80, 0x24, 0x8a, 0x08,
        0x48, 0x5f, 0xe2, 0xc4, 0x0d, 0x18, 0xb2, 0xdf, 0x5c, 0xcc, 0x7d, 0x22, 0x5e, 0x79, 0x4b,
        0x63, 0xe7,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_anchor() -> AuditRoundAnchor {
        let leaf = format!("0x{}", "ab".repeat(32));
        AuditRoundAnchor {
            signer_did: "did:key:z6MkServer".to_string(),
            session_id: "sess-abc123".to_string(),
            turn_id: format!("0x1620{}", "cd".repeat(32)),
            turn_index: 0,
            artifact_count: 1,
            leaf_hashes: vec![leaf.clone()],
            merkle_root: leaf,
            closed_at: 1747526460,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_anchor();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditRoundAnchor =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2, "canonical serialization stable");
    }

    #[test]
    fn validate_accepts_valid() {
        assert!(make_anchor().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditRoundAnchor {
            signer_did: String::new(),
            ..make_anchor()
        };
        assert_eq!(bad.validate(), Err(AuditRoundAnchorError::EmptySignerDid));
    }

    #[test]
    fn validate_rejects_empty_leaf_hashes() {
        let bad = AuditRoundAnchor {
            leaf_hashes: vec![],
            artifact_count: 0,
            ..make_anchor()
        };
        assert_eq!(bad.validate(), Err(AuditRoundAnchorError::EmptyLeafHashes));
    }

    #[test]
    fn validate_rejects_bare_turn_id() {
        // PCA-0015: turn_id is a naming value; the legacy bare form (66 chars)
        // is rejected — only the full registry multihash (70 chars) is valid.
        let bad = AuditRoundAnchor {
            turn_id: format!("0x{}", "cd".repeat(32)),
            ..make_anchor()
        };
        assert_eq!(bad.validate(), Err(AuditRoundAnchorError::InvalidTurnId));
    }

    #[test]
    fn validate_accepts_bare_merkle_root() {
        // merkle_root is an app-defined Merkle root (§3.3 out-of-scope) and
        // stays a bare 66-char SHA3-256 digest — it is NOT a multihash.
        let anchor = make_anchor();
        assert_eq!(anchor.merkle_root.len(), 66);
        assert!(anchor.validate().is_ok());
    }

    #[test]
    fn validate_rejects_mismatched_count() {
        let bad = AuditRoundAnchor {
            artifact_count: 99,
            ..make_anchor()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditRoundAnchorError::MismatchedArtifactCount)
        );
    }

    /// Parse TEMPLATE_JSON and confirm the ancestry chain
    /// `audit_round_anchor -> audit_artifact -> identity_base`.
    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditRoundAnchor::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

        let parent_hash = "0x1620431668e53b2181311ec43db30ff4d4cf738059051829a5a4f3398c22440a16f3";
        assert_eq!(
            template["derives_from"]
                .as_str()
                .expect("derives_from is a string"),
            parent_hash,
            "derives_from must be audit_artifact real hash"
        );

        let ancestry = template["ancestry"]
            .as_array()
            .expect("ancestry is an array");
        assert_eq!(ancestry.len(), 1, "ancestry must have exactly 1 entry");
        assert_eq!(
            ancestry[0].as_str().unwrap(),
            parent_hash,
            "ancestry[0] must be audit_artifact real hash"
        );
    }
}
