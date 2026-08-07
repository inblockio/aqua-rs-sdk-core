use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Valid reasons a session can be closed.
const VALID_REASONS: &[&str] = &[
    "user_ended",
    "idle_timeout",
    "time_exhausted",
    "admin_stopped",
    "container_crashed",
];

/// Validation errors for an `AuditSessionClose` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditSessionCloseError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("session_id must not be empty")]
    EmptySessionId,
    #[error("reason must be one of: user_ended, idle_timeout, time_exhausted, admin_stopped, container_crashed")]
    InvalidReason,
    #[error("last_turn_id must be either empty or a 0x-prefixed registry multihash (70-char hex: 0x16/0x1e + 0x20 + 64 hex digits)")]
    InvalidLastTurnId,
    #[error("last_round_anchor_hash must be either empty or a 0x-prefixed registry multihash (70-char hex: 0x16/0x1e + 0x20 + 64 hex digits)")]
    InvalidLastRoundAnchorHash,
}

/// TC0 / session-close seal. Server-signed artifact marking the cryptographic
/// boundary of a session.
///
/// Spec reference: the session-close seal is emitted once per session, after
/// the last audit round. Its revision hash serves as the tamper-evident
/// end-point of the audit chain. All audit artifacts for the session are
/// reachable by walking backwards from this seal via `last_round_anchor_hash`.
///
/// `last_turn_id` and `last_round_anchor_hash` are allowed to be empty strings
/// for zero-turn sessions (sessions that were closed before the user sent any
/// message).
///
/// Ancestry: `audit_session_close -> audit_artifact -> identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditSessionClose {
    pub signer_did: String,
    pub session_id: String,
    pub total_turns: u64,
    pub last_turn_id: String,
    pub last_round_anchor_hash: String,
    pub reason: String,
    pub closed_at: u64,
}

impl AuditSessionClose {
    pub fn validate(&self) -> Result<(), AuditSessionCloseError> {
        if self.signer_did.is_empty() {
            return Err(AuditSessionCloseError::EmptySignerDid);
        }
        if self.session_id.is_empty() {
            return Err(AuditSessionCloseError::EmptySessionId);
        }
        if !VALID_REASONS.contains(&self.reason.as_str()) {
            return Err(AuditSessionCloseError::InvalidReason);
        }
        if !is_valid_hash_or_empty(&self.last_turn_id) {
            return Err(AuditSessionCloseError::InvalidLastTurnId);
        }
        if !is_valid_hash_or_empty(&self.last_round_anchor_hash) {
            return Err(AuditSessionCloseError::InvalidLastRoundAnchorHash);
        }
        Ok(())
    }
}

/// Returns true if the value is either an empty string (zero-turn session)
/// or a PCA-0015 registry multihash naming value. `last_turn_id` and
/// `last_round_anchor_hash` reference Aqua revision hashes (§3.3 naming
/// values), so a non-empty value MUST be the full multihash form, not a
/// bare 32-byte digest.
fn is_valid_hash_or_empty(value: &str) -> bool {
    value.is_empty() || is_multihash_hex(value)
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

impl BuiltInTemplate for AuditSessionClose {
    const TEMPLATE_JSON: &'static str = include_str!("audit_session_close.json");
    /// Placeholder hash, populated by `verify-templates --fix` (cascade-aware).
    const TEMPLATE_LINK: [u8; 32] = [
        0x90, 0x69, 0x52, 0x51, 0x03, 0xb9, 0x40, 0x8f, 0x03, 0x9a, 0x41, 0x45, 0x4d, 0x25, 0xed,
        0x5f, 0xfc, 0x59, 0xae, 0xd9, 0xe4, 0x62, 0x24, 0xcb, 0x19, 0x86, 0x4f, 0x2e, 0x71, 0xe0,
        0xc2, 0x3b,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_close() -> AuditSessionClose {
        AuditSessionClose {
            signer_did: "did:key:z6MkServer".to_string(),
            session_id: "sess-abc123".to_string(),
            total_turns: 5,
            last_turn_id: "0x1620".to_string() + &"ab".repeat(32),
            last_round_anchor_hash: "0x1620".to_string() + &"cd".repeat(32),
            reason: "user_ended".to_string(),
            closed_at: 1747526400,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_close();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditSessionClose =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2, "canonical serialization stable");
    }

    #[test]
    fn validate_accepts_valid() {
        assert!(make_close().validate().is_ok());
    }

    #[test]
    fn validate_accepts_all_valid_reasons() {
        for reason in VALID_REASONS {
            let close = AuditSessionClose {
                reason: reason.to_string(),
                ..make_close()
            };
            assert!(
                close.validate().is_ok(),
                "reason '{}' should be accepted",
                reason
            );
        }
    }

    #[test]
    fn validate_accepts_zero_turn_session() {
        let close = AuditSessionClose {
            total_turns: 0,
            last_turn_id: String::new(),
            last_round_anchor_hash: String::new(),
            reason: "idle_timeout".to_string(),
            ..make_close()
        };
        assert!(
            close.validate().is_ok(),
            "zero-turn session with empty hashes should be valid"
        );
    }

    #[test]
    fn validate_rejects_empty_signer() {
        let bad = AuditSessionClose {
            signer_did: String::new(),
            ..make_close()
        };
        assert_eq!(bad.validate(), Err(AuditSessionCloseError::EmptySignerDid));
    }

    #[test]
    fn validate_rejects_empty_session_id() {
        let bad = AuditSessionClose {
            session_id: String::new(),
            ..make_close()
        };
        assert_eq!(bad.validate(), Err(AuditSessionCloseError::EmptySessionId));
    }

    #[test]
    fn validate_rejects_invalid_reason() {
        let bad = AuditSessionClose {
            reason: "not_a_real_reason".to_string(),
            ..make_close()
        };
        assert_eq!(bad.validate(), Err(AuditSessionCloseError::InvalidReason));
    }

    #[test]
    fn validate_rejects_malformed_last_turn_id() {
        // Missing 0x prefix
        let bad = AuditSessionClose {
            last_turn_id: "abcdef1234".to_string(),
            ..make_close()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditSessionCloseError::InvalidLastTurnId)
        );

        // Wrong length (too short)
        let bad2 = AuditSessionClose {
            last_turn_id: "0xabcd".to_string(),
            ..make_close()
        };
        assert_eq!(
            bad2.validate(),
            Err(AuditSessionCloseError::InvalidLastTurnId)
        );
    }

    #[test]
    fn validate_rejects_bare_pre_multihash_hash() {
        // PCA-0015: the legacy bare 32-byte form (0x + 64 hex = 66 chars) is no
        // longer a valid naming value; it must be the full registry multihash.
        let bad = AuditSessionClose {
            last_turn_id: "0x".to_string() + &"ab".repeat(32),
            ..make_close()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditSessionCloseError::InvalidLastTurnId)
        );

        // Unknown multicodec code (0x17) is rejected even at the correct length.
        let bad_code = AuditSessionClose {
            last_round_anchor_hash: "0x1720".to_string() + &"cd".repeat(32),
            ..make_close()
        };
        assert_eq!(
            bad_code.validate(),
            Err(AuditSessionCloseError::InvalidLastRoundAnchorHash)
        );
    }

    #[test]
    fn validate_rejects_malformed_last_round_anchor_hash() {
        let bad = AuditSessionClose {
            last_round_anchor_hash: "not-a-hash".to_string(),
            ..make_close()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditSessionCloseError::InvalidLastRoundAnchorHash)
        );
    }

    /// Parse TEMPLATE_JSON and confirm the ancestry chain
    /// `audit_session_close -> audit_artifact -> identity_base`.
    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditSessionClose::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

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
