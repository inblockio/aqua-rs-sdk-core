use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditAgentThinking` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditAgentThinkingError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("turn_id must not be empty")]
    EmptyTurnId,
    #[error("claude_round_id must not be empty")]
    EmptyClaudeRoundId,
}

/// T3 — agent thinking artifact. Signed by the agent_key DID.
///
/// Spec §7.3, §7.6: T3 records Claude's reasoning trace for one round
/// within a turn. Linked to T1 via `turn_id`. `thinking_text` is a
/// redaction target for the `pseudonymous` disclosure preset.
///
/// Multiple T3 artifacts may exist per turn (one per Claude round);
/// `seq_in_turn` orders them deterministically.
///
/// Ancestry: `audit_agent_thinking → audit_artifact → identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditAgentThinking {
    pub signer_did: String,
    pub turn_id: String,
    pub seq_in_turn: u64,
    pub thinking_text: String,
    pub claude_round_id: String,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<u32>,
}

impl AuditAgentThinking {
    pub fn validate(&self) -> Result<(), AuditAgentThinkingError> {
        if self.signer_did.is_empty() {
            return Err(AuditAgentThinkingError::EmptySignerDid);
        }
        if self.turn_id.is_empty() {
            return Err(AuditAgentThinkingError::EmptyTurnId);
        }
        if self.claude_round_id.is_empty() {
            return Err(AuditAgentThinkingError::EmptyClaudeRoundId);
        }
        Ok(())
    }

    /// JSON-Pointer paths consumed by the P3 Disclosure Builder
    /// `pseudonymous` redaction preset for T3 artifacts.
    pub fn pseudonymous_redaction_pointers() -> &'static [&'static str] {
        &["/thinking_text"]
    }
}

impl BuiltInTemplate for AuditAgentThinking {
    const TEMPLATE_JSON: &'static str = include_str!("audit_agent_thinking.json");
    /// Placeholder hash — Task 16 cascades the real value via `verify-templates --fix`.
    const TEMPLATE_LINK: [u8; 32] = [
        0x19, 0xfe, 0x5e, 0xa9, 0x15, 0xa1, 0x29, 0xfd, 0xa1, 0x64, 0x0a, 0xfb, 0x12, 0xe4, 0x4d,
        0x1f, 0x46, 0xa9, 0x9e, 0x3e, 0x99, 0x41, 0xb1, 0x47, 0x7b, 0xdc, 0xf2, 0x66, 0x64, 0x29,
        0x0f, 0xb0,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_thinking() -> AuditAgentThinking {
        AuditAgentThinking {
            signer_did: "did:key:z6MkAgent".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 1,
            thinking_text: "User wants federal tax. Need to check W4 first...".to_string(),
            claude_round_id: "round-001".to_string(),
            created_at: 1747526402,
            model_name: None,
            tokens_used: None,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_thinking();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditAgentThinking =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2);
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let t = make_thinking();
        let serialized = serde_json::to_string(&t).expect("serialize");
        assert!(!serialized.contains("model_name"));
        assert!(!serialized.contains("tokens_used"));
    }

    #[test]
    fn with_optional_fields_round_trips() {
        let t = AuditAgentThinking {
            model_name: Some("claude-opus-4.6".to_string()),
            tokens_used: Some(1234),
            ..make_thinking()
        };
        let serialized = serde_json::to_string(&t).expect("serialize");
        let deserialized: AuditAgentThinking =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(t, deserialized);
    }

    #[test]
    fn validate_accepts_valid_thinking() {
        assert!(make_thinking().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditAgentThinking {
            signer_did: String::new(),
            ..make_thinking()
        };
        assert_eq!(bad.validate(), Err(AuditAgentThinkingError::EmptySignerDid));
    }

    #[test]
    fn validate_rejects_empty_turn_id() {
        let bad = AuditAgentThinking {
            turn_id: String::new(),
            ..make_thinking()
        };
        assert_eq!(bad.validate(), Err(AuditAgentThinkingError::EmptyTurnId));
    }

    #[test]
    fn validate_rejects_empty_claude_round_id() {
        let bad = AuditAgentThinking {
            claude_round_id: String::new(),
            ..make_thinking()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditAgentThinkingError::EmptyClaudeRoundId)
        );
    }

    #[test]
    fn pseudonymous_pointers_match_spec() {
        let pointers = AuditAgentThinking::pseudonymous_redaction_pointers();
        assert_eq!(pointers, &["/thinking_text"]);
    }

    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditAgentThinking::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

        let parent_hash = "0x1620111d65c253f72bc4e2b69ede969b26785dc5e54bd6b2906d79887232be242665";
        let identity_base_hash =
            "0x1620812b61a5906095bc375273813918e994555e1f386595c0187438c00435b107b4";

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
        assert_eq!(ancestry.len(), 2, "ancestry must have exactly 2 entries");
        assert_eq!(
            ancestry[0].as_str().unwrap(),
            identity_base_hash,
            "ancestry[0] must be identity_base real hash"
        );
        assert_eq!(
            ancestry[1].as_str().unwrap(),
            parent_hash,
            "ancestry[1] must be audit_artifact real hash"
        );
    }
}
