use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditAgentResponse` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditAgentResponseError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("turn_id must not be empty")]
    EmptyTurnId,
}

/// T8 — agent response artifact. Signed by the agent_key DID.
///
/// Spec §7.3, §7.6: T8 records the agent's response text shown to the
/// user. Linked to T1 via `turn_id`. The artifact with `is_final = true`
/// closes the turn (the verifier expects exactly one final T8 per turn).
///
/// `response_text` is the primary redaction target for the
/// `pseudonymous` disclosure preset.
///
/// Ancestry: `audit_agent_response → audit_artifact → identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditAgentResponse {
    pub signer_did: String,
    pub turn_id: String,
    pub response_text: String,
    pub is_final: bool,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<String>,
}

impl AuditAgentResponse {
    pub fn validate(&self) -> Result<(), AuditAgentResponseError> {
        if self.signer_did.is_empty() {
            return Err(AuditAgentResponseError::EmptySignerDid);
        }
        if self.turn_id.is_empty() {
            return Err(AuditAgentResponseError::EmptyTurnId);
        }
        Ok(())
    }

    /// JSON-Pointer paths consumed by the P3 Disclosure Builder
    /// `pseudonymous` redaction preset for T8 artifacts.
    pub fn pseudonymous_redaction_pointers() -> &'static [&'static str] {
        &["/response_text", "/thinking"]
    }
}

impl BuiltInTemplate for AuditAgentResponse {
    const TEMPLATE_JSON: &'static str = include_str!("audit_agent_response.json");
    /// Placeholder hash — Task 16 cascades the real value via `verify-templates --fix`.
    const TEMPLATE_LINK: [u8; 32] = [
        0xe3, 0x6f, 0x3a, 0xf1, 0x1b, 0x2c, 0x6d, 0x5c, 0x94, 0xe2, 0x86, 0x2e, 0x4a, 0x66, 0xdb,
        0x01, 0x6f, 0xf8, 0xe8, 0xf5, 0x48, 0x6f, 0xe7, 0x25, 0x94, 0xda, 0xa7, 0xdf, 0x48, 0x0c,
        0x54, 0x13,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response() -> AuditAgentResponse {
        AuditAgentResponse {
            signer_did: "did:key:z6MkAgent".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            response_text: "Your federal tax liability is $4,231.50.".to_string(),
            is_final: true,
            created_at: 1747526407,
            model_name: None,
            tokens_used: None,
            thinking: None,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_response();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditAgentResponse =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2);
    }

    #[test]
    fn optional_fields_omitted_when_none() {
        let r = make_response();
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("model_name"));
        assert!(!s.contains("tokens_used"));
    }

    #[test]
    fn non_final_intermediate_response_round_trips() {
        let r = AuditAgentResponse {
            is_final: false,
            response_text: "Checking your W-4 ...".to_string(),
            model_name: Some("claude-opus-4.6".to_string()),
            tokens_used: Some(187),
            thinking: Some("User wants W-4 status. Let me check.".to_string()),
            ..make_response()
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: AuditAgentResponse = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn validate_accepts_valid_response() {
        assert!(make_response().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditAgentResponse {
            signer_did: String::new(),
            ..make_response()
        };
        assert_eq!(bad.validate(), Err(AuditAgentResponseError::EmptySignerDid));
    }

    #[test]
    fn validate_rejects_empty_turn_id() {
        let bad = AuditAgentResponse {
            turn_id: String::new(),
            ..make_response()
        };
        assert_eq!(bad.validate(), Err(AuditAgentResponseError::EmptyTurnId));
    }

    #[test]
    fn pseudonymous_pointers_match_spec() {
        assert_eq!(
            AuditAgentResponse::pseudonymous_redaction_pointers(),
            &["/response_text", "/thinking"]
        );
    }

    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditAgentResponse::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

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
