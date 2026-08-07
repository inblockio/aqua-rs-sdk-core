use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditToolResult` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditToolResultError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("turn_id must not be empty")]
    EmptyTurnId,
    #[error("tool_name must not be empty")]
    EmptyToolName,
}

/// T6 — tool result artifact. Signed by the agent_key DID.
///
/// Spec §7.3, §7.6: T6 records the result of a tool invocation observed
/// by the agent (the local-side observation, paired with T5 when the
/// tool is a third-party API attested independently). Linked to T1 via
/// `turn_id`.
///
/// `result_payload` (opaque JSON) and `error_message` (when present) are
/// redaction targets for the `pseudonymous` disclosure preset.
///
/// Ancestry: `audit_tool_result → audit_artifact → identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditToolResult {
    pub signer_did: String,
    pub turn_id: String,
    pub seq_in_turn: u64,
    pub tool_name: String,
    pub result_payload: serde_json::Value,
    pub success: bool,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl AuditToolResult {
    pub fn validate(&self) -> Result<(), AuditToolResultError> {
        if self.signer_did.is_empty() {
            return Err(AuditToolResultError::EmptySignerDid);
        }
        if self.turn_id.is_empty() {
            return Err(AuditToolResultError::EmptyTurnId);
        }
        if self.tool_name.is_empty() {
            return Err(AuditToolResultError::EmptyToolName);
        }
        Ok(())
    }

    /// JSON-Pointer paths consumed by the P3 Disclosure Builder
    /// `pseudonymous` redaction preset for T6 artifacts.
    pub fn pseudonymous_redaction_pointers() -> &'static [&'static str] {
        &["/result_payload", "/error_message"]
    }
}

impl BuiltInTemplate for AuditToolResult {
    const TEMPLATE_JSON: &'static str = include_str!("audit_tool_result.json");
    /// Placeholder hash — Task 16 cascades the real value via `verify-templates --fix`.
    const TEMPLATE_LINK: [u8; 32] = [
        0x61, 0xea, 0xea, 0x9d, 0x2a, 0xf4, 0xae, 0xe4, 0x9a, 0xb8, 0x31, 0x57, 0xdd, 0x8d, 0x3c,
        0x3e, 0x83, 0xe7, 0x08, 0xaf, 0xb1, 0x68, 0x5a, 0xae, 0xa1, 0x1c, 0x21, 0x3b, 0x75, 0x0c,
        0x24, 0xf7,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result() -> AuditToolResult {
        AuditToolResult {
            signer_did: "did:key:z6MkAgent".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 4,
            tool_name: "inventory.item.create".to_string(),
            result_payload: serde_json::json!({"employee_id": "emp_42"}),
            success: true,
            created_at: 1747526405,
            error_message: None,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_result();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditToolResult = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2);
    }

    #[test]
    fn optional_error_message_omitted_when_none() {
        let r = make_result();
        let serialized = serde_json::to_string(&r).unwrap();
        assert!(!serialized.contains("error_message"));
    }

    #[test]
    fn failure_with_error_message_round_trips() {
        let r = AuditToolResult {
            success: false,
            error_message: Some("API returned 422".to_string()),
            ..make_result()
        };
        let serialized = serde_json::to_string(&r).unwrap();
        let deserialized: AuditToolResult = serde_json::from_str(&serialized).unwrap();
        assert_eq!(r, deserialized);
    }

    #[test]
    fn validate_accepts_valid_result() {
        assert!(make_result().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditToolResult {
            signer_did: String::new(),
            ..make_result()
        };
        assert_eq!(bad.validate(), Err(AuditToolResultError::EmptySignerDid));
    }

    #[test]
    fn validate_rejects_empty_turn_id() {
        let bad = AuditToolResult {
            turn_id: String::new(),
            ..make_result()
        };
        assert_eq!(bad.validate(), Err(AuditToolResultError::EmptyTurnId));
    }

    #[test]
    fn validate_rejects_empty_tool_name() {
        let bad = AuditToolResult {
            tool_name: String::new(),
            ..make_result()
        };
        assert_eq!(bad.validate(), Err(AuditToolResultError::EmptyToolName));
    }

    #[test]
    fn pseudonymous_pointers_match_spec() {
        assert_eq!(
            AuditToolResult::pseudonymous_redaction_pointers(),
            &["/result_payload", "/error_message"]
        );
    }

    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditToolResult::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

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
