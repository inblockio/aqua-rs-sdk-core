use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditHitlApproval` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditHitlApprovalError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("turn_id must not be empty")]
    EmptyTurnId,
    #[error("decision must be one of: approved, rejected")]
    InvalidDecision,
    #[error("prompt_shown must not be empty")]
    EmptyPromptShown,
}

/// HITL decision enum. Concrete strings as serialized: `"approved"` / `"rejected"`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HitlDecision {
    Approved,
    Rejected,
}

/// T7 — HITL (human-in-the-loop) approval artifact. Signed by the
/// user_app_session_key DID — the human authorizing the action.
///
/// Spec §7.3, §7.6: T7 records a user's explicit approval or rejection
/// of a high-risk action surfaced by the agent. Linked to T1 via
/// `turn_id`. `prompt_shown` and `rationale` are redaction targets for
/// the `pseudonymous` disclosure preset.
///
/// **P2/P3 split:** P2 emits a placeholder T7 stub; P3 owns the full
/// signed-approval upgrade (separate from the audit round emission
/// pipeline). The SDK template is identical in both phases.
///
/// Ancestry: `audit_hitl_approval → audit_artifact → identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditHitlApproval {
    pub signer_did: String,
    pub turn_id: String,
    pub decision: HitlDecision,
    pub prompt_shown: String,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

impl AuditHitlApproval {
    pub fn validate(&self) -> Result<(), AuditHitlApprovalError> {
        if self.signer_did.is_empty() {
            return Err(AuditHitlApprovalError::EmptySignerDid);
        }
        if self.turn_id.is_empty() {
            return Err(AuditHitlApprovalError::EmptyTurnId);
        }
        if self.prompt_shown.is_empty() {
            return Err(AuditHitlApprovalError::EmptyPromptShown);
        }
        // Decision enum is enforced by serde at deserialization; this method
        // is a no-op for in-memory values — but the JSON schema also pins
        // {"approved", "rejected"} for revisions consumed via TEMPLATE_JSON.
        Ok(())
    }

    /// JSON-Pointer paths consumed by the P3 Disclosure Builder
    /// `pseudonymous` redaction preset for T7 artifacts.
    pub fn pseudonymous_redaction_pointers() -> &'static [&'static str] {
        &["/prompt_shown", "/rationale"]
    }
}

impl BuiltInTemplate for AuditHitlApproval {
    const TEMPLATE_JSON: &'static str = include_str!("audit_hitl_approval.json");
    /// Placeholder hash — Task 16 cascades the real value via `verify-templates --fix`.
    const TEMPLATE_LINK: [u8; 32] = [
        0xe8, 0x5b, 0x06, 0x71, 0x51, 0xb0, 0x68, 0x72, 0x14, 0x32, 0x3e, 0xba, 0x4e, 0x1f, 0x2a,
        0x14, 0xa4, 0x7f, 0xb6, 0xf4, 0x5a, 0xff, 0x82, 0x7f, 0x05, 0x4d, 0x65, 0x54, 0x0d, 0xc3,
        0x29, 0x81,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_approval() -> AuditHitlApproval {
        AuditHitlApproval {
            signer_did: "did:key:z6MkUserSession".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            decision: HitlDecision::Approved,
            prompt_shown: "Process payroll for 3 employees?".to_string(),
            created_at: 1747526406,
            rationale: None,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_approval();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditHitlApproval =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2);
    }

    #[test]
    fn decision_serializes_lowercase() {
        let approved = make_approval();
        let s = serde_json::to_string(&approved).unwrap();
        assert!(
            s.contains("\"decision\":\"approved\""),
            "decision must serialize as lowercase string, got: {}",
            s
        );

        let rejected = AuditHitlApproval {
            decision: HitlDecision::Rejected,
            ..make_approval()
        };
        let s2 = serde_json::to_string(&rejected).unwrap();
        assert!(s2.contains("\"decision\":\"rejected\""));
    }

    /// Serde must reject any decision string outside the enum.
    #[test]
    fn deserialize_rejects_unknown_decision() {
        let json = serde_json::json!({
            "signer_did": "did:key:z6MkUserSession",
            "turn_id": format!("0x{}", "ab".repeat(32)),
            "decision": "maybe",
            "prompt_shown": "anything",
            "created_at": 1747526406_u64,
        });
        let result: Result<AuditHitlApproval, _> = serde_json::from_value(json);
        assert!(result.is_err(), "decision='maybe' must fail to deserialize");
    }

    #[test]
    fn optional_rationale_omitted_when_none() {
        let a = make_approval();
        let s = serde_json::to_string(&a).unwrap();
        assert!(!s.contains("rationale"));
    }

    #[test]
    fn rejected_with_rationale_round_trips() {
        let a = AuditHitlApproval {
            decision: HitlDecision::Rejected,
            rationale: Some("Off-cycle payrolls require accounting review".to_string()),
            ..make_approval()
        };
        let s = serde_json::to_string(&a).unwrap();
        let back: AuditHitlApproval = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn validate_accepts_valid_approval() {
        assert!(make_approval().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditHitlApproval {
            signer_did: String::new(),
            ..make_approval()
        };
        assert_eq!(bad.validate(), Err(AuditHitlApprovalError::EmptySignerDid));
    }

    #[test]
    fn validate_rejects_empty_prompt_shown() {
        let bad = AuditHitlApproval {
            prompt_shown: String::new(),
            ..make_approval()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditHitlApprovalError::EmptyPromptShown)
        );
    }

    #[test]
    fn pseudonymous_pointers_match_spec() {
        assert_eq!(
            AuditHitlApproval::pseudonymous_redaction_pointers(),
            &["/prompt_shown", "/rationale"]
        );
    }

    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditHitlApproval::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

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

    /// Spec §7.3: the schema must enumerate decision values to prevent
    /// off-protocol decisions in revisions consumed via TEMPLATE_JSON.
    #[test]
    fn template_json_pins_decision_enum() {
        let template: serde_json::Value =
            serde_json::from_str(AuditHitlApproval::TEMPLATE_JSON).unwrap();
        let decision_enum = template["schema"]["properties"]["decision"]["enum"]
            .as_array()
            .expect("decision enum must be an array");
        let values: Vec<&str> = decision_enum.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(values, vec!["approved", "rejected"]);
    }
}
