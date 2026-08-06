use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditAgentToolCall` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditAgentToolCallError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("turn_id must not be empty")]
    EmptyTurnId,
    #[error("tool_name must not be empty")]
    EmptyToolName,
    #[error("risk_level must not be empty")]
    EmptyRiskLevel,
}

/// T4 — agent tool-call artifact. Signed by the agent_key DID.
///
/// Spec §7.3, §7.6: T4 records an MCP tool invocation issued by the agent
/// within a turn. Linked to T1 via `turn_id`. `tool_args` is a redaction
/// target for the `pseudonymous` disclosure preset.
///
/// **Parent of further-derived templates.** T4 is itself a parent for
/// concrete tool-call templates (e.g. `gusto_employee_create`). The SDK
/// max-depth-4 rule (`src/schema/template.rs`: ancestry max length 3)
/// accommodates the chain
/// `audit_artifact → audit_agent_tool_call → <derivative>` with one
/// level of headroom. See `depth_headroom_for_t4_derivatives` test.
///
/// `risk_level` is a free-form string at this layer (not enum-locked).
/// Recommended values: `"low"`, `"medium"`, `"high"`, `"hitl-required"`.
/// Per-derivative templates may pin specific values via JSON-schema
/// `const`, similar to how W3 service_claim derivatives pin `service_kind`.
///
/// Ancestry: `audit_agent_tool_call → audit_artifact → identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditAgentToolCall {
    pub signer_did: String,
    pub turn_id: String,
    pub seq_in_turn: u64,
    pub tool_name: String,
    pub tool_args: serde_json::Value,
    pub risk_level: String,
    pub created_at: u64,
}

impl AuditAgentToolCall {
    pub fn validate(&self) -> Result<(), AuditAgentToolCallError> {
        if self.signer_did.is_empty() {
            return Err(AuditAgentToolCallError::EmptySignerDid);
        }
        if self.turn_id.is_empty() {
            return Err(AuditAgentToolCallError::EmptyTurnId);
        }
        if self.tool_name.is_empty() {
            return Err(AuditAgentToolCallError::EmptyToolName);
        }
        if self.risk_level.is_empty() {
            return Err(AuditAgentToolCallError::EmptyRiskLevel);
        }
        Ok(())
    }

    /// JSON-Pointer paths consumed by the P3 Disclosure Builder
    /// `pseudonymous` redaction preset for T4 artifacts.
    pub fn pseudonymous_redaction_pointers() -> &'static [&'static str] {
        &["/tool_args"]
    }
}

impl BuiltInTemplate for AuditAgentToolCall {
    const TEMPLATE_JSON: &'static str = include_str!("audit_agent_tool_call.json");
    /// Placeholder hash — Task 16 cascades the real value via `verify-templates --fix`.
    const TEMPLATE_LINK: [u8; 32] = [
        0x63, 0xf6, 0xa4, 0x0e, 0xe6, 0xc5, 0xfb, 0x9a, 0x3f, 0x93, 0xcb, 0x6e, 0xcf, 0xdc, 0x91,
        0x7d, 0xc5, 0xc0, 0x38, 0x96, 0xcf, 0x88, 0xf3, 0x37, 0x9c, 0x97, 0xc2, 0x90, 0x50, 0x19,
        0x66, 0xd0,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tool_call() -> AuditAgentToolCall {
        AuditAgentToolCall {
            signer_did: "did:key:z6MkAgent".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 2,
            tool_name: "gusto.employee.create".to_string(),
            tool_args: serde_json::json!({"first_name": "Ada", "last_name": "Lovelace"}),
            risk_level: "medium".to_string(),
            created_at: 1747526403,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_tool_call();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditAgentToolCall =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2);
    }

    #[test]
    fn validate_accepts_valid_tool_call() {
        assert!(make_tool_call().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditAgentToolCall {
            signer_did: String::new(),
            ..make_tool_call()
        };
        assert_eq!(bad.validate(), Err(AuditAgentToolCallError::EmptySignerDid));
    }

    #[test]
    fn validate_rejects_empty_turn_id() {
        let bad = AuditAgentToolCall {
            turn_id: String::new(),
            ..make_tool_call()
        };
        assert_eq!(bad.validate(), Err(AuditAgentToolCallError::EmptyTurnId));
    }

    #[test]
    fn validate_rejects_empty_tool_name() {
        let bad = AuditAgentToolCall {
            tool_name: String::new(),
            ..make_tool_call()
        };
        assert_eq!(bad.validate(), Err(AuditAgentToolCallError::EmptyToolName));
    }

    #[test]
    fn validate_rejects_empty_risk_level() {
        let bad = AuditAgentToolCall {
            risk_level: String::new(),
            ..make_tool_call()
        };
        assert_eq!(bad.validate(), Err(AuditAgentToolCallError::EmptyRiskLevel));
    }

    #[test]
    fn risk_level_is_free_form_string() {
        // T4 deliberately does NOT enforce an enum on risk_level — this is
        // a parent template; per-derivative templates may pin specific values.
        let custom = AuditAgentToolCall {
            risk_level: "hitl-required".to_string(),
            ..make_tool_call()
        };
        assert!(custom.validate().is_ok());

        let unusual = AuditAgentToolCall {
            risk_level: "experimental-classification".to_string(),
            ..make_tool_call()
        };
        assert!(unusual.validate().is_ok());
    }

    #[test]
    fn tool_args_accepts_arbitrary_json() {
        let obj = AuditAgentToolCall {
            tool_args: serde_json::json!({"nested": {"deep": [1, 2, 3]}}),
            ..make_tool_call()
        };
        assert!(obj.validate().is_ok());

        let arr = AuditAgentToolCall {
            tool_args: serde_json::json!([1, 2, 3]),
            ..make_tool_call()
        };
        let s = serde_json::to_string(&arr).unwrap();
        let back: AuditAgentToolCall = serde_json::from_str(&s).unwrap();
        assert_eq!(arr, back);
    }

    /// Gate check for AUDIT-LINKS: can a derived template narrow `tool_args`
    /// from opaque (any JSON) to a specific object schema with required fields?
    ///
    /// This is the go/no-go gate for creating operational templates (depth 3)
    /// that refine T4's unconstrained `tool_args` into concrete per-tool schemas.
    #[test]
    fn gate_narrowing_allows_tool_args_refinement() {
        use crate::core::template::create_derived_template_util;
        use crate::schema::template::Template;

        let t4: Template = serde_json::from_str(AuditAgentToolCall::TEMPLATE_JSON)
            .expect("T4 template must parse");

        // Verify T4 is at depth 2 (ancestry length 2) so a derivative will be at depth 3
        assert_eq!(t4.depth(), 2, "T4 must be at depth 2 before deriving");

        // Child schema: identical top-level keys, tool_name narrowed to const,
        // tool_args narrowed from opaque (any JSON) to a specific object with
        // required fields and additionalProperties: false.
        let child_schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "signer_did": {
                    "type": "string",
                    "pattern": "^did:(pkh|key):",
                    "maxLength": 256
                },
                "turn_id": {
                    "type": "string",
                    "pattern": "^0x[0-9a-f]{64}$"
                },
                "seq_in_turn": {
                    "type": "integer",
                    "minimum": 0
                },
                "tool_name": {
                    "type": "string",
                    "const": "test_employee_create"
                },
                "tool_args": {
                    "type": "object",
                    "required": ["company_id", "first_name", "last_name"],
                    "properties": {
                        "company_id": { "type": "string" },
                        "first_name": { "type": "string", "minLength": 1 },
                        "last_name": { "type": "string", "minLength": 1 },
                        "email": { "type": "string" }
                    },
                    "additionalProperties": false
                },
                "risk_level": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64
                },
                "created_at": {
                    "type": "integer",
                    "minimum": 0
                }
            },
            "required": [
                "signer_did", "turn_id", "seq_in_turn",
                "tool_name", "tool_args", "risk_level", "created_at"
            ],
            "additionalProperties": false
        });

        let result = create_derived_template_util(&t4, child_schema, None, true);
        assert!(
            result.is_ok(),
            "GATE FAILED: narrowing tool_args from any-JSON to specific object \
             was rejected by the SDK narrowing validator: {result:?}. \
             AUDIT-LINKS Option B is blocked. See spec for fallback."
        );

        // Verify the derived template is at depth 3 (ancestry length 3 = max)
        let derived = result.unwrap();
        assert_eq!(
            derived.ancestry().map(|a| a.len()),
            Some(3),
            "derived operational template must be at depth 3 (max)"
        );
    }

    #[test]
    fn pseudonymous_pointers_match_spec() {
        assert_eq!(
            AuditAgentToolCall::pseudonymous_redaction_pointers(),
            &["/tool_args"]
        );
    }

    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditAgentToolCall::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

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

    /// T4 is itself a parent for further-derived tool-call templates
    /// (e.g. gusto_employee_create). The SDK max-depth-4 rule
    /// (`src/schema/template.rs`: ancestry max length 3) requires that
    /// the chain `<derivative> → audit_agent_tool_call → audit_artifact
    /// → identity_base` fit within 3 ancestry entries.
    ///
    /// T4's ancestry has 2 entries today (audit_artifact placeholder,
    /// identity_base). One additional entry is reserved for derivatives,
    /// keeping the depth at the limit (3) when a derivative is added.
    #[test]
    fn depth_headroom_for_t4_derivatives() {
        let template: serde_json::Value =
            serde_json::from_str(AuditAgentToolCall::TEMPLATE_JSON).unwrap();
        let ancestry_len = template["ancestry"].as_array().unwrap().len();
        // T4's own ancestry has 2 entries; a derivative adds 1 to its own
        // ancestry (since derivative.ancestry = [parent, ...parent.ancestry]).
        // Max allowed is 3 — confirm derivative would fit.
        let derivative_ancestry_len = ancestry_len + 1;
        assert!(
            derivative_ancestry_len <= 3,
            "T4 derivative ancestry length {} must not exceed SDK max depth 3",
            derivative_ancestry_len
        );
    }
}
