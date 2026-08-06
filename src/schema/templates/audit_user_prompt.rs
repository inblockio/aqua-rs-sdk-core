use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditUserPrompt` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditUserPromptError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("session_id must not be empty")]
    EmptySessionId,
    #[error("turn_id must not be empty")]
    EmptyTurnId,
}

/// Attachment record for a user prompt — references content by hash.
///
/// Attachments are referenced by hash, NOT inlined, so prompts remain
/// small enough to sign and so attachments may be redacted independently.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AttachedFile {
    pub filename: String,
    pub hash: String,
    pub size: u64,
}

/// T2 — user prompt artifact. Signed by the user_app_session_key DID.
///
/// Spec §7.3, §7.6: T2 records the user's prompt for one turn. Linked to
/// T1 via `turn_id` (hex hash of the T1 marker). `prompt_text` and
/// `audio_recording_hash` are redaction targets for the `pseudonymous`
/// disclosure preset (P3 Disclosure Builder).
///
/// Ancestry: `audit_user_prompt → audit_artifact → identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditUserPrompt {
    pub signer_did: String,
    pub session_id: String,
    pub turn_id: String,
    pub prompt_text: String,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_recording_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attached_files: Option<Vec<AttachedFile>>,
}

impl AuditUserPrompt {
    pub fn validate(&self) -> Result<(), AuditUserPromptError> {
        if self.signer_did.is_empty() {
            return Err(AuditUserPromptError::EmptySignerDid);
        }
        if self.session_id.is_empty() {
            return Err(AuditUserPromptError::EmptySessionId);
        }
        if self.turn_id.is_empty() {
            return Err(AuditUserPromptError::EmptyTurnId);
        }
        Ok(())
    }

    /// JSON-Pointer paths consumed by the P3 Disclosure Builder
    /// `pseudonymous` redaction preset for T2 artifacts.
    ///
    /// Spec §8 (selective disclosure): these fields are replaced with
    /// salted leaf hashes when disclosing a redacted T2 to a third party.
    pub fn pseudonymous_redaction_pointers() -> &'static [&'static str] {
        &["/prompt_text", "/audio_recording_hash"]
    }
}

impl BuiltInTemplate for AuditUserPrompt {
    const TEMPLATE_JSON: &'static str = include_str!("audit_user_prompt.json");
    /// Placeholder hash — Task 16 cascades the real value via `verify-templates --fix`.
    const TEMPLATE_LINK: [u8; 32] = [
        0xe4, 0x7c, 0x71, 0xa7, 0x21, 0x87, 0xc5, 0xe0, 0xba, 0x11, 0x90, 0x82, 0xdd, 0x4f, 0x44,
        0x0b, 0x2d, 0xc9, 0xb4, 0x27, 0x13, 0x12, 0x12, 0x56, 0xe3, 0xb1, 0x17, 0xe1, 0x96, 0x36,
        0x9b, 0xa1,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_prompt() -> AuditUserPrompt {
        AuditUserPrompt {
            signer_did: "did:key:z6MkUserSession".to_string(),
            session_id: "sess-abc123".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            prompt_text: "What is my federal tax liability?".to_string(),
            created_at: 1747526401,
            audio_recording_hash: None,
            attached_files: None,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_prompt();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditUserPrompt = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2, "canonical serialization stable");
    }

    /// Optional fields must be omitted from canonical JSON when None
    /// (hash stability — absent keys must not introduce null bytes).
    #[test]
    fn optional_fields_omitted_when_none() {
        let p = make_prompt();
        let serialized = serde_json::to_string(&p).expect("serialize");
        assert!(
            !serialized.contains("audio_recording_hash"),
            "None audio_recording_hash must be omitted, not serialized as null"
        );
        assert!(
            !serialized.contains("attached_files"),
            "None attached_files must be omitted, not serialized as null"
        );
    }

    #[test]
    fn with_attached_files_round_trips() {
        let p = AuditUserPrompt {
            attached_files: Some(vec![AttachedFile {
                filename: "form_w4.pdf".to_string(),
                hash: format!("0x{}", "cd".repeat(32)),
                size: 8192,
            }]),
            audio_recording_hash: Some(format!("0x{}", "ef".repeat(32))),
            ..make_prompt()
        };
        let serialized = serde_json::to_string(&p).expect("serialize");
        let deserialized: AuditUserPrompt = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(p, deserialized);
    }

    #[test]
    fn validate_accepts_valid_prompt() {
        assert!(make_prompt().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditUserPrompt {
            signer_did: String::new(),
            ..make_prompt()
        };
        assert_eq!(bad.validate(), Err(AuditUserPromptError::EmptySignerDid));
    }

    #[test]
    fn validate_rejects_empty_session_id() {
        let bad = AuditUserPrompt {
            session_id: String::new(),
            ..make_prompt()
        };
        assert_eq!(bad.validate(), Err(AuditUserPromptError::EmptySessionId));
    }

    #[test]
    fn validate_rejects_empty_turn_id() {
        let bad = AuditUserPrompt {
            turn_id: String::new(),
            ..make_prompt()
        };
        assert_eq!(bad.validate(), Err(AuditUserPromptError::EmptyTurnId));
    }

    #[test]
    fn pseudonymous_pointers_match_spec() {
        let pointers = AuditUserPrompt::pseudonymous_redaction_pointers();
        assert!(pointers.contains(&"/prompt_text"));
        assert!(pointers.contains(&"/audio_recording_hash"));
        assert_eq!(pointers.len(), 2);
    }

    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditUserPrompt::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

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
