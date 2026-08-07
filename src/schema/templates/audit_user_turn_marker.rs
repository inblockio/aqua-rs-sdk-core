use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditUserTurnMarker` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditUserTurnMarkerError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("session_id must not be empty")]
    EmptySessionId,
}

/// T1 — user turn marker. Server-signed artifact opening a new turn.
///
/// Spec §7.3: T1 is the first artifact of every turn. Its revision hash defines
/// the `turn_id` referenced by all subsequent T2–T8 artifacts in the same turn
/// via the `aqua:in_user_turn` link.
///
/// `opens_at` substitutes the abstract `created_at` field inherited from
/// `audit_artifact` because a turn marker opens a turn rather than recording
/// the creation time of arbitrary content.
///
/// Ancestry: `audit_user_turn_marker → audit_artifact → identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditUserTurnMarker {
    pub signer_did: String,
    pub session_id: String,
    pub turn_index: u64,
    pub opens_at: u64,
}

impl AuditUserTurnMarker {
    pub fn validate(&self) -> Result<(), AuditUserTurnMarkerError> {
        if self.signer_did.is_empty() {
            return Err(AuditUserTurnMarkerError::EmptySignerDid);
        }
        if self.session_id.is_empty() {
            return Err(AuditUserTurnMarkerError::EmptySessionId);
        }
        Ok(())
    }
}

impl BuiltInTemplate for AuditUserTurnMarker {
    const TEMPLATE_JSON: &'static str = include_str!("audit_user_turn_marker.json");
    /// Placeholder hash — Task 16 cascades the real value via `verify-templates --fix`.
    const TEMPLATE_LINK: [u8; 32] = [
        0x9b, 0xf3, 0x89, 0x92, 0xcb, 0x2c, 0xc1, 0x23, 0x0e, 0xdb, 0x65, 0x39, 0xa9, 0x8e, 0x6d,
        0x3c, 0x88, 0x9c, 0x69, 0xaa, 0x09, 0xb1, 0x76, 0x4a, 0x4b, 0x91, 0xb3, 0x0c, 0xb6, 0xa3,
        0x69, 0x90,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_marker() -> AuditUserTurnMarker {
        AuditUserTurnMarker {
            signer_did: "did:key:z6MkServer".to_string(),
            session_id: "sess-abc123".to_string(),
            turn_index: 0,
            opens_at: 1747526400,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_marker();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditUserTurnMarker =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2, "canonical serialization stable");
    }

    #[test]
    fn validate_accepts_valid_turn_marker() {
        assert!(make_marker().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditUserTurnMarker {
            signer_did: String::new(),
            ..make_marker()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditUserTurnMarkerError::EmptySignerDid)
        );
    }

    #[test]
    fn validate_rejects_empty_session_id() {
        let bad = AuditUserTurnMarker {
            session_id: String::new(),
            ..make_marker()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditUserTurnMarkerError::EmptySessionId)
        );
    }

    /// Parse TEMPLATE_JSON and confirm the ancestry chain
    /// `audit_user_turn_marker → audit_artifact → identity_base`.
    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditUserTurnMarker::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

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
