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
        0xc5, 0x5a, 0x5e, 0x5d, 0xbd, 0x7f, 0x32, 0x89, 0xdb, 0x68, 0x68, 0x07, 0xd5, 0xb8, 0x63,
        0x06, 0xef, 0xd0, 0x52, 0xb5, 0x39, 0x88, 0xe7, 0x39, 0xe3, 0xa3, 0xaa, 0xc5, 0x2c, 0xdb,
        0x12, 0x82,
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
