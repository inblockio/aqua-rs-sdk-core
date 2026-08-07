use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditApiResponse` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditApiResponseError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
    #[error("turn_id must not be empty")]
    EmptyTurnId,
    #[error("method must not be empty")]
    EmptyMethod,
    #[error("endpoint must not be empty")]
    EmptyEndpoint,
    #[error("attested_origin must not be empty")]
    EmptyAttestedOrigin,
}

/// T5 — third-party API response observation. Signed by an API attestor DID.
///
/// Spec §7.3, §7.6: T5 records an attested third-party API response
/// (e.g. a vendor sandbox). Linked to T1 via `turn_id`. The `response_body`
/// is opaque JSON and is the primary redaction target for the
/// `pseudonymous` disclosure preset.
///
/// `attested_origin` records the origin the attestor claims to have
/// observed (e.g. `"api.example.com"`). The attestor's signature binds
/// the observation to the origin.
///
/// Ancestry: `audit_api_response → audit_artifact → identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditApiResponse {
    pub signer_did: String,
    pub turn_id: String,
    pub seq_in_turn: u64,
    pub method: String,
    pub endpoint: String,
    pub status_code: u16,
    pub request_hash: String,
    pub response_body: serde_json::Value,
    pub attested_origin: String,
    pub created_at: u64,
}

impl AuditApiResponse {
    pub fn validate(&self) -> Result<(), AuditApiResponseError> {
        if self.signer_did.is_empty() {
            return Err(AuditApiResponseError::EmptySignerDid);
        }
        if self.turn_id.is_empty() {
            return Err(AuditApiResponseError::EmptyTurnId);
        }
        if self.method.is_empty() {
            return Err(AuditApiResponseError::EmptyMethod);
        }
        if self.endpoint.is_empty() {
            return Err(AuditApiResponseError::EmptyEndpoint);
        }
        if self.attested_origin.is_empty() {
            return Err(AuditApiResponseError::EmptyAttestedOrigin);
        }
        Ok(())
    }

    /// JSON-Pointer paths consumed by the P3 Disclosure Builder
    /// `pseudonymous` redaction preset for T5 artifacts.
    pub fn pseudonymous_redaction_pointers() -> &'static [&'static str] {
        &["/response_body"]
    }
}

impl BuiltInTemplate for AuditApiResponse {
    const TEMPLATE_JSON: &'static str = include_str!("audit_api_response.json");
    /// Placeholder hash — Task 16 cascades the real value via `verify-templates --fix`.
    const TEMPLATE_LINK: [u8; 32] = [
        0x6d, 0x1e, 0x30, 0x0b, 0xbb, 0x01, 0x45, 0xce, 0xdc, 0x1a, 0x2f, 0xf1, 0x9f, 0xd1, 0xad,
        0x0e, 0x0d, 0xcf, 0xcf, 0xde, 0x6a, 0x4a, 0x9b, 0x0d, 0x6e, 0xa6, 0x7c, 0x7d, 0x31, 0xc4,
        0xa1, 0x29,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response() -> AuditApiResponse {
        AuditApiResponse {
            signer_did: "did:key:z6MkApiAttestor".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 3,
            method: "POST".to_string(),
            endpoint: "/v1/companies/12345/employees".to_string(),
            status_code: 201,
            request_hash: format!("0x{}", "cd".repeat(32)),
            response_body: serde_json::json!({"id": "emp_42", "uuid": "abc-def"}),
            attested_origin: "api.example-demo.com".to_string(),
            created_at: 1747526404,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_response();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditApiResponse =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(serialized, serialized2);
    }

    #[test]
    fn validate_accepts_valid_response() {
        assert!(make_response().validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditApiResponse {
            signer_did: String::new(),
            ..make_response()
        };
        assert_eq!(bad.validate(), Err(AuditApiResponseError::EmptySignerDid));
    }

    #[test]
    fn validate_rejects_empty_method() {
        let bad = AuditApiResponse {
            method: String::new(),
            ..make_response()
        };
        assert_eq!(bad.validate(), Err(AuditApiResponseError::EmptyMethod));
    }

    #[test]
    fn validate_rejects_empty_endpoint() {
        let bad = AuditApiResponse {
            endpoint: String::new(),
            ..make_response()
        };
        assert_eq!(bad.validate(), Err(AuditApiResponseError::EmptyEndpoint));
    }

    #[test]
    fn validate_rejects_empty_attested_origin() {
        let bad = AuditApiResponse {
            attested_origin: String::new(),
            ..make_response()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditApiResponseError::EmptyAttestedOrigin)
        );
    }

    #[test]
    fn pseudonymous_pointers_match_spec() {
        assert_eq!(
            AuditApiResponse::pseudonymous_redaction_pointers(),
            &["/response_body"]
        );
    }

    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditApiResponse::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

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
