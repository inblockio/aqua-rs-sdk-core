use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an `AuditGustoApiResponse` payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditGustoApiResponseError {
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

/// T5 — Gusto API response observation. Signed by an API attestor DID.
///
/// Spec §7.3, §7.6: T5 records an attested third-party API response
/// (e.g. Gusto sandbox). Linked to T1 via `turn_id`. The `response_body`
/// is opaque JSON and is the primary redaction target for the
/// `pseudonymous` disclosure preset.
///
/// `attested_origin` records the origin the attestor claims to have
/// observed (e.g. `"api.gusto.com"`). The attestor's signature binds
/// the observation to the origin.
///
/// Ancestry: `audit_gusto_api_response → audit_artifact → identity_base`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditGustoApiResponse {
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

impl AuditGustoApiResponse {
    pub fn validate(&self) -> Result<(), AuditGustoApiResponseError> {
        if self.signer_did.is_empty() {
            return Err(AuditGustoApiResponseError::EmptySignerDid);
        }
        if self.turn_id.is_empty() {
            return Err(AuditGustoApiResponseError::EmptyTurnId);
        }
        if self.method.is_empty() {
            return Err(AuditGustoApiResponseError::EmptyMethod);
        }
        if self.endpoint.is_empty() {
            return Err(AuditGustoApiResponseError::EmptyEndpoint);
        }
        if self.attested_origin.is_empty() {
            return Err(AuditGustoApiResponseError::EmptyAttestedOrigin);
        }
        Ok(())
    }

    /// JSON-Pointer paths consumed by the P3 Disclosure Builder
    /// `pseudonymous` redaction preset for T5 artifacts.
    pub fn pseudonymous_redaction_pointers() -> &'static [&'static str] {
        &["/response_body"]
    }
}

impl BuiltInTemplate for AuditGustoApiResponse {
    const TEMPLATE_JSON: &'static str = include_str!("audit_gusto_api_response.json");
    /// Placeholder hash — Task 16 cascades the real value via `verify-templates --fix`.
    const TEMPLATE_LINK: [u8; 32] = [
        0xb5, 0x0e, 0xda, 0xa8, 0xc4, 0xe7, 0xae, 0xad, 0x8c, 0x93, 0x25, 0x6d, 0x9d, 0x72, 0xb7,
        0xc0, 0xe5, 0xb1, 0xdd, 0xb8, 0x8e, 0xda, 0x54, 0x3a, 0x76, 0xcd, 0xa4, 0x3e, 0xb1, 0xc7,
        0xb8, 0x98,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response() -> AuditGustoApiResponse {
        AuditGustoApiResponse {
            signer_did: "did:key:z6MkApiAttestor".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 3,
            method: "POST".to_string(),
            endpoint: "/v1/companies/12345/employees".to_string(),
            status_code: 201,
            request_hash: format!("0x{}", "cd".repeat(32)),
            response_body: serde_json::json!({"id": "emp_42", "uuid": "abc-def"}),
            attested_origin: "api.gusto-demo.com".to_string(),
            created_at: 1747526404,
        }
    }

    #[test]
    fn schema_round_trip() {
        let original = make_response();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditGustoApiResponse =
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
        let bad = AuditGustoApiResponse {
            signer_did: String::new(),
            ..make_response()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditGustoApiResponseError::EmptySignerDid)
        );
    }

    #[test]
    fn validate_rejects_empty_method() {
        let bad = AuditGustoApiResponse {
            method: String::new(),
            ..make_response()
        };
        assert_eq!(bad.validate(), Err(AuditGustoApiResponseError::EmptyMethod));
    }

    #[test]
    fn validate_rejects_empty_endpoint() {
        let bad = AuditGustoApiResponse {
            endpoint: String::new(),
            ..make_response()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditGustoApiResponseError::EmptyEndpoint)
        );
    }

    #[test]
    fn validate_rejects_empty_attested_origin() {
        let bad = AuditGustoApiResponse {
            attested_origin: String::new(),
            ..make_response()
        };
        assert_eq!(
            bad.validate(),
            Err(AuditGustoApiResponseError::EmptyAttestedOrigin)
        );
    }

    #[test]
    fn pseudonymous_pointers_match_spec() {
        assert_eq!(
            AuditGustoApiResponse::pseudonymous_redaction_pointers(),
            &["/response_body"]
        );
    }

    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditGustoApiResponse::TEMPLATE_JSON)
                .expect("parse TEMPLATE_JSON");

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
