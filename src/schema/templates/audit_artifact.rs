use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation errors for an AuditArtifact payload.
#[derive(Debug, Error, PartialEq)]
pub enum AuditArtifactError {
    #[error("signer_did must not be empty")]
    EmptySignerDid,
}

/// Abstract root template for the audit family (T1–T8).
///
/// `AuditArtifact` is **NEVER instantiated directly**. It exists solely as the
/// ancestry terminator for the eight audit templates: `audit_user_turn_marker`
/// (T1), `audit_user_prompt` (T2), `audit_agent_thinking` (T3),
/// `audit_agent_tool_call` (T4), `audit_api_response` (T5),
/// `audit_tool_result` (T6), `audit_hitl_approval` (T7), `audit_agent_response`
/// (T8).
///
/// Verifiers walk each audit revision's `ancestry()` and confirm it terminates
/// at `audit_artifact_root_hash` (the value of `TEMPLATE_LINK` computed in
/// Task 16). Bare `audit_artifact` revisions MUST be rejected by the verifier
/// topology layer (NOT this `validate()` method, which only enforces field
/// presence — same convention as W2 `service_claim`).
///
/// Common fields inherited by all T1–T8 derivatives:
/// - `signer_did` — the entity signing the artifact (server, user-session,
///   agent, or API attestor).
/// - `created_at` — Unix-seconds timestamp of artifact creation.
///
/// **T1 exception:** `audit_user_turn_marker` (Task 5) substitutes `opens_at`
/// for `created_at` because a turn marker opens a turn rather than recording
/// creation of an arbitrary artifact. T1's derivation will override the
/// `created_at` field; the JSON-schema additivity rules permit this since each
/// derivative declares its own required fields.
///
/// Spec: audit-rounds spec §7.3, §7.6.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditArtifact {
    pub signer_did: String,
    pub created_at: u64,
}

impl AuditArtifact {
    pub fn validate(&self) -> Result<(), AuditArtifactError> {
        if self.signer_did.is_empty() {
            return Err(AuditArtifactError::EmptySignerDid);
        }
        Ok(())
    }
}

impl BuiltInTemplate for AuditArtifact {
    const TEMPLATE_JSON: &'static str = include_str!("audit_artifact.json");
    /// Placeholder hash — Task 16 computes the real value via `verify-templates --fix`.
    /// This becomes `audit_artifact_root_hash` per spec §7.6.
    const TEMPLATE_LINK: [u8; 32] = [
        0x11, 0x1d, 0x65, 0xc2, 0x53, 0xf7, 0x2b, 0xc4, 0xe2, 0xb6, 0x9e, 0xde, 0x96, 0x9b, 0x26,
        0x78, 0x5d, 0xc5, 0xe5, 0x4b, 0xd6, 0xb2, 0x90, 0x6d, 0x79, 0x88, 0x72, 0x32, 0xbe, 0x24,
        0x26, 0x65,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_audit_artifact() -> AuditArtifact {
        AuditArtifact {
            signer_did: "did:key:z6MkAUDIT".to_string(),
            created_at: 1747526400,
        }
    }

    // ── Test 1: Schema round-trip ─────────────────────────────────────────────

    /// Serialize → deserialize → assert structural equality.
    /// Also verifies that canonical serialization produces a stable byte sequence.
    #[test]
    fn schema_round_trip() {
        let original = make_audit_artifact();
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AuditArtifact = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);

        // Second serialization must be byte-identical (serde_json produces
        // deterministic output for the same value).
        let serialized2 = serde_json::to_string(&deserialized).expect("re-serialize");
        assert_eq!(
            serialized, serialized2,
            "canonical serialization must be stable"
        );
    }

    // ── Test 2: Positive-path validation ─────────────────────────────────────

    /// A well-formed `AuditArtifact` must pass validation. Regression anchor for
    /// any future check added to `validate()` that might accidentally reject
    /// valid artifacts.
    #[test]
    fn validate_accepts_valid_artifact() {
        let good = make_audit_artifact();
        assert!(good.validate().is_ok());
    }

    // ── Test 3: Validation rejects empty signer_did ───────────────────────────

    #[test]
    fn validate_rejects_empty_signer_did() {
        let bad = AuditArtifact {
            signer_did: "".to_string(),
            created_at: 1747526400,
        };
        assert_eq!(bad.validate(), Err(AuditArtifactError::EmptySignerDid));
    }

    // ── Test 4: Ancestry via TEMPLATE_JSON ───────────────────────────────────

    /// Parse TEMPLATE_JSON and assert:
    /// - `derives_from` equals the identity_base real hash.
    /// - `ancestry` has exactly 1 entry equal to that same hash.
    #[test]
    fn ancestry_via_template_json() {
        let template: serde_json::Value =
            serde_json::from_str(AuditArtifact::TEMPLATE_JSON).expect("parse TEMPLATE_JSON");

        let identity_base_hash =
            "0x1620812b61a5906095bc375273813918e994555e1f386595c0187438c00435b107b4";

        assert_eq!(
            template["derives_from"]
                .as_str()
                .expect("derives_from is a string"),
            identity_base_hash,
            "audit_artifact must derive from identity_base"
        );

        let ancestry = template["ancestry"]
            .as_array()
            .expect("ancestry is an array");
        assert_eq!(ancestry.len(), 1, "ancestry must have exactly 1 entry");
        assert_eq!(
            ancestry[0].as_str().expect("ancestry[0] is a string"),
            identity_base_hash,
            "ancestry[0] must equal identity_base hash"
        );
    }

    // ── Test 5: Abstract-root convention ─────────────────────────────────────

    /// AuditArtifact is abstract — only T1-T8 derivatives are valid instantiations.
    ///
    /// This test confirms that `validate()` does NOT reject a bare `AuditArtifact`
    /// with valid fields. Bare-artifact rejection is the verifier topology's
    /// responsibility (spec §10.1 invariant I4), NOT the template's `validate()`
    /// method.
    ///
    /// NOTE: abstract-root rejection lives at verifier topology (spec §10.1 I4),
    /// not here. The template validate() enforces only field-level invariants
    /// (non-empty signer_did). Shape-level rejection of bare audit_artifact
    /// revisions is the verifier's job, consistent with the service_claim
    /// pattern established in W2.
    #[test]
    fn abstract_root_convention() {
        // A bare AuditArtifact with valid fields MUST pass validate().
        // Verifier topology (not this method) is responsible for rejecting
        // bare audit_artifact revisions without a T1-T8 derivative in ancestry.
        let bare = AuditArtifact {
            signer_did: "did:key:z6MkAUDIT".to_string(),
            created_at: 1747526400,
        };
        assert!(
            bare.validate().is_ok(),
            "validate() must not reject a bare AuditArtifact — abstract-root \
             rejection is the verifier topology's concern (spec §10.1 I4)"
        );
    }
}
