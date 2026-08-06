use serde::{Deserialize, Serialize};

/// How a non-fatal verification decision point is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Treat the condition as a hard error — verification fails.
    Fail,
    /// Treat the condition as a warning — verification passes with a warning attached.
    Warn,
}

/// Identifies which verification decision point triggered a warning or error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionPoint {
    /// An external timestamp service was unreachable.
    TimestampUnavailable,
    /// The revision's template could not be resolved.
    TemplateNotFound,
    /// A parent template in the derivation chain could not be resolved.
    AncestorTemplateNotFound,
    /// WASM template compute failed at runtime.
    WasmExecutionFailed,
    /// A batch Merkle inclusion proof could not be verified.
    BatchProofFailed,
    /// The WASM module's signer is not in the trust store.
    WasmUntrustedSigner,
    /// A WASM-bearing custom template carries no cryptographically valid vendor signature.
    UnsignedTemplate,
}

/// Trust domain evaluated by the template execution gate
/// (DRAFT-ICP-template-execution-policy D-2).
pub const TEMPLATE_VENDOR_TRUST_DOMAIN: &str = "template_vendor";

/// Controls how non-fatal verification decision points are treated.
///
/// L1 structural and hash integrity always hard-fail regardless of policy.
/// This policy only governs relaxable decision points: missing templates,
/// unavailable timestamps, WASM execution failures, batch proof failures,
/// untrusted WASM signers, and unsigned WASM-bearing templates.
///
/// # Presets
///
/// - [`strict()`](Self::strict) — all decision points fail (default, recommended for production).
/// - [`offline()`](Self::offline) — relaxes external dependencies (timestamps, templates, WASM) to warnings.
/// - [`debug()`](Self::debug) — all warnings, including untrusted WASM (**never use in production**).
/// - [`custom()`](Self::custom) — start from strict and selectively relax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub timestamp_unavailable: Severity,
    pub template_not_found: Severity,
    /// An ancestor template in a derivation chain could not be resolved, so its
    /// (security-critical) WASM cannot run on the child. Defaults to Fail: a child
    /// must never silently bypass a parent's verification invariants (spec-object-model
    /// §6). Defaulted via serde for backward compatibility with policies serialized
    /// before this field existed.
    #[serde(default = "default_fail")]
    pub ancestor_template_not_found: Severity,
    pub wasm_execution_failed: Severity,
    pub batch_proof_failed: Severity,
    pub wasm_untrusted_signer: Severity,
    /// A custom template that carries executable WASM has no cryptographically
    /// valid vendor signature branch. Defaults to Fail: resolution is not
    /// authorization (DRAFT-ICP-template-execution-policy D-1). Serde-defaulted
    /// for backward compatibility with policies serialized before this field
    /// existed.
    #[serde(default = "default_fail")]
    pub unsigned_template: Severity,
}

fn default_fail() -> Severity {
    Severity::Fail
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyConcern {
    ConflictingWasmPolicy,
    UntrustedWasmWithoutOtherRelaxation,
    UnsignedWeakerThanUntrusted,
}

impl std::fmt::Display for PolicyConcern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyConcern::ConflictingWasmPolicy => write!(
                f,
                "wasm_untrusted_signer is Warn but wasm_execution_failed is Fail: \
                 untrusted WASM will execute, but runtime errors will fail verification"
            ),
            PolicyConcern::UntrustedWasmWithoutOtherRelaxation => write!(
                f,
                "wasm_untrusted_signer is Warn with no other relaxation: \
                 may indicate accidental debug configuration in production"
            ),
            PolicyConcern::UnsignedWeakerThanUntrusted => write!(
                f,
                "unsigned_template is Warn but wasm_untrusted_signer is Fail: \
                 unsigned templates would execute while signed-but-untrusted \
                 templates fail; unsigned is the weaker guarantee"
            ),
        }
    }
}

impl VerificationPolicy {
    /// All decision points fail. Default and recommended for production.
    pub fn strict() -> Self {
        Self {
            timestamp_unavailable: Severity::Fail,
            template_not_found: Severity::Fail,
            ancestor_template_not_found: Severity::Fail,
            wasm_execution_failed: Severity::Fail,
            batch_proof_failed: Severity::Fail,
            wasm_untrusted_signer: Severity::Fail,
            unsigned_template: Severity::Fail,
        }
    }

    /// Relaxes external dependencies to warnings while keeping security invariants strict.
    pub fn offline() -> Self {
        Self {
            timestamp_unavailable: Severity::Warn,
            template_not_found: Severity::Warn,
            // Ancestor WASM is a security invariant, not an external dependency:
            // an unresolved ancestor fails even offline (mirrors wasm_untrusted_signer).
            ancestor_template_not_found: Severity::Fail,
            wasm_execution_failed: Severity::Warn,
            batch_proof_failed: Severity::Fail,
            wasm_untrusted_signer: Severity::Fail,
            // Template authorization is a security invariant, not an external
            // dependency: unsigned WASM fails even offline.
            unsigned_template: Severity::Fail,
        }
    }

    /// All decision points warn. **Never use in production** — enables untrusted WASM execution.
    pub fn debug() -> Self {
        eprintln!(
            "WARNING: VerificationPolicy::debug() enables untrusted WASM execution. \
             Do not use in production."
        );
        Self {
            timestamp_unavailable: Severity::Warn,
            template_not_found: Severity::Warn,
            ancestor_template_not_found: Severity::Warn,
            wasm_execution_failed: Severity::Warn,
            batch_proof_failed: Severity::Warn,
            wasm_untrusted_signer: Severity::Warn,
            unsigned_template: Severity::Warn,
        }
    }

    /// Start from [`strict()`](Self::strict) and apply selective relaxations.
    ///
    /// ```rust,ignore
    /// let policy = VerificationPolicy::custom(|p| {
    ///     p.timestamp_unavailable = Severity::Warn;
    /// });
    /// ```
    pub fn custom<F>(f: F) -> Self
    where
        F: FnOnce(&mut Self),
    {
        let mut policy = Self::strict();
        f(&mut policy);
        policy
    }

    /// Check for potentially problematic policy combinations.
    ///
    /// Returns a list of concerns (e.g., conflicting WASM trust settings).
    /// Does not prevent use — informational only.
    pub fn validate(&self) -> Vec<PolicyConcern> {
        let mut concerns = Vec::new();

        if self.wasm_untrusted_signer == Severity::Warn
            && self.wasm_execution_failed == Severity::Fail
        {
            concerns.push(PolicyConcern::ConflictingWasmPolicy);
        }

        if self.wasm_untrusted_signer == Severity::Warn
            && self.timestamp_unavailable == Severity::Fail
            && self.template_not_found == Severity::Fail
            && self.wasm_execution_failed == Severity::Fail
            && self.batch_proof_failed == Severity::Fail
            && self.unsigned_template == Severity::Fail
        {
            concerns.push(PolicyConcern::UntrustedWasmWithoutOtherRelaxation);
        }

        if self.unsigned_template == Severity::Warn && self.wasm_untrusted_signer == Severity::Fail
        {
            concerns.push(PolicyConcern::UnsignedWeakerThanUntrusted);
        }

        concerns
    }
}

/// Per-object template-trust label produced by the template execution gate
/// (DRAFT-ICP-template-execution-policy 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "trust", content = "did")]
pub enum TemplateTrust {
    /// The template is a built-in, trusted via binary distribution.
    Builtin,
    /// The DID that satisfied the gate.
    TrustedSigner(String),
    /// Policy relaxed; never under strict().
    UnsignedAllowed,
    /// Policy relaxed; never under strict(). Carries one valid-but-untrusted
    /// signer DID.
    UntrustedAllowed(String),
}

impl TemplateTrust {
    /// Weakest-link ordering: lower is weaker (ICP 4.3 weakest-link semantics).
    pub fn strength(&self) -> u8 {
        match self {
            TemplateTrust::UnsignedAllowed => 0,
            TemplateTrust::UntrustedAllowed(_) => 1,
            TemplateTrust::TrustedSigner(_) => 2,
            TemplateTrust::Builtin => 3,
        }
    }
}

/// A non-fatal issue that the verification policy tolerated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyWarning {
    /// Which decision point produced this warning.
    pub decision_point: DecisionPoint,
    /// The revision hash where the issue occurred (hex string).
    pub revision_hash: String,
    /// Human-readable description of the issue.
    pub message: String,
}

/// A fatal verification error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationError {
    /// Machine-readable error code (e.g., `"HASH_VERIFICATION_FAILED"`).
    pub code: String,
    /// The revision hash where the error occurred (hex string), or empty for tree-level errors.
    pub revision_hash: String,
    /// Human-readable description of the error.
    pub message: String,
}

/// The canonical outcome of verifying an Aqua tree.
///
/// This is the single source of truth for verification results. Consumers
/// should read it via [`VerificationResult::is_verified`],
/// [`VerificationResult::warnings`], and [`VerificationResult::errors`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// All verification stages passed with no warnings.
    Verified,
    /// All stages passed but some decision points produced warnings.
    VerifiedWithWarnings(Vec<PolicyWarning>),
    /// Verification failed with one or more errors.
    Failed(Vec<VerificationError>),
}

impl Serialize for VerificationOutcome {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        match self {
            VerificationOutcome::Verified => {
                map.serialize_entry("result", "verified")?;
            }
            VerificationOutcome::VerifiedWithWarnings(warnings) => {
                map.serialize_entry("result", "verified_with_warnings")?;
                map.serialize_entry("warnings", warnings)?;
            }
            VerificationOutcome::Failed(errors) => {
                map.serialize_entry("result", "failed")?;
                map.serialize_entry("errors", errors)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for VerificationOutcome {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Repr {
            result: String,
            #[serde(default)]
            warnings: Vec<PolicyWarning>,
            #[serde(default)]
            errors: Vec<VerificationError>,
        }
        let repr = Repr::deserialize(deserializer)?;
        match repr.result.as_str() {
            "verified" => Ok(VerificationOutcome::Verified),
            "verified_with_warnings" => {
                Ok(VerificationOutcome::VerifiedWithWarnings(repr.warnings))
            }
            "failed" => Ok(VerificationOutcome::Failed(repr.errors)),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["verified", "verified_with_warnings", "failed"],
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_all_fail() {
        let p = VerificationPolicy::strict();
        assert_eq!(p.timestamp_unavailable, Severity::Fail);
        assert_eq!(p.template_not_found, Severity::Fail);
        assert_eq!(p.ancestor_template_not_found, Severity::Fail);
        assert_eq!(p.wasm_execution_failed, Severity::Fail);
        assert_eq!(p.batch_proof_failed, Severity::Fail);
        assert_eq!(p.wasm_untrusted_signer, Severity::Fail);
        assert_eq!(p.unsigned_template, Severity::Fail);
    }

    #[test]
    fn offline_relaxes_external_deps() {
        let p = VerificationPolicy::offline();
        assert_eq!(p.timestamp_unavailable, Severity::Warn);
        assert_eq!(p.template_not_found, Severity::Warn);
        assert_eq!(p.ancestor_template_not_found, Severity::Fail);
        assert_eq!(p.wasm_execution_failed, Severity::Warn);
        assert_eq!(p.batch_proof_failed, Severity::Fail);
        assert_eq!(p.wasm_untrusted_signer, Severity::Fail);
        assert_eq!(p.unsigned_template, Severity::Fail);
    }

    #[test]
    fn custom_starts_from_strict() {
        let p = VerificationPolicy::custom(|p| {
            p.template_not_found = Severity::Warn;
        });
        assert_eq!(p.template_not_found, Severity::Warn);
        assert_eq!(p.timestamp_unavailable, Severity::Fail);
        assert_eq!(p.ancestor_template_not_found, Severity::Fail);
        assert_eq!(p.wasm_execution_failed, Severity::Fail);
        assert_eq!(p.batch_proof_failed, Severity::Fail);
        assert_eq!(p.wasm_untrusted_signer, Severity::Fail);
        assert_eq!(p.unsigned_template, Severity::Fail);
    }

    #[test]
    fn unsigned_template_defaults_to_fail_when_absent() {
        // A policy serialized before `unsigned_template` existed must
        // deserialize with the secure default (Fail), never silently
        // permissive (same pattern as ancestor_template_not_found).
        let legacy = r#"{
            "timestamp_unavailable": "warn",
            "template_not_found": "warn",
            "ancestor_template_not_found": "warn",
            "wasm_execution_failed": "warn",
            "batch_proof_failed": "warn",
            "wasm_untrusted_signer": "warn"
        }"#;
        let p: VerificationPolicy = serde_json::from_str(legacy).unwrap();
        assert_eq!(p.unsigned_template, Severity::Fail);
    }

    #[test]
    fn unsigned_template_preset_semantics() {
        assert_eq!(
            VerificationPolicy::strict().unsigned_template,
            Severity::Fail
        );
        assert_eq!(
            VerificationPolicy::offline().unsigned_template,
            Severity::Fail
        );
        assert_eq!(
            VerificationPolicy::debug().unsigned_template,
            Severity::Warn
        );
    }

    #[test]
    fn validate_unsigned_weaker_than_untrusted() {
        let p = VerificationPolicy::custom(|p| {
            p.unsigned_template = Severity::Warn;
        });
        assert!(p
            .validate()
            .contains(&PolicyConcern::UnsignedWeakerThanUntrusted));
        // Relaxing both removes the incoherence.
        let p = VerificationPolicy::custom(|p| {
            p.unsigned_template = Severity::Warn;
            p.wasm_untrusted_signer = Severity::Warn;
        });
        assert!(!p
            .validate()
            .contains(&PolicyConcern::UnsignedWeakerThanUntrusted));
    }

    #[test]
    fn template_trust_serde_roundtrip() {
        let variants = vec![
            TemplateTrust::Builtin,
            TemplateTrust::TrustedSigner("did:key:z6MkExample".to_string()),
            TemplateTrust::UnsignedAllowed,
            TemplateTrust::UntrustedAllowed("did:key:z6MkOther".to_string()),
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: TemplateTrust = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn template_trust_weakest_link_ordering() {
        // UnsignedAllowed < UntrustedAllowed < TrustedSigner < Builtin.
        assert!(
            TemplateTrust::UnsignedAllowed.strength()
                < TemplateTrust::UntrustedAllowed("d".into()).strength()
        );
        assert!(
            TemplateTrust::UntrustedAllowed("d".into()).strength()
                < TemplateTrust::TrustedSigner("d".into()).strength()
        );
        assert!(
            TemplateTrust::TrustedSigner("d".into()).strength() < TemplateTrust::Builtin.strength()
        );
    }

    #[test]
    fn ancestor_template_not_found_defaults_to_fail_when_absent() {
        // A policy serialized before `ancestor_template_not_found` existed must
        // deserialize with the secure default (Fail), never silently permissive.
        let legacy = r#"{
            "timestamp_unavailable": "warn",
            "template_not_found": "warn",
            "wasm_execution_failed": "warn",
            "batch_proof_failed": "warn",
            "wasm_untrusted_signer": "warn"
        }"#;
        let p: VerificationPolicy = serde_json::from_str(legacy).unwrap();
        assert_eq!(p.ancestor_template_not_found, Severity::Fail);
    }

    #[test]
    fn validate_conflicting_wasm() {
        let p = VerificationPolicy::custom(|p| {
            p.wasm_untrusted_signer = Severity::Warn;
        });
        let concerns = p.validate();
        assert!(concerns.contains(&PolicyConcern::ConflictingWasmPolicy));
        assert!(concerns.contains(&PolicyConcern::UntrustedWasmWithoutOtherRelaxation));
    }

    #[test]
    fn validate_clean_strict() {
        let concerns = VerificationPolicy::strict().validate();
        assert!(concerns.is_empty());
    }

    #[test]
    fn validate_clean_offline() {
        let concerns = VerificationPolicy::offline().validate();
        assert!(concerns.is_empty());
    }

    #[test]
    fn outcome_serde_verified() {
        let outcome = VerificationOutcome::Verified;
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: VerificationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outcome);
    }

    #[test]
    fn outcome_serde_with_warnings() {
        let outcome = VerificationOutcome::VerifiedWithWarnings(vec![PolicyWarning {
            decision_point: DecisionPoint::TemplateNotFound,
            revision_hash: "0xabc".to_string(),
            message: "Template not found".to_string(),
        }]);
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: VerificationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outcome);
    }

    #[test]
    fn outcome_serde_failed() {
        let outcome = VerificationOutcome::Failed(vec![VerificationError {
            code: "HASH_MISMATCH".to_string(),
            revision_hash: "0xdef".to_string(),
            message: "Hash mismatch".to_string(),
        }]);
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: VerificationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outcome);
    }
}
