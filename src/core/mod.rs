use std::collections::HashMap;

use crate::{
    primitives::{
        log::{LogData, LogType},
        MethodError, RevisionLink,
    },
    schema::{tree::Tree, AnyRevision, AquaTreeWrapper, FileData, Template},
};

/// Result of verifying an Aqua tree or individual revision.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VerificationResult {
    /// Canonical verification outcome. Single source of truth. Consumers read it
    /// via [`VerificationResult::is_verified`], [`VerificationResult::warnings`],
    /// and [`VerificationResult::errors`].
    pub outcome: VerificationOutcome,
    pub logs: Vec<LogData>,
    /// WASM verification outputs keyed by revision hash string.
    /// Each value is a JSON object with at minimum `{"state": "<name>", "state_index": <n>}`.
    /// Only populated for revisions whose WASM verification passed.
    pub wasm_outputs: HashMap<String, serde_json::Value>,
    /// Template-trust labels keyed by revision hash string: the weakest-link
    /// label across that revision's executed template chain (ICP 4.3). Only
    /// populated for revisions whose WASM verification executed. Serde-defaulted
    /// for results serialized before this field existed.
    #[serde(default)]
    pub template_trust: HashMap<String, TemplateTrust>,
}

impl VerificationResult {
    /// Construct from the canonical outcome. The only sanctioned way to build a result.
    pub(crate) fn from_outcome(
        outcome: VerificationOutcome,
        logs: Vec<LogData>,
        wasm_outputs: HashMap<String, serde_json::Value>,
        template_trust: HashMap<String, TemplateTrust>,
    ) -> Self {
        Self {
            outcome,
            logs,
            wasm_outputs,
            template_trust,
        }
    }

    /// The weakest template-trust label across all gated WASM executions in
    /// this tree, or `None` if no template WASM was executed.
    pub fn weakest_template_trust(&self) -> Option<&TemplateTrust> {
        self.template_trust.values().min_by_key(|t| t.strength())
    }

    /// Returns `true` if verification passed (with or without warnings).
    ///
    /// Equivalent to checking that the outcome is `Verified` or
    /// `VerifiedWithWarnings`. Use [`is_clean`](Self::is_clean) to
    /// distinguish warning-free verification.
    pub fn is_verified(&self) -> bool {
        matches!(
            self.outcome,
            VerificationOutcome::Verified | VerificationOutcome::VerifiedWithWarnings(_)
        )
    }

    /// Returns `true` only if verification passed with zero warnings.
    pub fn is_clean(&self) -> bool {
        matches!(self.outcome, VerificationOutcome::Verified)
    }

    /// Returns policy warnings (non-fatal issues the verification policy tolerated).
    ///
    /// Empty unless the outcome is `VerifiedWithWarnings`.
    pub fn warnings(&self) -> &[PolicyWarning] {
        match &self.outcome {
            VerificationOutcome::VerifiedWithWarnings(w) => w,
            _ => &[],
        }
    }

    /// Returns verification errors that caused failure.
    ///
    /// Empty unless the outcome is `Failed`.
    pub fn errors(&self) -> &[PolicyVerificationError] {
        match &self.outcome {
            VerificationOutcome::Failed(e) => e,
            _ => &[],
        }
    }
}

pub mod verification_policy;
pub use verification_policy::{
    DecisionPoint, PolicyWarning, Severity, TemplateTrust,
    VerificationError as PolicyVerificationError, VerificationOutcome, VerificationPolicy,
    TEMPLATE_VENDOR_TRUST_DOMAIN,
};

mod structural;
pub(crate) mod verify_common;
mod verify_stages;

use structural::*;
use verify_stages::*;

pub(crate) use verify_stages::builtin_template_name;
pub(crate) use verify_stages::builtin_template_tree;
pub(crate) use verify_stages::builtin_template_tree_chain;
pub(crate) use verify_stages::builtin_templates;
pub use verify_stages::is_builtin_template_link;
pub use verify_stages::is_signature_revision_type;
pub use verify_stages::is_timestamp_revision_type;
pub use verify_stages::resolve_builtin_template;
pub(crate) use verify_stages::resolve_dependency_trees;
pub use verify_stages::signature_template_hash;
pub(crate) use verify_stages::verify_revision_compute;

pub mod compute;
pub mod disclosure;
pub mod genesis;
pub mod link;
pub mod object;
pub mod signature;
pub mod template;
pub mod verify_sync;

pub async fn verify_aqua_tree_util(
    aqua_tree_wrapper: &AquaTreeWrapper,
    file_objects: Vec<FileData>,
    linked_trees: &[AquaTreeWrapper],
    policy: &VerificationPolicy,
) -> Result<VerificationResult, MethodError> {
    let mut logs: Vec<LogData> = Vec::new();
    // Fatal errors and policy-tolerated warnings accumulate across stages.
    // Final outcome: any error => Failed; else any warning => VerifiedWithWarnings; else Verified.
    let mut errors: Vec<PolicyVerificationError> = Vec::new();
    let mut warnings: Vec<PolicyWarning> = Vec::new();
    // Revisions whose template could not be resolved but whose absence the policy
    // tolerated (template_not_found = Warn). Stage 3 skips them: structure and hash
    // are already verified; without a template there is no schema/WASM to run.
    let mut tolerated_missing_template: std::collections::HashSet<RevisionLink> =
        std::collections::HashSet::new();
    let wasm_outputs: HashMap<String, serde_json::Value> = HashMap::new();
    let template_trust: HashMap<String, TemplateTrust> = HashMap::new();
    let revisions = &aqua_tree_wrapper.aqua_tree.revisions;
    let indent = "\t";

    let is_scalar = aqua_tree_wrapper
        .aqua_tree
        .revisions
        .values()
        .find(|r| matches!(r, AnyRevision::Typed(_)))
        .map(|r| r.is_scalar())
        .unwrap_or(true);

    // ── Stage 0: Structural validation (O(n), zero I/O) ──────────────
    // L1 structural integrity is never policy-governed: it defines whether the
    // bytes are well-formed, and relaxing it would let implementations disagree.
    let mut structural_failed = false;

    // Anchor link resolution
    let (anchor_valid, anchor_logs) = resolve_anchor_links(revisions, linked_trees);
    logs.extend(anchor_logs);
    if !anchor_valid {
        structural_failed = true;
    }

    // Cycle detection
    let (cycles_ok, cycle_logs) = verify_no_cycles(revisions);
    logs.extend(cycle_logs);
    if !cycles_ok {
        structural_failed = true;
    }

    // Reference existence (previous_revision must exist in tree)
    let (refs_ok, ref_logs) = verify_reference_existence(revisions);
    logs.extend(ref_logs);
    if !refs_ok {
        structural_failed = true;
    }

    if structural_failed {
        errors.push(PolicyVerificationError {
            code: "STRUCTURAL_VALIDATION_FAILED".to_string(),
            revision_hash: String::new(),
            message: "Structural validation failed".to_string(),
        });
        return Ok(VerificationResult::from_outcome(
            VerificationOutcome::Failed(errors),
            logs,
            wasm_outputs,
            template_trust,
        ));
    }

    // ── Linked tree verification (topological order, each once) ─────
    let tree_order = match collect_linked_tree_order(aqua_tree_wrapper, linked_trees) {
        Ok(order) => order,
        Err(cycle_logs) => {
            logs.extend(cycle_logs);
            errors.push(PolicyVerificationError {
                code: "CROSS_TREE_CYCLE_DETECTED".to_string(),
                revision_hash: String::new(),
                message: "Cross-tree cycle detected".to_string(),
            });
            return Ok(VerificationResult::from_outcome(
                VerificationOutcome::Failed(errors),
                logs,
                wasm_outputs,
                template_trust,
            ));
        }
    };

    let mut verified_linked: Vec<AquaTreeWrapper> = Vec::new();
    // wasm_outputs from each verified linked tree, parallel to verified_linked.
    let mut lt_wasm_outputs: Vec<HashMap<String, serde_json::Value>> = Vec::new();
    let mut linked_failed = false;
    for idx in &tree_order {
        let lt = &linked_trees[*idx];
        let lt_file_objects: Vec<FileData> = lt
            .file_object
            .as_ref()
            .map(|f| vec![f.clone()])
            .unwrap_or_default();
        let lt_result = Box::pin(verify_aqua_tree_util(
            lt,
            lt_file_objects,
            &verified_linked,
            policy,
        ))
        .await?;

        let lt_verified = lt_result.is_verified();
        logs.extend(lt_result.logs);
        if !lt_verified {
            logs.push(LogData {
                log: format!(
                    "Linked tree verification failed for tree with {} revisions",
                    lt.aqua_tree.revisions.len()
                ),
                log_type: LogType::Error,
                ident: None,
            });
            linked_failed = true;
        } else {
            logs.push(LogData {
                log: "Linked tree verification passed".to_string(),
                log_type: LogType::Success,
                ident: None,
            });
            lt_wasm_outputs.push(lt_result.wasm_outputs);
            verified_linked.push(lt.clone());
        }
    }

    if linked_failed {
        errors.push(PolicyVerificationError {
            code: "LINKED_TREE_RESOLUTION_FAILED".to_string(),
            revision_hash: String::new(),
            message: "Linked tree resolution failed".to_string(),
        });
        return Ok(VerificationResult::from_outcome(
            VerificationOutcome::Failed(errors),
            logs,
            wasm_outputs,
            template_trust,
        ));
    }

    // ── Stage 1: Hash verification (O(n), CPU only) ──────────────────
    // L1 hash + leaf integrity is never policy-governed (defines revision identity).
    let mut hash_failed = false;
    for (revision_hash, revision) in revisions {
        logs.push(LogData {
            log_type: LogType::Info,
            log: format!(
                "Verifying revision type: {} with hash {}",
                revision.get_revision_type(),
                revision_hash
            ),
            ident: Some("".to_string()),
        });

        match verify_revision_hash(revision, revision_hash, indent) {
            Ok(hash_logs) => logs.extend(hash_logs),
            Err((_, _, hash_logs)) => {
                logs.extend(hash_logs);
                hash_failed = true;
            }
        }

        // Verify leaf integrity for Tree-method revisions
        match verify_revision_leaves(revision, revision_hash, indent) {
            Ok(leaf_logs) => logs.extend(leaf_logs),
            Err((_, _, leaf_logs)) => {
                logs.extend(leaf_logs);
                hash_failed = true;
            }
        }
    }

    if hash_failed {
        errors.push(PolicyVerificationError {
            code: "HASH_VERIFICATION_FAILED".to_string(),
            revision_hash: String::new(),
            message: "Hash verification failed".to_string(),
        });
        return Ok(VerificationResult::from_outcome(
            VerificationOutcome::Failed(errors),
            logs,
            wasm_outputs,
            template_trust,
        ));
    }

    // ── Stage 2: Schema + timestamps (O(n), CPU only) ────────────────
    // Schema validation for object revisions
    let mut resolved_templates: std::collections::HashMap<RevisionLink, Option<Template>> =
        std::collections::HashMap::new();
    // Set when a schema check fails for a non-policy reason (malformed payload).
    // template_not_found is policy-governed and handled inline (does not set this).
    let mut schema_failed = false;
    for (revision_hash, revision) in revisions {
        match verify_revision_schema(revision, revisions, &verified_linked, indent) {
            Ok((tmpl, schema_logs)) => {
                logs.extend(schema_logs);
                resolved_templates.insert(revision_hash.clone(), tmpl);
            }
            Err((_, code, schema_logs)) => {
                logs.extend(schema_logs);
                if code == "TEMPLATE_NOT_FOUND" {
                    // Governed decision point: the template could not be resolved.
                    // strict() fails; offline()/debug() tolerate and skip Stage 3 for
                    // this revision (structure + hash are already verified, and without
                    // a template there is no schema or WASM to run).
                    let fatal = verify_common::apply_policy_decision(
                        policy.template_not_found,
                        DecisionPoint::TemplateNotFound,
                        &revision_hash.to_string(),
                        &code,
                        format!("Template not found for revision {revision_hash}"),
                        &mut errors,
                        &mut warnings,
                    );
                    resolved_templates.insert(revision_hash.clone(), None);
                    if !fatal {
                        tolerated_missing_template.insert(revision_hash.clone());
                    }
                } else {
                    // Malformed payload (SCHEMA_VALIDATION_FAILED) is never policy-governed.
                    schema_failed = true;
                }
            }
        }
    }

    // Timestamp ordering — structural chain rule, never policy-governed.
    let (ts_ok, ts_logs) = verify_timestamps(revisions);
    logs.extend(ts_logs);
    if !ts_ok {
        schema_failed = true;
    }

    if schema_failed {
        errors.push(PolicyVerificationError {
            code: "SCHEMA_OR_CHAIN_FAILED".to_string(),
            revision_hash: String::new(),
            message: "Schema or chain validation failed".to_string(),
        });
    }

    // A fatal template_not_found (strict) or a schema/chain failure ends here.
    // Tolerated (Warn) template_not_found leaves errors empty, so we continue.
    if !errors.is_empty() {
        return Ok(VerificationResult::from_outcome(
            verify_common::build_outcome(errors, warnings),
            logs,
            wasm_outputs,
            template_trust,
        ));
    }

    // ── Stage 3: Compute + type-specific (async, I/O) ────────────────
    // Only runs for revisions that passed Stages 0-2.
    let chain = verify_common::build_chain(aqua_tree_wrapper);
    let _branches = verify_common::build_branches(aqua_tree_wrapper, &chain);
    let _current_time = verify_common::current_time_secs();
    let _linked_revisions = verify_common::build_linked_revisions(&verified_linked);
    let _linked_tree_states =
        verify_common::build_linked_tree_states(&verified_linked, &lt_wasm_outputs);
    let _linked_tree_payloads = verify_common::build_linked_tree_payloads(&verified_linked);

    for (revision_hash, revision) in revisions {
        // Policy tolerated a missing template for this revision (template_not_found = Warn).
        // Structure and hash are already verified; without a template there is no schema
        // or WASM to run, so nothing remains to check here.
        if tolerated_missing_template.contains(revision_hash) {
            continue;
        }

        let resolved_template = resolved_templates
            .get(revision_hash)
            .cloned()
            .unwrap_or(None);

        // ── Stage 2.5: Batch inclusion proof (timestamp revisions only) ──────
        // Runs after schema validation (Stage 2), before WASM compute (Stage 3).
        if is_timestamp_revision_type(&revision.get_revision_type()) {
            let revision_json = serde_json::to_value(revision).unwrap_or_default();
            let payloads = revision_json
                .get("payloads")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let prev_hash = revision_json
                .get("previous_revision")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match verify_common::verify_batch_inclusion(&payloads, prev_hash, indent) {
                Ok(mut inclusion_logs) => logs.append(&mut inclusion_logs),
                Err((_, code, mut err_logs)) => {
                    logs.append(&mut err_logs);
                    logs.push(LogData {
                        log: format!("Batch inclusion check failed: {code}"),
                        log_type: LogType::Error,
                        ident: Some(indent.to_string()),
                    });
                    // Governed decision point: batch Merkle inclusion proof failed.
                    // strict()/offline() fail; debug() tolerates. Skip compute either way.
                    verify_common::apply_policy_decision(
                        policy.batch_proof_failed,
                        DecisionPoint::BatchProofFailed,
                        &revision_hash.to_string(),
                        &code,
                        format!("Batch inclusion check failed: {code}"),
                        &mut errors,
                        &mut warnings,
                    );
                    continue;
                }
            }
        }

        // Try compute verification first
        {
            match verify_revision_compute(
                revision,
                &resolved_template,
                revisions,
                &verified_linked,
                indent,
            ) {
                Ok(Some(skip_logs)) => {
                    // Built-in template WASM present but not executed
                    // (aqua-rs-sdk-core D7): record the explicit skip and
                    // fall through to type-specific like a data-only chain.
                    logs.extend(skip_logs);
                }
                Ok(None) => {
                    // No compute module — fall through to type-specific
                }
                Err((_, code, compute_logs)) => {
                    logs.extend(compute_logs);
                    // Governed decision point. A timestamp revision whose compute failed
                    // because a verification host was unavailable maps to
                    // timestamp_unavailable; every other compute failure (including a
                    // timestamp revision failing for a non-host reason) maps to
                    // wasm_execution_failed.
                    let is_ts = is_timestamp_revision_type(&revision.get_revision_type());
                    let host_required = matches!(
                        code.as_str(),
                        "WEB_HOST_REQUIRED"
                            | "BLOCKCHAIN_HOST_REQUIRED"
                            | "IDENTITY_HOST_REQUIRED"
                            | "TRUST_STORE_REQUIRED"
                    );
                    let (severity, decision_point) = if code == "ANCESTOR_TEMPLATE_NOT_FOUND" {
                        (
                            policy.ancestor_template_not_found,
                            DecisionPoint::AncestorTemplateNotFound,
                        )
                    } else if code == "UNSIGNED_TEMPLATE" {
                        (policy.unsigned_template, DecisionPoint::UnsignedTemplate)
                    } else if code == "WASM_UNTRUSTED_SIGNER" {
                        (
                            policy.wasm_untrusted_signer,
                            DecisionPoint::WasmUntrustedSigner,
                        )
                    } else if is_ts && (host_required || code == "COMPUTE_UNSUPPORTED") {
                        (
                            policy.timestamp_unavailable,
                            DecisionPoint::TimestampUnavailable,
                        )
                    } else {
                        (
                            policy.wasm_execution_failed,
                            DecisionPoint::WasmExecutionFailed,
                        )
                    };
                    verify_common::apply_policy_decision(
                        severity,
                        decision_point,
                        &revision_hash.to_string(),
                        &code,
                        format!("Compute verification failed: {code}"),
                        &mut errors,
                        &mut warnings,
                    );
                    continue;
                }
            }
        }

        // Type-specific verification (file content, signatures, passthrough)
        let (type_valid, type_logs) = verify_revision_type_specific(
            revision,
            revision_hash,
            &aqua_tree_wrapper.aqua_tree.file_index,
            &file_objects,
            indent,
        )
        .await;
        logs.extend(type_logs);

        if type_valid {
            if is_scalar {
                logs.push(LogData {
                    log: "⏺️  Scalar revision verified successfully".to_string(),
                    log_type: LogType::Success,
                    ident: Some(indent.to_string()),
                });
            } else {
                logs.push(LogData {
                    log: "🌿 Tree  revision verified".to_string(),
                    log_type: LogType::Success,
                    ident: Some(indent.to_string()),
                });
            }
        } else {
            logs.push(LogData {
                log: format!(
                    "Error verifying revision type:{} with hash {}",
                    revision.get_revision_type(),
                    revision_hash
                ),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            logs.push(LogData {
                log: "\n".to_string(),
                log_type: LogType::Empty,
                ident: Some(indent.to_string()),
            });
            // Type-specific checks (file content, signature validity) are L1 integrity:
            // never policy-governed, always fatal.
            errors.push(PolicyVerificationError {
                code: "VERIFICATION_FAILED".to_string(),
                revision_hash: revision_hash.to_string(),
                message: format!("Type-specific verification failed for revision {revision_hash}"),
            });
        }
    }

    let outcome =
        verify_common::build_outcome(std::mem::take(&mut errors), std::mem::take(&mut warnings));
    if !matches!(outcome, VerificationOutcome::Failed(_)) {
        logs.push(LogData {
            log: "Chain verification passed".to_string(),
            log_type: LogType::Success,
            ident: None,
        });
    }

    Ok(VerificationResult::from_outcome(
        outcome,
        logs,
        wasm_outputs,
        template_trust,
    ))
}

pub fn delete_last_revision_util(aqua_tree_wrapper: AquaTreeWrapper) -> Result<Tree, MethodError> {
    let mut logs: Vec<LogData> = Vec::new();

    if aqua_tree_wrapper.aqua_tree.revisions.len() == 1 {
        logs.push(LogData {
            log_type: LogType::Error,
            log: "Aqua tree has only one revision".to_string(),
            ident: None,
        });
        return Err(MethodError::WithLogs(logs));
    }

    let last_revision = aqua_tree_wrapper.aqua_tree.get_last_revision();

    match last_revision {
        Some((last_revision_link, _last_revision_data)) => {
            // Manually create a new tree with the revision removed
            let mut new_revisions = aqua_tree_wrapper.aqua_tree.revisions.clone();
            let mut new_file_index = aqua_tree_wrapper.aqua_tree.file_index.clone();

            new_revisions.remove(&last_revision_link);
            new_file_index.remove(&last_revision_link);

            Ok(Tree {
                revisions: new_revisions,
                file_index: new_file_index,
            })
        }
        None => {
            logs.push(LogData {
                log_type: LogType::Error,
                log: "Could not find last revision".to_string(),
                ident: None,
            });
            Err(MethodError::WithLogs(logs))
        }
    }
}
