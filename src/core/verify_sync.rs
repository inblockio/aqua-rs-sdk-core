//! Synchronous verification pipeline.
//!
//! Mirrors the async `verify_aqua_tree_util` in `core/mod.rs` but uses
//! sync inner functions throughout. No tokio runtime required.

use std::collections::{BTreeMap, HashMap};

use crate::{
    core::{
        object::verify_object_sync,
        signature::verify_signature_sync,
        structural::{
            collect_linked_tree_order, resolve_anchor_links, verify_no_cycles,
            verify_reference_existence, verify_timestamps,
        },
        verify_common,
        verify_stages::{verify_revision_hash, verify_revision_leaves, verify_revision_schema},
        DecisionPoint, PolicyVerificationError, PolicyWarning, TemplateTrust, VerificationOutcome,
        VerificationPolicy, VerificationResult,
    },
    primitives::{
        log::{LogData, LogType},
        MethodError, RevisionLink,
    },
    schema::{AnyRevision, AquaTreeWrapper, FileData, Template},
};

/// Synchronous counterpart of `verify_aqua_tree_util`.
///
/// Performs the full L1-L3 verification pipeline without requiring
/// a tokio runtime. Uses `verify_signature_sync`, `verify_object_sync`,
/// and `ComputeEngine::execute_verification_sync` in place of their
/// async equivalents.
#[allow(clippy::too_many_arguments)]
pub fn verify_aqua_tree_sync(
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
    // tolerated (template_not_found = Warn). Stage 3 skips them.
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

    // -- Stage 0: Structural validation (O(n), zero I/O) --
    // L1 structural integrity is never policy-governed.
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

    // -- Linked tree verification (topological order, each once) --
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
        // Sync recursion (no Box::pin needed)
        let lt_result = verify_aqua_tree_sync(lt, lt_file_objects, &verified_linked, policy)?;

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

    // -- Stage 1: Hash verification (O(n), CPU only) --
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

    // -- Stage 2: Schema + timestamps (O(n), CPU only) --
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

    // Timestamp ordering -- structural chain rule, never policy-governed.
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

    // -- Stage 3: Compute + type-specific (sync) --
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

        // -- Stage 2.5: Batch inclusion proof (timestamp revisions only) --
        // Runs after schema validation (Stage 2), before WASM compute (Stage 3).
        if crate::core::is_timestamp_revision_type(&revision.get_revision_type()) {
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
            match crate::core::verify_revision_compute(
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
                    // No compute module, fall through to type-specific
                }
                Err((_, code, compute_logs)) => {
                    logs.extend(compute_logs);
                    // Governed decision point. A timestamp revision whose compute failed
                    // because a verification host was unavailable maps to
                    // timestamp_unavailable; every other compute failure (including a
                    // timestamp revision failing for a non-host reason) maps to
                    // wasm_execution_failed.
                    let is_ts =
                        crate::core::is_timestamp_revision_type(&revision.get_revision_type());
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
        let (type_valid, type_logs) = verify_revision_type_specific_sync(
            revision,
            revision_hash,
            &aqua_tree_wrapper.aqua_tree.file_index,
            &file_objects,
            indent,
        );
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

// -- Sync type-specific verification (mirrors verify_revision_type_specific) --

fn verify_revision_type_specific_sync(
    revision: &AnyRevision,
    revision_hash: &RevisionLink,
    file_index: &BTreeMap<RevisionLink, String>,
    file_objects: &[FileData],
    indent: &str,
) -> (bool, Vec<LogData>) {
    let revision_hash_str = revision_hash.to_string();
    let mut logs: Vec<LogData> = Vec::new();

    match revision {
        AnyRevision::Typed(_) => verify_object_sync(
            revision,
            revision_hash,
            Some(indent.to_string()),
            file_index,
            file_objects,
        ),
        AnyRevision::Template(template) => {
            // Hash already verified; that's the atomic check for templates.
            // Fail-closed compute-section consistency: when `source` is present,
            // its declared hash must match the actual code, and sizes must stay
            // within protocol bounds. `source`/`build` are never required for
            // execution, so a template without them always passes this check.
            if let Some(verification) = template.verification() {
                if let Err(e) = verification.validate_compute_section() {
                    logs.push(LogData {
                        log: format!("Compute section invalid: {e}"),
                        log_type: LogType::Error,
                        ident: Some(indent.to_string()),
                    });
                    return (false, logs);
                }
            }
            logs.push(LogData {
                log: "Template hash verified".to_string(),
                log_type: LogType::Success,
                ident: Some(indent.to_string()),
            });
            (true, logs)
        }
        AnyRevision::Signature(_) => {
            verify_signature_sync(revision, &revision_hash_str, Some(indent.to_string()))
        }
        AnyRevision::Anchor(_) => {
            logs.push(LogData {
                log: "Anchor hash verified".to_string(),
                log_type: LogType::Success,
                ident: Some(indent.to_string()),
            });
            (true, logs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::FileData;
    use crate::Aquafier;

    use std::path::PathBuf;

    #[test]
    fn aquafier_verify_tree_sync_public_api() {
        let aquafier = Aquafier::new();
        let file_data = FileData::new(
            "readme.txt".to_string(),
            b"Aqua Protocol".to_vec(),
            PathBuf::from("readme.txt"),
        );
        let tree = aquafier
            .create_genesis_revision(file_data.clone(), None)
            .unwrap();
        let wrapper = AquaTreeWrapper {
            aqua_tree: tree,
            file_object: Some(file_data.clone()),
            revision: None,
        };
        let result = aquafier.verify_tree_sync(wrapper, vec![file_data]).unwrap();
        assert!(
            result.is_verified(),
            "Aquafier::verify_tree_sync should pass: {:?}",
            result.logs
        );
    }

    #[test]
    fn verify_tree_sync_basic_file_tree() {
        let aquafier = Aquafier::new();
        let file_data = FileData::new(
            "test.txt".to_string(),
            b"hello world".to_vec(),
            PathBuf::from("test.txt"),
        );
        let tree = aquafier
            .create_genesis_revision(file_data.clone(), None)
            .unwrap();
        let wrapper = AquaTreeWrapper {
            aqua_tree: tree,
            file_object: Some(file_data.clone()),
            revision: None,
        };
        let result = verify_aqua_tree_sync(
            &wrapper,
            vec![file_data],
            &[],
            &VerificationPolicy::strict(),
        )
        .unwrap();
        assert!(
            result.is_verified(),
            "sync verification should pass: {:?}",
            result.logs
        );
    }

    #[test]
    fn verify_tree_sync_matches_async_result() {
        let aquafier = Aquafier::new();
        let file_data = FileData::new(
            "doc.md".to_string(),
            b"# Title\nBody text".to_vec(),
            PathBuf::from("doc.md"),
        );
        let tree = aquafier
            .create_genesis_revision(file_data.clone(), None)
            .unwrap();
        let wrapper = AquaTreeWrapper {
            aqua_tree: tree,
            file_object: Some(file_data.clone()),
            revision: None,
        };

        let sync_result = verify_aqua_tree_sync(
            &wrapper,
            vec![file_data],
            &[],
            &VerificationPolicy::strict(),
        )
        .unwrap();
        assert!(
            sync_result.is_verified(),
            "sync verification should pass for valid tree"
        );
        assert!(sync_result.is_clean());
    }

    #[test]
    fn verify_tree_sync_detects_tampered_hash() {
        let aquafier = Aquafier::new();
        let file_data = FileData::new(
            "test.txt".to_string(),
            b"hello".to_vec(),
            PathBuf::from("test.txt"),
        );
        let mut tree = aquafier
            .create_genesis_revision(file_data.clone(), None)
            .unwrap();

        // Tamper: insert a revision with a wrong hash
        let fake_hash = RevisionLink::new(vec![0xDE; 32]);
        if let Some((_, rev)) = tree.revisions.iter().next() {
            tree.revisions.insert(fake_hash.clone(), rev.clone());
        }

        let wrapper = AquaTreeWrapper {
            aqua_tree: tree,
            file_object: Some(file_data.clone()),
            revision: None,
        };
        let result = verify_aqua_tree_sync(
            &wrapper,
            vec![file_data],
            &[],
            &VerificationPolicy::strict(),
        )
        .unwrap();
        assert!(
            !result.is_verified(),
            "tampered hash should fail verification"
        );
    }
}
