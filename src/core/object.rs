use crate::{
    primitives::{
        log::{LogData, LogType},
        MethodError, RevisionLink, Timestamp,
    },
    schema::{link::Anchor, templates::File, tree::Tree, AnyRevision, FileData},
};
use serde_json;
use std::collections::BTreeMap;

use crate::{
    primitives::{HashType, Method},
    schema::Object,
    verification::Linkable,
};

/// Creates a new object revision, optionally chaining to an existing Tree
///
/// # Arguments
/// * `template_hash` - The hash of the template that defines this object's structure
/// * `previous_tree` - Optional existing Tree to chain from (will use last revision)
/// * `payload` - The object's payload data
/// * `method` - Canonicalization method (Scalar or Tree)
///
/// # Returns
/// * `Ok(Tree)` - A new Tree containing the object revision (and previous revisions if chained)
/// * `Err(MethodError)` - If there's an error calculating the hash
pub fn create_object_util(
    template_hash: RevisionLink,
    previous_tree: Option<Tree>,
    payload: serde_json::Value,
    method: Method,
    hash_type: HashType,
) -> Result<Tree, MethodError> {
    create_object_internal(
        template_hash,
        previous_tree,
        payload,
        method,
        None,
        None,
        hash_type,
    )
}

/// Creates a new object revision with a custom file index name
///
/// # Arguments
/// * `template_hash` - The hash of the template that defines this object's structure
/// * `previous_tree` - Optional existing Tree to chain from (will use last revision)
/// * `payload` - The object's payload data
/// * `method` - Canonicalization method (Scalar or Tree)
/// * `object_name` - Custom name for the file index
/// * `hash_type` - Hash algorithm to use for this tree
///
/// # Returns
/// * `Ok(Tree)` - A new Tree containing the object revision (and previous revisions if chained)
/// * `Err(MethodError)` - If there's an error calculating the hash
pub fn create_object_util_with_name(
    template_hash: RevisionLink,
    previous_tree: Option<Tree>,
    payload: serde_json::Value,
    method: Method,
    object_name: String,
    hash_type: HashType,
) -> Result<Tree, MethodError> {
    create_object_internal(
        template_hash,
        previous_tree,
        payload,
        method,
        Some(object_name),
        None,
        hash_type,
    )
}

/// Creates a new object revision with custom genesis anchor structural links.
///
/// Same as [`create_object_util`] but uses `structural_links` for the genesis anchor's
/// `structural_links` instead of `[template_hash]`.
///
/// This is the correct approach for building attestation trees, where the genesis
/// anchor should link to a claim signature hash rather than the template hash.
pub fn create_object_with_anchor_links_util(
    template_hash: RevisionLink,
    structural_links: Vec<RevisionLink>,
    payload: serde_json::Value,
    method: Method,
    hash_type: HashType,
) -> Result<Tree, MethodError> {
    create_object_internal(
        template_hash,
        None,
        payload,
        method,
        None,
        Some(structural_links),
        hash_type,
    )
}

/// Errors returned by [`create_object_validated_util`].
#[derive(Debug, thiserror::Error)]
pub enum CreateObjectError {
    /// No source could supply the template body, so the payload cannot be
    /// validated. Fail closed rather than create an object of an unknown type.
    #[error(
        "template {0} is not resolvable from the previous tree, the built-in \
         catalog, or the supplied template sources"
    )]
    TemplateNotFound(RevisionLink),
    /// The template resolved, but one of its ancestors did not. Verification
    /// resolves the whole `derives_from` chain, so an object created here
    /// would fail at the receiver.
    #[error("template {template} resolves but its ancestor {ancestor} does not")]
    AncestorTemplateNotFound {
        template: RevisionLink,
        ancestor: RevisionLink,
    },
    /// The payload does not satisfy the template's JSON Schema.
    #[error("payload does not satisfy template {template}:\n{}", .errors.join("\n"))]
    SchemaViolation {
        template: RevisionLink,
        errors: Vec<String>,
    },
    /// Hashing or serialization failed while building the revision.
    #[error(transparent)]
    Method(#[from] MethodError),
}

/// Resolve a template body for creation-time validation.
///
/// Deliberately the same order verification uses (`resolve_template`): the
/// tree's own revisions, then the built-in catalog, then the supplied trees.
/// Creating an object under one resolution order and verifying it under
/// another is how "it validated on my machine" happens.
fn resolve_template_for_creation(
    template_hash: &RevisionLink,
    previous_tree: Option<&Tree>,
    template_sources: &[Tree],
) -> Option<crate::schema::Template> {
    if let Some(template) = previous_tree
        .and_then(|tree| tree.revisions.get(template_hash))
        .and_then(|revision| revision.as_template())
    {
        return Some(template.clone());
    }
    if let Some(template) = super::verify_stages::resolve_builtin_template(template_hash) {
        return Some(template);
    }
    template_sources.iter().find_map(|source| {
        source
            .revisions
            .get(template_hash)
            .and_then(|revision| revision.as_template())
            .cloned()
    })
}

/// Create a typed object revision, validating the payload against a template
/// resolved from **explicit sources**.
///
/// See [`crate::Aquafier::create_object_validated`] for the full contract.
pub fn create_object_validated_util(
    template_hash: RevisionLink,
    previous_tree: Option<Tree>,
    payload: serde_json::Value,
    method: Method,
    hash_type: HashType,
    template_sources: &[Tree],
) -> Result<Tree, CreateObjectError> {
    let template =
        resolve_template_for_creation(&template_hash, previous_tree.as_ref(), template_sources)
            .ok_or_else(|| CreateObjectError::TemplateNotFound(template_hash.clone()))?;

    // Verification resolves the whole ancestry chain (a parent's rules apply to
    // every child instance), so an object whose ancestors are unreachable from
    // the same sources is dead on arrival. Say so now, not at the receiver.
    if let Some(ancestry) = template.ancestry() {
        for ancestor in ancestry {
            if resolve_template_for_creation(ancestor, previous_tree.as_ref(), template_sources)
                .is_none()
            {
                return Err(CreateObjectError::AncestorTemplateNotFound {
                    template: template_hash.clone(),
                    ancestor: ancestor.clone(),
                });
            }
        }
    }

    let validator = jsonschema::validator_for(template.schema()).map_err(|e| {
        CreateObjectError::Method(MethodError::Simple(format!(
            "failed to compile template schema: {e}"
        )))
    })?;
    let errors: Vec<String> = validator
        .iter_errors(&payload)
        .map(|e| {
            let path = if e.instance_path.as_str().is_empty() {
                "<root>".to_string()
            } else {
                e.instance_path.to_string()
            };
            format!("  - {path}: {e}")
        })
        .collect();
    if !errors.is_empty() {
        return Err(CreateObjectError::SchemaViolation {
            template: template_hash,
            errors,
        });
    }

    create_object_internal(
        template_hash,
        previous_tree,
        payload,
        method,
        None,
        None,
        hash_type,
    )
    .map_err(CreateObjectError::Method)
}

// Private helper that centralizes object creation logic for all public helpers.
fn create_object_internal(
    template_hash: RevisionLink,
    previous_tree: Option<Tree>,
    payload: serde_json::Value,
    method: Method,
    name: Option<String>,
    anchor_links_override: Option<Vec<RevisionLink>>,
    hash_type: HashType,
) -> Result<Tree, MethodError> {
    // ── Fail-fast payload validation against template schema ──────────
    if let Some(template) = super::verify_stages::resolve_builtin_template(&template_hash) {
        let schema = template.schema();
        match jsonschema::validator_for(schema) {
            Ok(validator) => {
                let errors: Vec<String> = validator
                    .iter_errors(&payload)
                    .map(|e| {
                        let path = if e.instance_path.as_str().is_empty() {
                            "<root>".to_string()
                        } else {
                            e.instance_path.to_string()
                        };
                        format!("  - {}: {}", path, e)
                    })
                    .collect();
                if !errors.is_empty() {
                    return Err(MethodError::Simple(format!(
                        "Payload validation failed:\n{}",
                        errors.join("\n")
                    )));
                }
            }
            Err(e) => {
                return Err(MethodError::Simple(format!(
                    "Failed to compile template schema: {e}"
                )));
            }
        }
    }

    // Initialize or clone existing maps
    let mut revision_data: BTreeMap<RevisionLink, AnyRevision> =
        if let Some(ref tree) = previous_tree {
            tree.revisions.clone()
        } else {
            BTreeMap::new()
        };

    let mut file_index_data: BTreeMap<RevisionLink, String> = if let Some(ref tree) = previous_tree
    {
        tree.file_index.clone()
    } else {
        BTreeMap::new()
    };

    // Determine previous revision (if any)
    let previous_revision_hash = previous_tree
        .as_ref()
        .and_then(|tree| tree.get_latest_revision_link());
    // Genesis case: create an anchor that cross-references the template tree via
    // structural_links, then chain the object directly from the anchor.
    // Templates are separate Aqua-Trees; they are NOT embedded inside object trees.
    // Non-genesis case: chain normally from the existing tree tip.
    //
    // Timestamps are assigned backward from `now()` so every revision gets a
    // distinct second while the latest revision (the object) keeps the real wall-clock
    // time.  This avoids creating future timestamps that would violate ordering when
    // a signature or timestamp revision is appended immediately afterward.
    let chain_to = if let Some(prev_rev_hash) = previous_revision_hash {
        prev_rev_hash
    } else {
        let now_secs = Timestamp::now().as_secs();

        // Create genesis anchor — structural links to template tree tip by default, or caller-supplied targets.
        // Anchor gets now - 1 (one second before the object).
        let genesis_links = anchor_links_override.unwrap_or_else(|| vec![template_hash.clone()]);
        let mut anchor = Anchor::genesis(Method::Scalar, genesis_links);
        anchor.set_local_timestamp(Timestamp::from_secs(now_secs.saturating_sub(1)));
        let anchor_hash = anchor.calculate_link(hash_type)?;
        anchor.populate_leaves(hash_type)?;
        let anchor_name = format!(
            "anchor_{}",
            anchor_hash.to_string().chars().take(8).collect::<String>()
        );
        revision_data.insert(anchor_hash.clone(), AnyRevision::Anchor(anchor));
        file_index_data.insert(anchor_hash.clone(), anchor_name);

        anchor_hash // object chains directly from anchor
    };

    // Build object revision chained to the resolved predecessor.
    // Object gets Timestamp::now() (the real wall-clock time, latest in chain).
    let mut object_revision = Object::new(chain_to, template_hash, method, payload);

    // Calculate verification hash only once (leaves is None → not serialized → hash correct)
    let verification_hash = object_revision.calculate_link(hash_type)?;
    object_revision.populate_leaves(hash_type)?;

    // Insert into revisions
    revision_data.insert(
        verification_hash.clone(),
        AnyRevision::Typed(object_revision),
    );

    // Insert into file index using provided name or generated one
    if let Some(provided_name) = name {
        file_index_data.insert(verification_hash, provided_name);
    } else {
        let file_index_name = format!(
            "object_{}",
            verification_hash
                .to_string()
                .chars()
                .take(8)
                .collect::<String>()
        );
        file_index_data.insert(verification_hash, file_index_name);
    }

    Ok(Tree {
        revisions: revision_data,
        file_index: file_index_data,
    })
}

/// Shared sync implementation for object (file content) verification.
///
/// Spec: "If a revision contains a file hash, implementations MUST verify
/// that the hash of the associated file matches the declared hash."
///
/// For non-file objects this returns (true, logs) -- template schema
/// validation already happened in the caller.
fn verify_object_inner(
    data: &AnyRevision,
    revision_hash: &RevisionLink,
    ident_character: Option<String>,
    file_index: &BTreeMap<RevisionLink, String>,
    file_objects: &[FileData],
) -> (bool, Vec<LogData>) {
    let mut logs: Vec<LogData> = Vec::new();

    let obj = match data {
        AnyRevision::Typed(o) => o,
        _ => {
            logs.push(LogData {
                log: "Revision is not an Object type".to_string(),
                log_type: LogType::Error,
                ident: ident_character,
            });
            return (false, logs);
        }
    };

    // Check if this is a file-template object
    use crate::schema::template::BuiltInTemplate;
    let file_template_link = RevisionLink::from_bytes(File::TEMPLATE_LINK);
    if *obj.revision_type() != file_template_link {
        // Not a file object — template schema validation already passed in caller.
        logs.push(LogData {
            log: "Non-file object verified (schema validated)".to_string(),
            log_type: LogType::Success,
            ident: ident_character,
        });
        return (true, logs);
    }

    // ── File content verification ──────────────────────────────────────
    logs.push(LogData {
        log: "Verifying file object content".to_string(),
        log_type: LogType::Info,
        ident: ident_character.clone(),
    });

    // Parse payload first to get the expected hash — this drives the lookup
    let payload: File = match serde_json::from_value(obj.payloads().clone()) {
        Ok(p) => p,
        Err(_) => {
            logs.push(LogData {
                log: "Failed to parse file payload".to_string(),
                log_type: LogType::Error,
                ident: ident_character,
            });
            return (false, logs);
        }
    };

    // Match file by content hash, not filename.
    // Filenames are mutable organizational metadata (via file_index);
    // the content hash is the only trustworthy identifier.
    // Size pre-filter avoids expensive hashing on non-candidates.
    let file_data = file_objects.iter().find(|f| {
        f.file_size() == payload.size && payload.hash_type.hash(&f.file_content) == payload.hash
    });

    let _file_data = match file_data {
        Some(fd) => fd,
        None => {
            // Use file_index for a human-readable error message
            let display_name = file_index
                .get(revision_hash)
                .map(|n| n.as_str())
                .unwrap_or("<unknown>");
            logs.push(LogData {
                log: format!(
                    "No file object matches expected hash for '{}' (expected 0x{})",
                    display_name,
                    hex::encode(&payload.hash)
                ),
                log_type: LogType::Error,
                ident: ident_character,
            });
            return (false, logs);
        }
    };

    logs.push(LogData {
        log: "File object content verified".to_string(),
        log_type: LogType::Success,
        ident: ident_character,
    });

    (true, logs)
}

/// Verify file content for a file-template object (async entry point).
///
/// Delegates to [`verify_object_inner`]. The async wrapper exists for API
/// compatibility; the actual verification is fully synchronous.
pub async fn verify_object(
    data: &AnyRevision,
    revision_hash: &RevisionLink,
    ident_character: Option<String>,
    file_index: &BTreeMap<RevisionLink, String>,
    file_objects: &[FileData],
) -> (bool, Vec<LogData>) {
    verify_object_inner(
        data,
        revision_hash,
        ident_character,
        file_index,
        file_objects,
    )
}

/// Verify file content for a file-template object (sync entry point).
///
/// Identical to [`verify_object`] but callable without an async runtime.
pub fn verify_object_sync(
    data: &AnyRevision,
    revision_hash: &RevisionLink,
    ident_character: Option<String>,
    file_index: &BTreeMap<RevisionLink, String>,
    file_objects: &[FileData],
) -> (bool, Vec<LogData>) {
    verify_object_inner(
        data,
        revision_hash,
        ident_character,
        file_index,
        file_objects,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::template::template_tree_util;
    use crate::schema::template::BuiltInTemplate;
    use crate::schema::templates::{AuditArtifact, AuditUserTurnMarker};
    use crate::schema::Template;

    fn turn_marker_template_link() -> RevisionLink {
        RevisionLink::from_bytes(AuditUserTurnMarker::TEMPLATE_LINK)
    }

    fn valid_payload() -> serde_json::Value {
        serde_json::json!({
            "signer_did": "did:key:z6MkServer",
            "session_id": "sess-abc123",
            "turn_index": 0,
            "opens_at": 1747526400
        })
    }

    /// T1 plus its audit_artifact ancestor, loaded from the on-disk fixtures.
    fn turn_marker_fixture_sources() -> Vec<Tree> {
        let artifact: Template = serde_json::from_str(AuditArtifact::TEMPLATE_JSON).unwrap();
        let child: Template = serde_json::from_str(AuditUserTurnMarker::TEMPLATE_JSON).unwrap();
        vec![
            template_tree_util(&artifact, Some("audit_artifact")).unwrap(),
            template_tree_util(&child, Some("audit_user_turn_marker")).unwrap(),
        ]
    }

    #[test]
    fn valid_payload_succeeds() {
        let result = create_object_validated_util(
            turn_marker_template_link(),
            None,
            valid_payload(),
            Method::Scalar,
            HashType::Sha3_256,
            &turn_marker_fixture_sources(),
        );
        assert!(result.is_ok(), "valid turn marker payload should succeed");
    }

    #[test]
    fn missing_required_field_fails() {
        let mut payload = valid_payload();
        payload.as_object_mut().unwrap().remove("session_id");
        let result = create_object_validated_util(
            turn_marker_template_link(),
            None,
            payload,
            Method::Scalar,
            HashType::Sha3_256,
            &turn_marker_fixture_sources(),
        );
        assert!(result.is_err(), "missing session_id should fail");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("session_id"),
            "error should mention missing field, got: {}",
            err_msg
        );
    }

    #[test]
    fn extra_field_rejected() {
        let mut payload = valid_payload();
        payload.as_object_mut().unwrap().insert(
            "extra_field".to_string(),
            serde_json::json!("should not be here"),
        );
        let result = create_object_validated_util(
            turn_marker_template_link(),
            None,
            payload,
            Method::Scalar,
            HashType::Sha3_256,
            &turn_marker_fixture_sources(),
        );
        assert!(
            result.is_err(),
            "extra field should be rejected (additionalProperties: false)"
        );
        let err_msg = format!("{}", result.unwrap_err());
        let err_lower = err_msg.to_lowercase();
        assert!(
            err_lower.contains("additional"),
            "error should mention additionalProperties, got: {}",
            err_msg
        );
    }

    #[test]
    fn unknown_template_skips_validation() {
        let unknown_hash = RevisionLink::new(vec![0xAA; 32]);
        let payload = serde_json::json!({"anything": "goes"});
        let result = create_object_util(
            unknown_hash,
            None,
            payload,
            Method::Scalar,
            HashType::Sha3_256,
        );
        assert!(
            result.is_ok(),
            "unknown template should skip validation and succeed"
        );
    }

    #[test]
    fn negative_turn_index_fails() {
        let mut payload = valid_payload();
        payload["turn_index"] = serde_json::json!(-1);
        let result = create_object_validated_util(
            turn_marker_template_link(),
            None,
            payload,
            Method::Scalar,
            HashType::Sha3_256,
            &turn_marker_fixture_sources(),
        );
        assert!(
            result.is_err(),
            "negative turn_index should fail (minimum: 0)"
        );
    }

    #[test]
    fn create_object_does_not_schema_validate_audit_hashes() {
        // B11: audit types are not catalog members. create_object therefore
        // cannot resolve the schema and accepts a deliberately invalid
        // payload — the documented gap. create_object_validated without
        // sources fails closed; with fixture sources it schema-checks.
        let mut bad = valid_payload();
        bad.as_object_mut().unwrap().remove("session_id");

        assert!(
            create_object_util(
                turn_marker_template_link(),
                None,
                bad.clone(),
                Method::Scalar,
                HashType::Sha3_256,
            )
            .is_ok(),
            "catalog miss must skip create_object validation"
        );

        let err = create_object_validated_util(
            turn_marker_template_link(),
            None,
            bad.clone(),
            Method::Scalar,
            HashType::Sha3_256,
            &[],
        )
        .expect_err("no sources, not a built-in");
        assert!(
            matches!(err, CreateObjectError::TemplateNotFound(_)),
            "expected TemplateNotFound, got {err:?}"
        );

        let err = create_object_validated_util(
            turn_marker_template_link(),
            None,
            bad,
            Method::Scalar,
            HashType::Sha3_256,
            &turn_marker_fixture_sources(),
        )
        .expect_err("fixture sources enable schema check");
        assert!(
            matches!(err, CreateObjectError::SchemaViolation { .. }),
            "expected SchemaViolation, got {err:?}"
        );
    }

    // ── Validated creation against explicit sources (B6) ──────────────────

    mod validated {
        use super::*;
        use crate::core::template::template_tree_util;
        use crate::schema::templates::{AuditRoundAnchor, TemplateMeta};
        use crate::schema::{AquaTreeWrapper, Template};
        use crate::verification::Linkable;
        use crate::Aquafier;

        fn custom_template() -> (Template, RevisionLink) {
            let template = Template::new(
                Method::Scalar,
                serde_json::json!({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "properties": {
                        "reading": { "type": "number", "minimum": 0, "maximum": 100 },
                        "sensor_id": { "type": "string", "maxLength": 64 }
                    },
                    "required": ["reading", "sensor_id"],
                    "additionalProperties": false
                }),
                RevisionLink::from_bytes(TemplateMeta::TEMPLATE_LINK),
            );
            let link = template.calculate_link(HashType::Sha3_256).unwrap();
            (template, link)
        }

        fn good_payload() -> serde_json::Value {
            serde_json::json!({ "reading": 21.5, "sensor_id": "sensor-1" })
        }

        #[test]
        fn plain_create_object_does_not_validate_custom_types() {
            // The documented gap this method exists to close: create_object can
            // only validate what it can resolve, and it resolves built-ins only.
            let (_, link) = custom_template();
            let bad = serde_json::json!({ "reading": 999, "unexpected": true });
            assert!(
                create_object_util(link, None, bad, Method::Scalar, HashType::Sha3_256).is_ok(),
                "create_object still accepts anything for an unresolvable type"
            );
        }

        #[test]
        fn validated_accepts_a_conforming_payload_and_matches_create_object() {
            let (template, link) = custom_template();
            let source = template_tree_util(&template, Some("sensor_v1")).unwrap();

            let tree = create_object_validated_util(
                link.clone(),
                None,
                good_payload(),
                Method::Scalar,
                HashType::Sha3_256,
                &[source],
            )
            .expect("conforming payload");

            // Same construction as the unvalidated path: a gate, not a fork.
            let object = tree.revisions.values().find_map(|r| r.as_object()).unwrap();
            assert_eq!(object.revision_type(), &link);
            assert_eq!(object.payloads(), &good_payload());
            assert_eq!(tree.revisions.len(), 2, "anchor + object, no template");
        }

        #[test]
        fn validated_rejects_a_non_conforming_payload() {
            let (template, link) = custom_template();
            let source = template_tree_util(&template, None).unwrap();

            let err = create_object_validated_util(
                link,
                None,
                serde_json::json!({ "reading": 900, "sensor_id": "sensor-1" }),
                Method::Scalar,
                HashType::Sha3_256,
                &[source],
            )
            .expect_err("900 is outside the declared maximum");
            match err {
                CreateObjectError::SchemaViolation { errors, .. } => {
                    assert!(!errors.is_empty());
                    assert!(
                        format!("{errors:?}").contains("reading"),
                        "error should name the offending field: {errors:?}"
                    );
                }
                other => panic!("expected a schema violation, got {other:?}"),
            }
        }

        #[test]
        fn validated_fails_closed_without_a_source() {
            let (_, link) = custom_template();
            let err = create_object_validated_util(
                link.clone(),
                None,
                good_payload(),
                Method::Scalar,
                HashType::Sha3_256,
                &[],
            )
            .expect_err("nothing can supply the template");
            assert!(matches!(err, CreateObjectError::TemplateNotFound(l) if l == link));
        }

        #[test]
        fn validated_requires_the_ancestry_too() {
            // audit_round_anchor derives from audit_artifact. Supplying only the
            // child is a real-world mistake (publish the leaf, forget the root),
            // and it must surface here rather than at the receiver.
            let template: Template = serde_json::from_str(AuditRoundAnchor::TEMPLATE_JSON).unwrap();
            let link = template.calculate_link(HashType::Sha3_256).unwrap();
            let ancestor = template.ancestry().unwrap()[0].clone();

            // After B11, audit_artifact is not a built-in: supplying only the
            // child now fails for the real family too.
            let child_only = create_object_validated_util(
                link.clone(),
                None,
                serde_json::json!({
                    "signer_did": "did:key:z6MkExampleServer",
                    "session_id": "s",
                    "turn_id": format!("0x1620{}", "a".repeat(64)),
                    "turn_index": 0,
                    "artifact_count": 1,
                    "leaf_hashes": [format!("0x1620{}", "b".repeat(64))],
                    "merkle_root": format!("0x{}", "c".repeat(64)),
                    "closed_at": 1754500008u64,
                }),
                Method::Scalar,
                HashType::Sha3_256,
                &[template_tree_util(&template, None).unwrap()],
            )
            .expect_err("the ancestor is no longer a built-in");
            assert!(matches!(
                child_only,
                CreateObjectError::AncestorTemplateNotFound { .. }
            ));

            // The same gap with a custom parent that nobody supplies.
            let orphan = Template::new_derived(
                Method::Scalar,
                serde_json::json!({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "type": "object",
                    "properties": { "note": { "type": "string" } },
                    "required": ["note"],
                    "additionalProperties": false
                }),
                RevisionLink::from_bytes(TemplateMeta::TEMPLATE_LINK),
                RevisionLink::from_bytes([0xAB; 32]),
                vec![RevisionLink::from_bytes([0xAB; 32])],
                None,
            );
            let orphan_link = orphan.calculate_link(HashType::Sha3_256).unwrap();
            let source = template_tree_util(&orphan, None).unwrap();

            let err = create_object_validated_util(
                orphan_link,
                None,
                serde_json::json!({ "note": "hi" }),
                Method::Scalar,
                HashType::Sha3_256,
                &[source],
            )
            .expect_err("the parent template is unreachable");
            assert!(matches!(
                err,
                CreateObjectError::AncestorTemplateNotFound { .. }
            ));

            // Sanity: supplying BOTH the child and its audit_artifact ancestor
            // (neither is a built-in after B11) lets creation succeed.
            assert_ne!(ancestor, RevisionLink::from_bytes([0xAB; 32]));
            let artifact: Template =
                serde_json::from_str(crate::schema::templates::AuditArtifact::TEMPLATE_JSON)
                    .unwrap();
            let ok = create_object_validated_util(
                link,
                None,
                serde_json::json!({
                    "signer_did": "did:key:z6MkExampleServer",
                    "session_id": "s",
                    "turn_id": format!("0x1620{}", "a".repeat(64)),
                    "turn_index": 0,
                    "artifact_count": 1,
                    "leaf_hashes": [format!("0x1620{}", "b".repeat(64))],
                    "merkle_root": format!("0x{}", "c".repeat(64)),
                    "closed_at": 1754500008u64,
                }),
                Method::Scalar,
                HashType::Sha3_256,
                &[
                    template_tree_util(&template, None).unwrap(),
                    template_tree_util(&artifact, Some("audit_artifact")).unwrap(),
                ],
            );
            assert!(ok.is_ok(), "child + ancestor fixtures must resolve: {ok:?}");
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn a_validated_object_verifies_with_the_same_sources() {
            let (template, link) = custom_template();
            let source = template_tree_util(&template, Some("sensor_v1")).unwrap();
            let aquafier = Aquafier::new();

            let tree = aquafier
                .create_object_validated(link, None, good_payload(), None, &[source.clone()])
                .expect("conforming payload");

            let result = aquafier
                .verify_aqua_tree_with_linked_trees(
                    AquaTreeWrapper::new(tree, None, None),
                    vec![AquaTreeWrapper::new(source, None, None)],
                    vec![],
                )
                .await
                .unwrap();
            assert!(
                result.is_verified(),
                "creation-time validation must agree with verification: {:?}",
                result.logs
            );
        }
    }

    // ── Typed genesis anchor tests ────────────────────────────────────────

    #[test]
    fn typed_genesis_has_anchor_and_object() {
        let tree = create_object_util(
            turn_marker_template_link(),
            None,
            valid_payload(),
            Method::Scalar,
            HashType::Sha3_256,
        )
        .expect("valid payload");

        assert_eq!(
            tree.revisions.len(),
            2,
            "genesis tree must have anchor + object"
        );

        let (_, genesis_rev) = tree.get_genesis_revision().unwrap();
        assert!(
            genesis_rev.as_anchor().is_some(),
            "genesis revision must be an Anchor"
        );

        let has_object = tree.revisions.values().any(|r| r.as_object().is_some());
        assert!(has_object, "tree must contain an Object revision");
    }

    #[test]
    fn typed_genesis_anchor_links_template() {
        let tree = create_object_util(
            turn_marker_template_link(),
            None,
            valid_payload(),
            Method::Scalar,
            HashType::Sha3_256,
        )
        .expect("valid payload");

        let (_, genesis_rev) = tree.get_genesis_revision().unwrap();
        let anchor = genesis_rev.as_anchor().expect("genesis is anchor");

        assert!(
            anchor
                .structural_links()
                .contains(&turn_marker_template_link()),
            "anchor must link to the template hash"
        );
    }

    #[test]
    fn typed_genesis_object_chains_from_anchor() {
        let tree = create_object_util(
            turn_marker_template_link(),
            None,
            valid_payload(),
            Method::Scalar,
            HashType::Sha3_256,
        )
        .expect("valid payload");

        let (anchor_hash, _) = tree.get_genesis_revision().unwrap();

        // No template should be embedded in the object tree
        let has_template = tree
            .revisions
            .values()
            .any(|r| matches!(r, AnyRevision::Template(_)));
        assert!(
            !has_template,
            "object tree must NOT contain an embedded Template"
        );

        // The object must chain directly from the anchor
        let obj = tree
            .revisions
            .values()
            .find_map(|r| r.as_object())
            .expect("tree must contain an Object");
        assert_eq!(
            obj.previous_revision().unwrap(),
            &anchor_hash,
            "object must chain directly to the genesis anchor"
        );
    }

    #[test]
    fn chained_object_no_extra_anchor() {
        let base_tree = create_object_util(
            turn_marker_template_link(),
            None,
            valid_payload(),
            Method::Scalar,
            HashType::Sha3_256,
        )
        .expect("valid payload");

        let anchor_count_before = base_tree
            .revisions
            .values()
            .filter(|r| r.as_anchor().is_some())
            .count();
        assert_eq!(anchor_count_before, 1, "base tree has 1 anchor");
        assert_eq!(base_tree.revisions.len(), 2, "base tree = anchor + object");

        let mut payload2 = valid_payload();
        payload2["turn_index"] = serde_json::json!(1);

        let chained_tree = create_object_util(
            turn_marker_template_link(),
            Some(base_tree),
            payload2,
            Method::Scalar,
            HashType::Sha3_256,
        )
        .expect("chaining must succeed");

        let anchor_count_after = chained_tree
            .revisions
            .values()
            .filter(|r| r.as_anchor().is_some())
            .count();
        assert_eq!(
            anchor_count_after, 1,
            "chaining must NOT add another anchor"
        );
        assert_eq!(
            chained_tree.revisions.len(),
            3,
            "chained tree = anchor + first object + second object"
        );
    }

    #[test]
    fn typed_genesis_content_tip_is_object() {
        let tree = create_object_util(
            turn_marker_template_link(),
            None,
            valid_payload(),
            Method::Scalar,
            HashType::Sha3_256,
        )
        .expect("valid payload");

        let (_, content_tip) = tree
            .get_content_tip()
            .expect("tree must have a content tip");
        assert!(
            content_tip.as_object().is_some(),
            "content tip must be Object, not Anchor"
        );

        let (_, genesis) = tree.get_genesis_revision().unwrap();
        assert!(
            genesis.as_anchor().is_some(),
            "genesis must be Anchor, not Object"
        );
    }

    #[test]
    fn genesis_file_has_anchor_and_object() {
        use crate::core::genesis::create_genesis_revision;
        use std::path::PathBuf;

        let file_data = FileData::new(
            "test.txt".to_string(),
            b"hello".to_vec(),
            PathBuf::from("test.txt"),
        );
        let tree = create_genesis_revision(file_data, Method::Scalar).expect("genesis ok");

        assert_eq!(
            tree.revisions.len(),
            2,
            "genesis file tree = anchor + object"
        );

        let (_, genesis_rev) = tree.get_genesis_revision().unwrap();
        assert!(genesis_rev.as_anchor().is_some(), "genesis must be Anchor");

        let (_, content_tip) = tree.get_content_tip().unwrap();
        assert!(
            content_tip.as_object().is_some(),
            "content tip must be Object"
        );
    }

    #[test]
    fn genesis_from_metadata_matches_full_path() {
        use crate::core::genesis::{
            create_genesis_revision, create_genesis_revision_from_metadata,
        };
        use crate::primitives::HashType;
        use crate::schema::file_data::FileMetadata;
        use std::path::PathBuf;

        let content = b"hello world, this is a test file for metadata path";
        let hash = HashType::Sha3_256.hash(content);

        let file_data = FileData::new(
            "test.txt".to_string(),
            content.to_vec(),
            PathBuf::from("test.txt"),
        );
        let tree_full = create_genesis_revision(file_data, Method::Scalar).expect("full ok");

        let metadata = FileMetadata::new(
            "test.txt".to_string(),
            hash,
            content.len() as u64,
            PathBuf::from("test.txt"),
        );
        let tree_meta =
            create_genesis_revision_from_metadata(metadata, Method::Scalar).expect("meta ok");

        // Same structure: same number of revisions, same file_index keys
        assert_eq!(tree_full.revisions.len(), tree_meta.revisions.len());
        assert_eq!(tree_full.file_index.len(), tree_meta.file_index.len());

        // The content tip Object payloads must be identical (same hash, size, content_type)
        let (_, tip_full) = tree_full.get_content_tip().unwrap();
        let (_, tip_meta) = tree_meta.get_content_tip().unwrap();
        let obj_full = tip_full.as_object().unwrap();
        let obj_meta = tip_meta.as_object().unwrap();
        assert_eq!(obj_full.payloads(), obj_meta.payloads());
    }
}
