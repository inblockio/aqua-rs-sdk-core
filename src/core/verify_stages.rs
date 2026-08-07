use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use crate::{
    primitives::{
        log::{LogData, LogType},
        Method, RevisionLink,
    },
    schema::{tree::Tree, AnyRevision, FileData, Template},
};

use super::compute::TemplateVerification;
use super::object::verify_object;
use super::signature::verify_signature;

/// Human-readable names for each built-in template, keyed by TEMPLATE_LINK hash.
/// Used by the daemon's two-tier template name resolver.
pub(crate) static BUILTIN_TEMPLATE_NAMES: LazyLock<HashMap<[u8; 32], &'static str>> =
    LazyLock::new(|| {
        use crate::schema::template::BuiltInTemplate;
        use crate::schema::templates::*;

        [
            (File::TEMPLATE_LINK, "file"),
            (TimestampBase::TEMPLATE_LINK, "timestamp_base"),
            (EvmTimestampPayload::TEMPLATE_LINK, "timestamp_evm"),
            (TsaTimestampPayload::TEMPLATE_LINK, "timestamp_tsa"),
            (IdentityBase::TEMPLATE_LINK, "identity_base"),
            (SignatureEip191::TEMPLATE_LINK, "signature_eip191"),
            (SignatureEd25519::TEMPLATE_LINK, "signature_ed25519"),
            (SignatureP256::TEMPLATE_LINK, "signature_p256"),
            (SignatureWebauthn::TEMPLATE_LINK, "signature_webauthn"),
            (AuditArtifact::TEMPLATE_LINK, "audit_artifact"),
            (AuditUserTurnMarker::TEMPLATE_LINK, "audit_user_turn_marker"),
            (AuditUserPrompt::TEMPLATE_LINK, "audit_user_prompt"),
            (AuditAgentThinking::TEMPLATE_LINK, "audit_agent_thinking"),
            (AuditAgentToolCall::TEMPLATE_LINK, "audit_agent_tool_call"),
            (AuditApiResponse::TEMPLATE_LINK, "audit_api_response"),
            (AuditToolResult::TEMPLATE_LINK, "audit_tool_result"),
            (AuditHitlApproval::TEMPLATE_LINK, "audit_hitl_approval"),
            (AuditAgentResponse::TEMPLATE_LINK, "audit_agent_response"),
        ]
        .into_iter()
        .collect()
    });

/// Resolve a built-in template hash to its human-readable name.
///
/// Returns `None` for unknown (non-built-in) hashes.
pub(crate) fn resolve_builtin_name(hash: &[u8; 32]) -> Option<&'static str> {
    BUILTIN_TEMPLATE_NAMES.get(hash).copied()
}

/// PCA-0015: normalize a template-addressing link to its bare 32-byte SHA3-256
/// digest, the canonical internal index key.
///
/// Template ids are SHA3-256 always (PCA-0015 §3.9), so the 2-byte multihash
/// prefix carries no information for an index — the bare digest is the natural
/// fixed-size key. This accepts either form a link may arrive in:
///   * a bare 32-byte digest (internal template-tree links built via
///     `RevisionLink::new(hash.to_vec())`), or
///   * a full SHA3-256 multihash (external `revision_type` / naming-value links).
/// Returns `None` — never panics — for any malformed, wrong-code, or
/// wrong-length input (closes the prior `try_into().unwrap()` DoS sites).
pub(crate) fn template_digest_key(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() == 32 {
        return bytes.try_into().ok();
    }
    match crate::primitives::multihash_decode(bytes) {
        Ok((crate::primitives::HashType::Sha3_256, digest)) if digest.len() == 32 => {
            digest.try_into().ok()
        }
        _ => None,
    }
}

/// Built-in templates parsed once and cached for the lifetime of the process.
static BUILTIN_TEMPLATES: LazyLock<HashMap<[u8; 32], Template>> = LazyLock::new(|| {
    use crate::schema::template::BuiltInTemplate;
    use crate::schema::templates::*;

    let entries: &[([u8; 32], &str)] = &[
        (
            File::TEMPLATE_LINK,
            include_str!("../schema/templates/file.json"),
        ),
        (
            TimestampBase::TEMPLATE_LINK,
            include_str!("../schema/templates/timestamp_base.json"),
        ),
        (
            EvmTimestampPayload::TEMPLATE_LINK,
            include_str!("../schema/templates/timestamp_evm.json"),
        ),
        (
            TsaTimestampPayload::TEMPLATE_LINK,
            include_str!("../schema/templates/timestamp_tsa.json"),
        ),
        (
            IdentityBase::TEMPLATE_LINK,
            include_str!("../schema/templates/identity_base.json"),
        ),
        (
            SignatureEip191::TEMPLATE_LINK,
            include_str!("../schema/templates/signature_eip191.json"),
        ),
        (
            SignatureEd25519::TEMPLATE_LINK,
            include_str!("../schema/templates/signature_ed25519.json"),
        ),
        (
            SignatureP256::TEMPLATE_LINK,
            include_str!("../schema/templates/signature_p256.json"),
        ),
        (
            SignatureWebauthn::TEMPLATE_LINK,
            include_str!("../schema/templates/signature_webauthn.json"),
        ),
        (
            AuditArtifact::TEMPLATE_LINK,
            include_str!("../schema/templates/audit_artifact.json"),
        ),
        (
            AuditUserTurnMarker::TEMPLATE_LINK,
            include_str!("../schema/templates/audit_user_turn_marker.json"),
        ),
        (
            AuditUserPrompt::TEMPLATE_LINK,
            include_str!("../schema/templates/audit_user_prompt.json"),
        ),
        (
            AuditAgentThinking::TEMPLATE_LINK,
            include_str!("../schema/templates/audit_agent_thinking.json"),
        ),
        (
            AuditAgentToolCall::TEMPLATE_LINK,
            include_str!("../schema/templates/audit_agent_tool_call.json"),
        ),
        (
            AuditApiResponse::TEMPLATE_LINK,
            include_str!("../schema/templates/audit_api_response.json"),
        ),
        (
            AuditToolResult::TEMPLATE_LINK,
            include_str!("../schema/templates/audit_tool_result.json"),
        ),
        (
            AuditHitlApproval::TEMPLATE_LINK,
            include_str!("../schema/templates/audit_hitl_approval.json"),
        ),
        (
            AuditAgentResponse::TEMPLATE_LINK,
            include_str!("../schema/templates/audit_agent_response.json"),
        ),
    ];

    entries
        .iter()
        .map(|(link, json)| {
            let template: Template = serde_json::from_str(json)
                .unwrap_or_else(|e| panic!("built-in template JSON is invalid: {e}"));
            (*link, template)
        })
        .collect()
});

/// Built-in template trees: single-revision trees wrapping each built-in template.
/// Used by `resolve_anchor_links` to recognise genesis anchors that link to built-in templates.
static BUILTIN_TEMPLATE_TREES: LazyLock<HashMap<[u8; 32], Tree>> = LazyLock::new(|| {
    BUILTIN_TEMPLATES
        .iter()
        .map(|(link, template)| {
            let rev_link = RevisionLink::new(link.to_vec());
            let mut revisions = BTreeMap::new();
            let mut file_index = BTreeMap::new();
            revisions.insert(rev_link.clone(), AnyRevision::Template(template.clone()));
            file_index.insert(rev_link.clone(), template.schema().to_string());
            (
                *link,
                Tree {
                    revisions,
                    file_index,
                },
            )
        })
        .collect()
});

/// Return all SDK built-in templates, keyed by their 32-byte SHA3-256 hash.
pub(crate) fn builtin_templates() -> &'static HashMap<[u8; 32], Template> {
    &BUILTIN_TEMPLATES
}

/// Check whether a revision link matches a known built-in template tree tip.
pub fn is_builtin_template_link(link: &RevisionLink) -> bool {
    template_digest_key(link.as_ref()).is_some_and(|key| BUILTIN_TEMPLATE_TREES.contains_key(&key))
}

/// Resolve a template by its hash — checks tree revisions first, then built-in cache.
/// Resolve a built-in template by hash alone (no tree context needed).
pub fn resolve_builtin_template(template_hash: &RevisionLink) -> Option<Template> {
    template_digest_key(template_hash.as_ref()).and_then(|key| BUILTIN_TEMPLATES.get(&key).cloned())
}

/// Construct a single-revision template tree for a built-in template.
///
/// Every template tree — root or derived — is a single `Template` revision.
/// The hierarchy is expressed via `derives_from` / `ancestry` fields on the
/// Template itself, not through Anchor revisions.  Adding an Anchor would
/// require the Template to carry `previous_revision = anchor_hash`, which
/// changes the Template's SHA3-256 hash and breaks `TEMPLATE_LINK` identity.
pub(crate) fn builtin_template_tree(hash: &[u8; 32]) -> Option<Tree> {
    let template = BUILTIN_TEMPLATES.get(hash)?.clone();
    let rev_link = RevisionLink::new(hash.to_vec());
    let mut revisions = BTreeMap::new();
    let mut file_index = BTreeMap::new();

    let name = resolve_builtin_name(hash).unwrap_or("template").to_string();
    revisions.insert(rev_link.clone(), AnyRevision::Template(template));
    file_index.insert(rev_link, name);

    Some(Tree {
        revisions,
        file_index,
    })
}

/// Return template trees for the given hash and all ancestors (root first).
pub(crate) fn builtin_template_tree_chain(hash: &[u8; 32]) -> Vec<Tree> {
    let mut chain = Vec::new();
    if let Some(template) = BUILTIN_TEMPLATES.get(hash) {
        // Ancestors first (root → ... → parent)
        if let Some(ancestry) = template.ancestry() {
            for ancestor in ancestry {
                // Ancestry links are multihash naming-value references (PCA-0015);
                // strip to the bare SHA3-256 digest used as the index key.
                if let Some(key) = template_digest_key(ancestor.as_ref()) {
                    if let Some(tree) = builtin_template_tree(&key) {
                        chain.push(tree);
                    }
                }
            }
        }
        // Self last
        if let Some(tree) = builtin_template_tree(hash) {
            chain.push(tree);
        }
    }
    chain
}

/// Resolve a built-in template hash to its human-readable name (public).
pub(crate) fn builtin_template_name(hash: &[u8; 32]) -> Option<&'static str> {
    resolve_builtin_name(hash)
}

/// All signature template hashes, indexed by signature_type string.
static SIGNATURE_TEMPLATE_HASHES: LazyLock<HashMap<&'static str, [u8; 32]>> = LazyLock::new(|| {
    use crate::schema::template::BuiltInTemplate;
    use crate::schema::templates::*;
    [
        ("ethereum:eip-191", SignatureEip191::TEMPLATE_LINK),
        ("ed25519", SignatureEd25519::TEMPLATE_LINK),
        ("ecdsa:p256", SignatureP256::TEMPLATE_LINK),
        ("webauthn:p256", SignatureWebauthn::TEMPLATE_LINK),
    ]
    .into_iter()
    .collect()
});

/// Returns the 32-byte template hash for a given signature_type string.
pub fn signature_template_hash(signature_type: &str) -> Option<[u8; 32]> {
    SIGNATURE_TEMPLATE_HASHES.get(signature_type).copied()
}

/// Returns `true` if `revision_type` classifies as a signature kind.
///
/// Thin wrapper over [`resolve_revision_kind`] retained as a stable
/// public predicate; the classifier is the single source of truth.
pub fn is_signature_revision_type(revision_type: &str) -> bool {
    crate::primitives::resolve_revision_kind(revision_type)
        == crate::primitives::RevisionKind::Signature
}

/// Returns `true` if `revision_type` classifies as a timestamp kind.
///
/// Thin wrapper over [`resolve_revision_kind`].
pub fn is_timestamp_revision_type(revision_type: &str) -> bool {
    crate::primitives::resolve_revision_kind(revision_type)
        == crate::primitives::RevisionKind::Timestamp
}

/// Given a tree, extract its genesis anchor's structural_links
/// and return all dependency template trees (root-first, deduplicated).
///
/// Also scans all revisions for signature nodes whose revision_type is a
/// signature template hash, and includes those template trees so that
/// `--keep` output and forest navigation can follow signature→template edges.
pub(crate) fn resolve_dependency_trees(tree: &Tree) -> Vec<Tree> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    // Collect template hashes from genesis anchor structural_links
    let mut template_keys: Vec<[u8; 32]> = Vec::new();

    if let Some((_, AnyRevision::Anchor(anchor))) = tree.get_genesis_revision() {
        for link in anchor.structural_links() {
            // Structural links to templates are multihash naming-value references
            // (PCA-0015); normalize to the bare SHA3-256 index key.
            if let Some(key) = template_digest_key(link.as_ref()) {
                template_keys.push(key);
            }
        }
    }

    // Scan all revisions for signature nodes with template-based revision_type
    for (_, revision) in &tree.revisions {
        if let AnyRevision::Signature(sig) = revision {
            let sig_type = sig.signature().signature_type();
            if let Some(tmpl_hash) = signature_template_hash(sig_type) {
                template_keys.push(tmpl_hash);
            }
        }
    }

    // Resolve each template key into its full ancestry chain
    for key in &template_keys {
        let chain = builtin_template_tree_chain(key);
        for tmpl_tree in chain {
            let tip = tmpl_tree.get_latest_revision_link();
            if let Some(tip_hash) = tip {
                if seen.insert(tip_hash) {
                    result.push(tmpl_tree);
                }
            }
        }
    }
    result
}

/// Resolve a template by its hash — checks tree revisions, built-in cache, then linked trees.
///
/// Resolution order:
/// 1. Current tree's own revisions (embedded templates, if any).
/// 2. Built-in template cache (constant-time lookup by 32-byte hash).
/// 3. Linked trees (e.g., template trees cross-referenced via anchor links).
pub(crate) fn resolve_template(
    template_hash: &RevisionLink,
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
    linked_trees: &[crate::schema::AquaTreeWrapper],
) -> Option<Template> {
    // 1. Check current tree's own revisions first
    if let Some(AnyRevision::Template(t)) = revisions.get(template_hash) {
        return Some(t.clone());
    }

    // 2. Look up in cached built-in templates (normalize multihash → bare key)
    if let Some(key) = template_digest_key(template_hash.as_ref()) {
        if let Some(t) = BUILTIN_TEMPLATES.get(&key) {
            return Some(t.clone());
        }
    }

    // 3. Search linked trees (templates are separate Aqua-Trees)
    for wrapper in linked_trees {
        if let Some(AnyRevision::Template(t)) = wrapper.aqua_tree.revisions.get(template_hash) {
            return Some(t.clone());
        }
    }

    None
}

// ── Stage 1: Atomic hash verification ────────────────────────────────────
// Spec: "Implementations MUST compute the revision hash using the
// algorithm specified by the `method` field and verify that it matches
// the declared revision hash."
pub(crate) fn verify_revision_hash(
    revision: &AnyRevision,
    revision_hash: &RevisionLink,
    indent: &str,
) -> Result<Vec<LogData>, (bool, String, Vec<LogData>)> {
    let mut logs: Vec<LogData> = Vec::new();

    // The algorithm is the multicodec the addressing link commits to (§3.5).
    // A malformed addressing multihash MUST be rejected, never skipped (§3.11.6).
    let hash_type = match revision_hash.hash_type() {
        Ok(ht) => ht,
        Err(e) => {
            logs.push(LogData {
                log: format!("Declared revision hash is not a valid multihash: {e}"),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "INVALID_REVISION_HASH_ENCODING".to_string(), logs));
        }
    };

    let computed_hash = match revision.global_calculate_hash(hash_type) {
        Ok(h) => h,
        Err(e) => {
            logs.push(LogData {
                log: format!("Failed to compute revision hash: {e}"),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "HASH_COMPUTE_FAILED".to_string(), logs));
        }
    };

    if computed_hash != *revision_hash {
        logs.push(LogData {
            log: format!("Hash mismatch: declared {revision_hash} but computed {computed_hash}"),
            log_type: LogType::Error,
            ident: Some(indent.to_string()),
        });
        return Err((false, "HASH_MISMATCH".to_string(), logs));
    }

    logs.push(LogData {
        log: "Revision hash verified".to_string(),
        log_type: LogType::Success,
        ident: Some(indent.to_string()),
    });

    Ok(logs)
}

// ── Stage 1b: Leaf integrity verification for Tree-method revisions ──────
// Spec: For Tree-method revisions, the stored `leaves` field MUST match the
// leaf hashes recomputed from the revision's serialized fields.
pub(crate) fn verify_revision_leaves(
    revision: &AnyRevision,
    revision_hash: &RevisionLink,
    indent: &str,
) -> Result<Vec<LogData>, (bool, String, Vec<LogData>)> {
    let mut logs: Vec<LogData> = Vec::new();

    // Algorithm is recovered from the addressing multihash code (§3.5).
    let hash_type = match revision_hash.hash_type() {
        Ok(ht) => ht,
        Err(e) => {
            logs.push(LogData {
                log: format!("Declared revision hash is not a valid multihash: {e}"),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "INVALID_REVISION_HASH_ENCODING".to_string(), logs));
        }
    };

    // Extract method and stored leaves based on revision variant
    let (method, stored_leaves) = match revision {
        AnyRevision::Typed(obj) => {
            use crate::primitives::Canonicalizable;
            (*obj.method(), obj.leaves())
        }
        AnyRevision::Anchor(anchor) => {
            use crate::primitives::Canonicalizable;
            (*anchor.method(), anchor.leaves())
        }
        // Signature and Template revisions have no leaves — skip
        AnyRevision::Signature(_) | AnyRevision::Template(_) => return Ok(logs),
    };

    // Only Tree-method revisions have leaves
    if method != Method::Tree {
        return Ok(logs);
    }

    // Tree-method revisions MUST have a leaves field
    let stored = match stored_leaves {
        Some(leaves) => leaves,
        None => {
            logs.push(LogData {
                log: "Tree-method revision is missing the `leaves` field".to_string(),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "LEAVES_MISSING".to_string(), logs));
        }
    };

    // §3.6 precondition: every stored leaf is a BARE interior digest of exactly
    // the registry length (32 bytes). A non-bare or wrong-length leaf is rejected
    // before Merkle reconstruction (defends against a multihash-shaped leaf).
    let bare_len = hash_type.output_len();
    for (i, leaf) in stored.iter().enumerate() {
        let decoded = leaf.strip_prefix("0x").and_then(|h| hex::decode(h).ok());
        match decoded {
            Some(bytes) if bytes.len() == bare_len => {}
            _ => {
                logs.push(LogData {
                    log: format!("Stored leaf at index {i} is not a bare {bare_len}-byte digest"),
                    log_type: LogType::Error,
                    ident: Some(indent.to_string()),
                });
                return Err((false, "LEAF_NOT_BARE_DIGEST".to_string(), logs));
            }
        }
    }

    // Recompute expected leaves from the revision fields
    let expected_raw = match revision {
        AnyRevision::Typed(obj) => Method::leaves(obj, hash_type),
        AnyRevision::Anchor(anchor) => Method::leaves(anchor, hash_type),
        _ => unreachable!(),
    };

    let expected_raw = match expected_raw {
        Ok(leaves) => leaves,
        Err(e) => {
            logs.push(LogData {
                log: format!("Failed to recompute leaves: {e}"),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "LEAVES_COMPUTE_FAILED".to_string(), logs));
        }
    };

    // Convert to hex strings for comparison
    let expected: Vec<String> = expected_raw
        .iter()
        .map(|l| format!("0x{}", hex::encode(l)))
        .collect();

    // Compare count
    if stored.len() != expected.len() {
        logs.push(LogData {
            log: format!(
                "Leaves count mismatch: stored {} but expected {}",
                stored.len(),
                expected.len()
            ),
            log_type: LogType::Error,
            ident: Some(indent.to_string()),
        });
        return Err((false, "LEAVES_COUNT_MISMATCH".to_string(), logs));
    }

    // Compare values
    if stored != expected.as_slice() {
        // Find the first differing leaf to aid debugging
        for (i, (s, e)) in stored.iter().zip(expected.iter()).enumerate() {
            if s != e {
                logs.push(LogData {
                    log: format!("Leaf mismatch at index {i}: stored {s} but expected {e}"),
                    log_type: LogType::Error,
                    ident: Some(indent.to_string()),
                });
                break;
            }
        }
        return Err((false, "LEAVES_MISMATCH".to_string(), logs));
    }

    logs.push(LogData {
        log: "Revision leaves verified".to_string(),
        log_type: LogType::Success,
        ident: Some(indent.to_string()),
    });

    Ok(logs)
}

// ── Stage 2: Template schema validation for Objects ──────────────────────
// Spec: "Implementations MUST verify that the template referenced by
// `revision_type` exists and has been successfully verified."
// Spec: "For object revisions, implementations MUST verify that the
// revision structure conforms to the schema specified by the referenced
// template."
#[allow(clippy::type_complexity)]
pub(crate) fn verify_revision_schema(
    revision: &AnyRevision,
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
    linked_trees: &[crate::schema::AquaTreeWrapper],
    indent: &str,
) -> Result<(Option<Template>, Vec<LogData>), (bool, String, Vec<LogData>)> {
    let mut logs: Vec<LogData> = Vec::new();

    if let AnyRevision::Typed(obj) = revision {
        let template = resolve_template(obj.revision_type(), revisions, linked_trees);
        match template {
            Some(t) => match t.validate_object(obj) {
                Ok(()) => {
                    logs.push(LogData {
                        log: "Template schema validation passed".to_string(),
                        log_type: LogType::Success,
                        ident: Some(indent.to_string()),
                    });
                    Ok((Some(t), logs))
                }
                Err(e) => {
                    logs.push(LogData {
                        log: format!("Template schema validation failed: {e}"),
                        log_type: LogType::Error,
                        ident: Some(indent.to_string()),
                    });
                    Err((false, "SCHEMA_VALIDATION_FAILED".to_string(), logs))
                }
            },
            None => {
                logs.push(LogData {
                    log: format!(
                        "Template {} not found in tree or built-in registry",
                        obj.revision_type()
                    ),
                    log_type: LogType::Error,
                    ident: Some(indent.to_string()),
                });
                Err((false, "TEMPLATE_NOT_FOUND".to_string(), logs))
            }
        }
    } else {
        // Non-object revisions don't have schema validation
        Ok((None, logs))
    }
}

// ── Stage 3: Compute verification (aqua-rs-sdk-core subset) ──────────────
// The core build ships no WASM runtime (see the conformance profile in the
// README). Where the full SDK executes a template chain's WASM modules and
// records a wasm_state, core applies plan decision D7:
//
//  * Every WASM-carrying template in the resolved chain is a core built-in
//    (identity_base, timestamp_evm, timestamp_tsa): execution is SKIPPED with
//    an explicit Info log and verification falls through to the type-specific
//    stage — the same downstream path a data-only chain takes. Core records
//    no wasm_state; structural, hash, schema, and signature verification are
//    unchanged. Pass/fail parity with the full SDK is asserted by the
//    compat-tests suite.
//
//  * Any non-built-in template in the chain carries `verification`: fail
//    closed with COMPUTE_UNSUPPORTED. The full SDK gates non-built-in WASM
//    behind a trusted vendor signature (template execution gate); core cannot
//    evaluate that trust and must never be more permissive than the full SDK.
//
// Return contract consumed by both pipelines:
//    Ok(None)        — no compute anywhere in the chain; silent fall-through.
//    Ok(Some(logs))  — built-in WASM skipped; caller appends the logs and
//                      falls through to the type-specific stage.
//    Err((..))       — chain unresolvable or carries unsupported WASM; routed
//                      through the governed policy decision points.
pub(crate) fn verify_revision_compute(
    revision: &AnyRevision,
    resolved_template: &Option<Template>,
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
    linked_tree_wrappers: &[crate::schema::AquaTreeWrapper],
    indent: &str,
) -> Result<Option<Vec<LogData>>, (bool, String, Vec<LogData>)> {
    let tmpl = match resolved_template {
        Some(t) => t,
        None => return Ok(None),
    };

    // The executable template chain is identified by the object's template
    // link. Templates only resolve for Typed revisions (verify_revision_schema),
    // so a non-Typed revision has no chain to execute.
    let child_template_hash = match revision {
        AnyRevision::Typed(obj) => obj.revision_type().clone(),
        _ => return Ok(None),
    };

    let mut logs: Vec<LogData> = Vec::new();

    // Collect all TemplateVerification entries from root → parent → child,
    // resolving custom ancestors from the tree/linked trees (spec-object-model §6).
    // Unresolvable ancestors stay a hard error: running an incomplete chain
    // would be unsound in the full SDK and core keeps that invariant.
    let ancestor_verifications = match collect_ancestor_verifications(
        tmpl,
        &child_template_hash,
        revisions,
        linked_tree_wrappers,
    ) {
        Ok(v) => v,
        Err(missing) => {
            logs.push(LogData {
                log: format!(
                    "Ancestor template {missing} could not be resolved — \
                     cannot evaluate its verification chain"
                ),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "ANCESTOR_TEMPLATE_NOT_FOUND".to_string(), logs));
        }
    };

    // If no verification exists in the whole chain, fall through to type-specific
    if ancestor_verifications.is_empty() {
        return Ok(None);
    }

    for entry in &ancestor_verifications {
        if !is_builtin_template_link(&entry.template_hash) {
            logs.push(LogData {
                log: format!(
                    "Template {} carries WASM verification, but aqua-rs-sdk-core \
                     has no WASM runtime and cannot evaluate vendor trust for \
                     non-built-in templates. Verify this tree with the full \
                     aqua-rs-sdk.",
                    entry.template_hash
                ),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "COMPUTE_UNSUPPORTED".to_string(), logs));
        }
    }

    // Timestamp revisions: the chain's WASM performs the on-chain / TSA
    // attestation check, which core cannot run. Route through the governed
    // timestamp_unavailable decision point (COMPUTE_UNSUPPORTED is mapped
    // there by both pipelines for timestamp-typed revisions): strict policy
    // rejects the unverifiable attestation, a relaxed policy may tolerate it
    // with a warning. This matches the hostless full SDK's behavior, so core
    // is never more permissive under the same policy. The batch-inclusion
    // Merkle proof (Stage 2.5) has already run at this point.
    if is_timestamp_revision_type(&revision.get_revision_type()) {
        logs.push(LogData {
            log: "Timestamp attestation cannot be verified by aqua-rs-sdk-core \
                  (no WASM runtime, no providers); governed by the \
                  timestamp_unavailable policy decision"
                .to_string(),
            log_type: LogType::Error,
            ident: Some(indent.to_string()),
        });
        return Err((false, "COMPUTE_UNSUPPORTED".to_string(), logs));
    }

    logs.push(LogData {
        log: "Compute verification skipped: built-in template WASM is not \
              executed by aqua-rs-sdk-core (no wasm_state recorded); use the \
              full aqua-rs-sdk for compute-stage verification"
            .to_string(),
        log_type: LogType::Info,
        ident: Some(indent.to_string()),
    });
    Ok(Some(logs))
}

/// Collect `TemplateVerification` entries from root → parent → child.
///
/// For a root template (no ancestry), returns at most one entry (its own
/// `verification` if present).
///
/// For a derived template, walks the full ancestry chain resolving each ancestor
/// via [`resolve_template`] — the same resolution order used for the child's own
/// template (tree revisions → built-in cache → linked trees). This is a security
/// invariant: a parent's WASM defines verification rules that MUST run on every
/// child instance (spec-object-model §6, spec-template-hierarchy §4.1). Resolving
/// only built-in ancestors would let a child of a *custom* parent silently bypass
/// the parent's checks.
///
/// Returns `Err(ancestor_hash)` if any ancestor template cannot be resolved, so the
/// caller can apply the `ancestor_template_not_found` governed decision rather than
/// running an incomplete (and therefore unsound) verification chain.
pub(crate) fn collect_ancestor_verifications(
    template: &Template,
    child_template_hash: &RevisionLink,
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
    linked_trees: &[crate::schema::AquaTreeWrapper],
) -> Result<Vec<crate::core::verify_common::ChainVerification>, RevisionLink> {
    use crate::core::verify_common::ChainVerification;

    let mut result = Vec::new();

    if let Some(ancestry) = template.ancestry() {
        // Derived template: collect from each ancestor hash (root first).
        for ancestor_hash in ancestry {
            let ancestor_tmpl = resolve_template(ancestor_hash, revisions, linked_trees)
                .ok_or_else(|| ancestor_hash.clone())?;
            if let Some(v) = ancestor_tmpl.verification() {
                let mut v = v.clone();
                // Built-in ancestors may carry terminal states implicitly (annotated
                // here to avoid hash-breaking JSON changes). Custom ancestors declare
                // `terminal_states` directly in their verification JSON. See
                // spec-object-model §6.
                if v.terminal_states.is_empty() {
                    annotate_builtin_terminal_states(ancestor_hash, &mut v);
                }
                result.push(ChainVerification {
                    template_hash: ancestor_hash.clone(),
                    verification: v,
                });
            }
        }
    }

    // Add this template's own verification last (child runs after ancestors)
    if let Some(v) = template.verification() {
        result.push(ChainVerification {
            template_hash: child_template_hash.clone(),
            verification: v.clone(),
        });
    }

    Ok(result)
}

/// Annotate terminal states for known built-in templates.
///
/// Terminal states cause the ancestor WASM chain to stop — child WASM never runs.
/// This avoids modifying template JSON (which would change hashes and cascade through
/// all derived templates). Future: templates declare `terminal_states` in JSON directly.
fn annotate_builtin_terminal_states(
    template_hash: &RevisionLink,
    verification: &mut TemplateVerification,
) {
    use crate::schema::template::BuiltInTemplate;
    use crate::schema::templates::IdentityBase;

    // Ancestry entries are full multihashes (AD-21); normalize to bare digest
    // for comparison with BuiltInTemplate::TEMPLATE_LINK constants.
    let bare = match template_digest_key(template_hash.as_ref()) {
        Some(k) => k,
        None => return,
    };
    if bare == IdentityBase::TEMPLATE_LINK {
        // spec-object-model §6.3: expired and not_yet_valid are temporal facts, non-overridable
        verification.terminal_states = vec!["expired".to_string(), "not_yet_valid".to_string()];
    }
}

// ── Stage 4: Type-specific verification ──────────────────────────────────
// Timestamp objects go through the compute engine (Stage 3 above).
// All other objects go through file content verification.
pub(super) async fn verify_revision_type_specific(
    revision: &AnyRevision,
    revision_hash: &RevisionLink,
    file_index: &BTreeMap<RevisionLink, String>,
    file_objects: &[FileData],
    indent: &str,
) -> (bool, Vec<LogData>) {
    let revision_hash_str = revision_hash.to_string();
    let mut logs: Vec<LogData> = Vec::new();

    match revision {
        AnyRevision::Typed(_obj) => {
            let result = verify_object(
                revision,
                revision_hash,
                Some(indent.to_string()),
                file_index,
                file_objects,
            )
            .await;
            (result.0, result.1)
        }
        AnyRevision::Template(template) => {
            // Hash already verified — that's the atomic check for templates.
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
            verify_signature(revision, &revision_hash_str, Some(indent.to_string())).await
        }
        AnyRevision::Anchor(_anchor) => {
            // Hash already verified — that's the atomic check for anchors.
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
    use crate::core::genesis::create_genesis_revision;
    use crate::primitives::{HashType, Method};
    use crate::schema::template::BuiltInTemplate;
    use crate::schema::templates;
    use crate::schema::FileData;
    use crate::verification::Linkable;
    use std::path::PathBuf;

    fn make_genesis_tree() -> (crate::schema::tree::Tree, RevisionLink) {
        let file_data = FileData::new(
            "test.txt".into(),
            b"hello".to_vec(),
            PathBuf::from("test.txt"),
        );
        let tree = create_genesis_revision(file_data, Method::Scalar).unwrap();
        // Genesis is now an Anchor; return the Object (content tip) hash
        let obj_hash = tree.get_content_tip().unwrap().0;
        (tree, obj_hash)
    }

    // ── resolve_template ──────────────────────────────────────────────────

    #[test]
    fn test_resolve_builtin_file_template() {
        let link = RevisionLink::from_bytes(templates::File::TEMPLATE_LINK);
        let empty = BTreeMap::new();
        let result = resolve_template(&link, &empty, &[]);
        assert!(
            result.is_some(),
            "File template should resolve from built-in cache"
        );
    }

    #[test]
    fn test_resolve_all_builtin_templates() {
        // Derive expectations from BUILTIN_TEMPLATES itself rather than a
        // hardcoded list, so this test tracks whichever templates core ships
        // without needing to be updated when the built-in set changes.
        let empty = BTreeMap::new();
        for hash in builtin_templates().keys() {
            let link = RevisionLink::new(hash.to_vec());
            let name = resolve_builtin_name(hash).unwrap_or("<unnamed>");
            assert!(
                resolve_template(&link, &empty, &[]).is_some(),
                "built-in template '{name}' should resolve"
            );
        }
    }

    #[test]
    fn test_resolve_unknown_template_returns_none() {
        let link = RevisionLink::new(vec![0xAA; 32]);
        let empty = BTreeMap::new();
        assert!(resolve_template(&link, &empty, &[]).is_none());
    }

    // WS7 amendment A4 (steelman F5): close the latent "forgot the verify_stages
    // array" gap. `verify-templates` scans the templates DIRECTORY and checks each
    // file's hash against its own `.rs` TEMPLATE_LINK, but never consults these two
    // caches, so a template added to mod.rs+.rs+.json yet forgotten in a
    // `verify_stages` array compiles and passes `verify-templates`, failing only at
    // runtime resolution. This guard iterates the directory and asserts every
    // content template resolves in BOTH caches, turning that silent failure into a
    // red test (it also protects the WS5 PolicyCondition merge, and pins `manifest`).
    #[test]
    fn builtin_caches_are_complete() {
        use crate::verification::Linkable;
        use std::path::Path;

        // Foundation / structural templates deliberately NOT in the content
        // resolution caches (they are addressed structurally, never by an object
        // `revision_type`), so they have no entry here by design:
        //   - template_meta: the template-of-templates (its revision_type is the
        //     genesis bootstrap value, not its own content hash).
        //   - signature_base / anchor_template: abstract foundations; signatures
        //     resolve via SIGNATURE_TEMPLATE_HASHES and anchors are not object
        //     templates.
        //   - timestamp: legacy abstract timestamp (no BuiltInTemplate impl),
        //     superseded by timestamp_base.
        //   - audit_round_anchor / audit_session_close: audit anchor / lifecycle
        //     templates not wired into content resolution (pre-existing; out of
        //     WS7 scope, recorded here so the exclusion set stays explicit).
        const KNOWN_UNCACHED: &[&str] = &[
            "template_meta",
            "signature_base",
            "anchor_template",
            "audit_round_anchor",
            "audit_session_close",
        ];

        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/schema/templates");
        let mut checked = 0usize;
        for entry in std::fs::read_dir(&dir).expect("read templates dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let stem = path.file_stem().unwrap().to_str().unwrap().to_string();
            if stem.ends_with("_schema") || KNOWN_UNCACHED.contains(&stem.as_str()) {
                continue;
            }

            let json = std::fs::read_to_string(&path).expect("read template json");
            let template: Template = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("{stem}.json is not a valid Template: {e}"));
            let link = template
                .calculate_link(HashType::Sha3_256)
                .unwrap_or_else(|e| panic!("cannot hash {stem}: {e}"));
            let key = template_digest_key(link.as_ref())
                .unwrap_or_else(|| panic!("{stem} link is not a valid SHA3-256 multihash"));

            assert!(
                BUILTIN_TEMPLATES.contains_key(&key),
                "template `{stem}` is missing from BUILTIN_TEMPLATES (add its include_str entry)"
            );
            assert!(
                BUILTIN_TEMPLATE_NAMES.contains_key(&key),
                "template `{stem}` is missing from BUILTIN_TEMPLATE_NAMES (add its name entry)"
            );
            checked += 1;
        }

        assert!(checked > 0, "no templates were checked");
    }

    #[test]
    fn test_resolve_template_from_tree_revisions() {
        let template = Template::new(
            Method::Scalar,
            serde_json::json!({"type": "object"}),
            RevisionLink::from_bytes(templates::TemplateMeta::TEMPLATE_LINK),
        );
        let link = template.calculate_link(HashType::Sha3_256).unwrap();
        let mut revisions = BTreeMap::new();
        revisions.insert(link.clone(), AnyRevision::Template(template.clone()));
        let result = resolve_template(&link, &revisions, &[]);
        assert_eq!(result.unwrap(), template);
    }

    // ── verify_revision_hash ──────────────────────────────────────────────

    #[test]
    fn test_verify_hash_matching() {
        let (tree, genesis_hash) = make_genesis_tree();
        let revision = tree.revisions.get(&genesis_hash).unwrap();
        let result = verify_revision_hash(revision, &genesis_hash, "  ");
        assert!(result.is_ok(), "correct hash should pass verification");
        let logs = result.unwrap();
        assert!(logs
            .iter()
            .any(|l| l.log.contains("Revision hash verified")));
    }

    #[test]
    fn test_verify_hash_mismatch() {
        let (tree, genesis_hash) = make_genesis_tree();
        let revision = tree.revisions.get(&genesis_hash).unwrap();
        // Valid SHA3-256 multihash with a WRONG digest, so it passes the
        // encoding gate (§3.11.6) and reaches the HASH_MISMATCH comparison.
        let wrong_hash = RevisionLink::new(crate::primitives::multihash_encode(
            HashType::Sha3_256,
            &[0xFF; 32],
        ));
        let result = verify_revision_hash(revision, &wrong_hash, "  ");
        assert!(result.is_err(), "wrong hash should fail verification");
        let (is_valid, code, _) = result.unwrap_err();
        assert!(!is_valid);
        assert_eq!(code, "HASH_MISMATCH");
    }

    // ── verify_revision_schema ────────────────────────────────────────────

    #[test]
    fn test_schema_validation_passes_for_valid_object() {
        let (tree, genesis_hash) = make_genesis_tree();
        let revision = tree.revisions.get(&genesis_hash).unwrap();
        let result = verify_revision_schema(revision, &tree.revisions, &[], "  ");
        assert!(
            result.is_ok(),
            "valid genesis object should pass schema validation"
        );
        let (template, logs) = result.unwrap();
        assert!(
            template.is_some(),
            "file object should resolve its template"
        );
        assert!(logs
            .iter()
            .any(|l| l.log.contains("schema validation passed")));
    }

    #[test]
    fn test_schema_validation_skips_non_objects() {
        let template = Template::new(
            Method::Scalar,
            serde_json::json!({"type": "object"}),
            RevisionLink::from_bytes(templates::TemplateMeta::TEMPLATE_LINK),
        );
        let revision = AnyRevision::Template(template);
        let empty = BTreeMap::new();
        let result = verify_revision_schema(&revision, &empty, &[], "  ");
        assert!(
            result.is_ok(),
            "non-object revisions should skip schema validation"
        );
        let (template, logs) = result.unwrap();
        assert!(template.is_none());
        assert!(logs.is_empty());
    }

    #[test]
    fn test_schema_validation_fails_for_missing_template() {
        let (tree, genesis_hash) = make_genesis_tree();
        let revision = tree.revisions.get(&genesis_hash).unwrap();
        // Modify the object to point to an unknown template
        let mut json = serde_json::to_value(revision.as_object().unwrap()).unwrap();
        json["revision_type"] =
            serde_json::json!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        let bad_obj: crate::schema::Object = serde_json::from_value(json).unwrap();
        let bad_revision = AnyRevision::Typed(bad_obj);
        let empty = BTreeMap::new();
        let result = verify_revision_schema(&bad_revision, &empty, &[], "  ");
        assert!(result.is_err(), "unknown template should fail");
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "TEMPLATE_NOT_FOUND");
    }

    // ── builtin_template_tree / builtin_template_tree_chain ──────────────

    #[test]
    fn test_builtin_template_tree_root_has_one_revision() {
        // IdentityBase is a root (L1) template — single Template revision, no Anchor
        let tree = builtin_template_tree(&templates::IdentityBase::TEMPLATE_LINK)
            .expect("IdentityBase should produce a tree");
        assert_eq!(
            tree.revisions.len(),
            1,
            "root template tree should have 1 revision"
        );
        assert!(
            tree.revisions
                .values()
                .all(|r| matches!(r, AnyRevision::Template(_))),
            "the single revision should be a Template"
        );
    }

    #[test]
    fn test_builtin_template_tree_derived_is_single_revision() {
        // AuditUserPrompt derives from AuditArtifact, but is still a single Template revision.
        // Hierarchy is expressed via derives_from/ancestry, not via Anchor.
        let tree = builtin_template_tree(&templates::AuditUserPrompt::TEMPLATE_LINK)
            .expect("AuditUserPrompt should produce a tree");
        assert_eq!(
            tree.revisions.len(),
            1,
            "derived template tree should have 1 revision (Template only)"
        );
        assert!(
            tree.revisions
                .values()
                .all(|r| matches!(r, AnyRevision::Template(_))),
            "the single revision should be a Template"
        );
    }

    #[test]
    fn test_builtin_template_tree_chain_length() {
        // AuditUserTurnMarker: identity_base → audit_artifact → audit_user_turn_marker
        // (ancestry depth 2), so the resolved chain has 3 template trees.
        let chain = builtin_template_tree_chain(&templates::AuditUserTurnMarker::TEMPLATE_LINK);
        assert_eq!(
            chain.len(),
            3,
            "AuditUserTurnMarker chain should have 3 trees"
        );
        // All template trees are single-revision (Template only, no Anchor)
        for (i, tree) in chain.iter().enumerate() {
            assert_eq!(tree.revisions.len(), 1, "tree {i} should have 1 revision");
        }
    }

    #[test]
    fn test_builtin_template_tree_unknown_returns_none() {
        let unknown = [0xBB; 32];
        assert!(builtin_template_tree(&unknown).is_none());
    }

    // ── verify_revision_leaves ────────────────────────────────────────────

    fn make_tree_method_genesis() -> (crate::schema::tree::Tree, RevisionLink) {
        let file_data = FileData::new(
            "test.txt".into(),
            b"hello".to_vec(),
            PathBuf::from("test.txt"),
        );
        let tree = create_genesis_revision(file_data, Method::Tree).unwrap();
        let obj_hash = tree.get_content_tip().unwrap().0;
        (tree, obj_hash)
    }

    #[test]
    fn leaf_removal_detected() {
        let (tree, obj_hash) = make_tree_method_genesis();
        let revision = tree.revisions.get(&obj_hash).unwrap();

        // Tamper: remove the first leaf
        let mut json = serde_json::to_value(revision.as_object().unwrap()).unwrap();
        let leaves = json["leaves"].as_array_mut().unwrap();
        leaves.remove(0);
        let bad_obj: crate::schema::Object = serde_json::from_value(json).unwrap();
        let bad_revision = AnyRevision::Typed(bad_obj);

        let result = verify_revision_leaves(&bad_revision, &obj_hash, "  ");
        assert!(result.is_err(), "removing a leaf should fail verification");
        let (is_valid, code, _) = result.unwrap_err();
        assert!(!is_valid);
        assert_eq!(code, "LEAVES_COUNT_MISMATCH");
    }

    #[test]
    fn leaf_modification_detected() {
        let (tree, obj_hash) = make_tree_method_genesis();
        let revision = tree.revisions.get(&obj_hash).unwrap();

        // Tamper: modify the first leaf value
        let mut json = serde_json::to_value(revision.as_object().unwrap()).unwrap();
        let leaves = json["leaves"].as_array_mut().unwrap();
        leaves[0] =
            serde_json::json!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        let bad_obj: crate::schema::Object = serde_json::from_value(json).unwrap();
        let bad_revision = AnyRevision::Typed(bad_obj);

        let result = verify_revision_leaves(&bad_revision, &obj_hash, "  ");
        assert!(result.is_err(), "modifying a leaf should fail verification");
        let (is_valid, code, _) = result.unwrap_err();
        assert!(!is_valid);
        assert_eq!(code, "LEAVES_MISMATCH");
    }

    #[test]
    fn valid_leaves_pass() {
        let (tree, obj_hash) = make_tree_method_genesis();
        let revision = tree.revisions.get(&obj_hash).unwrap();

        let result = verify_revision_leaves(revision, &obj_hash, "  ");
        assert!(result.is_ok(), "correct leaves should pass verification");
        let logs = result.unwrap();
        assert!(logs
            .iter()
            .any(|l| l.log.contains("Revision leaves verified")));
    }

    #[test]
    fn scalar_revision_skipped() {
        let (tree, genesis_hash) = make_genesis_tree();
        let revision = tree.revisions.get(&genesis_hash).unwrap();

        let result = verify_revision_leaves(revision, &genesis_hash, "  ");
        assert!(
            result.is_ok(),
            "scalar revision should pass (skip) leaf verification"
        );
        let logs = result.unwrap();
        assert!(
            logs.is_empty(),
            "scalar revision should produce no leaf verification logs"
        );
    }

    // ── Compositional monotonicity (spec-object-model §6) ────────────────

    #[test]
    fn test_identity_base_root_has_no_terminal_states_annotation() {
        // identity_base itself (as root, no ancestry) should NOT have terminal_states
        // annotated — annotation only happens during ancestry collection.
        let link = RevisionLink::from_bytes(templates::IdentityBase::TEMPLATE_LINK);
        let empty = BTreeMap::new();
        let template = resolve_template(&link, &empty, &[]).unwrap();

        let verifications = collect_ancestor_verifications(&template, &link, &empty, &[]).unwrap();
        assert_eq!(verifications.len(), 1, "root template has 1 verification");
        // Root template's verification comes from template.verification() directly,
        // not from ancestry walk, so terminal_states is not annotated (empty from JSON).
        assert!(
            verifications[0].verification.terminal_states.is_empty(),
            "root template verification should not have terminal_states (no parent to protect from)"
        );
    }

    // ── Custom (non-builtin) ancestor resolution (Workstream C: C2/C3) ────
    // spec-template-hierarchy §4 (WASM inheritance), spec-object-model §6
    // (compositional monotonicity). Before C2, collect resolved ancestors via
    // the built-in cache only, so a child of a custom parent silently bypassed
    // the parent's WASM. These tests pin the resolved-via-typed-context behavior.

    fn custom_verification(states: Vec<&str>, terminal: Vec<&str>) -> TemplateVerification {
        TemplateVerification {
            computations: Vec::new(),
            host_dependencies: Vec::new(),
            states: states.into_iter().map(String::from).collect(),
            terminal_states: terminal.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn test_custom_parent_wasm_runs_for_child() {
        // H1 (spec-template-hierarchy §4): a child of a CUSTOM (non-builtin)
        // parent must collect the parent's verification so the parent's WASM
        // runs on the child instance. Before C2 this silently bypassed the
        // parent because resolution went through the built-in cache only.
        let parent = Template::new_derived(
            Method::Scalar,
            serde_json::json!({"type": "object"}),
            RevisionLink::from_bytes(templates::TemplateMeta::TEMPLATE_LINK),
            RevisionLink::new(vec![0x01; 32]),
            vec![],
            Some(custom_verification(vec!["draft", "active"], vec![])),
        );
        let parent_link = parent.calculate_link(HashType::Sha3_256).unwrap();

        let child = Template::new_derived(
            Method::Scalar,
            serde_json::json!({"type": "object"}),
            RevisionLink::from_bytes(templates::TemplateMeta::TEMPLATE_LINK),
            parent_link.clone(),
            vec![parent_link.clone()],
            Some(custom_verification(
                vec!["draft", "active", "endorsed"],
                vec![],
            )),
        );

        let child_link = child.calculate_link(HashType::Sha3_256).unwrap();
        let mut revisions = BTreeMap::new();
        revisions.insert(parent_link, AnyRevision::Template(parent));

        let verifications =
            collect_ancestor_verifications(&child, &child_link, &revisions, &[]).unwrap();
        assert_eq!(
            verifications.len(),
            2,
            "child of a custom parent collects parent + child verifications"
        );
        assert_eq!(
            verifications[0].verification.states,
            vec!["draft", "active"]
        );
        assert_eq!(
            verifications[1].verification.states,
            vec!["draft", "active", "endorsed"]
        );
    }

    #[test]
    fn test_custom_parent_terminal_states_carried_through() {
        // H2 (spec-object-model §6): a custom parent declaring terminal_states in
        // its verification JSON must have them preserved through collection so the
        // child's WASM is blocked when the parent returns a terminal state.
        let parent = Template::new_derived(
            Method::Scalar,
            serde_json::json!({"type": "object"}),
            RevisionLink::from_bytes(templates::TemplateMeta::TEMPLATE_LINK),
            RevisionLink::new(vec![0x02; 32]),
            vec![],
            Some(custom_verification(
                vec!["active", "revoked"],
                vec!["revoked"],
            )),
        );
        let parent_link = parent.calculate_link(HashType::Sha3_256).unwrap();

        let child = Template::new_derived(
            Method::Scalar,
            serde_json::json!({"type": "object"}),
            RevisionLink::from_bytes(templates::TemplateMeta::TEMPLATE_LINK),
            parent_link.clone(),
            vec![parent_link.clone()],
            Some(custom_verification(vec!["active"], vec![])),
        );

        let child_link = child.calculate_link(HashType::Sha3_256).unwrap();
        let mut revisions = BTreeMap::new();
        revisions.insert(parent_link, AnyRevision::Template(parent));

        let verifications =
            collect_ancestor_verifications(&child, &child_link, &revisions, &[]).unwrap();
        assert_eq!(
            verifications[0].verification.terminal_states,
            vec!["revoked".to_string()],
            "custom parent's JSON-declared terminal_states must be preserved (not clobbered)"
        );
    }

    #[test]
    fn test_missing_custom_ancestor_returns_err() {
        // H3 (governed decision AncestorTemplateNotFound): when a child's ancestor
        // cannot be resolved (not built-in, not in the tree, not in linked trees),
        // collection must Err with the missing hash so the caller applies the
        // governed decision (strict/offline fail, debug warns). A child must never
        // silently bypass an unresolved parent's WASM.
        let missing_link = RevisionLink::new(vec![0xAB; 32]);
        let child = Template::new_derived(
            Method::Scalar,
            serde_json::json!({"type": "object"}),
            RevisionLink::from_bytes(templates::TemplateMeta::TEMPLATE_LINK),
            missing_link.clone(),
            vec![missing_link.clone()],
            Some(custom_verification(vec!["active"], vec![])),
        );
        let child_link = child.calculate_link(HashType::Sha3_256).unwrap();
        let empty = BTreeMap::new();
        // ChainVerification (the Ok payload) has no Debug impl, so match
        // instead of unwrap_err() to avoid requiring one just for this test.
        match collect_ancestor_verifications(&child, &child_link, &empty, &[]) {
            Err(err) => assert_eq!(
                err, missing_link,
                "Err must carry the unresolved ancestor hash"
            ),
            Ok(_) => panic!("expected Err for an unresolvable custom ancestor"),
        }
    }
}
