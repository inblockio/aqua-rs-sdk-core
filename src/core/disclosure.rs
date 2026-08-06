//! Selective disclosure for Aqua trees.
//!
//! **L1 (field-level):** Redact individual fields from a tree-method revision.
//! The verifier reconstructs the Merkle root from disclosed fields and opaque hashes.
//!
//! **L2 (revision-level):** Export a tree with a disclosure policy — some revisions
//! fully disclosed, some field-redacted, some hidden (signatures/anchors omitted,
//! content revisions chain-linked only).

use crate::primitives::{
    merkle, multihash_encode, Canonicalizable, HashType, Method, MultihashError, RevisionLink,
};
use crate::schema::template::BuiltInTemplate;
use crate::schema::templates::{
    AuditAgentResponse, AuditAgentThinking, AuditAgentToolCall, AuditGustoApiResponse,
    AuditHitlApproval, AuditToolResult, AuditUserPrompt, AuditUserTurnMarker,
};
use crate::schema::tree::Tree;
use crate::schema::AnyRevision;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ── Error types ──────────────────────────────────────────────────────────

#[derive(thiserror::Error, Debug)]
pub enum RedactionError {
    #[error("Revision not found: {0}")]
    RevisionNotFound(String),
    #[error(
        "Revision uses scalar method — only tree-method revisions support field-level redaction"
    )]
    NotTreeMethod,
    #[error("Field not found in revision: {0}")]
    FieldNotFound(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Revision hash is not a valid multihash: {0}")]
    MalformedRevisionHash(MultihashError),
}

#[derive(thiserror::Error, Debug)]
pub enum DisclosureVerificationError {
    #[error("Leaf count mismatch: declared {declared}, provided {provided}")]
    LeafCountMismatch { declared: u32, provided: u32 },
    #[error("Duplicate leaf index: {0}")]
    DuplicateIndex(u32),
    #[error("Missing leaf index: {0}")]
    MissingIndex(u32),
    #[error("Merkle root mismatch: expected {expected}, computed {computed}")]
    MerkleRootMismatch { expected: String, computed: String },
    #[error("Revision hash is not a valid multihash: {0}")]
    MalformedRevisionHash(MultihashError),
}

// ── Core types ───────────────────────────────────────────────────────────

/// A leaf in a redacted revision — either disclosed (with value + salt)
/// or redacted (path + value commitment only; PCA-0016 AD-20).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum RedactedLeaf {
    /// Field is visible — verifier can recompute leaf hash from salt + path + value.
    Disclosed {
        index: u32,
        path: String,
        value: String,
        #[serde(with = "hex_bytes")]
        salt: Vec<u8>,
    },
    /// Field is hidden — path is presented in the clear and authenticated by the
    /// leaf construction; the salted value is sealed as `value_commit`
    /// (`HASH(0x02 || salt || value)`, AD-20). The verifier recomputes
    /// `label = HASH(0x03 || path)` and
    /// `leaf = HASH(0x00 || label || value_commit)`.
    Redacted {
        index: u32,
        path: String,
        #[serde(with = "hex_bytes")]
        value_commit: Vec<u8>,
    },
}

impl RedactedLeaf {
    fn index(&self) -> u32 {
        match self {
            Self::Disclosed { index, .. } | Self::Redacted { index, .. } => *index,
        }
    }
}

/// A redacted view of a tree-method revision.
///
/// The revision-hash algorithm is recovered from `revision_hash`'s multihash
/// code (PCA-0015 §3.5); it is no longer carried as a separate field.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedactedRevision {
    pub revision_hash: RevisionLink,
    pub leaf_count: u32,
    pub leaves: Vec<RedactedLeaf>,
}

// ── Leaf metadata (internal) ─────────────────────────────────────────────

/// Full leaf info needed for redaction — path, serialized value, salt, commitments.
struct LeafMeta {
    path: String,
    value: String,
    salt: Vec<u8>,
    /// `HASH(0x02 || salt || value)` — presented on Redacted leaves (AD-20).
    value_commit: Vec<u8>,
}

/// Compute all leaf metadata for a tree-method revision under `hash_type`
/// (recovered from the revision's addressing multihash, PCA-0015 §3.5).
fn compute_leaf_metadata(
    revision: &AnyRevision,
    hash_type: HashType,
) -> Result<Vec<LeafMeta>, RedactionError> {
    let nonce = match revision {
        AnyRevision::Typed(obj) => obj.nonce().clone(),
        AnyRevision::Template(t) => t.nonce().clone(),
        AnyRevision::Signature(sig) => sig.nonce().clone(),
        AnyRevision::Anchor(a) => a.nonce().clone(),
    };

    let prk = merkle::derive_prk(nonce.as_ref());

    let mut pointers = jsonpointer_flatten::from(revision)?;
    pointers.sort_all_objects();

    let metas = if let serde_json::Value::Object(p) = pointers {
        p.into_iter()
            .filter(|(k, _)| !k.starts_with("/leaves"))
            .map(|(k, v)| {
                let salt = merkle::derive_field_salt(&prk, &k);
                let value_str = format!("{v}");
                let value_commit = merkle::value_commit(&hash_type, &salt, &value_str);
                LeafMeta {
                    path: k,
                    value: value_str,
                    salt,
                    value_commit,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(metas)
}

// ── Audit-template detection ─────────────────────────────────────────────

/// Identifies which of the eight audit-family templates a revision uses.
/// Only `AnyRevision::Typed` revisions can match; Signature/Anchor/Template
/// variants always return `None`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditTemplateKind {
    /// T1 — user turn marker (treat as Full in pseudonymous preset).
    UserTurnMarker,
    /// T2 — user prompt.
    UserPrompt,
    /// T3 — agent thinking.
    AgentThinking,
    /// T4 — agent tool call.
    AgentToolCall,
    /// T5 — Gusto API response.
    GustoApiResponse,
    /// T6 — tool result.
    ToolResult,
    /// T7 — HITL approval.
    HitlApproval,
    /// T8 — agent response.
    AgentResponse,
}

/// Detect which audit template (T1–T8) a revision was created from, if any.
/// Returns `None` for Signature, Anchor, Template revisions and for Typed
/// revisions that do not match any of the eight audit templates.
fn detect_audit_template(rev: &AnyRevision) -> Option<AuditTemplateKind> {
    let obj = match rev {
        AnyRevision::Typed(o) => o,
        _ => return None,
    };
    let rt = obj.revision_type();
    let link = |bytes: [u8; 32]| RevisionLink::from_bytes(bytes);
    if *rt == link(AuditUserTurnMarker::TEMPLATE_LINK) {
        Some(AuditTemplateKind::UserTurnMarker)
    } else if *rt == link(AuditUserPrompt::TEMPLATE_LINK) {
        Some(AuditTemplateKind::UserPrompt)
    } else if *rt == link(AuditAgentThinking::TEMPLATE_LINK) {
        Some(AuditTemplateKind::AgentThinking)
    } else if *rt == link(AuditAgentToolCall::TEMPLATE_LINK) {
        Some(AuditTemplateKind::AgentToolCall)
    } else if *rt == link(AuditGustoApiResponse::TEMPLATE_LINK) {
        Some(AuditTemplateKind::GustoApiResponse)
    } else if *rt == link(AuditToolResult::TEMPLATE_LINK) {
        Some(AuditTemplateKind::ToolResult)
    } else if *rt == link(AuditHitlApproval::TEMPLATE_LINK) {
        Some(AuditTemplateKind::HitlApproval)
    } else if *rt == link(AuditAgentResponse::TEMPLATE_LINK) {
        Some(AuditTemplateKind::AgentResponse)
    } else {
        None
    }
}

/// Enumerate all JSON-Pointer leaf paths present in a revision.
/// Filters out `/leaves` entries (Merkle internals) just as `compute_leaf_metadata` does.
pub(crate) fn enumerate_leaf_paths(rev: &AnyRevision) -> Vec<String> {
    let mut pointers = match jsonpointer_flatten::from(rev) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    pointers.sort_all_objects();
    match pointers {
        serde_json::Value::Object(map) => map
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| !k.starts_with("/leaves"))
            .collect(),
        _ => Vec::new(),
    }
}

/// Returns `true` if `path` matches `/payloads/attached_files/<digits>/hash`.
fn is_attached_file_hash(path: &str) -> bool {
    let rest = match path.strip_prefix("/payloads/attached_files/") {
        Some(r) => r,
        None => return false,
    };
    // rest must be "<digits>/hash"
    let slash = match rest.find('/') {
        Some(i) => i,
        None => return false,
    };
    let index_part = &rest[..slash];
    let tail = &rest[slash + 1..];
    tail == "hash" && !index_part.is_empty() && index_part.chars().all(|c| c.is_ascii_digit())
}

/// Build the list of paths to disclose for a `pseudonymous` preset for the
/// given audit template kind. The caller supplies all actual leaf paths for
/// the revision so that dynamic entries (e.g. per-file attached_files) are
/// handled correctly.
fn pseudonymous_paths_for(kind: AuditTemplateKind, all_paths: &[String]) -> Vec<String> {
    // Fixed path sets per spec §7.6. Paths use the `/payloads/` prefix because
    // `Object` serialises payload fields under the `payloads` key.
    let fixed: &[&str] = match kind {
        // T1 — full; caller skips FieldRedacted for this kind
        AuditTemplateKind::UserTurnMarker => &[],

        // T2: /signer_did, /session_id, /turn_id, /created_at,
        //     + /attached_files/<i>/hash for all i
        AuditTemplateKind::UserPrompt => &[
            "/payloads/signer_did",
            "/payloads/session_id",
            "/payloads/turn_id",
            "/payloads/created_at",
        ],

        // T3: /signer_did, /turn_id, /seq_in_turn, /created_at, /model_name
        AuditTemplateKind::AgentThinking => &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/seq_in_turn",
            "/payloads/created_at",
            "/payloads/model_name",
        ],

        // T4: /signer_did, /turn_id, /tool_name, /risk_level, /created_at
        AuditTemplateKind::AgentToolCall => &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/tool_name",
            "/payloads/risk_level",
            "/payloads/created_at",
        ],

        // T5: /signer_did, /turn_id, /method, /endpoint, /status_code,
        //     /attested_origin, /created_at, /request_hash
        AuditTemplateKind::GustoApiResponse => &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/method",
            "/payloads/endpoint",
            "/payloads/status_code",
            "/payloads/attested_origin",
            "/payloads/created_at",
            "/payloads/request_hash",
        ],

        // T6: /signer_did, /turn_id, /tool_name, /success, /created_at
        AuditTemplateKind::ToolResult => &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/tool_name",
            "/payloads/success",
            "/payloads/created_at",
        ],

        // T7: /signer_did, /turn_id, /decision, /created_at
        AuditTemplateKind::HitlApproval => &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/decision",
            "/payloads/created_at",
        ],

        // T8: /signer_did, /turn_id, /created_at, /is_final, /model_name
        AuditTemplateKind::AgentResponse => &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/created_at",
            "/payloads/is_final",
            "/payloads/model_name",
        ],
    };

    // Start with intersected fixed paths (only those that actually appear).
    let mut result: Vec<String> = fixed
        .iter()
        .filter(|&&p| all_paths.iter().any(|ap| ap == p))
        .map(|p| p.to_string())
        .collect();

    // For T2, additionally disclose /payloads/attached_files/<i>/hash for
    // any attachment index present in the revision.
    if matches!(kind, AuditTemplateKind::UserPrompt) {
        for path in all_paths {
            if is_attached_file_hash(path) {
                result.push(path.clone());
            }
        }
    }

    result
}

// ── DisclosurePolicy preset constructors ─────────────────────────────────

impl DisclosurePolicy {
    /// Preset: **pseudonymous** — redact sensitive content while keeping
    /// structural and metadata fields visible.
    ///
    /// For each revision in `tree`:
    /// - Audit-family T2–T8: `FieldRedacted` with the spec §7.6 disclosed paths.
    /// - Audit T1 (`UserTurnMarker`): `Full` (the marker carries no sensitive content).
    /// - Signatures: `Full` (signature bytes must stay to verify authenticity).
    /// - Anchors: `Full`.
    /// - Non-audit content revisions (service claims, delegation, identity preamble):
    ///   `Full` (pseudonymizing these would break identity-ancestry verification).
    ///
    /// Revisions not mentioned in the returned policy map default to `Full`,
    /// so it is correct to omit non-audit revisions from the map.
    pub fn pseudonymous(tree: &Tree) -> Self {
        let mut revisions = BTreeMap::new();

        for (hash, rev) in &tree.revisions {
            match detect_audit_template(rev) {
                // T1 is treated as Full — no entry needed (default is Full).
                Some(AuditTemplateKind::UserTurnMarker) | None => {}

                Some(kind) => {
                    let all_paths = enumerate_leaf_paths(rev);
                    let disclosed = pseudonymous_paths_for(kind, &all_paths);
                    revisions.insert(hash.clone(), RevisionDisclosure::FieldRedacted(disclosed));
                }
            }
        }

        Self { revisions }
    }

    /// Preset: **full** — every revision is disclosed in its entirety.
    ///
    /// Equivalent to `DisclosurePolicy::default()`. The `tree` parameter is
    /// accepted for API symmetry with `pseudonymous` but is not inspected.
    pub fn full(_tree: &Tree) -> Self {
        Self::default()
    }
}

// ── Derivation-aware closed-world disclosure profiles (PCA-0018) ──────────

/// A per-family disclosure directive within a [`DisclosureProfile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Directive {
    /// Disclose the family's revisions in full.
    Full,
    /// Disclose only payload leaves matching one of these Aqua Pointer Form
    /// patterns. A pattern is an exact pointer, or a pointer with a single `*`
    /// segment matching one all-digits array index, e.g.
    /// `/payloads/attached_files/*/hash`.
    Disclose(Vec<String>),
}

/// A derivation-aware, closed-world disclosure profile (PCA-0018).
///
/// `rules` maps a *family* template-link to its [`Directive`]; `known_full` is a
/// set of template-links disclosed in full. Both are policy inputs only: never
/// part of a revision's verified data, and never serialized into the exported
/// artifact.
#[derive(Clone, Debug, Default)]
pub struct DisclosureProfile {
    pub rules: BTreeMap<RevisionLink, Directive>,
    pub known_full: BTreeSet<RevisionLink>,
}

/// Failure to resolve and hash-verify a template's derivation lineage.
/// Fail-closed: any such failure classifies the Object `Unknown` (redacted),
/// never `Full` (PCA-0018 §2.2, R4).
#[derive(Debug, Clone, PartialEq, Eq)]
enum LineageError {
    /// A template (the object's own, or an ancestor) could not be resolved.
    Unresolved(RevisionLink),
    /// The derivation chain exceeded the protocol depth bound.
    TooDeep,
}

/// Depth bound for a derivation chain (ancestry length <= 3, depth <= 4); a
/// small fixed cap keeps lineage resolution bounded (CCBC) and turns any cycle
/// into a fail-closed `TooDeep`.
const MAX_LINEAGE_DEPTH: usize = 8;

/// Resolve and hash-verify an Object template's derivation lineage from the
/// verified template trees, returning the candidate sequence **nearest-first**:
/// `[self, parent, ..., root]`.
///
/// Walks `derives_from` one step at a time and re-resolves each ancestor
/// template, rather than trusting the template's self-declared `ancestry`
/// array, so a forged or omitted ancestry cannot silently relax classification.
/// Fail-closed: any ancestor that cannot be resolved yields `Err` (the caller
/// classifies the Object `Unknown`).
///
/// Resolution is by hash (built-in cache / verified-tree revisions / verified
/// linked trees), so a successful resolution is a hash match; callers MUST pass
/// only verified trees.
fn resolve_verified_lineage(
    template_link: &RevisionLink,
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
    linked_trees: &[crate::schema::AquaTreeWrapper],
) -> Result<Vec<RevisionLink>, LineageError> {
    let mut chain = Vec::new();
    let mut current = template_link.clone();
    for _ in 0..=MAX_LINEAGE_DEPTH {
        let template =
            crate::core::verify_stages::resolve_template(&current, revisions, linked_trees)
                .ok_or_else(|| LineageError::Unresolved(current.clone()))?;
        chain.push(current.clone());
        match template.derives_from() {
            Some(parent) => current = parent.clone(),
            None => return Ok(chain),
        }
    }
    Err(LineageError::TooDeep)
}

/// Classification of an Object under a [`DisclosureProfile`].
#[derive(Clone, Debug, PartialEq, Eq)]
enum ObjectClass {
    /// Disclose in full (head `Full` directive, or head in `known_full`).
    Full,
    /// Field-redact to the disclose patterns of the nearest family rule.
    Disclose(Vec<String>),
    /// No recognised family / unresolved lineage: redact by default.
    Unknown,
}

/// Classify an Object's template link against a profile (PCA-0018 §2.2).
///
/// Priority: (1) the nearest family `Disclose` in the verified lineage dominates
/// (inherited redaction); (2) a `Full` directive is head-only; (3) `known_full`
/// is head-only; (4) otherwise `Unknown`. Unresolved lineage fails closed to
/// `Unknown`.
fn classify_object(
    template_link: &RevisionLink,
    profile: &DisclosureProfile,
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
    linked_trees: &[crate::schema::AquaTreeWrapper],
) -> ObjectClass {
    let candidates = match resolve_verified_lineage(template_link, revisions, linked_trees) {
        Ok(c) => c,
        Err(_) => return ObjectClass::Unknown, // fail-closed
    };
    // Priority 1: nearest family `Disclose` dominates the whole lineage.
    for c in &candidates {
        if let Some(Directive::Disclose(patterns)) = profile.rules.get(c) {
            return ObjectClass::Disclose(patterns.clone());
        }
    }
    // Priority 2: a `Full` directive is head-only (never propagates to descendants).
    if matches!(profile.rules.get(template_link), Some(Directive::Full)) {
        return ObjectClass::Full;
    }
    // Priority 3: known-full is head-only.
    if profile.known_full.contains(template_link) {
        return ObjectClass::Full;
    }
    ObjectClass::Unknown
}

/// Does `path` match `pattern`? `pattern` is an exact Aqua Pointer Form pointer,
/// or one with a single `*` segment matching an all-digits array index.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == path;
    }
    let mut p = pattern.split('/');
    let mut q = path.split('/');
    loop {
        match (p.next(), q.next()) {
            (Some(ps), Some(qs)) => {
                if ps == "*" {
                    if qs.is_empty() || !qs.chars().all(|c| c.is_ascii_digit()) {
                        return false;
                    }
                } else if ps != qs {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// Expand a family's disclose patterns against a revision's actual leaf paths.
fn expand_disclose(patterns: &[String], leaves: &[String]) -> Vec<String> {
    leaves
        .iter()
        .filter(|leaf| patterns.iter().any(|pat| pattern_matches(pat, leaf)))
        .cloned()
        .collect()
}

/// Push `path` into `out` if it is a present leaf and not already disclosed.
fn push_if_present(out: &mut Vec<String>, path: &str, leaves: &[String]) {
    if leaves.iter().any(|l| l == path) && !out.iter().any(|p| p == path) {
        out.push(path.to_string());
    }
}

impl DisclosurePolicy {
    /// Build a disclosure policy from a derivation-aware closed-world
    /// [`DisclosureProfile`] (PCA-0018).
    ///
    /// Every content Object is classified by its **verified** template lineage
    /// (fail-closed: unresolved lineage redacts). Structural revisions
    /// (Signature/Anchor/Template) stay `Full`. A classified scalar Object can
    /// only be `Hidden`. Each `FieldRedacted` Object force-discloses
    /// `/revision_type` (ND-3); `/previous_revision` is forced by the exporter;
    /// `/nonce` is never disclosed. `linked_trees` supplies the verified
    /// template trees needed to resolve custom (non-built-in) lineages.
    pub fn with_profile(
        tree: &Tree,
        profile: &DisclosureProfile,
        linked_trees: &[crate::schema::AquaTreeWrapper],
    ) -> Self {
        let mut revisions = BTreeMap::new();

        for (hash, rev) in &tree.revisions {
            // Only content Object revisions are classified; structural revisions
            // stay Full (omitted => default Full in the exporter).
            let obj = match rev {
                AnyRevision::Typed(o) => o,
                _ => continue,
            };
            let class =
                classify_object(obj.revision_type(), profile, &tree.revisions, linked_trees);
            if matches!(class, ObjectClass::Full) {
                continue; // default Full; no entry needed
            }
            // A scalar Object cannot be field-redacted (PCA-0004/0005): Hidden.
            if *obj.method() == Method::Scalar {
                revisions.insert(hash.clone(), RevisionDisclosure::Hidden);
                continue;
            }
            let leaves = enumerate_leaf_paths(rev);
            let mut disclosed = match class {
                ObjectClass::Disclose(patterns) => expand_disclose(&patterns, &leaves),
                ObjectClass::Unknown => Vec::new(),
                ObjectClass::Full => unreachable!("Full handled above"),
            };
            // ND-3: force /revision_type so type-walking consumers can resolve
            // the template from the wire (it is a hash, not PII).
            push_if_present(&mut disclosed, "/revision_type", &leaves);
            revisions.insert(hash.clone(), RevisionDisclosure::FieldRedacted(disclosed));
        }

        Self { revisions }
    }
}

impl DisclosureProfile {
    /// Case study (PCA-0018 §6, **non-normative**): the agentic audit-trail
    /// profile. Maps the eight built-in audit families (T1-T8) to their disclose
    /// directives. The concrete template links are bound from the built-in audit
    /// templates and **drift** as those templates evolve.
    pub fn audit() -> Self {
        let link = |bytes: [u8; 32]| RevisionLink::from_bytes(bytes);
        let disclose =
            |paths: &[&str]| Directive::Disclose(paths.iter().map(|s| s.to_string()).collect());
        let mut rules = BTreeMap::new();
        rules.insert(link(AuditUserTurnMarker::TEMPLATE_LINK), Directive::Full);
        rules.insert(
            link(AuditUserPrompt::TEMPLATE_LINK),
            disclose(&[
                "/payloads/signer_did",
                "/payloads/session_id",
                "/payloads/turn_id",
                "/payloads/created_at",
                "/payloads/attached_files/*/hash",
            ]),
        );
        rules.insert(
            link(AuditAgentThinking::TEMPLATE_LINK),
            disclose(&[
                "/payloads/signer_did",
                "/payloads/turn_id",
                "/payloads/seq_in_turn",
                "/payloads/created_at",
                "/payloads/model_name",
            ]),
        );
        rules.insert(
            link(AuditAgentToolCall::TEMPLATE_LINK),
            disclose(&[
                "/payloads/signer_did",
                "/payloads/turn_id",
                "/payloads/tool_name",
                "/payloads/risk_level",
                "/payloads/created_at",
            ]),
        );
        rules.insert(
            link(AuditGustoApiResponse::TEMPLATE_LINK),
            disclose(&[
                "/payloads/signer_did",
                "/payloads/turn_id",
                "/payloads/method",
                "/payloads/endpoint",
                "/payloads/status_code",
                "/payloads/attested_origin",
                "/payloads/created_at",
                "/payloads/request_hash",
            ]),
        );
        rules.insert(
            link(AuditToolResult::TEMPLATE_LINK),
            disclose(&[
                "/payloads/signer_did",
                "/payloads/turn_id",
                "/payloads/tool_name",
                "/payloads/success",
                "/payloads/created_at",
            ]),
        );
        rules.insert(
            link(AuditHitlApproval::TEMPLATE_LINK),
            disclose(&[
                "/payloads/signer_did",
                "/payloads/turn_id",
                "/payloads/decision",
                "/payloads/created_at",
            ]),
        );
        rules.insert(
            link(AuditAgentResponse::TEMPLATE_LINK),
            disclose(&[
                "/payloads/signer_did",
                "/payloads/turn_id",
                "/payloads/created_at",
                "/payloads/is_final",
                "/payloads/model_name",
            ]),
        );
        Self {
            rules,
            known_full: BTreeSet::new(),
        }
    }
}

// ── Public API ───────────────────────────────────────────────────────────

/// Redact a tree-method revision, disclosing only the specified fields.
///
/// # Arguments
/// * `revision` — The full revision to redact.
/// * `revision_hash` — The revision's hash (used in the output).
/// * `disclosed_paths` — JSON Pointer paths to keep visible (e.g., `"/payloads/email"`).
///   All other fields become opaque hashes. The nonce field (`/nonce`) is automatically
///   redacted unless explicitly included in `disclosed_paths`.
///
/// # Errors
/// * `NotTreeMethod` — Revision uses scalar method.
/// * `FieldNotFound` — A requested path doesn't exist in the revision.
pub fn redact_revision(
    revision: &AnyRevision,
    revision_hash: &RevisionLink,
    disclosed_paths: &[String],
) -> Result<RedactedRevision, RedactionError> {
    // Verify tree method
    let method = match revision {
        AnyRevision::Typed(obj) => obj.method(),
        AnyRevision::Template(t) => t.method(),
        AnyRevision::Signature(sig) => sig.method(),
        AnyRevision::Anchor(a) => a.method(),
    };
    if *method != Method::Tree {
        return Err(RedactionError::NotTreeMethod);
    }

    // The revision's algorithm is the code committed by its addressing
    // multihash (PCA-0015 §3.5) — never a stored field.
    let hash_type = revision_hash
        .hash_type()
        .map_err(RedactionError::MalformedRevisionHash)?;
    let metas = compute_leaf_metadata(revision, hash_type)?;

    // Validate all requested paths exist
    for path in disclosed_paths {
        if !metas.iter().any(|m| m.path == *path) {
            return Err(RedactionError::FieldNotFound(path.clone()));
        }
    }

    let leaves: Vec<RedactedLeaf> = metas
        .into_iter()
        .enumerate()
        .map(|(i, meta)| {
            if disclosed_paths.contains(&meta.path) {
                RedactedLeaf::Disclosed {
                    index: i as u32,
                    path: meta.path,
                    value: meta.value,
                    salt: meta.salt,
                }
            } else {
                RedactedLeaf::Redacted {
                    index: i as u32,
                    path: meta.path,
                    value_commit: meta.value_commit,
                }
            }
        })
        .collect();

    Ok(RedactedRevision {
        revision_hash: revision_hash.clone(),
        leaf_count: leaves.len() as u32,
        leaves,
    })
}

/// Verify a redacted revision — reconstruct the Merkle root from disclosed
/// fields and opaque hashes, then compare against the declared revision hash.
///
/// # Errors
/// * `LeafCountMismatch` — Wrong number of leaves provided.
/// * `DuplicateIndex` / `MissingIndex` — Leaf indices not contiguous 0..n.
/// * `MerkleRootMismatch` — Reconstructed root doesn't match declared hash.
pub fn verify_redacted_revision(
    redacted: &RedactedRevision,
) -> Result<(), DisclosureVerificationError> {
    let leaf_count = redacted.leaf_count;
    let provided = redacted.leaves.len() as u32;

    if provided != leaf_count {
        return Err(DisclosureVerificationError::LeafCountMismatch {
            declared: leaf_count,
            provided,
        });
    }

    // Validate contiguous indices 0..leaf_count
    let mut seen = vec![false; leaf_count as usize];
    for leaf in &redacted.leaves {
        let idx = leaf.index() as usize;
        if idx >= leaf_count as usize {
            return Err(DisclosureVerificationError::MissingIndex(leaf.index()));
        }
        if seen[idx] {
            return Err(DisclosureVerificationError::DuplicateIndex(leaf.index()));
        }
        seen[idx] = true;
    }
    for (i, &s) in seen.iter().enumerate() {
        if !s {
            return Err(DisclosureVerificationError::MissingIndex(i as u32));
        }
    }

    // Recover the algorithm from the declared addressing multihash (§3.5).
    let hash_type = redacted
        .revision_hash
        .hash_type()
        .map_err(DisclosureVerificationError::MalformedRevisionHash)?;

    // Reconstruct leaf hashes in index order (AD-20: path is authenticated).
    let mut leaf_hashes: Vec<(u32, Vec<u8>)> = redacted
        .leaves
        .iter()
        .map(|leaf| {
            let hash = match leaf {
                RedactedLeaf::Disclosed {
                    path, value, salt, ..
                } => merkle::leaf_hash(&hash_type, salt, path, value),
                RedactedLeaf::Redacted {
                    path, value_commit, ..
                } => {
                    let label = merkle::label_commit(&hash_type, path);
                    merkle::leaf_hash_from_commits(&hash_type, &label, value_commit)
                }
            };
            (leaf.index(), hash)
        })
        .collect();
    leaf_hashes.sort_by_key(|(idx, _)| *idx);
    let ordered_hashes: Vec<Vec<u8>> = leaf_hashes.into_iter().map(|(_, h)| h).collect();

    // Rebuild Merkle tree; the addressing link is the multihash of the root (§3.5).
    let computed_root = merkle::merkle_root(&ordered_hashes, &hash_type);
    let computed_link = RevisionLink::new(multihash_encode(hash_type, &computed_root));

    if computed_link != redacted.revision_hash {
        return Err(DisclosureVerificationError::MerkleRootMismatch {
            expected: redacted.revision_hash.to_string(),
            computed: computed_link.to_string(),
        });
    }

    Ok(())
}

// ── L2: Revision-level selective disclosure ──────────────────────────────

/// Disclosure policy for a single revision.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum RevisionDisclosure {
    /// Include the full revision as-is.
    Full,
    /// Field-redact: disclose only the listed JSON Pointer paths.
    /// Only valid for tree-method revisions.
    FieldRedacted(Vec<String>),
    /// Completely hide — for signatures/anchors this means omission;
    /// for content revisions, disclose only `/previous_revision` for chain linkage.
    Hidden,
}

/// Disclosure policy for a whole tree.
///
/// Revisions not mentioned in the policy default to `Full` (fully disclosed).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DisclosurePolicy {
    pub revisions: BTreeMap<RevisionLink, RevisionDisclosure>,
}

/// An entry in a `SelectiveTree` — one of three forms.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "disclosure")]
pub enum SelectiveRevision {
    /// Fully disclosed revision.
    Full { revision: AnyRevision },
    /// Field-level redacted revision (tree-method only).
    Redacted { redacted: RedactedRevision },
    /// Chain-linked placeholder — only the revision hash is present.
    /// Verifiers trust chain continuity but learn nothing about content.
    Hidden,
}

/// A tree exported with a selective disclosure policy applied.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SelectiveTree {
    pub revisions: BTreeMap<RevisionLink, SelectiveRevision>,
    pub file_index: BTreeMap<RevisionLink, String>,
}

#[derive(thiserror::Error, Debug)]
pub enum ExportError {
    #[error(transparent)]
    Redaction(#[from] RedactionError),
    #[error("Revision {0} not found in tree")]
    RevisionNotFound(String),
    #[error("Cannot field-redact scalar-method revision {0} — use Hidden instead")]
    ScalarFieldRedact(String),
}

#[derive(thiserror::Error, Debug)]
pub enum SelectiveVerificationError {
    #[error("Disclosed revision hash mismatch for {hash}: {source}")]
    HashMismatch {
        hash: String,
        source: crate::primitives::MethodError,
    },
    #[error("Redacted revision verification failed for {hash}: {source}")]
    RedactionFailed {
        hash: String,
        source: DisclosureVerificationError,
    },
    #[error(
        "Chain break: revision {child} references {parent} which is not in the selective tree"
    )]
    ChainBreak { child: String, parent: String },
}

/// Export a tree applying a disclosure policy.
///
/// # Arguments
/// * `tree` — The full tree.
/// * `policy` — Per-revision disclosure rules. Revisions not in the policy
///   default to `Full` (fully disclosed).
///
/// # Behavior
/// * `Full` — Revision included as-is.
/// * `FieldRedacted(paths)` — Tree-method revision field-redacted to `paths`.
///   The `/previous_revision` path is always disclosed for chain linkage.
/// * `Hidden` — Signatures/anchors are omitted entirely. Content revisions
///   (Object/Template) become chain-linked placeholders with only the hash.
pub fn export_selective_tree(
    tree: &Tree,
    policy: &DisclosurePolicy,
) -> Result<SelectiveTree, ExportError> {
    let mut selective_revisions = BTreeMap::new();
    let mut selective_file_index = BTreeMap::new();

    for (hash, revision) in &tree.revisions {
        let disclosure = policy
            .revisions
            .get(hash)
            .cloned()
            .unwrap_or(RevisionDisclosure::Full);

        match disclosure {
            RevisionDisclosure::Full => {
                selective_revisions.insert(
                    hash.clone(),
                    SelectiveRevision::Full {
                        revision: revision.clone(),
                    },
                );
                // Preserve file_index for fully disclosed revisions
                if let Some(filename) = tree.file_index.get(hash) {
                    selective_file_index.insert(hash.clone(), filename.clone());
                }
            }
            RevisionDisclosure::FieldRedacted(paths) => {
                // Ensure /previous_revision is always disclosed for chain linkage,
                // but only if the field exists (genesis revisions omit it).
                let mut all_paths = paths;
                let prev_path = "/previous_revision".to_string();
                if !all_paths.contains(&prev_path)
                    && revision.get_previous_revision_hash().is_some()
                {
                    all_paths.push(prev_path);
                }
                let redacted = redact_revision(revision, hash, &all_paths)?;
                selective_revisions.insert(hash.clone(), SelectiveRevision::Redacted { redacted });
            }
            RevisionDisclosure::Hidden => {
                // Signatures/anchors: omit entirely (dead-end branches)
                // Content revisions: include as hidden placeholder
                match revision {
                    AnyRevision::Signature(_) | AnyRevision::Anchor(_) => {
                        // Omit — not inserted into selective_revisions
                    }
                    AnyRevision::Typed(_) | AnyRevision::Template(_) => {
                        selective_revisions.insert(hash.clone(), SelectiveRevision::Hidden);
                    }
                }
            }
        }
    }

    Ok(SelectiveTree {
        revisions: selective_revisions,
        file_index: selective_file_index,
    })
}

/// Verify a selective tree — check disclosed revision hashes, verify redacted
/// Merkle proofs, and confirm chain linkage is unbroken.
///
/// Hidden revisions are trusted for chain continuity (their hash is present
/// as a key but their content is unknown).
pub fn verify_selective_tree(selective: &SelectiveTree) -> Result<(), SelectiveVerificationError> {
    for (hash, entry) in &selective.revisions {
        match entry {
            SelectiveRevision::Full { revision } => {
                // The algorithm is the code committed by the addressing multihash (§3.5).
                let hash_type =
                    hash.hash_type()
                        .map_err(|e| SelectiveVerificationError::HashMismatch {
                            hash: hash.to_string(),
                            source: crate::primitives::MethodError::Simple(format!(
                                "malformed revision hash: {e}"
                            )),
                        })?;
                // Verify hash matches computed hash
                let computed = revision.global_calculate_hash(hash_type).map_err(|e| {
                    SelectiveVerificationError::HashMismatch {
                        hash: hash.to_string(),
                        source: e,
                    }
                })?;
                if computed != *hash {
                    return Err(SelectiveVerificationError::HashMismatch {
                        hash: hash.to_string(),
                        source: crate::primitives::MethodError::Simple(format!(
                            "declared {hash} but computed {computed}"
                        )),
                    });
                }

                // Verify chain linkage
                if let Some(prev) = revision.get_previous_revision_hash() {
                    if !selective.revisions.contains_key(&prev) {
                        return Err(SelectiveVerificationError::ChainBreak {
                            child: hash.to_string(),
                            parent: prev.to_string(),
                        });
                    }
                }
            }
            SelectiveRevision::Redacted { redacted } => {
                // Verify Merkle proof
                verify_redacted_revision(redacted).map_err(|e| {
                    SelectiveVerificationError::RedactionFailed {
                        hash: hash.to_string(),
                        source: e,
                    }
                })?;

                // Check chain linkage from disclosed /previous_revision
                let prev_leaf = redacted.leaves.iter().find(|l| {
                    matches!(l, RedactedLeaf::Disclosed { path, .. } if path == "/previous_revision")
                });
                if let Some(RedactedLeaf::Disclosed { value, .. }) = prev_leaf {
                    // Value is a JSON-serialized string like "\"0xabcd...\""
                    // or "null" for genesis
                    if value != "null" {
                        let prev_str = value.trim_matches('"');
                        if let Ok(prev_link) = prev_str.parse::<RevisionLink>() {
                            if !selective.revisions.contains_key(&prev_link) {
                                return Err(SelectiveVerificationError::ChainBreak {
                                    child: hash.to_string(),
                                    parent: prev_link.to_string(),
                                });
                            }
                        }
                    }
                }
            }
            SelectiveRevision::Hidden => {
                // Nothing to verify — chain linkage trusted by presence of hash
            }
        }
    }

    Ok(())
}

// ── Hex serialization helper ─────────────────────────────────────────────

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let stripped = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(stripped).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::genesis::create_genesis_revision;
    use crate::primitives::Method;
    use crate::schema::FileData;
    use std::path::PathBuf;

    /// Helper: create a tree-method genesis revision and return (hash, revision).
    fn make_tree_revision() -> (RevisionLink, AnyRevision) {
        let file_data = FileData::new(
            "test.txt".to_string(),
            b"hello world".to_vec(),
            PathBuf::new(),
        );
        let tree = create_genesis_revision(file_data, Method::Tree).unwrap();
        let (hash, rev) = tree.get_content_tip().unwrap();
        (hash, rev.clone())
    }

    /// Helper: create a scalar-method genesis revision.
    fn make_scalar_revision() -> (RevisionLink, AnyRevision) {
        let file_data = FileData::new(
            "test.txt".to_string(),
            b"hello world".to_vec(),
            PathBuf::new(),
        );
        let tree = create_genesis_revision(file_data, Method::Scalar).unwrap();
        let (hash, rev) = tree.get_content_tip().unwrap();
        (hash, rev.clone())
    }

    #[test]
    fn test_redact_and_verify_roundtrip() {
        let (hash, rev) = make_tree_revision();

        // Disclose only version and method
        let redacted = redact_revision(
            &rev,
            &hash,
            &["/version".to_string(), "/method".to_string()],
        )
        .unwrap();

        assert_eq!(redacted.revision_hash, hash);
        assert!(redacted.leaf_count > 0);

        // Count disclosed vs redacted
        let disclosed_count = redacted
            .leaves
            .iter()
            .filter(|l| matches!(l, RedactedLeaf::Disclosed { .. }))
            .count();
        let redacted_count = redacted
            .leaves
            .iter()
            .filter(|l| matches!(l, RedactedLeaf::Redacted { .. }))
            .count();
        assert_eq!(disclosed_count, 2);
        assert_eq!(redacted_count, redacted.leaf_count as usize - 2);

        // Verify succeeds
        verify_redacted_revision(&redacted).unwrap();
    }

    #[test]
    fn test_redact_all_fields_disclosed() {
        let (hash, rev) = make_tree_revision();

        // Get all leaf paths by computing metadata
        let metas = compute_leaf_metadata(&rev, HashType::Sha3_256).unwrap();
        let all_paths: Vec<String> = metas.iter().map(|m| m.path.clone()).collect();

        let redacted = redact_revision(&rev, &hash, &all_paths).unwrap();

        // All leaves should be Disclosed
        assert!(redacted
            .leaves
            .iter()
            .all(|l| matches!(l, RedactedLeaf::Disclosed { .. })));

        verify_redacted_revision(&redacted).unwrap();
    }

    #[test]
    fn test_redact_no_fields_disclosed() {
        let (hash, rev) = make_tree_revision();

        // Disclose nothing — all fields redacted
        let redacted = redact_revision(&rev, &hash, &[]).unwrap();

        // All leaves should be Redacted
        assert!(redacted
            .leaves
            .iter()
            .all(|l| matches!(l, RedactedLeaf::Redacted { .. })));

        verify_redacted_revision(&redacted).unwrap();
    }

    #[test]
    fn test_redact_scalar_method_rejected() {
        let (hash, rev) = make_scalar_revision();
        let err = redact_revision(&rev, &hash, &[]).unwrap_err();
        assert!(matches!(err, RedactionError::NotTreeMethod));
    }

    #[test]
    fn test_redact_nonexistent_field_rejected() {
        let (hash, rev) = make_tree_revision();
        let err = redact_revision(&rev, &hash, &["/nonexistent/field".to_string()]).unwrap_err();
        assert!(matches!(err, RedactionError::FieldNotFound(_)));
    }

    #[test]
    fn test_tampered_disclosed_value_detected() {
        let (hash, rev) = make_tree_revision();
        let mut redacted = redact_revision(&rev, &hash, &["/version".to_string()]).unwrap();

        // Tamper with a disclosed value
        for leaf in &mut redacted.leaves {
            if let RedactedLeaf::Disclosed { value, .. } = leaf {
                *value = "\"tampered\"".to_string();
                break;
            }
        }

        let err = verify_redacted_revision(&redacted).unwrap_err();
        assert!(matches!(
            err,
            DisclosureVerificationError::MerkleRootMismatch { .. }
        ));
    }

    #[test]
    fn test_tampered_salt_detected() {
        let (hash, rev) = make_tree_revision();
        let mut redacted = redact_revision(&rev, &hash, &["/version".to_string()]).unwrap();

        // Tamper with a disclosed salt
        for leaf in &mut redacted.leaves {
            if let RedactedLeaf::Disclosed { salt, .. } = leaf {
                salt[0] ^= 0xff;
                break;
            }
        }

        let err = verify_redacted_revision(&redacted).unwrap_err();
        assert!(matches!(
            err,
            DisclosureVerificationError::MerkleRootMismatch { .. }
        ));
    }

    #[test]
    fn test_tampered_redacted_value_commit_detected() {
        let (hash, rev) = make_tree_revision();
        let mut redacted = redact_revision(&rev, &hash, &["/version".to_string()]).unwrap();

        // Tamper with a redacted value_commit
        for leaf in &mut redacted.leaves {
            if let RedactedLeaf::Redacted { value_commit, .. } = leaf {
                value_commit[0] ^= 0xff;
                break;
            }
        }

        let err = verify_redacted_revision(&redacted).unwrap_err();
        assert!(matches!(
            err,
            DisclosureVerificationError::MerkleRootMismatch { .. }
        ));
    }

    /// AD-20: relabeling a Redacted leaf's path must break root reconstruction.
    /// Present a Redacted `/previous_revision` leaf under a fake `/payloads/...`
    /// path while keeping value_commit fixed: the reconstructed root must fail.
    #[test]
    fn test_relabel_redacted_path_fails() {
        let (hash, rev) = make_tree_revision();
        // Disclose nothing structural that would force previous_revision open;
        // redact everything except a non-structural field so previous_revision
        // (if present) or another leaf stays Redacted.
        let mut redacted = redact_revision(&rev, &hash, &["/version".to_string()]).unwrap();

        // Find a Redacted leaf and relabel its path to a schema-legal looking
        // payload path without changing value_commit.
        let mut relabeled = false;
        for leaf in &mut redacted.leaves {
            if let RedactedLeaf::Redacted { path, .. } = leaf {
                let original = path.clone();
                *path = "/payloads/forged_field".to_string();
                assert_ne!(original, *path, "test setup must change the path");
                relabeled = true;
                break;
            }
        }
        assert!(relabeled, "expected at least one Redacted leaf to relabel");

        let err = verify_redacted_revision(&redacted).unwrap_err();
        assert!(
            matches!(err, DisclosureVerificationError::MerkleRootMismatch { .. }),
            "path relabel must fail root reconstruction (AD-20), got {err:?}"
        );
    }

    #[test]
    fn test_leaf_count_mismatch_detected() {
        let (hash, rev) = make_tree_revision();
        let mut redacted = redact_revision(&rev, &hash, &[]).unwrap();

        // Lie about leaf count
        redacted.leaf_count += 1;

        let err = verify_redacted_revision(&redacted).unwrap_err();
        assert!(matches!(
            err,
            DisclosureVerificationError::LeafCountMismatch { .. }
        ));
    }

    #[test]
    fn test_duplicate_index_detected() {
        let (hash, rev) = make_tree_revision();
        let mut redacted = redact_revision(&rev, &hash, &[]).unwrap();

        // Duplicate first leaf's index on second leaf
        if redacted.leaves.len() >= 2 {
            let first_idx = redacted.leaves[0].index();
            match &mut redacted.leaves[1] {
                RedactedLeaf::Redacted { index, .. } => *index = first_idx,
                RedactedLeaf::Disclosed { index, .. } => *index = first_idx,
            }

            let err = verify_redacted_revision(&redacted).unwrap_err();
            assert!(
                matches!(err, DisclosureVerificationError::DuplicateIndex(_))
                    || matches!(err, DisclosureVerificationError::MissingIndex(_))
            );
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (hash, rev) = make_tree_revision();
        let redacted = redact_revision(&rev, &hash, &["/version".to_string()]).unwrap();

        let json = serde_json::to_string_pretty(&redacted).unwrap();
        let deserialized: RedactedRevision = serde_json::from_str(&json).unwrap();

        assert_eq!(redacted, deserialized);
        verify_redacted_revision(&deserialized).unwrap();
    }

    #[test]
    fn test_nonce_redacted_by_default() {
        let (hash, rev) = make_tree_revision();

        // Disclose version but NOT nonce
        let redacted = redact_revision(&rev, &hash, &["/version".to_string()]).unwrap();

        // Nonce should be in the redacted set (not disclosed)
        let nonce_leaf = redacted
            .leaves
            .iter()
            .find(|l| matches!(l, RedactedLeaf::Disclosed { path, .. } if path == "/nonce"));
        assert!(nonce_leaf.is_none(), "nonce should be redacted by default");

        verify_redacted_revision(&redacted).unwrap();
    }

    #[test]
    fn test_nonce_can_be_explicitly_disclosed() {
        let (hash, rev) = make_tree_revision();

        let redacted =
            redact_revision(&rev, &hash, &["/nonce".to_string(), "/version".to_string()]).unwrap();

        let nonce_leaf = redacted
            .leaves
            .iter()
            .find(|l| matches!(l, RedactedLeaf::Disclosed { path, .. } if path == "/nonce"));
        assert!(
            nonce_leaf.is_some(),
            "nonce should be disclosed when explicitly requested"
        );

        verify_redacted_revision(&redacted).unwrap();
    }

    // ── L2 tests ─────────────────────────────────────────────────────────

    use crate::core::signature::sign_aqua_tree_with_signer;
    use crate::schema::tree::Tree;
    use crate::schema::AquaTreeWrapper;

    /// Helper: create a tree with genesis + signature for L2 tests.
    fn make_signed_tree() -> Tree {
        let file_data = FileData::new(
            "test.txt".to_string(),
            b"hello world".to_vec(),
            PathBuf::new(),
        );
        let tree = create_genesis_revision(file_data, Method::Tree).unwrap();

        let secret_key: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let signer = crate::Ed25519Signer::new(secret_key.to_vec());
        let wrapper = AquaTreeWrapper::new(tree, None, None);

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(sign_aqua_tree_with_signer(
                &wrapper,
                &signer,
                Method::Tree,
                None,
            ))
            .unwrap();
        result.aqua_tree
    }

    #[test]
    fn test_export_selective_tree_all_full() {
        let tree = make_signed_tree();
        let policy = DisclosurePolicy::default(); // all default to Full
        let selective = export_selective_tree(&tree, &policy).unwrap();

        // All revisions should be present and Full
        assert_eq!(selective.revisions.len(), tree.revisions.len());
        for (_, entry) in &selective.revisions {
            assert!(matches!(entry, SelectiveRevision::Full { .. }));
        }

        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn test_export_selective_tree_hidden_signature() {
        let tree = make_signed_tree();

        // Find the signature revision
        let sig_hash = tree
            .revisions
            .iter()
            .find(|(_, rev)| matches!(rev, AnyRevision::Signature(_)))
            .map(|(h, _)| h.clone())
            .unwrap();

        let mut policy = DisclosurePolicy::default();
        policy
            .revisions
            .insert(sig_hash.clone(), RevisionDisclosure::Hidden);

        let selective = export_selective_tree(&tree, &policy).unwrap();

        // Signature should be omitted (dead-end branch)
        assert!(!selective.revisions.contains_key(&sig_hash));
        assert_eq!(selective.revisions.len(), tree.revisions.len() - 1);

        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn test_export_selective_tree_hidden_content() {
        let tree = make_signed_tree();

        // Find the Object revision (not a tip after signing, so use iter)
        let (obj_hash, _) = tree
            .revisions
            .iter()
            .find(|(_, rev)| matches!(rev, AnyRevision::Typed(_)))
            .map(|(h, r)| (h.clone(), r.clone()))
            .unwrap();

        let mut policy = DisclosurePolicy::default();
        policy
            .revisions
            .insert(obj_hash.clone(), RevisionDisclosure::Hidden);

        let selective = export_selective_tree(&tree, &policy).unwrap();

        // Content revision should be present but Hidden
        assert!(matches!(
            selective.revisions.get(&obj_hash),
            Some(SelectiveRevision::Hidden)
        ));

        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn test_export_selective_tree_field_redacted() {
        let tree = make_signed_tree();
        // Find the Object revision (Tree method) — genesis is now an Anchor
        let (obj_hash, obj_rev) = tree
            .revisions
            .iter()
            .find(|(_, rev)| matches!(rev, AnyRevision::Typed(_)))
            .map(|(h, r)| (h.clone(), r.clone()))
            .unwrap();

        let mut policy = DisclosurePolicy::default();
        policy.revisions.insert(
            obj_hash.clone(),
            RevisionDisclosure::FieldRedacted(vec!["/version".to_string()]),
        );

        let selective = export_selective_tree(&tree, &policy).unwrap();

        // Object should be Redacted
        match selective.revisions.get(&obj_hash) {
            Some(SelectiveRevision::Redacted { redacted }) => {
                let disclosed_paths: Vec<&str> = redacted
                    .leaves
                    .iter()
                    .filter_map(|l| match l {
                        RedactedLeaf::Disclosed { path, .. } => Some(path.as_str()),
                        _ => None,
                    })
                    .collect();
                assert!(disclosed_paths.contains(&"/version"));
                // Content object has /previous_revision (chained to anchor)
                if obj_rev.get_previous_revision_hash().is_some() {
                    assert!(disclosed_paths.contains(&"/previous_revision"));
                }
            }
            other => panic!("Expected Redacted, got {:?}", other),
        }

        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn test_export_scalar_field_redact_rejected() {
        let file_data = FileData::new("test.txt".to_string(), b"hello".to_vec(), PathBuf::new());
        let tree = create_genesis_revision(file_data, Method::Scalar).unwrap();
        // Use content tip (Scalar Object) — genesis is now an Anchor (also Scalar)
        let (obj_hash, _) = tree.get_content_tip().unwrap();

        let mut policy = DisclosurePolicy::default();
        policy.revisions.insert(
            obj_hash.clone(),
            RevisionDisclosure::FieldRedacted(vec!["/version".to_string()]),
        );

        let err = export_selective_tree(&tree, &policy).unwrap_err();
        assert!(matches!(
            err,
            ExportError::Redaction(RedactionError::NotTreeMethod)
        ));
    }

    #[test]
    fn test_selective_tree_serialization_roundtrip() {
        let tree = make_signed_tree();
        // Find the Object revision (Tree method, supports field redaction)
        let obj_hash = tree
            .revisions
            .iter()
            .find(|(_, rev)| matches!(rev, AnyRevision::Typed(_)))
            .map(|(h, _)| h.clone())
            .unwrap();

        let sig_hash = tree
            .revisions
            .iter()
            .find(|(_, rev)| matches!(rev, AnyRevision::Signature(_)))
            .map(|(h, _)| h.clone())
            .unwrap();

        let mut policy = DisclosurePolicy::default();
        policy.revisions.insert(
            obj_hash.clone(),
            RevisionDisclosure::FieldRedacted(vec!["/version".to_string()]),
        );
        policy
            .revisions
            .insert(sig_hash, RevisionDisclosure::Hidden);

        let selective = export_selective_tree(&tree, &policy).unwrap();
        let json = serde_json::to_string_pretty(&selective).unwrap();
        let deserialized: SelectiveTree = serde_json::from_str(&json).unwrap();

        // Verify the deserialized version
        verify_selective_tree(&deserialized).unwrap();
    }

    #[test]
    fn test_verify_detects_tampered_full_revision() {
        let tree = make_signed_tree();
        let selective = export_selective_tree(&tree, &DisclosurePolicy::default()).unwrap();

        // Tamper by replacing a revision hash with a wrong one
        let mut tampered = selective;
        if let Some((hash, entry)) = tampered.revisions.iter().next() {
            if let SelectiveRevision::Full { revision: _ } = entry {
                // Create a new entry with wrong content by using a different revision
                let wrong_revision = AnyRevision::Typed(crate::schema::Object::genesis(
                    RevisionLink::new(vec![0u8; 32]),
                    Method::Tree,
                    serde_json::Value::Null,
                ));
                let hash = hash.clone();
                tampered.revisions.insert(
                    hash,
                    SelectiveRevision::Full {
                        revision: wrong_revision,
                    },
                );
            }
        }

        let err = verify_selective_tree(&tampered).unwrap_err();
        assert!(matches!(
            err,
            SelectiveVerificationError::HashMismatch { .. }
        ));
    }

    // ── Preset tests ──────────────────────────────────────────────────────

    use crate::primitives::HashType;
    use crate::schema::templates::{
        AttachedFile, AuditAgentResponse, AuditAgentThinking, AuditAgentToolCall,
        AuditGustoApiResponse, AuditHitlApproval, AuditToolResult, AuditUserPrompt,
        AuditUserTurnMarker, HitlDecision,
    };

    /// Build a single-revision Tree containing an `Object` with the given
    /// payload typed by template `T`.  Returns `(Tree, RevisionLink)`.
    fn make_audit_tree<T>(payload: T) -> (Tree, RevisionLink)
    where
        T: crate::schema::template::BuiltInTemplate + serde::Serialize,
    {
        let obj = T::to_genesis(payload, Method::Tree);
        let any_rev = AnyRevision::Typed(obj.genericize().unwrap());
        let hash = any_rev.global_calculate_hash(HashType::Sha3_256).unwrap();
        let mut tree = Tree {
            revisions: BTreeMap::new(),
            file_index: BTreeMap::new(),
        };
        tree.revisions.insert(hash.clone(), any_rev);
        (tree, hash)
    }

    /// Collect disclosed path strings from a SelectiveRevision::Redacted entry.
    fn disclosed_paths_in(selective: &SelectiveTree, hash: &RevisionLink) -> Vec<String> {
        match selective.revisions.get(hash) {
            Some(SelectiveRevision::Redacted { redacted }) => redacted
                .leaves
                .iter()
                .filter_map(|l| match l {
                    RedactedLeaf::Disclosed { path, .. } => Some(path.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    // ── T1: pseudonymous preset treats UserTurnMarker as Full ────────────

    #[test]
    fn pseudonymous_preset_t1_is_full() {
        let payload = AuditUserTurnMarker {
            signer_did: "did:key:z6MkServer".to_string(),
            session_id: "sess-t1".to_string(),
            turn_index: 0,
            opens_at: 1_747_526_400,
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);

        // T1 must NOT appear in the policy map — falls through to Full.
        assert!(
            !policy.revisions.contains_key(&hash),
            "T1 should not be in the policy map (default Full)"
        );

        let selective = export_selective_tree(&tree, &policy).unwrap();
        assert!(matches!(
            selective.revisions.get(&hash),
            Some(SelectiveRevision::Full { .. })
        ));
        verify_selective_tree(&selective).unwrap();
    }

    // ── T2: spec paths per template ──────────────────────────────────────

    #[test]
    fn pseudonymous_preset_matches_spec_t2() {
        let payload = AuditUserPrompt {
            signer_did: "did:key:z6MkUser".to_string(),
            session_id: "sess-t2".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            prompt_text: "secret prompt".to_string(),
            created_at: 1_747_526_401,
            audio_recording_hash: None,
            attached_files: None,
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);
        let selective = export_selective_tree(&tree, &policy).unwrap();

        let disclosed = disclosed_paths_in(&selective, &hash);
        // Must disclose the four spec-mandated metadata paths.
        for expected in &[
            "/payloads/signer_did",
            "/payloads/session_id",
            "/payloads/turn_id",
            "/payloads/created_at",
        ] {
            assert!(
                disclosed.iter().any(|p| p == expected),
                "T2 pseudonymous should disclose {expected}, got {disclosed:?}"
            );
        }
        // Must NOT disclose prompt_text.
        assert!(
            !disclosed.iter().any(|p| p == "/payloads/prompt_text"),
            "T2 pseudonymous must redact prompt_text"
        );

        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn pseudonymous_preset_matches_spec_t3() {
        let payload = AuditAgentThinking {
            signer_did: "did:key:z6MkAgent".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 1,
            thinking_text: "secret thinking".to_string(),
            claude_round_id: "round-001".to_string(),
            created_at: 1_747_526_402,
            model_name: Some("claude-opus-4.6".to_string()),
            tokens_used: None,
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);
        let selective = export_selective_tree(&tree, &policy).unwrap();

        let disclosed = disclosed_paths_in(&selective, &hash);
        for expected in &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/seq_in_turn",
            "/payloads/created_at",
            "/payloads/model_name",
        ] {
            assert!(
                disclosed.iter().any(|p| p == expected),
                "T3 should disclose {expected}, got {disclosed:?}"
            );
        }
        assert!(
            !disclosed.iter().any(|p| p == "/payloads/thinking_text"),
            "T3 must redact thinking_text"
        );
        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn pseudonymous_preset_matches_spec_t4() {
        let payload = AuditAgentToolCall {
            signer_did: "did:key:z6MkAgent".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 2,
            tool_name: "gusto.employee.create".to_string(),
            tool_args: serde_json::json!({"secret": "args"}),
            risk_level: "medium".to_string(),
            created_at: 1_747_526_403,
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);
        let selective = export_selective_tree(&tree, &policy).unwrap();

        let disclosed = disclosed_paths_in(&selective, &hash);
        for expected in &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/tool_name",
            "/payloads/risk_level",
            "/payloads/created_at",
        ] {
            assert!(
                disclosed.iter().any(|p| p == expected),
                "T4 should disclose {expected}, got {disclosed:?}"
            );
        }
        // tool_args must be redacted — check no /payloads/tool_args path disclosed
        assert!(
            disclosed
                .iter()
                .all(|p| !p.starts_with("/payloads/tool_args")),
            "T4 must redact tool_args, disclosed: {disclosed:?}"
        );
        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn pseudonymous_preset_matches_spec_t5() {
        let payload = AuditGustoApiResponse {
            signer_did: "did:key:z6MkAttest".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 3,
            method: "POST".to_string(),
            endpoint: "/v1/employees".to_string(),
            status_code: 201,
            request_hash: format!("0x{}", "cd".repeat(32)),
            response_body: serde_json::json!({"secret": "body"}),
            attested_origin: "api.gusto-demo.com".to_string(),
            created_at: 1_747_526_404,
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);
        let selective = export_selective_tree(&tree, &policy).unwrap();

        let disclosed = disclosed_paths_in(&selective, &hash);
        for expected in &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/method",
            "/payloads/endpoint",
            "/payloads/status_code",
            "/payloads/attested_origin",
            "/payloads/created_at",
            "/payloads/request_hash",
        ] {
            assert!(
                disclosed.iter().any(|p| p == expected),
                "T5 should disclose {expected}, got {disclosed:?}"
            );
        }
        assert!(
            disclosed
                .iter()
                .all(|p| !p.starts_with("/payloads/response_body")),
            "T5 must redact response_body"
        );
        verify_selective_tree(&selective).unwrap();
    }

    // ── PCA-0018: derivation-aware closed-world disclosure profiles ──────

    fn t5_payload() -> AuditGustoApiResponse {
        AuditGustoApiResponse {
            signer_did: "did:key:z6MkAttest".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 3,
            method: "POST".to_string(),
            endpoint: "/v1/employees".to_string(),
            status_code: 201,
            request_hash: format!("0x{}", "cd".repeat(32)),
            response_body: serde_json::json!({"secret": "body"}),
            attested_origin: "api.gusto-demo.com".to_string(),
            created_at: 1_747_526_404,
        }
    }

    #[test]
    fn profile_audit_discloses_safe_fields_and_revision_type() {
        let (tree, hash) = make_audit_tree(t5_payload());
        let policy = DisclosurePolicy::with_profile(&tree, &DisclosureProfile::audit(), &[]);
        let selective = export_selective_tree(&tree, &policy).unwrap();
        let disclosed = disclosed_paths_in(&selective, &hash);

        assert!(disclosed.iter().any(|p| p == "/payloads/signer_did"));
        assert!(disclosed.iter().any(|p| p == "/payloads/endpoint"));
        // ND-3: /revision_type force-disclosed for type-walking consumers.
        assert!(
            disclosed.iter().any(|p| p == "/revision_type"),
            "revision_type must be disclosed, got {disclosed:?}"
        );
        // Sensitive body redacted; nonce never disclosed.
        assert!(disclosed
            .iter()
            .all(|p| !p.starts_with("/payloads/response_body")));
        assert!(disclosed.iter().all(|p| p != "/nonce"));
        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn profile_unknown_template_redacted_closed_world() {
        // The T5 object, under an EMPTY profile, is unrecognised => redact by default.
        let (tree, hash) = make_audit_tree(t5_payload());
        let policy = DisclosurePolicy::with_profile(&tree, &DisclosureProfile::default(), &[]);
        let selective = export_selective_tree(&tree, &policy).unwrap();
        let disclosed = disclosed_paths_in(&selective, &hash);

        // Closed-world: only /revision_type disclosed (genesis => no /previous_revision).
        assert_eq!(
            disclosed,
            vec!["/revision_type".to_string()],
            "unknown template must disclose only revision_type, got {disclosed:?}"
        );
        assert!(disclosed.iter().all(|p| !p.starts_with("/payloads/")));
        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn profile_known_full_head_only_discloses_full() {
        let (tree, hash) = make_audit_tree(t5_payload());
        let mut profile = DisclosureProfile::default();
        profile.known_full.insert(RevisionLink::from_bytes(
            AuditGustoApiResponse::TEMPLATE_LINK,
        ));
        let policy = DisclosurePolicy::with_profile(&tree, &profile, &[]);
        let selective = export_selective_tree(&tree, &policy).unwrap();
        match selective.revisions.get(&hash) {
            Some(SelectiveRevision::Full { .. }) => {}
            other => panic!("known_full head must disclose Full, got {other:?}"),
        }
    }

    #[test]
    fn fail_closed_unresolvable_lineage_errors() {
        // A template link present nowhere (not built-in, no tree, no linked) fails closed.
        let bogus = RevisionLink::from_bytes([0x42u8; 32]);
        let empty: BTreeMap<RevisionLink, AnyRevision> = BTreeMap::new();
        let result = resolve_verified_lineage(&bogus, &empty, &[]);
        assert!(
            matches!(result, Err(LineageError::Unresolved(_))),
            "unresolvable lineage must fail closed, got {result:?}"
        );
    }

    #[test]
    fn pattern_matches_index_wildcard_and_exact() {
        assert!(pattern_matches(
            "/payloads/attached_files/*/hash",
            "/payloads/attached_files/0/hash"
        ));
        assert!(pattern_matches(
            "/payloads/attached_files/*/hash",
            "/payloads/attached_files/12/hash"
        ));
        assert!(!pattern_matches(
            "/payloads/attached_files/*/hash",
            "/payloads/attached_files/x/hash"
        ));
        assert!(!pattern_matches(
            "/payloads/attached_files/*/hash",
            "/payloads/attached_files/0/name"
        ));
        assert!(pattern_matches(
            "/payloads/signer_did",
            "/payloads/signer_did"
        ));
        assert!(!pattern_matches("/payloads/signer_did", "/payloads/signer"));
    }

    #[test]
    fn profile_derived_template_inherits_family_rule() {
        // The headline leak: a CUSTOM template that derives from T5
        // (GustoApiResponse) must inherit T5's Disclose rule, not export Full.
        use crate::verification::Linkable;
        let t5_link = RevisionLink::from_bytes(AuditGustoApiResponse::TEMPLATE_LINK);
        let derived = crate::schema::Template::new_derived(
            Method::Tree,
            serde_json::json!({"type": "object"}),
            RevisionLink::from_bytes(crate::schema::templates::TemplateMeta::TEMPLATE_LINK),
            t5_link.clone(),
            vec![t5_link.clone()],
            None,
        );
        let custom_link = derived.calculate_link(HashType::Sha3_256).unwrap();
        let mut revisions: BTreeMap<RevisionLink, AnyRevision> = BTreeMap::new();
        revisions.insert(custom_link.clone(), AnyRevision::Template(derived));

        // Lineage is re-resolved through T5 from the verified trees (not the
        // self-declared ancestry array).
        let chain = resolve_verified_lineage(&custom_link, &revisions, &[]).unwrap();
        assert!(chain.contains(&custom_link));
        assert!(
            chain.contains(&t5_link),
            "verified lineage must reach T5, got {chain:?}"
        );

        // Classification inherits T5's Disclose at a non-head candidate.
        let class = classify_object(&custom_link, &DisclosureProfile::audit(), &revisions, &[]);
        assert!(
            matches!(class, ObjectClass::Disclose(_)),
            "derived template must inherit the T5 Disclose rule, got {class:?}"
        );
    }

    #[test]
    fn pseudonymous_preset_matches_spec_t6() {
        let payload = AuditToolResult {
            signer_did: "did:key:z6MkAgent".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 4,
            tool_name: "gusto.employee.create".to_string(),
            result_payload: serde_json::json!({"secret": "result"}),
            success: true,
            created_at: 1_747_526_405,
            error_message: None,
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);
        let selective = export_selective_tree(&tree, &policy).unwrap();

        let disclosed = disclosed_paths_in(&selective, &hash);
        for expected in &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/tool_name",
            "/payloads/success",
            "/payloads/created_at",
        ] {
            assert!(
                disclosed.iter().any(|p| p == expected),
                "T6 should disclose {expected}, got {disclosed:?}"
            );
        }
        assert!(
            disclosed
                .iter()
                .all(|p| !p.starts_with("/payloads/result_payload")),
            "T6 must redact result_payload"
        );
        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn pseudonymous_preset_matches_spec_t7() {
        let payload = AuditHitlApproval {
            signer_did: "did:key:z6MkUser".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            decision: HitlDecision::Approved,
            prompt_shown: "secret prompt shown".to_string(),
            created_at: 1_747_526_406,
            rationale: None,
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);
        let selective = export_selective_tree(&tree, &policy).unwrap();

        let disclosed = disclosed_paths_in(&selective, &hash);
        for expected in &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/decision",
            "/payloads/created_at",
        ] {
            assert!(
                disclosed.iter().any(|p| p == expected),
                "T7 should disclose {expected}, got {disclosed:?}"
            );
        }
        assert!(
            !disclosed.iter().any(|p| p == "/payloads/prompt_shown"),
            "T7 must redact prompt_shown"
        );
        verify_selective_tree(&selective).unwrap();
    }

    #[test]
    fn pseudonymous_preset_matches_spec_t8() {
        let payload = AuditAgentResponse {
            signer_did: "did:key:z6MkAgent".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            response_text: "secret response".to_string(),
            is_final: true,
            created_at: 1_747_526_407,
            model_name: Some("claude-opus-4.6".to_string()),
            tokens_used: None,
            thinking: Some("secret thinking".to_string()),
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);
        let selective = export_selective_tree(&tree, &policy).unwrap();

        let disclosed = disclosed_paths_in(&selective, &hash);
        for expected in &[
            "/payloads/signer_did",
            "/payloads/turn_id",
            "/payloads/created_at",
            "/payloads/is_final",
            "/payloads/model_name",
        ] {
            assert!(
                disclosed.iter().any(|p| p == expected),
                "T8 should disclose {expected}, got {disclosed:?}"
            );
        }
        assert!(
            !disclosed.iter().any(|p| p == "/payloads/response_text"),
            "T8 must redact response_text"
        );
        assert!(
            !disclosed.iter().any(|p| p == "/payloads/thinking"),
            "T8 must redact thinking"
        );
        verify_selective_tree(&selective).unwrap();
    }

    // ── T2 with two attached files ────────────────────────────────────────

    #[test]
    fn pseudonymous_preset_t2_with_two_attached_files() {
        let payload = AuditUserPrompt {
            signer_did: "did:key:z6MkUser".to_string(),
            session_id: "sess-t2-files".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            prompt_text: "secret prompt".to_string(),
            created_at: 1_747_526_401,
            audio_recording_hash: None,
            attached_files: Some(vec![
                AttachedFile {
                    filename: "form1.pdf".to_string(),
                    hash: format!("0x{}", "11".repeat(32)),
                    size: 1024,
                },
                AttachedFile {
                    filename: "form2.pdf".to_string(),
                    hash: format!("0x{}", "22".repeat(32)),
                    size: 2048,
                },
            ]),
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);
        let selective = export_selective_tree(&tree, &policy).unwrap();

        let disclosed = disclosed_paths_in(&selective, &hash);

        // Both file hashes must be disclosed.
        assert!(
            disclosed
                .iter()
                .any(|p| p == "/payloads/attached_files/0/hash"),
            "must disclose /payloads/attached_files/0/hash, got {disclosed:?}"
        );
        assert!(
            disclosed
                .iter()
                .any(|p| p == "/payloads/attached_files/1/hash"),
            "must disclose /payloads/attached_files/1/hash, got {disclosed:?}"
        );

        // filename and size must be redacted (not in disclosed list).
        assert!(
            !disclosed
                .iter()
                .any(|p| p == "/payloads/attached_files/0/filename"),
            "filename must be redacted"
        );
        assert!(
            !disclosed
                .iter()
                .any(|p| p == "/payloads/attached_files/0/size"),
            "size must be redacted"
        );
        assert!(
            !disclosed.iter().any(|p| p == "/payloads/prompt_text"),
            "prompt_text must be redacted"
        );

        verify_selective_tree(&selective).unwrap();
    }

    // ── full preset ───────────────────────────────────────────────────────

    #[test]
    fn full_preset_discloses_everything() {
        let payload = AuditAgentThinking {
            signer_did: "did:key:z6MkAgent".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 1,
            thinking_text: "visible thinking".to_string(),
            claude_round_id: "round-002".to_string(),
            created_at: 1_747_526_402,
            model_name: None,
            tokens_used: None,
        };
        let (tree, hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::full(&tree);

        // full() must return an empty map (default Full for everything).
        assert!(
            policy.revisions.is_empty(),
            "full() policy must have empty revisions map"
        );

        let selective = export_selective_tree(&tree, &policy).unwrap();
        // The revision must be Full.
        assert!(matches!(
            selective.revisions.get(&hash),
            Some(SelectiveRevision::Full { .. })
        ));
        verify_selective_tree(&selective).unwrap();
    }

    // ── Merkle verification after pseudonymous export ─────────────────────

    #[test]
    fn pseudonymous_preset_passes_verify_selective_tree() {
        // Build a tree with one T5 revision.
        let payload = AuditGustoApiResponse {
            signer_did: "did:key:z6MkAttest".to_string(),
            turn_id: format!("0x{}", "ab".repeat(32)),
            seq_in_turn: 1,
            method: "GET".to_string(),
            endpoint: "/v1/companies".to_string(),
            status_code: 200,
            request_hash: format!("0x{}", "cc".repeat(32)),
            response_body: serde_json::json!({"companies": ["acme"]}),
            attested_origin: "api.gusto-demo.com".to_string(),
            created_at: 1_747_526_404,
        };
        let (tree, _hash) = make_audit_tree(payload);
        let policy = DisclosurePolicy::pseudonymous(&tree);
        let selective = export_selective_tree(&tree, &policy).unwrap();

        // Merkle proofs must reconstruct correctly.
        verify_selective_tree(&selective).unwrap();
    }
}
