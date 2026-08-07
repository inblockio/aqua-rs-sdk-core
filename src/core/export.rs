//! Self-descriptive tree export: embed the templates a tree references.
//!
//! A typed object revision names its type by hash (`revision_type`). A
//! verifier that does not already hold that template cannot check the object,
//! so a tree of a custom or imported type is only meaningful where the
//! receiver happens to have the type declaration. This module closes that gap:
//! [`export_tree_util`] walks every typed revision's template plus the full
//! `derives_from` ancestry chain and embeds each template revision into a
//! clone of the tree, under its canonical full multihash link.
//!
//! Embedding is the portable-template pattern that
//! `docs/template-authoring.md` section 6 describes, applied automatically:
//! template resolution during verification checks the tree's own revisions
//! first, so an exported tree resolves its own types with no linked trees and
//! no built-in catalog entry.
//!
//! Embedding is the **default** ([`ExportOptions::default`]). Callers who
//! deliberately want a bare tree opt out at the export call site.
//!
//! ## Receiver-relative built-ins
//!
//! "Built-in" is a property of the receiver, not of the sender: this crate's
//! audit templates are built-in here and unresolvable in the current full
//! `aqua-rs-sdk`. A self-descriptive export therefore embeds built-in
//! templates too ([`ExportOptions::include_builtin_templates`] defaults to
//! `true`). Set it to `false` only when the receiver is known to share this
//! crate's catalog and the bytes matter.
//!
//! ## Fail closed
//!
//! If any referenced template (or any ancestor of one) cannot be resolved
//! from the tree, the built-in catalog, or the caller-supplied sources, the
//! export fails with [`ExportTreeError::UnresolvedTemplates`] listing the
//! missing hashes. A partially self-descriptive tree would be a tree that
//! claims completeness it does not have. Use [`missing_templates`] to inspect
//! a tree before exporting, or in CI as a lint.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    primitives::{HashType, MethodError, RevisionLink},
    schema::{tree::Tree, AnyRevision, Template},
    verification::Linkable,
};

/// What an export embeds.
///
/// The default is the self-descriptive export: every referenced template and
/// its full ancestry travels inside the tree.
///
/// ```rust,ignore
/// use aqua_rs_sdk_core::{Aquafier, ExportOptions};
///
/// let aquafier = Aquafier::new();
/// // Self-descriptive (default): templates embedded.
/// let portable = aquafier.export_tree(&tree, &[], &ExportOptions::default())?;
/// // Opt out: a plain clone, templates must be resolvable at the receiver.
/// let bare = aquafier.export_tree(&tree, &[], &ExportOptions::bare())?;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportOptions {
    /// Embed referenced template revisions at all. Default `true`.
    ///
    /// `false` is the full opt-out: the export is a plain clone of the input
    /// and objects of non-built-in types only verify where the receiver
    /// already holds the template.
    pub include_templates: bool,
    /// Embed templates that are built into this crate's catalog. Default
    /// `true`, because "built-in" is receiver-relative (see the module docs).
    ///
    /// `false` embeds only the templates that are not built into this crate,
    /// which is the smaller export for a receiver known to run this crate.
    /// Ignored when `include_templates` is `false`.
    pub include_builtin_templates: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            include_templates: true,
            include_builtin_templates: true,
        }
    }
}

impl ExportOptions {
    /// The default: embed every referenced template, built-in or not.
    pub fn self_descriptive() -> Self {
        Self::default()
    }

    /// Embed only templates that are not built into this crate's catalog.
    ///
    /// Smaller output, but the receiver must share this crate's built-in
    /// catalog for the tree to verify.
    pub fn non_builtin_only() -> Self {
        Self {
            include_templates: true,
            include_builtin_templates: false,
        }
    }

    /// Embed nothing: the export is a plain clone of the input tree.
    pub fn bare() -> Self {
        Self {
            include_templates: false,
            include_builtin_templates: false,
        }
    }
}

/// Errors returned by [`export_tree_util`].
#[derive(Debug, thiserror::Error)]
pub enum ExportTreeError {
    /// One or more referenced templates (or their ancestors) could not be
    /// resolved from the tree, the built-in catalog, or the extra sources.
    /// No partial embedding is performed.
    #[error(
        "cannot export a self-descriptive tree: {} referenced template(s) unresolved: {}",
        .0.len(),
        .0.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ")
    )]
    UnresolvedTemplates(Vec<RevisionLink>),
    /// Computing a resolved template's canonical link failed.
    #[error("template link computation failed: {0}")]
    HashError(#[from] MethodError),
}

impl ExportTreeError {
    /// The unresolved template hashes, or an empty slice for other errors.
    pub fn unresolved(&self) -> &[RevisionLink] {
        match self {
            ExportTreeError::UnresolvedTemplates(links) => links,
            _ => &[],
        }
    }
}

/// Every template hash a tree references through its typed object revisions.
///
/// Signature, anchor, and template revisions are deliberately excluded: they
/// dispatch on foundation hash constants rather than on a resolvable template
/// body, exactly as the verification pipeline treats them.
fn referenced_template_links(tree: &Tree) -> BTreeSet<RevisionLink> {
    tree.revisions
        .values()
        .filter_map(|revision| match revision {
            AnyRevision::Typed(obj) => Some(obj.revision_type().clone()),
            _ => None,
        })
        .collect()
}

/// Resolve one template body, in the export resolution order:
/// 1. the tree's own revisions (already embedded templates),
/// 2. this crate's built-in catalog,
/// 3. the caller-supplied extra sources (for example trees from an import
///    store or a template registry client).
fn resolve_template_body(
    link: &RevisionLink,
    tree: &Tree,
    extra_template_sources: &[Tree],
) -> Option<Template> {
    if let Some(AnyRevision::Template(t)) = tree.revisions.get(link) {
        return Some(t.clone());
    }

    if let Some(t) = crate::core::resolve_builtin_template(link) {
        return Some(t);
    }

    for source in extra_template_sources {
        if let Some(AnyRevision::Template(t)) = source.revisions.get(link) {
            return Some(t.clone());
        }
    }

    // Extra sources may key their template revisions differently (a bare
    // 32-byte digest instead of the full multihash, as the internal built-in
    // template trees do). Fall back to matching on the canonical link the
    // template body itself computes, so a correct template body is never
    // rejected over its container's key encoding.
    let wanted = digest_key(link)?;
    for source in extra_template_sources {
        for revision in source.revisions.values() {
            if let AnyRevision::Template(t) = revision {
                let Ok(canonical) = t.calculate_link(HashType::Sha3_256) else {
                    continue;
                };
                if digest_key(&canonical) == Some(wanted) {
                    return Some(t.clone());
                }
            }
        }
    }

    None
}

/// Normalize a template-addressing link to the bare SHA3-256 digest this
/// crate indexes templates by (accepts both the full multihash and the bare
/// digest form).
fn digest_key(link: &RevisionLink) -> Option<[u8; 32]> {
    super::verify_stages::template_digest_key(link.as_ref())
}

/// Walk the template closure of `tree`: every referenced template plus every
/// ancestor in its `derives_from` chain.
///
/// Returns the resolved bodies keyed by the canonical full multihash link,
/// and the links that could not be resolved (in deterministic order).
fn collect_template_closure(
    tree: &Tree,
    extra_template_sources: &[Tree],
) -> Result<(BTreeMap<RevisionLink, Template>, Vec<RevisionLink>), MethodError> {
    let mut resolved: BTreeMap<RevisionLink, Template> = BTreeMap::new();
    let mut missing: BTreeSet<RevisionLink> = BTreeSet::new();
    let mut seen: BTreeSet<RevisionLink> = BTreeSet::new();
    let mut queue: Vec<RevisionLink> = referenced_template_links(tree).into_iter().collect();

    while let Some(link) = queue.pop() {
        if !seen.insert(link.clone()) {
            continue;
        }

        let template = match resolve_template_body(&link, tree, extra_template_sources) {
            Some(t) => t,
            None => {
                // The body is unavailable, so its own ancestry is unknowable.
                // Record the miss and keep walking the rest of the closure so
                // the error lists every gap, not just the first.
                missing.insert(link);
                continue;
            }
        };

        // Ancestry entries are the authoritative chain (root first, last entry
        // equals `derives_from`); `derives_from` is queued as well so a
        // malformed template missing it from `ancestry` still gets its parent
        // embedded rather than silently exported incomplete.
        if let Some(ancestry) = template.ancestry() {
            queue.extend(ancestry.iter().cloned());
        }
        if let Some(parent) = template.derives_from() {
            queue.push(parent.clone());
        }

        // Template ids are always SHA3-256 (PCA-0015 section 3.9). Keying the
        // embedded revision by the canonical link keeps the tree verifiable:
        // Stage 1 recomputes each revision's hash from its own key.
        let canonical = template.calculate_link(HashType::Sha3_256)?;
        resolved.insert(canonical, template);
    }

    Ok((resolved, missing.into_iter().collect()))
}

/// Export a tree as a self-descriptive object: embed the templates it
/// references so it verifies on its own.
///
/// See [`crate::Aquafier::export_tree`] for the public entry point and the
/// module documentation for the semantics (resolution order, receiver-relative
/// built-ins, fail-closed behavior).
///
/// The input tree is never mutated; the result is a clone plus the embedded
/// template revisions. Exporting an already-exported tree is a no-op, so
/// `export(export(t))` serializes byte-for-byte identically to `export(t)`.
pub fn export_tree_util(
    tree: &Tree,
    extra_template_sources: &[Tree],
    options: &ExportOptions,
) -> Result<Tree, ExportTreeError> {
    let mut exported = tree.clone();

    if !options.include_templates {
        return Ok(exported);
    }

    let (resolved, missing) = collect_template_closure(tree, extra_template_sources)?;
    if !missing.is_empty() {
        return Err(ExportTreeError::UnresolvedTemplates(missing));
    }

    for (link, template) in resolved {
        if exported.revisions.contains_key(&link) {
            continue; // already embedded, which keeps the export idempotent
        }
        if !options.include_builtin_templates && crate::core::is_builtin_template_link(&link) {
            continue;
        }

        let name = template_index_name(&link, extra_template_sources);
        exported
            .revisions
            .insert(link.clone(), AnyRevision::Template(template));
        exported.file_index.entry(link).or_insert(name);
    }

    Ok(exported)
}

/// Human-readable `file_index` label for an embedded template: the built-in
/// name when this crate knows it, the name the source tree used otherwise, and
/// a hash-derived fallback last. Labels are organizational metadata only; they
/// are never part of any hash.
fn template_index_name(link: &RevisionLink, extra_template_sources: &[Tree]) -> String {
    if let Some(name) = digest_key(link).and_then(|key| crate::core::builtin_template_name(&key)) {
        return name.to_string();
    }
    for source in extra_template_sources {
        if let Some(name) = source.file_index.get(link) {
            return name.clone();
        }
    }
    format!(
        "template_{}",
        link.to_string().chars().skip(2).take(8).collect::<String>()
    )
}

/// Export lint: the template hashes this tree references that are neither
/// embedded in it nor built into this crate.
///
/// A receiver can call this on an incoming tree to learn exactly which type
/// declarations it must obtain before the tree can verify; a publisher can
/// call it in CI to catch trees that were shipped without their types. An
/// empty result means the tree is self-descriptive for this crate's catalog.
///
/// The walk covers referenced templates and their `derives_from` ancestry,
/// mirroring what verification resolves. Ancestors of an unresolvable
/// template cannot be enumerated (its body is what names them), so a fixed
/// closure may reveal further gaps; rerun the lint after supplying the
/// missing templates.
pub fn missing_templates(tree: &Tree) -> Vec<RevisionLink> {
    match collect_template_closure(tree, &[]) {
        Ok((_, missing)) => missing,
        // A template body that cannot be canonicalized is not a resolvable
        // type declaration either; report the references rather than panic.
        Err(_) => referenced_template_links(tree).into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::template::create_derived_template_util;
    use crate::primitives::Method;
    use crate::schema::template::BuiltInTemplate;
    use crate::schema::templates::{AuditRoundAnchor, AuditUserTurnMarker, TemplateMeta};
    use crate::schema::{AquaTreeWrapper, SigningCredentials};
    use crate::Aquafier;
    use serde_json::json;

    fn test_key() -> Vec<u8> {
        (1..=32).collect()
    }

    /// A template this crate has never seen: a fresh random nonce makes its
    /// hash unique per run, so nothing can resolve it from any catalog.
    fn synthesized_root() -> Template {
        Template::new(
            Method::Scalar,
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "reading": { "type": "number" },
                    "sensor_id": { "type": "string", "maxLength": 64 }
                },
                "required": ["reading", "sensor_id"],
                "additionalProperties": false
            }),
            RevisionLink::from_bytes(TemplateMeta::TEMPLATE_LINK),
        )
    }

    /// Child of [`synthesized_root`], narrowing `reading` to a range. Proves
    /// the export walks the ancestry chain, not just the leaf type.
    fn synthesized_child(parent: &Template) -> Template {
        create_derived_template_util(
            parent,
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "reading": { "type": "number", "minimum": 0, "maximum": 100 },
                    "sensor_id": { "type": "string", "maxLength": 64 }
                },
                "required": ["reading", "sensor_id"],
                "additionalProperties": false
            }),
            None,
            true,
        )
        .expect("child narrows the parent")
    }

    fn template_source_tree(templates: &[&Template]) -> Tree {
        let mut revisions = BTreeMap::new();
        let mut file_index = BTreeMap::new();
        for (i, t) in templates.iter().enumerate() {
            let link = t.calculate_link(HashType::Sha3_256).unwrap();
            revisions.insert(link.clone(), AnyRevision::Template((*t).clone()));
            file_index.insert(link, format!("synthesized_{i}"));
        }
        Tree {
            revisions,
            file_index,
        }
    }

    /// A tree whose object is of a synthesized type, plus the source trees
    /// that can supply the two template bodies.
    fn synthesized_object_tree() -> (Tree, Tree, RevisionLink) {
        let root = synthesized_root();
        let child = synthesized_child(&root);
        let child_link = child.calculate_link(HashType::Sha3_256).unwrap();
        let sources = template_source_tree(&[&root, &child]);
        let tree = Aquafier::new()
            .create_object(
                child_link.clone(),
                None,
                json!({ "reading": 21.5, "sensor_id": "sensor-1" }),
                None,
            )
            .expect("object creation");
        (tree, sources, child_link)
    }

    /// Round trip through the wire format, the way a receiver gets a tree.
    fn wire_round_trip(tree: &Tree) -> Tree {
        serde_json::from_str(&serde_json::to_string(tree).unwrap()).unwrap()
    }

    fn embedded_template_count(tree: &Tree) -> usize {
        tree.revisions
            .values()
            .filter(|r| matches!(r, AnyRevision::Template(_)))
            .count()
    }

    async fn verify_standalone(tree: &Tree) -> bool {
        Aquafier::new()
            .verify_aqua_tree(AquaTreeWrapper::new(tree.clone(), None, None), vec![])
            .await
            .unwrap()
            .is_verified()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn synthesized_type_verifies_after_export_and_wire_round_trip() {
        let (tree, sources, _) = synthesized_object_tree();

        // Control: without the export the type is unresolvable, so a receiver
        // with no linked trees and no catalog entry must reject the tree.
        // Without this control the positive case below would be vacuous.
        assert!(
            !verify_standalone(&wire_round_trip(&tree)).await,
            "un-exported tree of a synthesized type must not verify standalone"
        );

        let exported =
            export_tree_util(&tree, &[sources], &ExportOptions::default()).expect("export");
        assert_eq!(
            embedded_template_count(&exported),
            2,
            "child and its synthesized parent must both be embedded"
        );
        assert!(
            verify_standalone(&wire_round_trip(&exported)).await,
            "exported tree must verify with no linked trees and no extra sources"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn opt_out_returns_a_plain_clone_that_does_not_verify() {
        let (tree, sources, _) = synthesized_object_tree();

        let exported = export_tree_util(&tree, &[sources], &ExportOptions::bare()).expect("export");
        assert_eq!(exported, tree, "opt-out must return a plain clone");
        assert_eq!(embedded_template_count(&exported), 0);
        assert!(
            !verify_standalone(&wire_round_trip(&exported)).await,
            "the opt-out must be real: no templates embedded, so no standalone verification"
        );
    }

    #[test]
    fn export_does_not_mutate_the_input() {
        let (tree, sources, _) = synthesized_object_tree();
        let before = tree.clone();
        let _ = export_tree_util(&tree, &[sources], &ExportOptions::default()).expect("export");
        assert_eq!(tree, before, "export must never mutate its input");
    }

    #[test]
    fn export_is_idempotent_byte_for_byte() {
        let (tree, sources, _) = synthesized_object_tree();
        let once = export_tree_util(&tree, &[sources.clone()], &ExportOptions::default()).unwrap();
        // The second pass gets no extra sources at all: an exported tree must
        // already carry everything the walk needs.
        let twice = export_tree_util(&once, &[], &ExportOptions::default()).unwrap();
        assert_eq!(
            serde_json::to_string(&once).unwrap(),
            serde_json::to_string(&twice).unwrap(),
            "export(export(t)) must serialize identically to export(t)"
        );
    }

    #[test]
    fn unresolvable_template_fails_closed() {
        let (tree, _, child_link) = synthesized_object_tree();
        let err = export_tree_util(&tree, &[], &ExportOptions::default())
            .expect_err("no source can supply the synthesized template");
        assert_eq!(
            err.unresolved().to_vec(),
            vec![child_link.clone()],
            "the error must name the missing template hash"
        );
        assert!(
            format!("{err}").contains(&child_link.to_string()),
            "the message must list the missing hash: {err}"
        );
    }

    #[test]
    fn missing_templates_reports_then_clears() {
        let (tree, sources, child_link) = synthesized_object_tree();
        assert_eq!(
            missing_templates(&tree),
            vec![child_link],
            "the lint must report the unresolvable type"
        );

        let exported = export_tree_util(&tree, &[sources], &ExportOptions::default()).unwrap();
        assert!(
            missing_templates(&exported).is_empty(),
            "an exported tree must be self-descriptive"
        );
    }

    #[test]
    fn missing_templates_is_empty_for_builtin_types() {
        let tree = Aquafier::new()
            .create_object(
                RevisionLink::from_bytes(AuditUserTurnMarker::TEMPLATE_LINK),
                None,
                json!({
                    "signer_did": "did:key:z6MkExampleServer",
                    "session_id": "lint-session",
                    "turn_index": 0,
                    "opens_at": 1754500000u64,
                }),
                None,
            )
            .unwrap();
        assert!(
            missing_templates(&tree).is_empty(),
            "built-in types resolve from the catalog"
        );
    }

    // ── audit family: embedding must not disturb the declared bounds ──────

    async fn signed_turn_marker_tree() -> Tree {
        let aquafier = Aquafier::new();
        let tree = aquafier
            .create_object(
                RevisionLink::from_bytes(AuditUserTurnMarker::TEMPLATE_LINK),
                None,
                json!({
                    "signer_did": "did:key:z6MkExampleServer",
                    "session_id": "export-session",
                    "turn_index": 0,
                    "opens_at": 1754500000u64,
                }),
                None,
            )
            .unwrap();
        aquafier
            .sign_aqua_tree(
                AquaTreeWrapper::new(tree, None, None),
                &SigningCredentials::Did {
                    did_key: test_key(),
                },
                None,
                None,
            )
            .await
            .unwrap()
            .aqua_tree
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn signed_audit_tree_export_stays_within_declared_bounds() {
        use crate::schema::bounds::resolve_bounds;

        let signed = signed_turn_marker_tree().await;
        let exported =
            export_tree_util(&signed, &[], &ExportOptions::default()).expect("built-ins resolve");

        // T1 plus its audit_artifact root, both built-in and both embedded
        // because built-in is receiver-relative.
        assert_eq!(embedded_template_count(&exported), 2);

        let bounds = resolve_bounds(&AuditUserTurnMarker::TEMPLATE_LINK);
        assert_eq!(bounds.max_total_revisions, 16);
        assert!(
            exported.revisions.len() <= bounds.max_total_revisions as usize,
            "embedding must keep the tree within audit_artifact's declared \
             max_total_revisions ({} revisions)",
            exported.revisions.len()
        );
        assert!(
            verify_standalone(&wire_round_trip(&exported)).await,
            "a signed, exported audit tree must verify standalone"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_builtin_only_embeds_the_uncached_template_alone() {
        // audit_round_anchor ships with this crate but is deliberately NOT in
        // the verification catalog, while its audit_artifact root is. The two
        // flags therefore have visibly different outputs on the same tree.
        let template: Template = serde_json::from_str(AuditRoundAnchor::TEMPLATE_JSON).unwrap();
        let link = template.calculate_link(HashType::Sha3_256).unwrap();
        let source = template_source_tree(&[&template]);

        let payload = json!({
            "signer_did": "did:key:z6MkExampleServer",
            "session_id": "export-session",
            "turn_id": format!("0x1620{}", "a".repeat(64)),
            "turn_index": 0,
            "artifact_count": 1,
            "leaf_hashes": [format!("0x1620{}", "b".repeat(64))],
            "merkle_root": format!("0x{}", "c".repeat(64)),
            "closed_at": 1754500008u64,
        });
        let tree = Aquafier::new()
            .create_object(link, None, payload, None)
            .unwrap();

        let full = export_tree_util(&tree, &[source.clone()], &ExportOptions::default()).unwrap();
        assert_eq!(
            embedded_template_count(&full),
            2,
            "default export embeds the round anchor and its built-in root"
        );
        assert!(verify_standalone(&wire_round_trip(&full)).await);

        let lean = export_tree_util(&tree, &[source], &ExportOptions::non_builtin_only()).unwrap();
        assert_eq!(
            embedded_template_count(&lean),
            1,
            "non-builtin-only export leaves audit_artifact to the receiver's catalog"
        );
        assert!(
            verify_standalone(&wire_round_trip(&lean)).await,
            "this crate is a receiver that holds audit_artifact, so the lean \
             export still verifies here"
        );
    }
}
