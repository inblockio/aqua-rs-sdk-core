use std::collections::BTreeMap;

use crate::{
    core::compute::TemplateVerification,
    primitives::{HashType, Method, MethodError, RevisionLink},
    schema::{
        narrowing::NarrowingError, template::BuiltInTemplate, templates::TemplateMeta, tree::Tree,
        AnyRevision, Template,
    },
    verification::Linkable,
};

/// Errors returned by `create_derived_template_util`.
#[derive(Debug, thiserror::Error)]
pub enum DerivedTemplateError {
    #[error("schema narrowing violation: {0}")]
    NarrowingViolation(#[from] NarrowingError),
    #[error("maximum derivation depth exceeded (max 4 levels, i.e., ancestry length <= 3)")]
    MaxDepthExceeded,
    #[error("hash computation failed: {0}")]
    HashError(#[from] MethodError),
}

/// Create a derived template that narrows `parent`.
///
/// - Validates that `child_schema` is a valid narrowing of `parent.schema()`.
/// - Builds `derives_from` and `ancestry` automatically.
/// - Enforces max depth of 4 (ancestry length <= 3).
/// - Returns the new `Template` (caller hashes it to get its immutable type ID).
pub fn create_derived_template_util(
    parent: &Template,
    child_schema: serde_json::Value,
    child_verification: Option<TemplateVerification>,
    enable_scalar: bool,
) -> Result<Template, DerivedTemplateError> {
    // 1. Validate narrowing
    crate::schema::narrowing::validate_narrowing(parent.schema(), &child_schema)?;

    // 2. Compute parent hash (template ids are always SHA3-256, §3.9)
    let parent_hash = parent.calculate_link(HashType::Sha3_256)?;

    // 3. Build ancestry: parent's ancestry + parent's own hash
    let mut ancestry: Vec<RevisionLink> = parent.ancestry().map(|a| a.to_vec()).unwrap_or_default();
    ancestry.push(parent_hash.clone());

    // 4. Check depth: ancestry length must be <= 3 (so total depth <= 4)
    if ancestry.len() > 3 {
        return Err(DerivedTemplateError::MaxDepthExceeded);
    }

    let method = if enable_scalar {
        Method::Scalar
    } else {
        Method::Tree
    };

    Ok(Template::new_derived(
        method,
        child_schema,
        RevisionLink::from_bytes(TemplateMeta::TEMPLATE_LINK),
        parent_hash,
        ancestry,
        child_verification,
    ))
}

/// Human-readable label for a template revision: the built-in name when this
/// crate knows the hash, a hash-derived fallback otherwise.
///
/// `file_index` labels are organizational metadata, never part of any hash.
pub(crate) fn template_display_name(link: &RevisionLink) -> String {
    if let Some(name) = link
        .bare_digest()
        .and_then(|key| crate::core::builtin_template_name(&key))
    {
        return name.to_string();
    }
    format!(
        "template_{}",
        link.to_string().chars().skip(2).take(8).collect::<String>()
    )
}

/// Wrap an existing template definition as a one-revision Aqua tree keyed by
/// its **full multihash** link.
///
/// See [`crate::Aquafier::template_tree`] for the rationale and the usage.
pub fn template_tree_util(template: &Template, name: Option<&str>) -> Result<Tree, MethodError> {
    // Template ids are always SHA3-256 (PCA-0015 §3.9).
    let link = template.calculate_link(HashType::Sha3_256)?;
    let label = name
        .map(|n| n.to_string())
        .unwrap_or_else(|| template_display_name(&link));

    let mut revisions: BTreeMap<RevisionLink, AnyRevision> = BTreeMap::new();
    let mut file_index: BTreeMap<RevisionLink, String> = BTreeMap::new();
    revisions.insert(link.clone(), AnyRevision::Template(template.clone()));
    file_index.insert(link, label);

    Ok(Tree {
        revisions,
        file_index,
    })
}

pub fn create_template_util(
    json_schema: serde_json::Value,
    template_name: String,
    enable_scalar: bool,
) -> Result<Tree, MethodError> {
    let mut file_index_data: BTreeMap<RevisionLink, String> = BTreeMap::new();
    let mut revision_data: BTreeMap<RevisionLink, AnyRevision> = BTreeMap::new();

    // Create genesis Object with GenesisObjectValue as the payload type
    let template_revision = Template::new(
        if enable_scalar {
            Method::Scalar
        } else {
            Method::Tree
        },
        json_schema,
        RevisionLink::from_bytes(TemplateMeta::TEMPLATE_LINK),
    );

    let verification_hash = template_revision.calculate_link(HashType::Sha3_256)?;

    revision_data.insert(
        verification_hash.clone(),
        AnyRevision::Template(template_revision),
    );
    file_index_data.insert(verification_hash, template_name);

    Ok(Tree {
        revisions: revision_data,
        file_index: file_index_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::Linkable;
    use serde_json::json;

    fn platform_identity_schema() -> serde_json::Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "signer_did":   { "type": "string", "pattern": "^did:pkh:", "maxLength": 256 },
                "provider":     { "type": "string", "minLength": 1, "maxLength": 64 },
                "provider_id":  { "type": "string", "minLength": 1, "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 },
                "email":        { "type": "string", "format": "idn-email" },
                "proof_url":    { "type": "string", "maxLength": 2048 },
                "valid_from":   { "type": "integer", "minimum": 0 },
                "valid_until":  { "type": "integer", "minimum": 0 },
                "metadata":     { "type": "object" }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name"],
            "additionalProperties": false
        })
    }

    fn make_root_template() -> Template {
        Template::new(
            Method::Scalar,
            platform_identity_schema(),
            RevisionLink::from_bytes(TemplateMeta::TEMPLATE_LINK),
        )
    }

    #[test]
    fn create_derived_sets_derives_from_and_ancestry() {
        let parent = make_root_template();
        let parent_hash = parent.calculate_link(HashType::Sha3_256).unwrap();

        let child_schema = json!({
            "type": "object",
            "properties": {
                "signer_did":   { "type": "string", "pattern": "^did:pkh:", "maxLength": 256 },
                "provider":     { "type": "string", "const": "email" },
                "provider_id":  { "type": "string", "minLength": 1, "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 },
                "email":        { "type": "string", "format": "idn-email" }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name", "email"],
            "additionalProperties": false
        });

        let child = create_derived_template_util(&parent, child_schema, None, true).unwrap();

        assert!(child.is_derived());
        assert_eq!(child.derives_from().unwrap(), &parent_hash);
        assert_eq!(child.ancestry().unwrap(), &[parent_hash.clone()]);
        assert_eq!(child.depth(), 1);
    }

    #[test]
    fn create_derived_rejects_widening() {
        let parent = make_root_template();
        // Try to add a new property
        let bad_schema = json!({
            "type": "object",
            "properties": {
                "signer_did":   { "type": "string" },
                "provider":     { "type": "string" },
                "provider_id":  { "type": "string" },
                "display_name": { "type": "string" },
                "new_field":    { "type": "string" }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name"],
            "additionalProperties": false
        });
        let err = create_derived_template_util(&parent, bad_schema, None, true).unwrap_err();
        assert!(matches!(err, DerivedTemplateError::NarrowingViolation(_)));
    }

    #[test]
    fn create_derived_chain_builds_ancestry() {
        let root = make_root_template();
        let root_hash = root.calculate_link(HashType::Sha3_256).unwrap();

        let email_schema = json!({
            "type": "object",
            "properties": {
                "signer_did":   { "type": "string", "pattern": "^did:pkh:", "maxLength": 256 },
                "provider":     { "type": "string", "const": "email" },
                "provider_id":  { "type": "string", "minLength": 1, "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 },
                "email":        { "type": "string", "format": "idn-email" }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name", "email"],
            "additionalProperties": false
        });
        let email_tmpl = create_derived_template_util(&root, email_schema, None, true).unwrap();
        let email_hash = email_tmpl.calculate_link(HashType::Sha3_256).unwrap();

        let vendor_schema = json!({
            "type": "object",
            "properties": {
                "signer_did":   { "type": "string", "pattern": "^did:pkh:", "maxLength": 256 },
                "provider":     { "type": "string", "const": "email" },
                "provider_id":  { "type": "string", "pattern": "^[^@]+@acme\\.corp$", "minLength": 1, "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 },
                "email":        { "type": "string", "format": "idn-email" }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name", "email"],
            "additionalProperties": false
        });
        let vendor_tmpl =
            create_derived_template_util(&email_tmpl, vendor_schema, None, true).unwrap();

        assert_eq!(vendor_tmpl.depth(), 2);
        let ancestry = vendor_tmpl.ancestry().unwrap();
        assert_eq!(&ancestry[0], &root_hash);
        assert_eq!(&ancestry[1], &email_hash);
    }

    #[test]
    fn create_derived_enforces_max_depth() {
        // Build a chain of 3 levels (root→L1→L2→L3), then attempt L4 which should fail
        let simple_parent = json!({
            "type": "object",
            "properties": { "x": { "type": "string" } },
            "required": ["x"]
        });
        let narrow_child = json!({
            "type": "object",
            "properties": { "x": { "type": "string", "maxLength": 100 } },
            "required": ["x"]
        });

        let l0 = Template::new(
            Method::Scalar,
            simple_parent,
            RevisionLink::from_bytes(TemplateMeta::TEMPLATE_LINK),
        );
        let l1 = create_derived_template_util(&l0, narrow_child.clone(), None, true).unwrap();
        let l2 = create_derived_template_util(&l1, narrow_child.clone(), None, true).unwrap();
        let l3 = create_derived_template_util(&l2, narrow_child.clone(), None, true).unwrap();
        // l3 is at depth 3 (ancestry length 3). One more level would exceed limit.
        let err = create_derived_template_util(&l3, narrow_child.clone(), None, true).unwrap_err();
        assert!(
            matches!(err, DerivedTemplateError::MaxDepthExceeded),
            "should reject depth > 4"
        );
    }

    #[test]
    fn root_template_is_not_derived() {
        let tmpl = make_root_template();
        assert!(!tmpl.is_derived());
        assert!(tmpl.derives_from().is_none());
        assert!(tmpl.ancestry().is_none());
        assert_eq!(tmpl.depth(), 0);
    }
}

#[cfg(test)]
mod template_tree_tests {
    use super::*;
    use crate::primitives::HashType;
    use crate::schema::template::BuiltInTemplate;
    use crate::schema::templates::AuditRoundAnchor;
    use crate::verification::Linkable;
    use crate::Aquafier;

    fn round_anchor_template() -> Template {
        serde_json::from_str(AuditRoundAnchor::TEMPLATE_JSON).unwrap()
    }

    #[test]
    fn template_tree_is_keyed_by_the_full_multihash() {
        let template = round_anchor_template();
        let tree = Aquafier::new().template_tree(&template, None).unwrap();

        assert_eq!(tree.revisions.len(), 1, "a template tree is one revision");
        let (link, revision) = tree.revisions.iter().next().unwrap();
        assert_eq!(
            link.as_ref().len(),
            34,
            "the key must be the full multihash, not the bare digest"
        );
        assert_eq!(
            link,
            &template.calculate_link(HashType::Sha3_256).unwrap(),
            "the key must be the template's canonical link"
        );
        assert!(matches!(revision, AnyRevision::Template(_)));
        assert_eq!(
            link.bare_digest(),
            Some(AuditRoundAnchor::TEMPLATE_LINK),
            "and it must name the pinned template hash"
        );
    }

    #[test]
    fn template_tree_labels_the_revision() {
        let template = round_anchor_template();
        let aquafier = Aquafier::new();

        let named = aquafier
            .template_tree(&template, Some("audit_round_anchor"))
            .unwrap();
        assert_eq!(
            named.file_index.values().next().unwrap(),
            "audit_round_anchor"
        );

        // audit_round_anchor is shipped but deliberately outside the
        // verification catalog, so the default label is the hash fallback.
        let unnamed = aquafier.template_tree(&template, None).unwrap();
        let label = unnamed.file_index.values().next().unwrap();
        assert!(label.starts_with("template_"), "unexpected label: {label}");

        // A catalog template gets its built-in name for free.
        let file_template: Template =
            serde_json::from_str(crate::schema::templates::File::TEMPLATE_JSON).unwrap();
        let builtin = aquafier.template_tree(&file_template, None).unwrap();
        assert_eq!(builtin.file_index.values().next().unwrap(), "file");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn template_tree_resolves_a_custom_type_as_a_linked_tree() {
        use crate::primitives::{Method, RevisionLink};
        use crate::schema::templates::TemplateMeta;
        use crate::schema::AquaTreeWrapper;

        // A template core has never seen: only the tree that ships with the
        // object can make it resolvable.
        let template = Template::new(
            Method::Scalar,
            serde_json::json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": { "note": { "type": "string", "maxLength": 64 } },
                "required": ["note"],
                "additionalProperties": false
            }),
            RevisionLink::from_bytes(TemplateMeta::TEMPLATE_LINK),
        );
        let link = template.calculate_link(HashType::Sha3_256).unwrap();

        let aquafier = Aquafier::new();
        let source = aquafier.template_tree(&template, Some("note_v1")).unwrap();
        let tree = aquafier
            .create_object(link, None, serde_json::json!({ "note": "hello" }), None)
            .unwrap();

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
            "a template tree must resolve the object's type: {:?}",
            result.logs
        );
    }
}
