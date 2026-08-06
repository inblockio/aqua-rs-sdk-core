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
