use crate::core::compute::TemplateVerification;
use crate::primitives::*;
use crate::schema::Object;
use crate::verification::Linkable;
use serde::{Deserialize, Serialize};

/// A template definition (type declaration).
///
/// `revision_type` is a full multihash naming value (PCA-0015 / PCA-0016 AD-21):
/// the genesis bootstrap self-reference for `template_meta` itself, and the
/// `template_meta` content multihash for every other template. The legacy
/// string discriminants `"template"` / `"anchor"` are retired.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Template {
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_revision: Option<RevisionLink>,
    /// Full multihash of the template-template (`template_meta`), or the
    /// genesis bootstrap value when this IS `template_meta` (AD-21).
    revision_type: RevisionLink,
    nonce: Nonce,
    local_timestamp: Timestamp,
    version: Version,
    method: Method,
    schema: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification: Option<TemplateVerification>,
    /// Direct parent template hash (present only in derived templates).
    /// Full multihash (PCA-0015 / AD-21). Part of the template JSON hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    derives_from: Option<RevisionLink>,
    /// Full ancestor chain [root, ..., parent] (present only in derived templates).
    /// The last element MUST equal `derives_from`. Max length: 3 (giving max depth 4).
    /// Each entry is a full multihash (AD-21).
    #[serde(skip_serializing_if = "Option::is_none")]
    ancestry: Option<Vec<RevisionLink>>,
    /// Template-declared bounds on Object subgraph structure.
    /// Part of the template JSON and therefore part of its SHA3-256 hash.
    /// `None` for templates that don't declare bounds (uses `ObjectBounds::permissive()`).
    #[serde(skip_serializing_if = "Option::is_none")]
    bounds: Option<crate::schema::bounds::ObjectBounds>,
}

impl Template {
    /// Create a root template definition.
    ///
    /// `revision_type` MUST be the full multihash of `template_meta` (or the
    /// genesis bootstrap when constructing `template_meta` itself). Callers
    /// typically pass `RevisionLink::from_bytes(TemplateMeta::TEMPLATE_LINK)`.
    pub fn new(method: Method, schema: serde_json::Value, revision_type: RevisionLink) -> Self {
        Self {
            previous_revision: None,
            revision_type,
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            schema,
            verification: None,
            derives_from: None,
            ancestry: None,
            bounds: None,
        }
    }

    /// Create a derived template.  Callers should prefer `create_derived_template`
    /// in the core API which also runs the narrowing validator.
    ///
    /// `revision_type` MUST be the full multihash of `template_meta` (AD-21).
    pub fn new_derived(
        method: Method,
        schema: serde_json::Value,
        revision_type: RevisionLink,
        derives_from: RevisionLink,
        ancestry: Vec<RevisionLink>,
        verification: Option<TemplateVerification>,
    ) -> Self {
        Self {
            previous_revision: None,
            revision_type,
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            schema,
            verification,
            derives_from: Some(derives_from),
            ancestry: Some(ancestry),
            bounds: None,
        }
    }

    /// The wire `revision_type` of this template definition (full multihash).
    pub fn revision_type(&self) -> &RevisionLink {
        &self.revision_type
    }

    pub fn verification(&self) -> Option<&TemplateVerification> {
        self.verification.as_ref()
    }

    pub fn previous_revision(&self) -> Option<&RevisionLink> {
        self.previous_revision.as_ref()
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn local_timestamp(&self) -> &Timestamp {
        &self.local_timestamp
    }

    pub fn schema(&self) -> &serde_json::Value {
        &self.schema
    }

    /// Returns the direct parent template hash if this is a derived template.
    pub fn derives_from(&self) -> Option<&RevisionLink> {
        self.derives_from.as_ref()
    }

    /// Returns the full ancestor chain `[root, ..., parent]` if this is a derived template.
    pub fn ancestry(&self) -> Option<&[RevisionLink]> {
        self.ancestry.as_deref()
    }

    /// Returns `true` if this template is derived from another template.
    pub fn is_derived(&self) -> bool {
        self.derives_from.is_some()
    }

    /// Returns the derivation depth (0 for root templates, 1–3 for derived).
    /// Depth equals `ancestry.len()`.
    pub fn depth(&self) -> usize {
        self.ancestry.as_ref().map(|a| a.len()).unwrap_or(0)
    }

    /// Returns the template-declared bounds, or `ObjectBounds::permissive()` if not declared.
    ///
    /// Does NOT walk ancestry — use `resolve_bounds(hash)` for inheritance.
    pub fn bounds(&self) -> crate::schema::bounds::ObjectBounds {
        self.bounds
            .clone()
            .unwrap_or_else(crate::schema::bounds::ObjectBounds::permissive)
    }

    /// Returns the raw declared bounds (None if not declared in this template's JSON).
    ///
    /// Used by `resolve_bounds` to distinguish "no bounds declared" (inherit)
    /// from "bounds explicitly set".
    pub fn raw_bounds(&self) -> Option<&crate::schema::bounds::ObjectBounds> {
        self.bounds.as_ref()
    }

    pub fn set_previous_revision(&mut self, link: RevisionLink) {
        self.previous_revision = Some(link);
    }

    pub fn set_local_timestamp(&mut self, ts: Timestamp) {
        self.local_timestamp = ts;
    }

    pub fn validate_object(&self, revision: &Object) -> Result<(), Box<dyn std::error::Error>> {
        // Template ids are always SHA3-256 (PCA-0015 §3.9).
        if revision.revision_type() != &self.calculate_link(HashType::Sha3_256)? {
            return Err("Revision type does not match template link".into());
        }
        if !jsonschema::validator_for(self.schema())?.is_valid(revision.payloads()) {
            return Err("Revision payloads do not conform to template schema".into());
        }
        Ok(())
    }
}

impl Hashable for Template {
    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

impl Canonicalizable for Template {
    fn method(&self) -> &Method {
        &self.method
    }
}

pub trait BuiltInTemplate {
    const TEMPLATE_LINK: [u8; 32];
    const TEMPLATE_JSON: &'static str = "";

    fn to_object(self, previous_revision: RevisionLink, method: Method) -> Object<Self>
    where
        Self: Sized,
    {
        Object::new_with_template(previous_revision, method, self)
    }

    fn to_genesis(self, method: Method) -> Object<Self>
    where
        Self: Sized,
    {
        Object::genesis_with_template(method, self)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::core::genesis::create_genesis_revision;
    use crate::primitives::{HashType, HexString, Method};
    use crate::schema::{templates::File, FileData};
    use crate::verification::Linkable;

    #[test]
    fn test_file_template() {
        let template_str = include_str!("./templates/file.json");
        let schema_str = include_str!("./templates/file_schema.json");

        let file_template_json: Template = serde_json::from_str(template_str).unwrap();
        let file_template = Template {
            previous_revision: None,
            revision_type: file_template_json.revision_type().clone(),
            nonce: HexString([
                0x2b, 0xa6, 0xa8, 0xb9, 0xb9, 0x87, 0xcf, 0x8c, 0x35, 0x67, 0xf7, 0x28, 0x71, 0x81,
                0x2a, 0xe9,
            ]),
            local_timestamp: Timestamp::from_secs(1762266013),
            version: Version::V4,
            method: Method::Scalar,
            schema: serde_json::from_str(schema_str).unwrap(),
            verification: None,
            derives_from: None,
            ancestry: None,
            bounds: Some(crate::schema::bounds::ObjectBounds {
                max_chain_depth: 64,
                structural_links: crate::schema::bounds::StructuralLinkSpec {
                    required: 0,
                    max: 0,
                },
                max_signature_branches: 4,
                max_timestamp_branches: 1,
                max_anchor_branches: 4,
                max_total_revisions: 1024,
            }),
        };

        assert_eq!(file_template_json, file_template);
        assert_eq!(
            RevisionLink::from_bytes(File::TEMPLATE_LINK),
            file_template.calculate_link(HashType::Sha3_256).unwrap()
        );
        assert_eq!(
            file_template_json
                .calculate_link(HashType::Sha3_256)
                .unwrap(),
            file_template.calculate_link(HashType::Sha3_256).unwrap()
        );

        // basic test for genesis revision type
        let genesis_tree = create_genesis_revision(
            FileData::new("".to_string(), vec![], PathBuf::new()),
            Method::Scalar,
        )
        .unwrap();

        let genesis_rev = genesis_tree
            .get_content_tip()
            .unwrap()
            .1
            .as_object()
            .unwrap()
            .clone();

        let schema_validator = jsonschema::validator_for(file_template.schema()).unwrap();
        assert!(schema_validator.is_valid(genesis_rev.payloads()));
        assert_eq!(
            genesis_rev.revision_type(),
            &file_template.calculate_link(HashType::Sha3_256).unwrap()
        );
    }

    #[test]
    fn test_hardcoded_links() {
        use crate::schema::templates::*;
        use crate::verification::Linkable;

        let templates: &[(&str, &str, &[u8; 32])] = &[
            (
                "file",
                include_str!("./templates/file.json"),
                &File::TEMPLATE_LINK,
            ),
                        (
                "timestamp_base",
                include_str!("./templates/timestamp_base.json"),
                &TimestampBase::TEMPLATE_LINK,
            ),
            (
                "timestamp_evm",
                include_str!("./templates/timestamp_evm.json"),
                &EvmTimestampPayload::TEMPLATE_LINK,
            ),
                                                                                                            (
                "timestamp_tsa",
                include_str!("./templates/timestamp_tsa.json"),
                &TsaTimestampPayload::TEMPLATE_LINK,
            ),
                        (
                "identity_base",
                include_str!("./templates/identity_base.json"),
                &IdentityBase::TEMPLATE_LINK,
            ),
                                                                                                                                                                        (
                "signature_eip191",
                include_str!("./templates/signature_eip191.json"),
                &SignatureEip191::TEMPLATE_LINK,
            ),
            (
                "signature_ed25519",
                include_str!("./templates/signature_ed25519.json"),
                &SignatureEd25519::TEMPLATE_LINK,
            ),
            (
                "signature_p256",
                include_str!("./templates/signature_p256.json"),
                &SignatureP256::TEMPLATE_LINK,
            ),
            (
                "signature_webauthn",
                include_str!("./templates/signature_webauthn.json"),
                &SignatureWebauthn::TEMPLATE_LINK,
            ),
                                            ];

        for (name, json, expected) in templates {
            let computed = serde_json::from_str::<Template>(json)
                .unwrap()
                .calculate_link(HashType::Sha3_256)
                .unwrap();
            assert_eq!(
                &computed.as_ref()[2..],
                *expected,
                "{} template hash mismatch",
                name
            );
        }
    }


    /// Prints actual SHA3-256 hashes for timestamp templates.
    ///
    /// Run with: `cargo test print_timestamp_template_hashes -- --nocapture`
    /// Use output to update TEMPLATE_LINK constants and derives_from fields.
    #[test]
    fn print_timestamp_template_hashes() {
        use crate::verification::Linkable;

        let pairs: &[(&str, &str)] = &[
            (
                "timestamp_base",
                include_str!("./templates/timestamp_base.json"),
            ),
            (
                "timestamp_evm",
                include_str!("./templates/timestamp_evm.json"),
            ),
            (
                "timestamp_tsa",
                include_str!("./templates/timestamp_tsa.json"),
            ),
        ];

        for (name, json) in pairs {
            let hash = serde_json::from_str::<Template>(json)
                .unwrap()
                .calculate_link(HashType::Sha3_256)
                .unwrap();
            let hex = hex::encode(hash.as_ref());
            println!("{name}: 0x{hex}");
            println!("  bytes: {:?}", hash.as_ref());
        }
    }

    /// Print ALL template hashes.
    /// Run with: `cargo test print_all_template_hashes -- --nocapture`
    #[test]
    fn print_all_template_hashes() {
        use crate::verification::Linkable;

        let pairs: &[(&str, &str)] = &[
            (
                "identity_base",
                include_str!("./templates/identity_base.json"),
            ),
                                                                                                                                                                                                                    ];

        for (name, json) in pairs {
            let hash = serde_json::from_str::<Template>(json)
                .unwrap()
                .calculate_link(HashType::Sha3_256)
                .unwrap();
            let hex_str = hex::encode(hash.as_ref());
            println!("{name}: 0x{hex_str}");
            println!("  bytes: {:?}", hash.as_ref());
        }
    }
}
