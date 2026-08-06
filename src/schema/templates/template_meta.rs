use crate::schema::template::BuiltInTemplate;

/// Foundational template for template revisions (the template-template).
///
/// `TEMPLATE_LINK` is the canonical SHA3-256 of `template_meta.json`. All
/// other built-in template JSONs declare `revision_type: "template"` at the
/// wire level, but state extracted from those revisions classifies them via
/// this hash through `resolve_revision_kind`. The synthetic genesis hash
/// `SHA3-256("aqua:genesis:template_meta")` exposed by
/// `crate::primitives::revision_kind::GENESIS_TYPE_HASH` is reserved for the
/// future fully-unified wire format and is not used as a key today.
pub struct TemplateMeta;

impl BuiltInTemplate for TemplateMeta {
    const TEMPLATE_JSON: &'static str = include_str!("template_meta.json");
    const TEMPLATE_LINK: [u8; 32] = [
        0xf3, 0x04, 0x08, 0x50, 0xa8, 0x83, 0x67, 0x17, 0xdd, 0x73, 0xe8, 0x7d, 0x04, 0x67, 0x23,
        0xe1, 0x1f, 0x9e, 0x98, 0x70, 0xe3, 0xb2, 0xe2, 0x46, 0x80, 0x3a, 0xd8, 0x42, 0xfb, 0xf0,
        0x11, 0x55,
    ];
}
