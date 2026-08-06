use crate::schema::template::BuiltInTemplate;

/// Foundational template for anchor revisions.
///
/// Anchors carry structural and compositional links between revisions and
/// trees. Today the wire format still uses the literal string `"anchor"`
/// as `revision_type`, but `resolve_revision_kind` maps that legacy form
/// to this template hash so all downstream consumers can dispatch on a
/// single classification key.
pub struct AnchorTemplate;

impl BuiltInTemplate for AnchorTemplate {
    const TEMPLATE_JSON: &'static str = include_str!("anchor_template.json");
    const TEMPLATE_LINK: [u8; 32] = [
        0x47, 0x9a, 0x30, 0x49, 0x27, 0xc4, 0x7f, 0x43, 0x08, 0xd0, 0x27, 0xa8, 0x58, 0x06, 0x0c,
        0xe2, 0x87, 0xa9, 0xbd, 0xb4, 0x5f, 0x22, 0x03, 0xf8, 0x13, 0x05, 0x74, 0xa7, 0x35, 0x11,
        0xe8, 0x99,
    ];
}
