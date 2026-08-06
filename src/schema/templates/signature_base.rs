use crate::schema::template::BuiltInTemplate;

/// Foundational base template for all signature revisions.
///
/// Algorithm-specific signature templates (Ed25519, EIP-191, P-256,
/// WebAuthn) derive from this base. Classification of a signature
/// revision uses ancestry membership of this hash via
/// `resolve_revision_kind`.
pub struct SignatureBase;

impl BuiltInTemplate for SignatureBase {
    const TEMPLATE_JSON: &'static str = include_str!("signature_base.json");
    const TEMPLATE_LINK: [u8; 32] = [
        0xbd, 0xc9, 0x3b, 0x41, 0x52, 0xc0, 0x16, 0x3e, 0x40, 0xd3, 0xbf, 0x8c, 0xb9, 0x56, 0xe2,
        0x35, 0xf0, 0x15, 0x07, 0x31, 0xc1, 0xe8, 0xc8, 0xb5, 0x0d, 0x9c, 0x3b, 0x7a, 0xbe, 0x50,
        0xe4, 0xa7,
    ];
}
