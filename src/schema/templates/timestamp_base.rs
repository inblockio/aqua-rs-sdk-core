use crate::schema::template::BuiltInTemplate;

/// Root timestamp template -- shared schema for all timestamp types.
///
/// Defines the common fields (type, merkle_root, timestamp, network,
/// transaction_hash, merkle_proof) and two optional fields:
/// `sender_account_address` (used by EVM) and `tsa_provider` (used by TSA).
/// Derived templates narrow this schema by constraining the `network` field,
/// requiring their specific optional field, and adding protocol-specific WASM.
pub struct TimestampBase;

impl BuiltInTemplate for TimestampBase {
    const TEMPLATE_JSON: &'static str = include_str!("timestamp_base.json");
    const TEMPLATE_LINK: [u8; 32] = [
        0xb6, 0xea, 0xdc, 0x83, 0x07, 0x04, 0x02, 0xc7, 0x3a, 0x6a, 0xf8, 0x2d, 0x56, 0x66, 0x4c,
        0xa8, 0x90, 0xf2, 0xdb, 0x65, 0x39, 0x53, 0x0e, 0xa5, 0xac, 0x12, 0xd5, 0xe2, 0x79, 0x8d,
        0xfd, 0xd6,
    ];
}
