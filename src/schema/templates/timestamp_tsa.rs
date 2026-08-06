use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TsaTimestampPayload {
    #[serde(rename = "type")]
    pub timestamp_type: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub network: String,
    pub transaction_hash: String,
    pub tsa_provider: String,
    pub merkle_proof: Vec<String>,
    pub batch_tree_size: usize,
    pub batch_leaf_index: usize,
    pub shielding_nonce: String,
}

impl BuiltInTemplate for TsaTimestampPayload {
    const TEMPLATE_LINK: [u8; 32] = [
        0x65, 0xfb, 0xe6, 0x7e, 0x03, 0xcd, 0x43, 0x73, 0x26, 0xc8, 0x49, 0x11, 0x55, 0xb6, 0xfb,
        0x29, 0x49, 0xeb, 0x52, 0x8a, 0x24, 0x94, 0x52, 0xea, 0xff, 0xf0, 0xcc, 0x67, 0x38, 0xd5,
        0x01, 0xa8,
    ];
}
