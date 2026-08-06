use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct EvmTimestampPayload {
    #[serde(rename = "type")]
    pub timestamp_type: String,
    pub merkle_root: String,
    pub timestamp: u64,
    pub network: String,
    pub smart_contract_address: String,
    pub transaction_hash: String,
    pub sender_account_address: String,
    pub merkle_proof: Vec<String>,
    pub batch_tree_size: usize,
    pub batch_leaf_index: usize,
    pub shielding_nonce: String,
}

impl BuiltInTemplate for EvmTimestampPayload {
    const TEMPLATE_JSON: &'static str = include_str!("timestamp_evm.json");
    const TEMPLATE_LINK: [u8; 32] = [
        0xd1, 0x6c, 0xba, 0x5a, 0xd8, 0x17, 0x45, 0xc8, 0xd4, 0x1c, 0x04, 0x23, 0xfb, 0x55, 0x43,
        0x7a, 0xf6, 0x0e, 0xcc, 0x4d, 0xb4, 0x91, 0xc9, 0x43, 0xea, 0x26, 0x1f, 0x41, 0x8e, 0xc0,
        0xa5, 0x30,
    ];
}
