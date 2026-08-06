use crate::primitives::HashType;
use crate::schema::{signature::Hex0xLowercase, template::BuiltInTemplate};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct File {
    #[serde(rename = "type")]
    pub file_type: String,
    #[serde_as(as = "Hex0xLowercase")]
    pub hash: Vec<u8>,
    pub hash_type: HashType,
    pub descriptor: String,
    pub size: u64,
    pub content_type: String,
}

impl BuiltInTemplate for File {
    const TEMPLATE_JSON: &'static str = include_str!("file.json");
    const TEMPLATE_LINK: [u8; 32] = [
        0x00, 0xf3, 0xab, 0xb3, 0xd7, 0x4f, 0xc9, 0xdf, 0xc2, 0xb9, 0x61, 0xce, 0xa9, 0x06, 0xb3,
        0x21, 0x17, 0x16, 0x18, 0x8f, 0x4d, 0xe6, 0xf5, 0x88, 0x18, 0x0f, 0xdf, 0xcb, 0xbf, 0xa3,
        0xfe, 0x53,
    ];
}
