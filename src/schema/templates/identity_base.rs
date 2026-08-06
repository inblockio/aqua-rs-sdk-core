use crate::schema::template::BuiltInTemplate;
use serde::{Deserialize, Serialize};

/// Root identity template — 45-field union of all identity claim types.
///
/// Only `signer_did` is required. All other fields are optional.
/// All derived identity templates (PlatformIdentity, Attestation, EmailClaim, etc.)
/// narrow this schema by constraining or requiring specific subsets of these fields.
///
/// WASM states: `["unsigned", "self_signed", "untrusted", "attested", "expired", "not_yet_valid"]`
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct IdentityBase {
    /// The DID being bound (did:key:z6Mk... / did:key:zDn... / did:pkh:eip155:...)
    pub signer_did: String,

    // ── Temporal bounds ──────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,

    // ── Attestation ──────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,

    // ── Platform identity ────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,

    // ── Name (OIDC, mDL, eIDAS, ICAO) ───────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_suffix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    // ── Birth (split for selective disclosure) ───────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_year: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_month: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_day: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthplace: Option<String>,

    // ── Age ──────────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_over_18: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_over_21: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_in_years: Option<u32>,

    // ── Address ──────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    // ── Phone ────────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,

    // ── DNS ──────────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,

    // ── Government document ──────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_date: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nationality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personal_id_number: Option<String>,

    // ── Physical ─────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sex: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height_cm: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eye_colour: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portrait_hash: Option<String>,

    // ── Extensible ───────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl BuiltInTemplate for IdentityBase {
    const TEMPLATE_LINK: [u8; 32] = [
        0x81, 0x2b, 0x61, 0xa5, 0x90, 0x60, 0x95, 0xbc, 0x37, 0x52, 0x73, 0x81, 0x39, 0x18, 0xe9,
        0x94, 0x55, 0x5e, 0x1f, 0x38, 0x65, 0x95, 0xc0, 0x18, 0x74, 0x38, 0xc0, 0x04, 0x35, 0xb1,
        0x07, 0xb4,
    ];
}
