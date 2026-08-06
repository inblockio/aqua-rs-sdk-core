use crate::primitives::*;

type EthersAddress = [u8; 20];

fn to_checksum(addr: &EthersAddress, _chain_id: Option<u64>) -> String {
    crate::core::signature::sign_eth::eip55_checksum(addr)
}

fn parse_checksummed(addr_str: &str, _chain_id: Option<u64>) -> Result<EthersAddress, String> {
    let cleaned = addr_str.trim().trim_start_matches("0x");
    let bytes = hex::decode(cleaned).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 20 {
        return Err(format!("Address must be 20 bytes, got {}", bytes.len()));
    }
    let mut result = [0u8; 20];
    result.copy_from_slice(&bytes);
    Ok(result)
}

use hex::FromHex;
use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use std::fmt::Display;

/// Signature revision_type: a template hash `"0x<hex>"`.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct RevisionType(String);

impl RevisionType {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn from_signature_type(signature_type: &str) -> Self {
        let hash = crate::core::signature_template_hash(signature_type)
            .unwrap_or_else(|| panic!("unknown signature_type: {signature_type}"));
        // PCA-0015 §3.3: a `revision_type` naming-value reference is the full
        // SHA3-256 multihash of the signature template id, not a bare digest.
        RevisionType(format!(
            "0x{}",
            hex::encode(crate::primitives::template_id_multihash(&hash))
        ))
    }
}

impl Serialize for RevisionType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RevisionType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.starts_with("0x") {
            Ok(RevisionType(s))
        } else {
            Err(serde::de::Error::custom(format!(
                "invalid signature revision_type: expected '0x<hex>', got: {s}"
            )))
        }
    }
}

/// V4 Signature revision.
///
/// Per the spec, the `signer` field is the protocol-level identity (a DID).
/// The `signature` object contains `signature_type`, `signature`, and
/// `signature_public_identifier`.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    previous_revision: RevisionLink,
    revision_type: RevisionType,
    nonce: Nonce,
    local_timestamp: Timestamp,
    version: Version,
    method: Method,
    signer: String,
    signature: SignatureValue,
}

// SignatureValue with custom serialization — uniform shape:
// { signature_type, signature, signature_public_identifier }
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SignatureValue {
    Eip191 {
        signature: [u8; 65],
        signature_public_identifier: EthersAddress,
    },
    Ed25519 {
        signature: [u8; 64],
        signature_public_identifier: [u8; 32],
    },
    P256 {
        signature: [u8; 64],
        signature_public_identifier: [u8; 33],
    },
    WebAuthn {
        signature: [u8; 64],
        signature_public_identifier: [u8; 33],
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
    },
}

impl SignatureValue {
    /// Returns the signature_type string for this variant.
    pub fn signature_type(&self) -> &str {
        match self {
            SignatureValue::Eip191 { .. } => "ethereum:eip-191",
            SignatureValue::Ed25519 { .. } => "ed25519",
            SignatureValue::P256 { .. } => "ecdsa:p256",
            SignatureValue::WebAuthn { .. } => "webauthn:p256",
        }
    }
}

// Custom serialization for SignatureValue
impl Serialize for SignatureValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        match self {
            SignatureValue::Eip191 {
                signature,
                signature_public_identifier,
            } => {
                let mut state = serializer.serialize_struct("SignatureValue", 3)?;
                state.serialize_field("signature_type", "ethereum:eip-191")?;
                state.serialize_field("signature", &format!("0x{}", hex::encode(signature)))?;
                state.serialize_field(
                    "signature_public_identifier",
                    &to_checksum(signature_public_identifier, None),
                )?;
                state.end()
            }
            SignatureValue::Ed25519 {
                signature,
                signature_public_identifier,
            } => {
                let mut state = serializer.serialize_struct("SignatureValue", 3)?;
                state.serialize_field("signature_type", "ed25519")?;
                state.serialize_field("signature", &format!("0x{}", hex::encode(signature)))?;
                state.serialize_field(
                    "signature_public_identifier",
                    &format!("0x{}", hex::encode(signature_public_identifier)),
                )?;
                state.end()
            }
            SignatureValue::P256 {
                signature,
                signature_public_identifier,
            } => {
                let mut state = serializer.serialize_struct("SignatureValue", 3)?;
                state.serialize_field("signature_type", "ecdsa:p256")?;
                state.serialize_field("signature", &format!("0x{}", hex::encode(signature)))?;
                state.serialize_field(
                    "signature_public_identifier",
                    &format!("0x{}", hex::encode(signature_public_identifier)),
                )?;
                state.end()
            }
            SignatureValue::WebAuthn {
                signature,
                signature_public_identifier,
                authenticator_data,
                client_data_json,
            } => {
                let mut state = serializer.serialize_struct("SignatureValue", 5)?;
                state.serialize_field("signature_type", "webauthn:p256")?;
                state.serialize_field("signature", &format!("0x{}", hex::encode(signature)))?;
                state.serialize_field(
                    "signature_public_identifier",
                    &format!("0x{}", hex::encode(signature_public_identifier)),
                )?;
                state.serialize_field(
                    "authenticator_data",
                    &format!("0x{}", hex::encode(authenticator_data)),
                )?;
                state.serialize_field(
                    "client_data_json",
                    &format!("0x{}", hex::encode(client_data_json)),
                )?;
                state.end()
            }
        }
    }
}

// Custom deserialization for SignatureValue
impl<'de> Deserialize<'de> for SignatureValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;

        struct SignatureValueVisitor;

        impl<'de> Visitor<'de> for SignatureValueVisitor {
            type Value = SignatureValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a signature value object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut signature_type: Option<String> = None;
                let mut signature: Option<String> = None;
                let mut signature_public_identifier: Option<String> = None;
                let mut authenticator_data: Option<String> = None;
                let mut client_data_json: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "signature_type" => {
                            signature_type = Some(map.next_value()?);
                        }
                        "signature" => {
                            signature = Some(map.next_value()?);
                        }
                        "signature_public_identifier" => {
                            signature_public_identifier = Some(map.next_value()?);
                        }
                        "authenticator_data" => {
                            authenticator_data = Some(map.next_value()?);
                        }
                        "client_data_json" => {
                            client_data_json = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                &key,
                                &[
                                    "signature_type",
                                    "signature",
                                    "signature_public_identifier",
                                    "authenticator_data",
                                    "client_data_json",
                                ],
                            ));
                        }
                    }
                }

                let sig_type = signature_type
                    .ok_or_else(|| serde::de::Error::missing_field("signature_type"))?;

                let sig_hex_raw =
                    signature.ok_or_else(|| serde::de::Error::missing_field("signature"))?;
                let pubid_raw = signature_public_identifier.ok_or_else(|| {
                    serde::de::Error::missing_field("signature_public_identifier")
                })?;

                // Strip 0x prefix for hex decoding
                let sig_hex = sig_hex_raw.strip_prefix("0x").unwrap_or(&sig_hex_raw);

                match sig_type.as_str() {
                    "ethereum:eip-191" => {
                        let sig_bytes = hex::decode(sig_hex).map_err(serde::de::Error::custom)?;

                        let sig_array: [u8; 65] = sig_bytes
                            .try_into()
                            .map_err(|_| serde::de::Error::custom("signature must be 65 bytes"))?;

                        let addr = parse_checksummed(&pubid_raw, None)
                            .map_err(serde::de::Error::custom)?;

                        Ok(SignatureValue::Eip191 {
                            signature: sig_array,
                            signature_public_identifier: addr,
                        })
                    }
                    "ed25519" => {
                        let sig_bytes = hex::decode(sig_hex).map_err(serde::de::Error::custom)?;
                        let pubid_hex = pubid_raw.strip_prefix("0x").unwrap_or(&pubid_raw);
                        let pubkey_bytes =
                            hex::decode(pubid_hex).map_err(serde::de::Error::custom)?;

                        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
                            serde::de::Error::custom("Ed25519 signature must be 64 bytes")
                        })?;

                        let pubkey_array: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
                            serde::de::Error::custom("Ed25519 public key must be 32 bytes")
                        })?;

                        Ok(SignatureValue::Ed25519 {
                            signature: sig_array,
                            signature_public_identifier: pubkey_array,
                        })
                    }
                    "ecdsa:p256" => {
                        let sig_bytes = hex::decode(sig_hex).map_err(serde::de::Error::custom)?;
                        let pubid_hex = pubid_raw.strip_prefix("0x").unwrap_or(&pubid_raw);
                        let pubkey_bytes =
                            hex::decode(pubid_hex).map_err(serde::de::Error::custom)?;

                        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
                            serde::de::Error::custom("P-256 signature must be 64 bytes")
                        })?;

                        let pubkey_array: [u8; 33] = pubkey_bytes.try_into().map_err(|_| {
                            serde::de::Error::custom(
                                "P-256 public key must be 33 bytes (compressed SEC1)",
                            )
                        })?;

                        Ok(SignatureValue::P256 {
                            signature: sig_array,
                            signature_public_identifier: pubkey_array,
                        })
                    }
                    "webauthn:p256" => {
                        let sig_bytes = hex::decode(sig_hex).map_err(serde::de::Error::custom)?;
                        let pubid_hex = pubid_raw.strip_prefix("0x").unwrap_or(&pubid_raw);
                        let pubkey_bytes =
                            hex::decode(pubid_hex).map_err(serde::de::Error::custom)?;

                        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
                            serde::de::Error::custom("WebAuthn signature must be 64 bytes")
                        })?;

                        let pubkey_array: [u8; 33] = pubkey_bytes.try_into().map_err(|_| {
                            serde::de::Error::custom(
                                "WebAuthn public key must be 33 bytes (compressed SEC1)",
                            )
                        })?;

                        let auth_data_raw = authenticator_data
                            .ok_or_else(|| serde::de::Error::missing_field("authenticator_data"))?;
                        let auth_data_hex =
                            auth_data_raw.strip_prefix("0x").unwrap_or(&auth_data_raw);
                        let auth_data_bytes =
                            hex::decode(auth_data_hex).map_err(serde::de::Error::custom)?;
                        if auth_data_bytes.len() < 37 {
                            return Err(serde::de::Error::custom(
                                "authenticator_data must be at least 37 bytes",
                            ));
                        }

                        let cdj_raw = client_data_json
                            .ok_or_else(|| serde::de::Error::missing_field("client_data_json"))?;
                        let cdj_hex = cdj_raw.strip_prefix("0x").unwrap_or(&cdj_raw);
                        let cdj_bytes = hex::decode(cdj_hex).map_err(serde::de::Error::custom)?;
                        if cdj_bytes.is_empty() {
                            return Err(serde::de::Error::custom(
                                "client_data_json must not be empty",
                            ));
                        }

                        Ok(SignatureValue::WebAuthn {
                            signature: sig_array,
                            signature_public_identifier: pubkey_array,
                            authenticator_data: auth_data_bytes,
                            client_data_json: cdj_bytes,
                        })
                    }
                    _ => Err(serde::de::Error::custom(format!(
                        "unknown signature type: {sig_type}"
                    ))),
                }
            }
        }

        deserializer.deserialize_map(SignatureValueVisitor)
    }
}

/// Pre-signature state: holds all common fields before the actual signature is produced.
///
/// Per V4 spec, the signing input is the Aqua Pointer Form (APF) canonical JSON
/// of the "pre-signature inner object" -- all Signature fields except the
/// `signature` object, with an added top-level `signature_type`. See
/// spec-core-protocol.md §Aqua Pointer Form for the normative algorithm.
pub struct PreSignature {
    previous_revision: RevisionLink,
    nonce: Nonce,
    local_timestamp: Timestamp,
    version: Version,
    method: Method,
    /// Creation-time algorithm selector. Not stored on the finalized
    /// [`Signature`] (the algorithm is recovered from the addressing multihash
    /// at verification, PCA-0015 §3.10); used here only to bind the signature to
    /// its algorithm via the `hash_codec` number in the signing input.
    hash_type: HashType,
    signer: String,
}

/// Helper struct for serializing the pre-signature to canonical JSON.
///
/// `hash_codec` is the decimal multicodec of the revision-hash algorithm
/// (`22` for SHA3-256, `30` for BLAKE3), a JSON **number** that binds the
/// signature to its algorithm (PCA-0015 §3.10). It replaces the former
/// string `hash_type` field and is never a wire field on [`Signature`].
#[derive(Serialize)]
struct PreSignatureJson<'a> {
    hash_codec: u8,
    local_timestamp: &'a Timestamp,
    method: &'a Method,
    nonce: &'a Nonce,
    previous_revision: &'a RevisionLink,
    revision_type: &'a str,
    signature_type: &'a str,
    signer: &'a str,
    version: &'a Version,
}

impl PreSignature {
    /// Creates a new pre-signature, generating nonce and timestamp.
    pub fn new(
        previous_revision: RevisionLink,
        method: Method,
        hash_type: HashType,
        signer: String,
    ) -> Self {
        Self {
            previous_revision,
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            hash_type,
            signer,
        }
    }

    /// Returns the signer DID string.
    pub fn signer(&self) -> &str {
        &self.signer
    }

    /// Produces the canonical JSON bytes of the pre-signature object per V4 spec.
    ///
    /// This is the signing input: all fields + `signature_type` (no `signature` object).
    /// Keys are sorted lexicographically per Aqua Pointer Form (UTF-8 byte-wise on JSON Pointer paths).
    pub fn canonical_json(&self, signature_type: &str) -> Vec<u8> {
        let revision_type = RevisionType::from_signature_type(signature_type);
        let pre = PreSignatureJson {
            hash_codec: self.hash_type.multicodec(),
            local_timestamp: &self.local_timestamp,
            method: &self.method,
            nonce: &self.nonce,
            previous_revision: &self.previous_revision,
            revision_type: revision_type.as_str(),
            signature_type,
            signer: &self.signer,
            version: &self.version,
        };
        let mut json = serde_json::to_value(&pre).expect("Pre-signature should serialize");
        json.sort_all_objects();
        serde_json::to_string(&json)
            .expect("JSON serialization should not fail")
            .into_bytes()
    }

    /// Finalize the pre-signature into a full Signature by attaching the actual signature.
    pub fn finalize(self, signature: SignatureValue) -> Signature {
        let revision_type = RevisionType::from_signature_type(signature.signature_type());
        Signature {
            previous_revision: self.previous_revision,
            revision_type,
            nonce: self.nonce,
            local_timestamp: self.local_timestamp,
            version: self.version,
            method: self.method,
            signer: self.signer,
            signature,
        }
    }
}

impl Signature {
    pub fn new(
        previous_revision: RevisionLink,
        method: Method,
        signer: String,
        signature: SignatureValue,
    ) -> Self {
        let revision_type = RevisionType::from_signature_type(signature.signature_type());
        Self {
            previous_revision,
            revision_type,
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            signer,
            signature,
        }
    }

    pub fn previous_revision(&self) -> &RevisionLink {
        &self.previous_revision
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn local_timestamp(&self) -> &Timestamp {
        &self.local_timestamp
    }

    pub fn signer(&self) -> &str {
        &self.signer
    }

    pub fn signature(&self) -> &SignatureValue {
        &self.signature
    }

    /// Reconstructs the pre-signature canonical JSON bytes from this Signature.
    ///
    /// Used during verification to recover the exact bytes that were signed.
    /// Per V4 spec: extract `signature_type` from the `signature` object,
    /// remove `signature`, add `signature_type` as top-level field.
    /// Returns the revision_type string for this signature.
    pub fn revision_type_str(&self) -> &str {
        self.revision_type.as_str()
    }

    /// Reconstruct the pre-signature canonical JSON bytes for verification.
    ///
    /// `hash_type` is supplied by the caller, derived from this signature's
    /// addressing multihash code (PCA-0015 §3.10 3-step procedure); it is never
    /// read from the revision struct.
    pub fn pre_signature_canonical_json(&self, hash_type: HashType) -> Vec<u8> {
        let pre = PreSignatureJson {
            hash_codec: hash_type.multicodec(),
            local_timestamp: &self.local_timestamp,
            method: &self.method,
            nonce: &self.nonce,
            previous_revision: &self.previous_revision,
            revision_type: self.revision_type.as_str(),
            signature_type: self.signature.signature_type(),
            signer: &self.signer,
            version: &self.version,
        };
        let mut json = serde_json::to_value(&pre).expect("Pre-signature should serialize");
        json.sort_all_objects();
        serde_json::to_string(&json)
            .expect("JSON serialization should not fail")
            .into_bytes()
    }
}

impl Hashable for Signature {
    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

impl Canonicalizable for Signature {
    fn method(&self) -> &Method {
        &self.method
    }
}

pub(crate) struct Hex0xLowercase;

impl<T> SerializeAs<T> for Hex0xLowercase
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&format!("0x{}", hex::encode(source)))
    }
}

impl<'de, T> DeserializeAs<'de, T> for Hex0xLowercase
where
    T: FromHex,
    <T as FromHex>::Error: Display,
    HexParseError: From<<T as FromHex>::Error>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(String::deserialize(deserializer)?
            .parse::<HexString<T>>()
            .map_err(D::Error::custom)?
            .0)
    }
}
