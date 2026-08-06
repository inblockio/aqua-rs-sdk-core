use crate::schema::signature::Hex0xLowercase;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SigningCredentials {
    Did {
        #[serde_as(as = "Hex0xLowercase")]
        did_key: Vec<u8>,
    },
    P256 {
        #[serde_as(as = "Hex0xLowercase")]
        p256_key: Vec<u8>,
    },
    /// Raw secp256k1 private key (32-byte scalar), used for EIP-191 signing.
    ///
    /// Unlike the former `Cli` variant (which derived keys from a BIP-39
    /// mnemonic and has been extracted to `aqua-evm-provider`), this variant
    /// holds the key material directly, useful for server-side daemons that
    /// store keys in a key store or HSM.
    Secp256k1 {
        #[serde_as(as = "Hex0xLowercase")]
        secp256k1_key: Vec<u8>,
    },
}

impl SigningCredentials {
    /// Converts credentials into a boxed `Signer` trait object.
    pub fn into_signer(
        &self,
    ) -> Result<
        Box<dyn crate::core::signature::traits::Signer>,
        crate::core::signature::traits::SignError,
    > {
        match self {
            SigningCredentials::Did { did_key } => Ok(Box::new(
                crate::core::signature::sign_did::Ed25519Signer::new(did_key.clone()),
            )),
            SigningCredentials::P256 { p256_key } => Ok(Box::new(
                crate::core::signature::sign_p256::P256KeySigner::new(p256_key.clone()),
            )),
            #[cfg(feature = "native")]
            SigningCredentials::Secp256k1 { secp256k1_key } => Ok(Box::new(
                crate::core::signature::sign_eth::Secp256k1Signer::new(secp256k1_key.clone()),
            )),
            #[cfg(not(feature = "native"))]
            SigningCredentials::Secp256k1 { .. } => {
                Err(crate::core::signature::traits::SignError::NotSupported(
                    "Secp256k1 signing requires the 'native' feature".to_string(),
                ))
            }
        }
    }
}

// TimestampCredentials, CredentialsFile, and the Metamask/Cli signing variants
// have been removed. EVM providers were extracted to `aqua-evm-provider`.
// Consumers should inject a TimestampProvider directly via AquafierBuilder
// or use batch_timestamp_with_provider.

// IdentityCredentials has been extracted to the `aqua-identity-provider` crate.
