use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Error returned when a DID string fails basic validation.
#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum DidError {
    /// The string does not start with `"did:"`.
    #[error("invalid DID: must start with 'did:' but got {0:?}")]
    InvalidPrefix(String),

    /// The string is empty.
    #[error("invalid DID: empty string")]
    Empty,
}

/// A validated DID string.
///
/// Validates that the value starts with `"did:"`. Further validation (method
/// syntax, method-specific rules) is left to the caller or a dedicated DID
/// resolver — this type enforces only the minimum required by the Aqua protocol.
///
/// # Example
///
/// ```
/// use aqua_rs_sdk_core::primitives::Did;
///
/// let did: Did = "did:pkh:eip155:1:0xabc".parse().unwrap();
/// assert_eq!(did.as_str(), "did:pkh:eip155:1:0xabc");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(pub String);

impl Did {
    /// Create a new `Did`, validating that the string starts with `"did:"`.
    ///
    /// # Errors
    ///
    /// Returns [`DidError::Empty`] for an empty string and
    /// [`DidError::InvalidPrefix`] if the value does not start with `"did:"`.
    pub fn new(s: impl Into<String>) -> Result<Self, DidError> {
        let s = s.into();
        if s.is_empty() {
            return Err(DidError::Empty);
        }
        if !s.starts_with("did:") {
            return Err(DidError::InvalidPrefix(s));
        }
        Ok(Self(s))
    }

    /// Return the underlying DID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Did {
    type Err = DidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Did::new(s)
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_did_pkh() {
        let did = Did::new("did:pkh:eip155:1:0xabc").unwrap();
        assert_eq!(did.as_str(), "did:pkh:eip155:1:0xabc");
    }

    #[test]
    fn test_valid_did_parse() {
        let did: Did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        assert_eq!(
            did.to_string(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[test]
    fn test_empty_rejected() {
        assert_eq!(Did::new(""), Err(DidError::Empty));
    }

    #[test]
    fn test_no_prefix_rejected() {
        let result = Did::new("not-a-did");
        assert!(matches!(result, Err(DidError::InvalidPrefix(_))));
    }

    #[test]
    fn test_plain_did_prefix_accepted() {
        // "did:" followed by nothing — technically invalid per DID spec,
        // but we only enforce the minimal prefix rule.
        let did = Did::new("did:").unwrap();
        assert_eq!(did.as_str(), "did:");
    }

    #[test]
    fn test_serde_roundtrip() {
        let did = Did::new("did:pkh:eip155:1:0xabc").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        // Transparent: serializes as a plain string.
        assert_eq!(json, "\"did:pkh:eip155:1:0xabc\"");
        let back: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(back, did);
    }
}
