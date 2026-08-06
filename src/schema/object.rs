use crate::primitives::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use super::template::BuiltInTemplate;

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Object<P = Value> {
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_revision: Option<RevisionLink>,
    revision_type: RevisionLink,
    nonce: Nonce,
    local_timestamp: Timestamp,
    version: Version,
    method: Method,
    payloads: P,
    #[serde(skip_serializing_if = "Option::is_none")]
    leaves: Option<Vec<String>>,
}

impl<P> Object<P> {
    pub fn genesis(revision_type: RevisionLink, method: Method, payloads: P) -> Self {
        Self {
            previous_revision: None,
            revision_type,
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            payloads,
            leaves: None,
        }
    }

    pub fn new(
        previous_revision: RevisionLink,
        revision_type: RevisionLink,
        method: Method,
        payloads: P,
    ) -> Self {
        Self {
            previous_revision: Some(previous_revision),
            revision_type,
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            payloads,
            leaves: None,
        }
    }

    pub fn genesis_with_template(method: Method, payloads: P) -> Self
    where
        P: BuiltInTemplate,
    {
        Self::genesis(RevisionLink::from_bytes(P::TEMPLATE_LINK), method, payloads)
    }

    pub fn new_with_template(previous_revision: RevisionLink, method: Method, payloads: P) -> Self
    where
        P: BuiltInTemplate,
    {
        Self::new(
            previous_revision,
            RevisionLink::from_bytes(P::TEMPLATE_LINK),
            method,
            payloads,
        )
    }

    pub fn previous_revision(&self) -> Option<&RevisionLink> {
        self.previous_revision.as_ref()
    }

    pub fn revision_type(&self) -> &RevisionLink {
        &self.revision_type
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn local_timestamp(&self) -> &Timestamp {
        &self.local_timestamp
    }

    pub fn payloads(&self) -> &P {
        &self.payloads
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn leaves(&self) -> Option<&[String]> {
        self.leaves.as_deref()
    }

    pub fn genericize(self) -> Result<Object<serde_json::Value>, serde_json::error::Error>
    where
        P: Serialize,
    {
        Ok(Object::<serde_json::Value> {
            previous_revision: self.previous_revision,
            revision_type: self.revision_type,
            nonce: self.nonce,
            local_timestamp: self.local_timestamp,
            version: self.version,
            method: self.method,
            payloads: serde_json::to_value(&self.payloads)?,
            leaves: self.leaves,
        })
    }
}

impl Object<serde_json::Value> {
    pub fn specific<P: DeserializeOwned>(self) -> Result<Object<P>, serde_json::error::Error> {
        Ok(Object::<P> {
            previous_revision: self.previous_revision,
            revision_type: self.revision_type,
            nonce: self.nonce,
            local_timestamp: self.local_timestamp,
            version: self.version,
            method: self.method,
            payloads: serde_json::from_value(self.payloads)?,
            leaves: self.leaves,
        })
    }
}

impl<P: Serialize> Object<P> {
    /// Populate the `leaves` field with hex-encoded leaf hashes when method is Tree.
    ///
    /// Must be called **after** `calculate_link()` so the hash is computed without
    /// the `leaves` field (which is `None` at that point and not serialized).
    /// `hash_type` must be the same algorithm used to compute the addressing link.
    pub fn populate_leaves(&mut self, hash_type: HashType) -> Result<(), MethodError> {
        if self.method == Method::Tree {
            let raw = Method::leaves(self, hash_type)?;
            self.leaves = Some(
                raw.iter()
                    .map(|l| format!("0x{}", hex::encode(l)))
                    .collect(),
            );
        }
        Ok(())
    }
}

impl<P> Hashable for Object<P> {
    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

impl<P> Canonicalizable for Object<P> {
    fn method(&self) -> &Method {
        &self.method
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::Linkable;

    #[test]
    fn tree_method_object_has_leaves_after_populate() {
        let mut obj = Object::genesis(
            RevisionLink::new(vec![1u8; 32]),
            Method::Tree,
            HashType::Sha3_256,
        );
        let hash = obj.calculate_link(HashType::Sha3_256).unwrap();
        obj.populate_leaves(HashType::Sha3_256).unwrap();

        let leaves = obj.leaves().expect("leaves should be Some for tree method");
        assert!(!leaves.is_empty(), "leaves should not be empty");
        for leaf in leaves {
            assert!(leaf.starts_with("0x"), "leaf should be 0x-prefixed hex");
            // Each leaf is a hash — decode should succeed
            hex::decode(leaf.strip_prefix("0x").unwrap()).unwrap();
        }

        // Verify the hash still matches after populate_leaves (filter works)
        let hash_after = obj.calculate_link(HashType::Sha3_256).unwrap();
        assert_eq!(
            hash, hash_after,
            "hash must be stable after populate_leaves"
        );
    }

    #[test]
    fn scalar_method_object_has_no_leaves() {
        let mut obj = Object::genesis(
            RevisionLink::new(vec![1u8; 32]),
            Method::Scalar,
            HashType::Sha3_256,
        );
        obj.populate_leaves(HashType::Sha3_256).unwrap();
        assert!(
            obj.leaves().is_none(),
            "scalar objects should have None leaves"
        );
    }

    #[test]
    fn deserialized_object_with_leaves_produces_correct_hash() {
        let mut obj = Object::genesis(
            RevisionLink::new(vec![2u8; 32]),
            Method::Tree,
            HashType::Sha3_256,
        );
        let original_hash = obj.calculate_link(HashType::Sha3_256).unwrap();
        obj.populate_leaves(HashType::Sha3_256).unwrap();

        // Serialize and deserialize
        let json = serde_json::to_string(&obj).unwrap();
        let deserialized: Object<serde_json::Value> = serde_json::from_str(&json).unwrap();

        // leaves field is present after deserialization
        assert!(deserialized.leaves().is_some());

        // Hash must still match (filter excludes /leaves/* paths)
        let recomputed_hash = deserialized.calculate_link(HashType::Sha3_256).unwrap();
        assert_eq!(original_hash, recomputed_hash);
    }

    #[test]
    fn genericize_preserves_leaves() {
        let mut obj = Object::genesis(
            RevisionLink::new(vec![3u8; 32]),
            Method::Tree,
            HashType::Sha3_256,
        );
        obj.populate_leaves(HashType::Sha3_256).unwrap();
        let leaves_before = obj.leaves().unwrap().to_vec();

        let generic = obj.genericize().unwrap();
        assert_eq!(generic.leaves().unwrap(), &leaves_before[..]);
    }
}
