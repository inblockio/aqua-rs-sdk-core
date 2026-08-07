use crate::{
    primitives::{log::LogData, *},
    schema::tree::Tree,
    verification::Linkable,
};
use serde::{Deserialize, Serialize};

pub mod bounds;
pub mod builder;
pub mod credentials;
pub mod file_data;
pub mod link;
pub mod narrowing;
pub mod object;
pub mod signature;
pub mod template;
pub mod template_descriptor;
pub mod templates;
pub mod tree;

pub use bounds::{ObjectBounds, StructuralLinkSpec};
pub use credentials::SigningCredentials;
pub use file_data::FileData;
pub use link::{Anchor, CompositionalLink};
pub use object::Object;
pub use signature::{PreSignature, Signature, SignatureValue};
pub use template::Template;
pub use tree::DagRevision;

/// A revision in an Aqua tree, covering all four revision types.
///
/// The Aqua protocol defines four kinds of revisions:
///
/// - **Object** (`Typed`) — a typed data payload validated against a template's JSON Schema.
/// - **Template** — a type definition (JSON Schema + optional WASM module).
/// - **Signature** — a cryptographic signature over a target revision (forms a branch).
/// - **Anchor** — a structural link to other trees or the genesis anchor connecting to a template.
///
/// `AnyRevision` is serialized as an untagged enum — the deserializer tries each variant
/// in order. All revision types share `previous_revision`, `local_timestamp`, and `hash_type`.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(untagged)]
pub enum AnyRevision {
    /// A typed data object validated against a template's JSON Schema.
    Typed(Object),
    /// A template definition (type declaration).
    Template(Template),
    /// A cryptographic signature over a target revision.
    Signature(Signature),
    /// A structural link (genesis anchor or cross-tree reference).
    Anchor(Anchor),
}

impl AnyRevision {
    fn is_genesis(&self) -> bool {
        match self {
            AnyRevision::Typed(obj) => obj.previous_revision().is_none(),
            AnyRevision::Template(_) => false,
            AnyRevision::Signature(_) => false,
            AnyRevision::Anchor(a) => a.previous_revision().is_none(),
        }
    }

    /// Returns the hash of the previous revision in the chain, or `None` for genesis.
    pub fn get_previous_revision_hash(&self) -> Option<RevisionLink> {
        match self {
            AnyRevision::Typed(obj) => obj.previous_revision().cloned(),
            AnyRevision::Template(t) => t.previous_revision().cloned(),
            AnyRevision::Signature(sig) => Some(sig.previous_revision().clone()),
            AnyRevision::Anchor(anchor) => anchor.previous_revision().cloned(),
        }
    }

    /// Returns the local timestamp of this revision.
    pub fn get_local_timestamp(&self) -> &Timestamp {
        match self {
            AnyRevision::Typed(obj) => obj.local_timestamp(),
            AnyRevision::Template(t) => t.local_timestamp(),
            AnyRevision::Signature(sig) => sig.local_timestamp(),
            AnyRevision::Anchor(anchor) => anchor.local_timestamp(),
        }
    }

    /// Returns the `revision_type` of this revision as a string suitable
    /// for [`crate::primitives::resolve_revision_kind`].
    ///
    /// Every variant returns a canonical classification key:
    ///
    /// - `Typed` returns the underlying object's `revision_type`
    ///   (`0x<template_hash>`), which classifies through the foundation
    ///   hash sets in [`crate::primitives::revision_kind`]. Timestamp
    ///   objects resolve to [`RevisionKind::Timestamp`], other objects
    ///   to [`RevisionKind::Object`].
    /// - `Template` returns [`crate::primitives::TEMPLATE_META_HEX`].
    /// - `Signature` returns the wire-format `revision_type` string,
    ///   already a `0x<template_hash>`.
    /// - `Anchor` returns [`crate::primitives::ANCHOR_TEMPLATE_HEX`].
    ///
    /// Stage 2.5 batch-inclusion gates on
    /// `is_timestamp_revision_type(get_revision_type(..))` and relies on
    /// this method returning the real template hash for typed timestamp
    /// objects so the check executes for them.
    ///
    /// [`RevisionKind::Timestamp`]: crate::primitives::RevisionKind::Timestamp
    /// [`RevisionKind::Object`]: crate::primitives::RevisionKind::Object
    pub fn get_revision_type(&self) -> String {
        match self {
            AnyRevision::Typed(obj) => obj.revision_type().to_string(),
            AnyRevision::Template(_) => crate::primitives::TEMPLATE_META_HEX.clone(),
            AnyRevision::Signature(sig) => sig.revision_type_str().to_string(),
            AnyRevision::Anchor(_) => crate::primitives::ANCHOR_TEMPLATE_HEX.clone(),
        }
    }

    /// Returns a reference to self (identity accessor for generic code).
    pub fn get_revision(&self) -> &AnyRevision {
        self
    }

    /// Consume self and return the inner revision (identity accessor).
    pub fn into_revision(self) -> AnyRevision {
        self
    }

    /// Returns `Some` if this is a typed data object, `None` otherwise.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            AnyRevision::Typed(obj) => Some(obj),
            _ => None,
        }
    }

    /// Returns `Some` if this is a template definition, `None` otherwise.
    pub fn as_template(&self) -> Option<&Template> {
        match self {
            AnyRevision::Template(template) => Some(template),
            _ => None,
        }
    }

    /// Returns `Some` if this is a signature revision, `None` otherwise.
    pub fn as_signature(&self) -> Option<&Signature> {
        match self {
            AnyRevision::Signature(signature) => Some(signature),
            _ => None,
        }
    }

    /// Returns `Some` if this is an anchor revision, `None` otherwise.
    pub fn as_anchor(&self) -> Option<&Anchor> {
        match self {
            AnyRevision::Anchor(anchor) => Some(anchor),
            _ => None,
        }
    }

    /// Compute the cryptographic hash of this revision (its `RevisionLink`)
    /// under `hash_type`. The algorithm is supplied by the caller — at
    /// verification, decode it from the addressing multihash via
    /// [`RevisionLink::hash_type`](crate::primitives::RevisionLink::hash_type);
    /// at creation, the builder's selector (PCA-0015 §3.5).
    ///
    /// Template revisions are always addressed by a SHA3-256 id (§3.9), so the
    /// `Template` arm ignores `hash_type` and uses SHA3-256.
    pub fn global_calculate_hash(&self, hash_type: HashType) -> Result<RevisionLink, MethodError> {
        match self {
            AnyRevision::Typed(obj) => obj.calculate_link(hash_type),
            AnyRevision::Template(template) => template.calculate_link(HashType::Sha3_256),
            AnyRevision::Signature(signature) => signature.calculate_link(hash_type),
            AnyRevision::Anchor(anchor) => anchor.calculate_link(hash_type),
        }
    }

    /// Returns `true` if this revision uses the Scalar canonicalization method (no Merkle leaves).
    pub fn is_scalar(&self) -> bool {
        match self {
            AnyRevision::Typed(obj) => {
                // Check if the payloads has a "leaves" property
                if let Ok(payload_value) = serde_json::to_value(obj.payloads()) {
                    if let Some(obj_map) = payload_value.as_object() {
                        // If it has leaves property, check if it's an array with length > 0
                        if let Some(leaves) = obj_map.get("leaves") {
                            if let Some(leaves_array) = leaves.as_array() {
                                return leaves_array.is_empty(); // is_scalar = true if leaves is empty
                            }
                            return false; // has leaves property but not an array, so not scalar
                        }
                    }
                }
                // No leaves property found, so it's scalar
                true
            }
            // All other revision types are considered scalar (no leaves property)
            AnyRevision::Template(_) => true,
            AnyRevision::Signature(_) => true,
            AnyRevision::Anchor(_) => true,
        }
    }
}

/// Wraps an Aqua [`Tree`] with optional associated file data and a target revision.
///
/// This is the primary input type for verification and signing operations.
/// The `file_object` provides the raw file content for genesis hash verification.
/// The `revision` optionally specifies which revision to target (defaults to the tip).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AquaTreeWrapper {
    /// The Aqua tree to operate on.
    pub aqua_tree: Tree,
    /// Optional file data for content hash verification.
    pub file_object: Option<FileData>,
    /// Optional target revision hash. When `None`, operations target the tree's tip.
    pub revision: Option<RevisionLink>,
}

impl AquaTreeWrapper {
    /// Create a new wrapper.
    pub fn new(
        aqua_tree: Tree,
        file_object: Option<FileData>,
        revision: Option<RevisionLink>,
    ) -> Self {
        Self {
            aqua_tree,
            file_object,
            revision,
        }
    }
}

/// Result of an Aqua tree mutation operation (sign, timestamp, link, create).
///
/// Contains the modified tree, any additional trees produced as side effects,
/// and diagnostic log messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AquaOperationData {
    /// The modified Aqua tree after the operation.
    pub aqua_tree: Tree,
    /// Additional trees produced as side effects (e.g., linked trees).
    pub aqua_trees: Vec<Tree>,
    /// Diagnostic log messages from the operation.
    pub log_data: Vec<LogData>,
}
