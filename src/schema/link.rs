use crate::primitives::*;
use crate::schema::template::BuiltInTemplate;
use crate::schema::templates::AnchorTemplate;
use serde::{Deserialize, Serialize};

/// A tagged link for application-level composition.
///
/// Compositional links are **not processed by the SDK** — they are passthrough
/// data for applications. The `role` field is freeform and application-defined,
/// enabling extensible link semantics without protocol changes.
///
/// Common roles:
/// - `"composition"` — tree composition, bundles, related documents.
/// - `"reference"` — metadata pointers, citations, provenance.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CompositionalLink {
    pub hash: RevisionLink,
    pub role: String,
}

impl CompositionalLink {
    pub fn new(hash: RevisionLink, role: impl Into<String>) -> Self {
        Self {
            hash,
            role: role.into(),
        }
    }

    /// Shorthand for a link with the "composition" role.
    pub fn composition(hash: RevisionLink) -> Self {
        Self::new(hash, "composition")
    }

    /// Shorthand for a link with the "reference" role.
    pub fn reference(hash: RevisionLink) -> Self {
        Self::new(hash, "reference")
    }
}

/// V4 Anchor revision.
///
/// Anchors enable linking multiple trees together or joining fork revisions
/// within one tree. Links are split into two categories:
///
/// - **structural_links**: WASM dependencies, L3 pending, resolution required by the SDK.
/// - **compositional_links**: Tagged application-level links, no SDK processing.
///   Each link carries a freeform `role` (e.g. "composition", "reference").
///
/// A **genesis anchor** has `previous_revision = None` and declares
/// dependencies (via `structural_links`) before any content.
///
/// `revision_type` is the full multihash of the anchor foundation template
/// (PCA-0016 AD-21). The legacy string discriminant `"anchor"` is retired.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_revision: Option<RevisionLink>,
    /// Full multihash of the anchor foundation template (AD-21).
    revision_type: RevisionLink,
    nonce: Nonce,
    local_timestamp: Timestamp,
    version: Version,
    method: Method,
    structural_links: Vec<RevisionLink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    compositional_links: Vec<CompositionalLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leaves: Option<Vec<String>>,
}

fn anchor_revision_type() -> RevisionLink {
    RevisionLink::from_bytes(AnchorTemplate::TEMPLATE_LINK)
}

impl Anchor {
    /// Create an anchor chained after an existing revision (structural links only).
    pub fn new(
        previous_revision: RevisionLink,
        method: Method,
        structural_links: Vec<RevisionLink>,
    ) -> Self {
        Self {
            previous_revision: Some(previous_revision),
            revision_type: anchor_revision_type(),
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            structural_links,
            compositional_links: Vec::new(),
            leaves: None,
        }
    }

    /// Create an anchor chained after an existing revision with compositional links.
    pub fn with_links(
        previous_revision: RevisionLink,
        method: Method,
        structural_links: Vec<RevisionLink>,
        compositional_links: Vec<CompositionalLink>,
    ) -> Self {
        Self {
            previous_revision: Some(previous_revision),
            revision_type: anchor_revision_type(),
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            structural_links,
            compositional_links,
            leaves: None,
        }
    }

    /// Create a genesis anchor — no previous revision, declares dependencies (structural only).
    pub fn genesis(method: Method, structural_links: Vec<RevisionLink>) -> Self {
        Self {
            previous_revision: None,
            revision_type: anchor_revision_type(),
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            structural_links,
            compositional_links: Vec::new(),
            leaves: None,
        }
    }

    /// Create a genesis anchor with compositional links.
    pub fn genesis_with_links(
        method: Method,
        structural_links: Vec<RevisionLink>,
        compositional_links: Vec<CompositionalLink>,
    ) -> Self {
        Self {
            previous_revision: None,
            revision_type: anchor_revision_type(),
            nonce: Nonce::random(),
            local_timestamp: Timestamp::now(),
            version: Version::V4,
            method,
            structural_links,
            compositional_links,
            leaves: None,
        }
    }

    /// The wire `revision_type` (full multihash of the anchor foundation).
    pub fn revision_type(&self) -> &RevisionLink {
        &self.revision_type
    }

    pub fn previous_revision(&self) -> Option<&RevisionLink> {
        self.previous_revision.as_ref()
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn local_timestamp(&self) -> &Timestamp {
        &self.local_timestamp
    }

    pub fn set_local_timestamp(&mut self, ts: Timestamp) {
        self.local_timestamp = ts;
    }

    pub fn structural_links(&self) -> &[RevisionLink] {
        &self.structural_links
    }

    pub fn compositional_links(&self) -> &[CompositionalLink] {
        &self.compositional_links
    }

    /// All links concatenated (structural + compositional hashes).
    pub fn all_links(&self) -> Vec<&RevisionLink> {
        self.structural_links
            .iter()
            .chain(self.compositional_links.iter().map(|cl| &cl.hash))
            .collect()
    }

    pub fn leaves(&self) -> Option<&[String]> {
        self.leaves.as_deref()
    }

    /// Populate the `leaves` field with hex-encoded leaf hashes when method is Tree.
    ///
    /// Must be called **after** `calculate_link()` so the hash is computed without
    /// the `leaves` field (which is `None` at that point and not serialized).
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

impl Hashable for Anchor {
    fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

impl Canonicalizable for Anchor {
    fn method(&self) -> &Method {
        &self.method
    }
}
