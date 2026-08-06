//! Shared utility functions for working with Aqua trees.
//!
//! These helpers extract common patterns that appear in multiple consumer crates
//! (CLI, state-viewer, etc.) and centralise them in the SDK.

pub mod clock;

pub use clock::{Clock, FixedClock, SystemClock};

use std::collections::HashSet;

use crate::primitives::RevisionLink;
use crate::schema::{AnyRevision, AquaTreeWrapper};

/// Extract non-zero structural link hashes from all anchor revisions in a tree.
///
/// Returns the string representations of each structural link that is not the
/// zero-sentinel (`0x000…000`), which is used for headless attestations.
pub fn anchor_link_hashes(wrapper: &AquaTreeWrapper) -> Vec<String> {
    let zero = RevisionLink::zero().to_string();
    let mut links = Vec::new();
    for rev in wrapper.aqua_tree.revisions.values() {
        if let AnyRevision::Anchor(anchor) = rev {
            for h in anchor.structural_links() {
                let s = h.to_string();
                if s != zero {
                    links.push(s);
                }
            }
        }
    }
    links
}

/// Extract all unique signer DIDs from signature revisions in a tree.
pub fn extract_signers_from_tree(wrapper: &AquaTreeWrapper) -> HashSet<String> {
    let mut signers = HashSet::new();
    for rev in wrapper.aqua_tree.revisions.values() {
        if let AnyRevision::Signature(sig) = rev {
            let did = sig.signer().to_string();
            if !did.is_empty() {
                signers.insert(did);
            }
        }
    }
    signers
}

/// Extract all unique signer DIDs from a batch of trees.
pub fn extract_signers_from_trees(wrappers: &[AquaTreeWrapper]) -> HashSet<String> {
    let mut signers = HashSet::new();
    for wrapper in wrappers {
        signers.extend(extract_signers_from_tree(wrapper));
    }
    signers
}

/// Parse a JSON string as an `AquaTreeWrapper`.
///
/// Tries `AquaTreeWrapper` format first (has `"aqua_tree"` key), then falls back
/// to a bare `Tree` (has `"revisions"` key at root). Returns `None` if neither
/// format parses.
pub fn parse_aqua_json(json: &str) -> Option<AquaTreeWrapper> {
    // Try AquaTreeWrapper first.
    if let Ok(w) = serde_json::from_str::<AquaTreeWrapper>(json) {
        return Some(w);
    }
    // Fall back: bare Tree.
    let tree: crate::schema::tree::Tree = serde_json::from_str(json).ok()?;
    Some(AquaTreeWrapper::new(tree, None, None))
}
