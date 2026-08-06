use crate::{primitives::*, schema::*};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// An Aqua tree: an ordered collection of cryptographically linked revisions.
///
/// A tree is the fundamental data structure of the Aqua protocol. It contains
/// a directed acyclic graph (DAG) of revisions, where each non-genesis revision
/// references its predecessor. The content chain is linear; signatures, timestamps,
/// and anchors form branches off the content chain.
///
/// The `file_index` maps revision hashes to human-readable file names, used for
/// content-addressed file storage.
///
/// # Serialization
///
/// Trees serialize to JSON with `revisions` and `file_index` as objects keyed
/// by hex-encoded revision hashes. Use [`to_ordered_json_value`](Tree::to_ordered_json_value)
/// for deterministic genesis-to-latest ordering.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct Tree {
    /// Revision hash → revision data. Keys are `0x`-prefixed hex hashes.
    pub revisions: BTreeMap<RevisionLink, AnyRevision>,
    /// Revision hash → file name. Maps content revisions to their file names.
    pub file_index: BTreeMap<RevisionLink, String>,
}

impl Tree {
    /// Gets the ordered list of revision links from genesis to latest
    fn get_ordered_revision_links(&self) -> Vec<RevisionLink> {
        let all_hashes: Vec<RevisionLink> = self.revisions.keys().cloned().collect();
        let mut ordered_hashes: Vec<RevisionLink> = Vec::new();

        // If only one revision, return as is
        if all_hashes.len() <= 1 {
            return all_hashes;
        }

        // Find the genesis revision
        for hash in &all_hashes {
            if let Some(revision) = self.revisions.get(hash) {
                if revision.is_genesis() {
                    ordered_hashes.push(hash.clone());
                    break;
                }
            }
        }

        // If no genesis found, return original order
        if ordered_hashes.is_empty() {
            return all_hashes;
        }

        // Find subsequent revisions in order (with cycle detection)
        let mut visited: std::collections::HashSet<RevisionLink> =
            ordered_hashes.iter().cloned().collect();
        loop {
            let next = self.find_next_revision_hash(ordered_hashes.last().unwrap());
            match next {
                Some(hash) if visited.insert(hash.clone()) => {
                    ordered_hashes.push(hash);
                }
                _ => break, // no successor, or cycle detected
            }
        }

        ordered_hashes
    }

    /// Returns the hash of the latest revision in the chain (the tip).
    pub fn get_latest_revision_link(&self) -> Option<RevisionLink> {
        self.get_ordered_revision_links().last().cloned()
    }

    /// Returns the genesis revision (the root with no `previous_revision`).
    pub fn get_genesis_revision(&self) -> Option<(RevisionLink, AnyRevision)> {
        for revision_item in &self.revisions {
            if revision_item.1.is_genesis() {
                return Some((revision_item.0.clone(), revision_item.1.clone()));
            }
        }
        None
    }

    pub fn get_main_file_name(&self) -> Option<String> {
        // Walk the chain from genesis and return the file_index name for the
        // first Object revision. Before typed creation, genesis itself was
        // an Object; now genesis may be an Anchor, so we scan forward.
        for (link, rev) in self.order_revisions() {
            if matches!(rev, AnyRevision::Typed(_) | AnyRevision::Template(_)) {
                return self.file_index.get(&link).cloned();
            }
        }
        // Fallback: try genesis hash directly (legacy trees)
        self.get_genesis_revision()
            .and_then(|(h, _)| self.file_index.get(&h).cloned())
    }

    /// Orders revisions chronologically, starting from genesis (empty previous_verification_hash)
    /// Returns a new Tree with revisions ordered correctly
    ///
    /// Note: This method now returns a properly ordered representation as a Vec of tuples
    /// since BTreeMap cannot maintain insertion order
    pub fn order_revisions(&self) -> Vec<(RevisionLink, AnyRevision)> {
        let ordered_links = self.get_ordered_revision_links();

        ordered_links
            .into_iter()
            .filter_map(|link| self.revisions.get(&link).map(|rev| (link, rev.clone())))
            .collect()
    }

    /// Finds the next revision hash that references the given hash
    fn find_next_revision_hash(&self, current_hash: &RevisionLink) -> Option<RevisionLink> {
        for (hash, revision) in &self.revisions {
            if let Some(prev_hash) = revision.get_previous_revision_hash() {
                if &prev_hash == current_hash {
                    return Some(hash.clone());
                }
            }
        }
        None
    }

    /// Gets the last revision in the chain (the one not referenced by any other revision).
    /// Standalone Template revisions (type declarations embedded for self-description)
    /// are skipped in favour of chain-connected revisions.
    pub fn get_last_revision(&self) -> Option<(RevisionLink, AnyRevision)> {
        // Get all revision links that are referenced as previous_revision
        let mut referenced_links = std::collections::HashSet::new();

        for revision in self.revisions.values() {
            if let Some(prev_link) = revision.get_previous_revision_hash() {
                referenced_links.insert(prev_link.clone());
            }
        }

        // Find the revision that is NOT referenced by any other revision,
        // preferring non-Template revisions over standalone Templates.
        let mut template_candidate = None;
        for (link, revision) in &self.revisions {
            if !referenced_links.contains(link) && !revision.is_genesis() {
                if matches!(revision, AnyRevision::Template(_)) {
                    template_candidate.get_or_insert_with(|| (link.clone(), revision.clone()));
                } else {
                    return Some((link.clone(), revision.clone()));
                }
            }
        }
        if let Some(candidate) = template_candidate {
            return Some(candidate);
        }

        // If no non-genesis unreferenced revision found, check if there's only a genesis
        if self.revisions.len() == 1 {
            return self.get_genesis_revision();
        }

        None
    }

    /// Look up a revision by its hash.
    pub fn get_revision_by_hash(&self, hash_par: &RevisionLink) -> Option<&AnyRevision> {
        self.revisions.get(hash_par)
    }

    /// Produce a `serde_json::Value` with revisions and file_index ordered
    /// from genesis to latest (chain order) instead of BTreeMap key order.
    pub fn to_ordered_json_value(&self) -> serde_json::Value {
        let ordered_links = self.get_ordered_revision_links();

        // Build ordered revisions map
        let mut revisions_map = serde_json::Map::new();
        for link in &ordered_links {
            if let Some(rev) = self.revisions.get(link) {
                if let Ok(val) = serde_json::to_value(rev) {
                    revisions_map.insert(link.to_string(), val);
                }
            }
        }

        // Build ordered file_index — same chain order first, then append
        // any extra entries (e.g. linked chain references) not in the revision set.
        let mut file_index_map = serde_json::Map::new();
        for link in &ordered_links {
            if let Some(name) = self.file_index.get(link) {
                file_index_map.insert(link.to_string(), serde_json::Value::String(name.clone()));
            }
        }
        // Append file_index entries whose keys are not revision hashes
        // (e.g. linked chain genesis hashes and tip hashes from linking).
        for (link, name) in &self.file_index {
            let key = link.to_string();
            if !file_index_map.contains_key(&key) {
                file_index_map.insert(key, serde_json::Value::String(name.clone()));
            }
        }

        let mut root = serde_json::Map::new();
        root.insert(
            "revisions".to_string(),
            serde_json::Value::Object(revisions_map),
        );
        root.insert(
            "file_index".to_string(),
            serde_json::Value::Object(file_index_map),
        );
        serde_json::Value::Object(root)
    }

    /// Returns all tip revisions — revisions not referenced as `previous_revision`
    /// by any other revision in the tree. In a linear chain this returns one tip;
    /// in a DAG with signature/anchor branches it returns multiple.
    pub fn get_all_tips(&self) -> Vec<(RevisionLink, AnyRevision)> {
        let mut referenced: std::collections::HashSet<RevisionLink> =
            std::collections::HashSet::new();
        for revision in self.revisions.values() {
            if let Some(prev) = revision.get_previous_revision_hash() {
                referenced.insert(prev);
            }
        }
        self.revisions
            .iter()
            .filter(|(link, _)| !referenced.contains(link))
            .map(|(link, rev)| (link.clone(), rev.clone()))
            .collect()
    }

    /// Returns the content chain tip — the tip that is an Object or Template,
    /// filtering out Signature and Anchor branches. For trees with a single
    /// content chain and signature/anchor forks, this returns the latest content.
    /// When both Object and Template tips exist (typed genesis trees carry an
    /// embedded template), Object is preferred.
    pub fn get_content_tip(&self) -> Option<(RevisionLink, AnyRevision)> {
        let content_tips: Vec<_> = self
            .get_all_tips()
            .into_iter()
            .filter(|(_, rev)| matches!(rev, AnyRevision::Typed(_) | AnyRevision::Template(_)))
            .collect();
        // Prefer Object (actual content) over standalone Template (type declaration)
        content_tips
            .iter()
            .find(|(_, rev)| matches!(rev, AnyRevision::Typed(_)))
            .or_else(|| content_tips.first())
            .cloned()
    }

    /// Returns all Signature revisions whose `previous_revision` equals the
    /// given link. Answers "who signed this revision?" without walking the tree.
    pub fn get_signatures_for(&self, revision: &RevisionLink) -> Vec<(RevisionLink, AnyRevision)> {
        self.revisions
            .iter()
            .filter(|(_, rev)| {
                matches!(rev, AnyRevision::Signature(_))
                    && rev.get_previous_revision_hash().as_ref() == Some(revision)
            })
            .map(|(link, rev)| (link.clone(), rev.clone()))
            .collect()
    }

    /// Returns all revisions whose `previous_revision` equals `parent`.
    fn find_all_children(&self, parent: &RevisionLink) -> Vec<(RevisionLink, AnyRevision)> {
        self.revisions
            .iter()
            .filter(|(_, rev)| rev.get_previous_revision_hash().as_ref() == Some(parent))
            .map(|(link, rev)| (link.clone(), rev.clone()))
            .collect()
    }

    /// Returns all revisions with DAG topology metadata.
    ///
    /// The linear content chain is identified first via
    /// [`get_ordered_revision_links`]. Every revision NOT on that chain is
    /// classified as a `"branch"` — its parent is its `previous_revision`.
    /// This includes signatures, timestamps, anchors, **and** content forks
    /// (two Objects sharing the same parent).
    ///
    /// **Ordering**: chain revisions first (genesis-to-tip), then branches
    /// grouped by their parent's chain position.
    pub fn order_revisions_dag(&self) -> Vec<DagRevision> {
        let chain_links = self.get_ordered_revision_links();
        let chain_set: std::collections::HashSet<&RevisionLink> = chain_links.iter().collect();

        let mut result = Vec::with_capacity(self.revisions.len());

        // Emit chain revisions in order, interleaving each position's branches.
        for (depth, chain_link) in chain_links.iter().enumerate() {
            let Some(rev) = self.revisions.get(chain_link) else {
                continue;
            };
            result.push(DagRevision {
                link: chain_link.clone(),
                revision: rev.clone(),
                edge_type: "chain",
                parent: rev.get_previous_revision_hash(),
                depth,
            });

            // Collect branches forking from this chain position.
            let mut branches: Vec<_> = self
                .find_all_children(chain_link)
                .into_iter()
                .filter(|(link, _)| !chain_set.contains(link))
                .collect();
            branches.sort_by(|(a, _), (b, _)| a.cmp(b));

            for (branch_link, branch_rev) in branches {
                result.push(DagRevision {
                    link: branch_link,
                    revision: branch_rev,
                    edge_type: "branch",
                    parent: Some(chain_link.clone()),
                    depth: depth + 1,
                });
            }
        }

        // Emit orphan branches not attached to any chain revision
        // (e.g., branches off other branches — deep forks).
        for (link, rev) in &self.revisions {
            if chain_set.contains(link) {
                continue;
            }
            if result.iter().any(|d| d.link == *link) {
                continue;
            }
            let parent = rev.get_previous_revision_hash();
            let parent_depth = parent
                .as_ref()
                .and_then(|p| result.iter().find(|d| d.link == *p).map(|d| d.depth));
            result.push(DagRevision {
                link: link.clone(),
                revision: rev.clone(),
                edge_type: "branch",
                parent,
                depth: parent_depth.map_or(0, |d| d + 1),
            });
        }

        result
    }
}

/// A revision with its position in the DAG topology.
///
/// Unlike [`Tree::order_revisions`] which returns only the linear content chain,
/// `DagRevision` captures both chain and branch revisions with their relationships.
/// Chain revisions form the linear spine; branches fork off chain positions
/// (e.g., signatures, timestamps, anchors, or content forks from `--previous-hash`).
#[derive(Clone, Debug)]
pub struct DagRevision {
    /// The revision's hash.
    pub link: RevisionLink,
    /// The revision data.
    pub revision: AnyRevision,
    /// `"chain"` for main-chain revisions, `"branch"` for forks.
    pub edge_type: &'static str,
    /// The parent revision's hash (`None` for genesis).
    pub parent: Option<RevisionLink>,
    /// Hop count from genesis (genesis = 0).
    pub depth: usize,
}

/// A [`Tree`] augmented with an explicit chronological ordering of revision hashes.
///
/// Unlike `Tree` (whose `BTreeMap` orders by key bytes), `OrderedTree` maintains
/// a `revision_order` vector reflecting the genesis-to-latest chain order.
/// Use [`from_tree`](OrderedTree::from_tree) to construct and
/// [`create_tree`](OrderedTree::create_tree) to convert back.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct OrderedTree {
    /// Revision hash → revision data (same as [`Tree::revisions`]).
    pub revisions: BTreeMap<RevisionLink, AnyRevision>,
    /// Chronological order of revision hashes (genesis first).
    pub revision_order: Vec<RevisionLink>,
    /// Revision hash → file name (same as [`Tree::file_index`]).
    pub file_index: BTreeMap<RevisionLink, String>,
}

impl OrderedTree {
    /// Creates an OrderedTree from a regular Tree
    pub fn from_tree(tree: &Tree) -> Self {
        let ordered_links = tree.get_ordered_revision_links();

        OrderedTree {
            revisions: tree.revisions.clone(),
            revision_order: ordered_links,
            file_index: tree.file_index.clone(),
        }
    }

    /// Convert back to a [`Tree`], discarding the explicit ordering.
    pub fn create_tree(&self) -> Tree {
        Tree {
            revisions: self.revisions.clone(),
            file_index: self.file_index.clone(),
        }
    }
}
// #[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
// pub struct ChildTree {
//     hash: RevisionLink,
//     children: Vec<ChildTree>
// }

// #[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
// pub struct TreeMapping {
//     paths: BTreeMap<RevisionLink, Vec<RevisionLink>>,
//     latest_hash: RevisionLink,
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::signature::SignatureValue;

    fn link(byte: u8) -> RevisionLink {
        RevisionLink::new(vec![byte])
    }

    fn dummy_type() -> RevisionLink {
        RevisionLink::new(vec![0xFF; 32])
    }

    fn genesis_object() -> AnyRevision {
        AnyRevision::Typed(Object::genesis(
            dummy_type(),
            Method::Scalar,
            serde_json::json!({"name": "test"}),
        ))
    }

    fn chained_object(prev: RevisionLink) -> AnyRevision {
        AnyRevision::Typed(Object::new(
            prev,
            dummy_type(),
            Method::Scalar,
            serde_json::json!({"name": "updated"}),
        ))
    }

    fn signature_for(prev: RevisionLink) -> AnyRevision {
        AnyRevision::Signature(Signature::new(
            prev,
            Method::Scalar,
            "did:pkh:eip155:1:0x1234".to_string(),
            SignatureValue::Ed25519 {
                signature: [0u8; 64],
                signature_public_identifier: [0u8; 32],
            },
        ))
    }

    fn genesis_anchor() -> AnyRevision {
        AnyRevision::Anchor(Anchor::genesis(Method::Scalar, vec![]))
    }

    fn empty_tree() -> Tree {
        Tree {
            revisions: BTreeMap::new(),
            file_index: BTreeMap::new(),
        }
    }

    // ── get_genesis_revision ────────────────────────────────────────────

    #[test]
    fn test_get_genesis_revision_empty_tree() {
        assert!(empty_tree().get_genesis_revision().is_none());
    }

    #[test]
    fn test_get_genesis_revision_single_object() {
        let mut tree = empty_tree();
        let l = link(0x01);
        tree.revisions.insert(l.clone(), genesis_object());
        let (gl, _) = tree.get_genesis_revision().unwrap();
        assert_eq!(gl, l);
    }

    #[test]
    fn test_get_genesis_revision_with_chain() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        let (gl, _) = tree.get_genesis_revision().unwrap();
        assert_eq!(gl, l1);
    }

    #[test]
    fn test_get_genesis_anchor() {
        let mut tree = empty_tree();
        let l = link(0x01);
        tree.revisions.insert(l.clone(), genesis_anchor());
        let (gl, rev) = tree.get_genesis_revision().unwrap();
        assert_eq!(gl, l);
        assert!(matches!(rev, AnyRevision::Anchor(_)));
    }

    // ── get_latest_revision_link ────────────────────────────────────────

    #[test]
    fn test_get_latest_revision_link_empty() {
        assert!(empty_tree().get_latest_revision_link().is_none());
    }

    #[test]
    fn test_get_latest_revision_link_single() {
        let mut tree = empty_tree();
        let l = link(0x01);
        tree.revisions.insert(l.clone(), genesis_object());
        assert_eq!(tree.get_latest_revision_link().unwrap(), l);
    }

    #[test]
    fn test_get_latest_revision_link_chain() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let l3 = link(0x03);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.revisions
            .insert(l3.clone(), chained_object(l2.clone()));
        assert_eq!(tree.get_latest_revision_link().unwrap(), l3);
    }

    // ── get_last_revision ───────────────────────────────────────────────

    #[test]
    fn test_get_last_revision_single_genesis() {
        let mut tree = empty_tree();
        let l = link(0x01);
        tree.revisions.insert(l.clone(), genesis_object());
        let (rl, _) = tree.get_last_revision().unwrap();
        assert_eq!(rl, l);
    }

    #[test]
    fn test_get_last_revision_chain() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        let (rl, _) = tree.get_last_revision().unwrap();
        assert_eq!(rl, l2);
    }

    // ── order_revisions ─────────────────────────────────────────────────

    #[test]
    fn test_order_revisions_empty() {
        assert!(empty_tree().order_revisions().is_empty());
    }

    #[test]
    fn test_order_revisions_chain() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let l3 = link(0x03);
        // Insert in reverse to verify ordering logic
        tree.revisions
            .insert(l3.clone(), chained_object(l2.clone()));
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        let ordered = tree.order_revisions();
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].0, l1);
        assert_eq!(ordered[1].0, l2);
        assert_eq!(ordered[2].0, l3);
    }

    // ── get_all_tips ────────────────────────────────────────────────────

    #[test]
    fn test_get_all_tips_single_genesis() {
        let mut tree = empty_tree();
        let l = link(0x01);
        tree.revisions.insert(l.clone(), genesis_object());
        let tips = tree.get_all_tips();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].0, l);
    }

    #[test]
    fn test_get_all_tips_dag_with_content_and_sig() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let l_sig = link(0x10);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.revisions
            .insert(l_sig.clone(), signature_for(l1.clone()));
        // l1 referenced by l2 and l_sig → not a tip
        // l2 and l_sig unreferenced → both tips
        let tips = tree.get_all_tips();
        assert_eq!(tips.len(), 2);
    }

    #[test]
    fn test_get_all_tips_multiple_signatures() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let ls1 = link(0x10);
        let ls2 = link(0x11);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.revisions
            .insert(ls1.clone(), signature_for(l2.clone()));
        tree.revisions
            .insert(ls2.clone(), signature_for(l2.clone()));
        // l2 referenced by ls1 and ls2, l1 referenced by l2
        // tips: ls1, ls2
        let tips = tree.get_all_tips();
        assert_eq!(tips.len(), 2);
    }

    // ── get_content_tip ─────────────────────────────────────────────────

    #[test]
    fn test_get_content_tip_with_signature_branch() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let l_sig = link(0x10);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.revisions
            .insert(l_sig.clone(), signature_for(l1.clone()));
        // Tips: l2 (Object) and l_sig (Signature)
        let (cl, rev) = tree.get_content_tip().unwrap();
        assert_eq!(cl, l2);
        assert!(matches!(rev, AnyRevision::Typed(_)));
    }

    #[test]
    fn test_get_content_tip_all_signatures() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l_sig = link(0x10);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l_sig.clone(), signature_for(l1.clone()));
        // Only tip is l_sig (Signature) → content tip is None
        assert!(tree.get_content_tip().is_none());
    }

    // ── get_signatures_for ──────────────────────────────────────────────

    #[test]
    fn test_get_signatures_for_matching() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let ls1 = link(0x10);
        let ls2 = link(0x11);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(ls1.clone(), signature_for(l1.clone()));
        tree.revisions
            .insert(ls2.clone(), signature_for(l1.clone()));
        let sigs = tree.get_signatures_for(&l1);
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn test_get_signatures_for_no_matching() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        // l2 is Object, not Signature → no signatures for l1
        let sigs = tree.get_signatures_for(&l1);
        assert_eq!(sigs.len(), 0);
    }

    #[test]
    fn test_get_signatures_for_nonexistent() {
        let tree = empty_tree();
        let sigs = tree.get_signatures_for(&link(0xFF));
        assert_eq!(sigs.len(), 0);
    }

    // ── get_main_file_name ──────────────────────────────────────────────

    #[test]
    fn test_get_main_file_name() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.file_index
            .insert(l1.clone(), "document.pdf".to_string());
        assert_eq!(tree.get_main_file_name().unwrap(), "document.pdf");
    }

    #[test]
    fn test_get_main_file_name_no_file_index() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        tree.revisions.insert(l1.clone(), genesis_object());
        assert!(tree.get_main_file_name().is_none());
    }

    #[test]
    fn test_get_main_file_name_empty_tree() {
        assert!(empty_tree().get_main_file_name().is_none());
    }

    // ── get_revision_by_hash ────────────────────────────────────────────

    #[test]
    fn test_get_revision_by_hash_found() {
        let mut tree = empty_tree();
        let l = link(0x01);
        tree.revisions.insert(l.clone(), genesis_object());
        assert!(tree.get_revision_by_hash(&l).is_some());
    }

    #[test]
    fn test_get_revision_by_hash_not_found() {
        assert!(empty_tree().get_revision_by_hash(&link(0xFF)).is_none());
    }

    // ── OrderedTree ─────────────────────────────────────────────────────

    #[test]
    fn test_ordered_tree_round_trip() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.file_index.insert(l1.clone(), "test.txt".to_string());
        let ordered = OrderedTree::from_tree(&tree);
        assert_eq!(ordered.revision_order.len(), 2);
        assert_eq!(ordered.revision_order[0], l1);
        assert_eq!(ordered.revision_order[1], l2);
        // Round-trip back to Tree
        let tree2 = ordered.create_tree();
        assert_eq!(tree2.revisions.len(), 2);
        assert_eq!(tree2.file_index.len(), 1);
    }

    // ── order_revisions_dag ────────────────────────────────────────────

    #[test]
    fn test_dag_empty_tree() {
        assert!(empty_tree().order_revisions_dag().is_empty());
    }

    #[test]
    fn test_dag_single_revision() {
        let mut tree = empty_tree();
        let l = link(0x01);
        tree.revisions.insert(l.clone(), genesis_object());
        let dag = tree.order_revisions_dag();
        assert_eq!(dag.len(), 1);
        assert_eq!(dag[0].link, l);
        assert_eq!(dag[0].edge_type, "chain");
        assert!(dag[0].parent.is_none());
        assert_eq!(dag[0].depth, 0);
    }

    #[test]
    fn test_dag_chain_only() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let l3 = link(0x03);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.revisions
            .insert(l3.clone(), chained_object(l2.clone()));
        let dag = tree.order_revisions_dag();
        assert_eq!(dag.len(), 3);
        assert!(dag.iter().all(|d| d.edge_type == "chain"));
        assert_eq!(dag[0].depth, 0);
        assert_eq!(dag[1].depth, 1);
        assert_eq!(dag[2].depth, 2);
    }

    #[test]
    fn test_dag_signature_branch() {
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let l_sig = link(0x10);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.revisions
            .insert(l_sig.clone(), signature_for(l1.clone()));

        let dag = tree.order_revisions_dag();
        assert_eq!(dag.len(), 3);

        // l1 = chain, l_sig = branch off l1, l2 = chain
        let chain: Vec<_> = dag.iter().filter(|d| d.edge_type == "chain").collect();
        let branches: Vec<_> = dag.iter().filter(|d| d.edge_type == "branch").collect();
        assert_eq!(chain.len(), 2);
        assert_eq!(branches.len(), 1);
        assert_eq!(branches[0].link, l_sig);
        assert_eq!(branches[0].parent, Some(l1.clone()));
    }

    #[test]
    fn test_dag_multi_signature_fork() {
        // genesis(l1) → object(l2), sig(ls1) off l1, sig(ls2) off l1
        // Both sigs fork from l1; l2 is the chain successor of l1.
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let ls1 = link(0x10);
        let ls2 = link(0x11);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.revisions
            .insert(ls1.clone(), signature_for(l1.clone()));
        tree.revisions
            .insert(ls2.clone(), signature_for(l1.clone()));

        let dag = tree.order_revisions_dag();
        assert_eq!(dag.len(), 4);

        let branches: Vec<_> = dag.iter().filter(|d| d.edge_type == "branch").collect();
        assert_eq!(branches.len(), 2);
        // Both branches should point to l1
        assert!(branches.iter().all(|b| b.parent == Some(l1.clone())));
    }

    #[test]
    fn test_dag_content_fork() {
        // Two content revisions sharing the same parent (content fork)
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let l3 = link(0x03);
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.revisions
            .insert(l3.clone(), chained_object(l1.clone()));

        let dag = tree.order_revisions_dag();
        assert_eq!(dag.len(), 3);

        // One of l2/l3 should be on the chain, the other a branch
        let chain: Vec<_> = dag.iter().filter(|d| d.edge_type == "chain").collect();
        let branches: Vec<_> = dag.iter().filter(|d| d.edge_type == "branch").collect();
        assert_eq!(chain.len(), 2); // genesis + one successor
        assert_eq!(branches.len(), 1); // the other successor
        assert_eq!(branches[0].parent, Some(l1.clone()));
    }

    #[test]
    fn test_dag_interleaving_order() {
        // Branches should appear immediately after their parent chain revision
        let mut tree = empty_tree();
        let l1 = link(0x01);
        let l2 = link(0x02);
        let l3 = link(0x03);
        let ls1 = link(0x10); // sig on l1
        let ls2 = link(0x20); // sig on l2
        tree.revisions.insert(l1.clone(), genesis_object());
        tree.revisions
            .insert(l2.clone(), chained_object(l1.clone()));
        tree.revisions
            .insert(l3.clone(), chained_object(l2.clone()));
        tree.revisions
            .insert(ls1.clone(), signature_for(l1.clone()));
        tree.revisions
            .insert(ls2.clone(), signature_for(l2.clone()));

        let dag = tree.order_revisions_dag();
        assert_eq!(dag.len(), 5);

        // Expected order: l1, ls1 (branch of l1), l2, ls2 (branch of l2), l3
        assert_eq!(dag[0].link, l1);
        assert_eq!(dag[0].edge_type, "chain");
        assert_eq!(dag[1].link, ls1);
        assert_eq!(dag[1].edge_type, "branch");
        assert_eq!(dag[2].link, l2);
        assert_eq!(dag[2].edge_type, "chain");
        assert_eq!(dag[3].link, ls2);
        assert_eq!(dag[3].edge_type, "branch");
        assert_eq!(dag[4].link, l3);
        assert_eq!(dag[4].edge_type, "chain");
    }
}
