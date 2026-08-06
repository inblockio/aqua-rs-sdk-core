use std::collections::BTreeMap;

use crate::{
    primitives::{
        log::{LogData, LogType},
        RevisionLink,
    },
    schema::{AnyRevision, AquaTreeWrapper},
};

/// The zero (all-zeros) `RevisionLink` used as a headless sentinel anchor.
/// Headless attestations embed this as their genesis anchor link to signal
/// "no linked claim" without introducing a dangling reference.
#[inline]
fn is_zero_link(link: &RevisionLink) -> bool {
    link == &RevisionLink::zero()
}

/// Resolve anchor structural_links against intra-tree revisions,
/// external linked_trees, and built-in template trees.
pub(crate) fn resolve_anchor_links(
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
    linked_trees: &[AquaTreeWrapper],
) -> (bool, Vec<LogData>) {
    let mut logs: Vec<LogData> = Vec::new();
    let mut is_valid = true;

    for (revision_hash, revision) in revisions {
        if let AnyRevision::Anchor(anchor) = revision {
            for link_hash in anchor.structural_links() {
                // Zero-hash sentinel: headless attestation — no linked claim by design.
                // Passes structural validation; WASM detects this via ctx_linked_tree_count().
                if is_zero_link(link_hash) {
                    logs.push(LogData {
                        log: format!(
                            "Anchor {revision_hash} carries zero-hash sentinel — headless attestation (structural pass)"
                        ),
                        log_type: LogType::Info,
                        ident: None,
                    });
                    continue;
                }

                // Intra-tree: the linked revision exists in this tree
                if revisions.contains_key(link_hash) {
                    continue;
                }

                // Cross-tree: the referenced revision exists in a linked tree.
                // Structural links are content-addressed revision references,
                // so containment (not tip equality) is the resolution test: a
                // template tree whose tip is a vendor signature branch still
                // resolves links to its template revision (same semantics as
                // resolve_template).
                let found_external = linked_trees
                    .iter()
                    .any(|lt| lt.aqua_tree.revisions.contains_key(link_hash));
                if found_external {
                    continue;
                }

                // Built-in template tree: link matches a known template tip
                if super::verify_stages::is_builtin_template_link(link_hash) {
                    continue;
                }

                // Unresolved link — anchor MUST be rejected (spec §6 MUST)
                logs.push(LogData {
                    log: format!(
                        "Anchor {revision_hash} references unresolved structural link {link_hash}"
                    ),
                    log_type: LogType::Error,
                    ident: None,
                });
                is_valid = false;
            }
        }
    }

    (is_valid, logs)
}

/// Cycle detection: walk chains backward, reject if any revision appears
/// in its own ancestor chain.
pub(crate) fn verify_no_cycles(
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
) -> (bool, Vec<LogData>) {
    let mut logs: Vec<LogData> = Vec::new();
    let mut is_valid = true;
    let mut explored: std::collections::HashSet<RevisionLink> = std::collections::HashSet::new();

    for hash in revisions.keys() {
        let mut path: std::collections::HashSet<RevisionLink> = std::collections::HashSet::new();
        let mut current = Some(hash.clone());
        while let Some(h) = current {
            if !path.insert(h.clone()) {
                logs.push(LogData {
                    log: format!("Cycle detected: revision {h} appears in its own ancestor chain"),
                    log_type: LogType::Error,
                    ident: None,
                });
                is_valid = false;
                break;
            }
            if !explored.insert(h.clone()) {
                break;
            }
            current = revisions
                .get(&h)
                .and_then(|r| r.get_previous_revision_hash());
        }
    }

    (is_valid, logs)
}

/// Reference existence: check every previous_revision points to a revision in the tree.
pub(crate) fn verify_reference_existence(
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
) -> (bool, Vec<LogData>) {
    let mut logs: Vec<LogData> = Vec::new();
    let mut is_valid = true;

    for (hash, revision) in revisions {
        if let Some(prev_hash) = revision.get_previous_revision_hash() {
            if !revisions.contains_key(&prev_hash) {
                logs.push(LogData {
                    log: format!(
                        "Broken chain: revision {hash} references non-existent previous {prev_hash}"
                    ),
                    log_type: LogType::Error,
                    ident: None,
                });
                is_valid = false;
            }
        }
    }

    (is_valid, logs)
}

/// Timestamp ordering: non-decreasing timestamps within each chain.
pub(crate) fn verify_timestamps(
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
) -> (bool, Vec<LogData>) {
    let mut logs: Vec<LogData> = Vec::new();
    let mut is_valid = true;

    for (hash, revision) in revisions {
        if let Some(prev_hash) = revision.get_previous_revision_hash() {
            if let Some(prev_revision) = revisions.get(&prev_hash) {
                let current_ts = revision.get_local_timestamp().as_secs();
                let prev_ts = prev_revision.get_local_timestamp().as_secs();
                if current_ts < prev_ts {
                    logs.push(LogData {
                        log: format!(
                            "Timestamp violation: revision {hash} (ts={current_ts}) precedes previous {prev_hash} (ts={prev_ts})"
                        ),
                        log_type: LogType::Error,
                        ident: None,
                    });
                    is_valid = false;
                }
            }
        }
    }

    (is_valid, logs)
}

/// Find which linked tree indices a tree's anchors depend on.
pub(super) fn get_tree_dependencies(
    revisions: &BTreeMap<RevisionLink, AnyRevision>,
    link_to_idx: &std::collections::HashMap<RevisionLink, usize>,
) -> Vec<usize> {
    let mut deps = Vec::new();
    for revision in revisions.values() {
        if let AnyRevision::Anchor(anchor) = revision {
            for link_hash in anchor.structural_links() {
                if revisions.contains_key(link_hash) {
                    continue; // intra-tree link
                }
                if let Some(&idx) = link_to_idx.get(link_hash) {
                    if !deps.contains(&idx) {
                        deps.push(idx);
                    }
                }
            }
        }
    }
    deps
}

/// DFS post-order for topological sort. Returns false if a cycle is detected.
pub(super) fn topo_dfs(
    node: usize,
    adj: &std::collections::HashMap<usize, Vec<usize>>,
    visited: &mut std::collections::HashSet<usize>,
    in_progress: &mut std::collections::HashSet<usize>,
    order: &mut Vec<usize>,
) -> bool {
    if in_progress.contains(&node) {
        return false; // cycle
    }
    if visited.contains(&node) {
        return true;
    }
    in_progress.insert(node);
    if let Some(deps) = adj.get(&node) {
        for &dep in deps {
            if !topo_dfs(dep, adj, visited, in_progress, order) {
                return false;
            }
        }
    }
    in_progress.remove(&node);
    visited.insert(node);
    order.push(node);
    true
}

/// Collect all linked trees in topological order (dependencies first).
/// Detects cross-tree cycles (including cycles through the main tree).
/// Deduplicates by index.
pub(crate) fn collect_linked_tree_order(
    main_tree: &AquaTreeWrapper,
    linked_trees: &[AquaTreeWrapper],
) -> Result<Vec<usize>, Vec<LogData>> {
    if linked_trees.is_empty() {
        return Ok(vec![]);
    }

    // Virtual node index for the main tree in the dependency graph
    const MAIN_NODE: usize = usize::MAX;

    // Map EVERY revision hash → owning tree index (MAIN_NODE for the main
    // tree). Structural links are content-addressed revision references, so a
    // dependency edge exists when an anchor references ANY revision of a tree,
    // not only its tip: a template tree whose tip is a vendor signature branch
    // must still be ordered (and verified) when an anchor links its template
    // revision. Revision hashes are globally unique (content addressing), so
    // cross-tree key collisions only occur for identical revisions.
    let mut link_to_idx: std::collections::HashMap<RevisionLink, usize> =
        std::collections::HashMap::new();
    for link in main_tree.aqua_tree.revisions.keys() {
        link_to_idx.insert(link.clone(), MAIN_NODE);
    }
    for (i, lt) in linked_trees.iter().enumerate() {
        for link in lt.aqua_tree.revisions.keys() {
            link_to_idx.insert(link.clone(), i);
        }
    }

    // Build dependency graph: adj[i] = indices that tree i depends on
    let mut adj: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();

    // Main tree's dependencies on linked trees
    let main_deps: Vec<usize> = get_tree_dependencies(&main_tree.aqua_tree.revisions, &link_to_idx)
        .into_iter()
        .filter(|&d| d != MAIN_NODE)
        .collect();
    if !main_deps.is_empty() {
        adj.insert(MAIN_NODE, main_deps);
    }

    // Linked trees' dependencies (may include MAIN_NODE)
    for (i, lt) in linked_trees.iter().enumerate() {
        let deps = get_tree_dependencies(&lt.aqua_tree.revisions, &link_to_idx);
        if !deps.is_empty() {
            adj.insert(i, deps);
        }
    }

    // Topological sort only trees reachable from the main tree's anchor dependencies.
    // Starting from MAIN_NODE's direct deps and letting DFS recurse transitively ensures
    // unreferenced linked trees are never verified (they contribute nothing to the result).
    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut in_progress: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut order: Vec<usize> = Vec::new();

    let roots: Vec<usize> = adj.get(&MAIN_NODE).cloned().unwrap_or_default();
    for dep in roots {
        if !topo_dfs(dep, &adj, &mut visited, &mut in_progress, &mut order) {
            return Err(vec![LogData {
                log: "Cross-tree cycle detected in linked trees".to_string(),
                log_type: LogType::Error,
                ident: None,
            }]);
        }
    }

    // Filter out MAIN_NODE — only return linked tree indices
    Ok(order.into_iter().filter(|&i| i != MAIN_NODE).collect())
}
