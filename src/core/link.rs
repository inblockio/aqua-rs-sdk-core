use std::collections::BTreeMap;

use crate::{
    primitives::{log::LogData, HashType, Method, MethodError, RevisionLink},
    schema::{tree::Tree, Anchor, AnyRevision, AquaTreeWrapper, CompositionalLink},
    verification::Linkable,
};

pub fn link_aqua_tree_util(
    aqua_tree_wrapper: AquaTreeWrapper,
    link_aqua_tree_wrapper: Vec<AquaTreeWrapper>,
    method: Method,
) -> Result<Tree, MethodError> {
    let mut logs: Vec<LogData> = Vec::new();
    if link_aqua_tree_wrapper.is_empty() {
        logs.push(LogData {
            log_type: crate::primitives::log::LogType::Error,
            log: "No link aqua trees provided".to_string(),
            ident: None,
        });
        return Err(MethodError::WithLogs(logs));
    }

    let mut file_index_data: BTreeMap<RevisionLink, String> = BTreeMap::new();
    let mut revision_data: BTreeMap<RevisionLink, AnyRevision> = BTreeMap::new();

    // seed the vectors with the data from the main aqua tree wrapper
    for revision_item in &aqua_tree_wrapper.aqua_tree.revisions {
        revision_data.insert(revision_item.0.clone(), revision_item.1.clone());
    }

    for file_index_item in &aqua_tree_wrapper.aqua_tree.file_index {
        file_index_data.insert(file_index_item.0.clone(), file_index_item.1.clone());
    }

    let latest_revision = match aqua_tree_wrapper.revision {
        None => aqua_tree_wrapper.aqua_tree.get_latest_revision_link(),
        Some(e) => Some(e),
    };
    // let latest_revision_data = latest_revision.unwrap();
    let latest_revision_data = match latest_revision {
        Some(rev) => rev,
        None => {
            logs.push(LogData {
                log_type: crate::primitives::log::LogType::Error,
                log: "No revision found in aqua tree".to_string(),
                ident: None,
            });
            return Err(MethodError::WithLogs(logs));
        }
    };

    let mut links: Vec<RevisionLink> = Vec::new();

    for aqua_tree_wrapper_item in link_aqua_tree_wrapper {
        let aqua_tree_item = aqua_tree_wrapper_item.aqua_tree;
        let link_latest_revision = aqua_tree_item.get_latest_revision_link();

        match link_latest_revision {
            Some(link_hash) => {
                links.push(link_hash.clone());

                // Map the linked tip hash (which ends up in
                // compositional_links) to the child's actual
                // file name in the parent's file_index.
                if let Some(file_name) = aqua_tree_item.get_main_file_name() {
                    file_index_data.insert(link_hash, file_name);
                } else {
                    logs.push(LogData {
                        log_type: crate::primitives::log::LogType::Error,
                        log: "File name for link aqua tree not found".to_string(),
                        ident: None,
                    });
                    return Err(MethodError::WithLogs(logs));
                }
            }
            None => {
                logs.push(LogData {
                    log_type: crate::primitives::log::LogType::Error,
                    log: "Revision item for Aqua tree in link aqua trees not found (its skipped) "
                        .to_string(),
                    ident: None,
                });

                continue;
            }
        }
    }

    let compositional: Vec<CompositionalLink> = links
        .into_iter()
        .map(CompositionalLink::composition)
        .collect();
    let hash_type = HashType::Sha3_256;
    let mut link_revision = Anchor::with_links(
        latest_revision_data,
        method,
        Vec::new(),    // no structural links
        compositional, // compositional links
    );

    let verification_hash = link_revision.calculate_link(hash_type)?;
    link_revision.populate_leaves(hash_type)?;

    revision_data.insert(
        verification_hash.clone(),
        AnyRevision::Anchor(link_revision),
    );

    Ok(Tree {
        revisions: revision_data,
        file_index: file_index_data,
    })
}
