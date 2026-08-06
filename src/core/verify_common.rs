//! Shared helper functions used by both async and sync verification pipelines.
//!
//! Extracted to eliminate duplication between `verify_aqua_tree_util` (async)
//! and `verify_aqua_tree_sync` (sync).

use std::collections::HashMap;

use crate::core::verification_policy::{
    DecisionPoint, PolicyWarning, Severity, VerificationError, VerificationOutcome,
};
use crate::primitives::log::{LogData, LogType};
use crate::primitives::merkle::{batch_leaf_hash, verify_inclusion};
use crate::primitives::{hex_to_bytes, HashType, RevisionLink};
use crate::schema::{AnyRevision, AquaTreeWrapper};

/// Apply a policy severity to a governed verification decision point.
///
/// Records the decision into the appropriate accumulator and reports whether it
/// is fatal: `Severity::Fail` pushes a `VerificationError` (fatal, returns
/// `true`); `Severity::Warn` pushes a `PolicyWarning` (non-fatal, returns
/// `false`). Shared by the async and sync pipelines so both apply identical
/// policy logic for identical input.
pub(crate) fn apply_policy_decision(
    severity: Severity,
    decision_point: DecisionPoint,
    revision_hash: &str,
    code: &str,
    message: String,
    errors: &mut Vec<VerificationError>,
    warnings: &mut Vec<PolicyWarning>,
) -> bool {
    match severity {
        Severity::Fail => {
            errors.push(VerificationError {
                code: code.to_string(),
                revision_hash: revision_hash.to_string(),
                message,
            });
            true
        }
        Severity::Warn => {
            warnings.push(PolicyWarning {
                decision_point,
                revision_hash: revision_hash.to_string(),
                message,
            });
            false
        }
    }
}

/// Reduce the accumulated errors and warnings into a final outcome.
///
/// Any error means `Failed`; otherwise any warning means `VerifiedWithWarnings`;
/// otherwise `Verified`.
pub(crate) fn build_outcome(
    errors: Vec<VerificationError>,
    warnings: Vec<PolicyWarning>,
) -> VerificationOutcome {
    if !errors.is_empty() {
        VerificationOutcome::Failed(errors)
    } else if !warnings.is_empty() {
        VerificationOutcome::VerifiedWithWarnings(warnings)
    } else {
        VerificationOutcome::Verified
    }
}

/// Build the ordered chain of (RevisionLink, JSON Value) pairs from a tree.
pub(crate) fn build_chain(
    aqua_tree_wrapper: &AquaTreeWrapper,
) -> Vec<(RevisionLink, serde_json::Value)> {
    let ordered = aqua_tree_wrapper.aqua_tree.order_revisions();
    ordered
        .iter()
        .map(|(link, rev)| (link.clone(), serde_json::to_value(rev).unwrap_or_default()))
        .collect()
}

/// Build fork-topology branches for each chain position.
///
/// Signatures and anchors are ALWAYS branches (even if they are the next
/// chain node). Only content revisions that are the next chain node are
/// excluded.
pub(crate) fn build_branches(
    aqua_tree_wrapper: &AquaTreeWrapper,
    chain: &[(RevisionLink, serde_json::Value)],
) -> Vec<Vec<serde_json::Value>> {
    let revisions = &aqua_tree_wrapper.aqua_tree.revisions;
    chain
        .iter()
        .enumerate()
        .map(|(i, (chain_link, _))| {
            let next_chain_hash = chain.get(i + 1).map(|(link, _)| link);
            let mut branch_revs: Vec<(RevisionLink, serde_json::Value)> = revisions
                .iter()
                .filter(|(rev_hash, rev)| {
                    let prev_matches =
                        rev.get_previous_revision_hash().as_ref() == Some(chain_link);
                    if !prev_matches {
                        return false;
                    }
                    let is_branch_type =
                        matches!(rev, AnyRevision::Signature(_) | AnyRevision::Anchor(_));
                    is_branch_type || Some(rev_hash) != next_chain_hash.as_ref()
                })
                .map(|(rev_hash, rev)| {
                    (
                        rev_hash.clone(),
                        serde_json::to_value(rev).unwrap_or_default(),
                    )
                })
                .collect();
            branch_revs.sort_by(|(a, _), (b, _)| a.cmp(b));
            branch_revs.into_iter().map(|(_, v)| v).collect()
        })
        .collect()
}

/// Wall-clock Unix timestamp in seconds (for ephemeral/non-daemon mode).
pub(crate) fn current_time_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Flatten all revisions from verified linked trees into JSON values.
pub(crate) fn build_linked_revisions(
    verified_linked: &[AquaTreeWrapper],
) -> Vec<serde_json::Value> {
    verified_linked
        .iter()
        .flat_map(|lt| lt.aqua_tree.revisions.values())
        .map(|rev| serde_json::to_value(rev).unwrap_or_default())
        .collect()
}

/// Extract the WASM state string for each verified linked tree.
pub(crate) fn build_linked_tree_states(
    verified_linked: &[AquaTreeWrapper],
    lt_wasm_outputs: &[HashMap<String, serde_json::Value>],
) -> Vec<String> {
    verified_linked
        .iter()
        .zip(lt_wasm_outputs.iter())
        .map(|(lt, wasm_out)| {
            lt.aqua_tree
                .revisions
                .iter()
                .find(|(_, rev)| matches!(rev, AnyRevision::Typed(_)))
                .and_then(|(hash, _)| wasm_out.get(&hash.to_string()))
                .and_then(|v| v.get("state"))
                .and_then(|s| s.as_str())
                .map(String::from)
                .unwrap_or_default()
        })
        .collect()
}

/// Extract the payloads field from each verified linked tree's Object revision.
pub(crate) fn build_linked_tree_payloads(
    verified_linked: &[AquaTreeWrapper],
) -> Vec<serde_json::Value> {
    verified_linked
        .iter()
        .map(|lt| {
            lt.aqua_tree
                .revisions
                .iter()
                .find(|(_, rev)| matches!(rev, AnyRevision::Typed(_)))
                .and_then(|(_, rev)| serde_json::to_value(rev).ok())
                .and_then(|v| v.get("payloads").cloned())
                .unwrap_or(serde_json::Value::Null)
        })
        .collect()
}

// ── Stage 2.5: Batch inclusion proof verification for timestamp revisions ──
// Verifies that the timestamped revision hash appears in the batch Merkle tree
// declared by the timestamp payloads. Runs after schema validation (Stage 2)
// and before WASM compute (Stage 3).



/// Verify the Merkle inclusion proof embedded in a timestamp revision's payloads.
///
/// The `target_revision_hash` is the hash of the revision being timestamped
/// (i.e., the `previous_revision` field of the timestamp revision; the `0x`
/// prefix is accepted on either side).
///
/// For single-leaf batches (`batch_tree_size == 1`) the proof degenerates to
/// `merkle_root == target_revision_hash`.  For multi-leaf batches the full
/// RFC 9162 inclusion proof is verified via `verify_inclusion`.
/// PCA-0015 §3.11.7: naming-value hex MUST be lowercase. `hex_to_bytes` itself
/// is case-insensitive, so callers handling naming values route through here first.
fn reject_uppercase_hex(
    field: &str,
    value: &str,
    indent: &str,
    base_logs: &[LogData],
) -> Result<(), (bool, String, Vec<LogData>)> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    if stripped.contains(|c: char| c.is_ascii_uppercase()) {
        let mut logs = base_logs.to_vec();
        logs.push(LogData {
            log: format!("{field} contains uppercase hex (must be lowercase, §3.11.7)"),
            log_type: LogType::Error,
            ident: Some(indent.to_string()),
        });
        return Err((false, "MERKLE_HEX_NOT_LOWERCASE".to_string(), logs));
    }
    Ok(())
}

/// PCA-0015: the `merkle_root` wire value is a multihash. Batch roots always use
/// SHA3-256 (PCA-0001/0002) regardless of the revision algorithm, so decode the
/// multihash, enforce the SHA3-256 codec, and return the bare 32-byte root digest.
fn decode_batch_merkle_root(
    merkle_root: &str,
    indent: &str,
    base_logs: &[LogData],
) -> Result<Vec<u8>, (bool, String, Vec<LogData>)> {
    reject_uppercase_hex("merkle_root", merkle_root, indent, base_logs)?;
    let mh = hex_to_bytes(merkle_root.strip_prefix("0x").unwrap_or(merkle_root)).map_err(|e| {
        let mut logs = base_logs.to_vec();
        logs.push(LogData {
            log: format!("Failed to decode merkle_root hex: {e}"),
            log_type: LogType::Error,
            ident: Some(indent.to_string()),
        });
        (false, "MERKLE_HEX_DECODE_FAILED".to_string(), logs)
    })?;
    match crate::primitives::multihash_decode(&mh) {
        Ok((HashType::Sha3_256, digest)) => Ok(digest),
        Ok((other, _)) => {
            let mut logs = base_logs.to_vec();
            logs.push(LogData {
                log: format!(
                    "merkle_root multihash codec is {other:?}; batch roots MUST be SHA3-256"
                ),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            Err((false, "MERKLE_ROOT_BAD_CODEC".to_string(), logs))
        }
        Err(e) => {
            let mut logs = base_logs.to_vec();
            logs.push(LogData {
                log: format!("merkle_root is not a valid multihash: {e}"),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            Err((false, "MERKLE_ROOT_BAD_MULTIHASH".to_string(), logs))
        }
    }
}

pub(crate) fn verify_batch_inclusion(
    payloads: &serde_json::Value,
    target_revision_hash: &str,
    indent: &str,
) -> Result<Vec<LogData>, (bool, String, Vec<LogData>)> {
    let mut logs: Vec<LogData> = Vec::new();

    // Extract required fields from payloads.
    let merkle_root = match payloads.get("merkle_root").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            logs.push(LogData {
                log: "Timestamp payload missing required merkle_root field".to_string(),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "MERKLE_ROOT_MISSING".to_string(), logs));
        }
    };

    let batch_tree_size = match payloads.get("batch_tree_size").and_then(|v| v.as_u64()) {
        Some(v) => v as usize,
        None => {
            logs.push(LogData {
                log: "Timestamp payload missing required batch_tree_size field".to_string(),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "BATCH_TREE_SIZE_MISSING".to_string(), logs));
        }
    };

    let batch_leaf_index = match payloads.get("batch_leaf_index").and_then(|v| v.as_u64()) {
        Some(v) => v as usize,
        None => {
            logs.push(LogData {
                log: "Timestamp payload missing required batch_leaf_index field".to_string(),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "BATCH_LEAF_INDEX_MISSING".to_string(), logs));
        }
    };

    let merkle_proof: Vec<String> = match payloads.get("merkle_proof").and_then(|v| v.as_array()) {
        Some(arr) => arr
            .iter()
            .filter_map(|e| e.as_str().map(String::from))
            .collect(),
        None => {
            logs.push(LogData {
                log: "Timestamp payload missing required merkle_proof field".to_string(),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "MERKLE_PROOF_MISSING".to_string(), logs));
        }
    };

    // Strip "0x" from the target hash to get the raw hex leaf value.
    let leaf_hex = target_revision_hash
        .strip_prefix("0x")
        .unwrap_or(target_revision_hash);

    if batch_tree_size == 0 {
        logs.push(LogData {
            log: "batch_tree_size must be >= 1, got 0".to_string(),
            log_type: LogType::Error,
            ident: Some(indent.to_string()),
        });
        return Err((false, "BATCH_TREE_SIZE_ZERO".to_string(), logs));
    }

    let shielding_nonce = match payloads.get("shielding_nonce").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            logs.push(LogData {
                log: "Timestamp payload missing required shielding_nonce field".to_string(),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "SHIELDING_NONCE_MISSING".to_string(), logs));
        }
    };

    // Decode raw revision hash and shielding nonce, then compute two-stage
    // leaf: shielded = H(raw || nonce), merkle_leaf = H(0x00 || shielded).
    let make_hex_err = |field: &str, e: String| {
        let mut logs = logs.clone();
        logs.push(LogData {
            log: format!("Failed to decode {field} hex: {e}"),
            log_type: LogType::Error,
            ident: Some(indent.to_string()),
        });
        (false, "MERKLE_HEX_DECODE_FAILED".to_string(), logs)
    };
    let raw_leaf_bytes = hex_to_bytes(leaf_hex).map_err(|e| make_hex_err("leaf hash", e))?;
    reject_uppercase_hex("shielding_nonce", &shielding_nonce, indent, &logs)?;
    let nonce_hex = shielding_nonce
        .strip_prefix("0x")
        .unwrap_or(&shielding_nonce);
    let nonce_bytes = hex_to_bytes(nonce_hex).map_err(|e| make_hex_err("shielding_nonce", e))?;

    let hash_type = HashType::Sha3_256;
    let mut shielded_input = Vec::with_capacity(64);
    shielded_input.extend_from_slice(&raw_leaf_bytes);
    shielded_input.extend_from_slice(&nonce_bytes);
    let shielded = hash_type.hash(&shielded_input);
    let leaf_bytes = batch_leaf_hash(&hash_type, &shielded);

    if batch_tree_size == 1 {
        // PCA-0015: merkle_root is a SHA3-256 multihash; compare the bare leaf
        // digest against the bare root digest recovered from it.
        let root_bytes = decode_batch_merkle_root(&merkle_root, indent, &logs)?;

        if leaf_bytes != root_bytes {
            logs.push(LogData {
                log: format!(
                    "Batch inclusion check failed: merkle_root ({merkle_root}) does not match \
                     domain-separated leaf hash of target revision ({target_revision_hash})"
                ),
                log_type: LogType::Error,
                ident: Some(indent.to_string()),
            });
            return Err((false, "MERKLE_ROOT_MISMATCH".to_string(), logs));
        }

        logs.push(LogData {
            log: "Batch inclusion proof verified (single-leaf batch)".to_string(),
            log_type: LogType::Success,
            ident: Some(indent.to_string()),
        });
        return Ok(logs);
    }

    // Multi-leaf batch: validate index bounds first.
    if batch_leaf_index >= batch_tree_size {
        logs.push(LogData {
            log: format!(
                "Batch inclusion check failed: leaf index {batch_leaf_index} is out of bounds \
                 for tree size {batch_tree_size}"
            ),
            log_type: LogType::Error,
            ident: Some(indent.to_string()),
        });
        return Err((false, "MERKLE_LEAF_INDEX_OUT_OF_BOUNDS".to_string(), logs));
    }

    let root_bytes = decode_batch_merkle_root(&merkle_root, indent, &logs)?;
    // Proof siblings are bare interior digests; enforce lowercase then decode.
    for sib in &merkle_proof {
        reject_uppercase_hex("merkle_proof", sib, indent, &logs)?;
    }
    let proof_bytes: Vec<Vec<u8>> = merkle_proof
        .iter()
        .map(|s| hex_to_bytes(s.strip_prefix("0x").unwrap_or(s)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| make_hex_err("merkle_proof", e))?;

    if !verify_inclusion(
        &leaf_bytes,
        batch_leaf_index,
        batch_tree_size,
        &proof_bytes,
        &root_bytes,
        &HashType::Sha3_256,
    ) {
        logs.push(LogData {
            log: format!(
                "Batch inclusion proof verification failed for leaf index {batch_leaf_index} \
                 in tree of size {batch_tree_size}"
            ),
            log_type: LogType::Error,
            ident: Some(indent.to_string()),
        });
        return Err((false, "MERKLE_INCLUSION_FAILED".to_string(), logs));
    }

    logs.push(LogData {
        log: format!(
            "Batch inclusion proof verified (leaf {batch_leaf_index} of {batch_tree_size})"
        ),
        log_type: LogType::Success,
        ident: Some(indent.to_string()),
    });

    Ok(logs)
}

/// One executable entry in a template chain (root first, child last):
/// a template's identity hash together with its `verification` section.
#[derive(Debug)]
pub(crate) struct ChainVerification {
    pub template_hash: RevisionLink,
    /// The template's verification section. Collected for chain-shape
    /// fidelity with the full SDK; core never executes it (D7).
    #[allow(dead_code)]
    pub verification: crate::core::compute::TemplateVerification,
}


#[cfg(test)]
mod tests {
    use super::*;

    // ── hex_to_bytes ─────────────────────────────────────────────────────────

    #[test]
    fn hex_to_bytes_strips_prefix() {
        let with_prefix = hex_to_bytes("0xdeadbeef").unwrap();
        let without_prefix = hex_to_bytes("deadbeef").unwrap();
        assert_eq!(with_prefix, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(with_prefix, without_prefix);
    }

    #[test]
    fn hex_to_bytes_empty_string() {
        assert!(hex_to_bytes("").unwrap().is_empty());
        assert!(hex_to_bytes("0x").unwrap().is_empty());
    }

    #[test]
    fn hex_to_bytes_rejects_odd_length() {
        assert!(hex_to_bytes("0xabc").is_err());
        assert!(hex_to_bytes("abc").is_err());
    }

    #[test]
    fn hex_to_bytes_rejects_non_hex() {
        assert!(hex_to_bytes("0xzzzz").is_err());
        assert!(hex_to_bytes("ghij").is_err());
    }

    // ── verify_batch_inclusion — single-leaf batch ────────────────────────────

    fn make_hash_hex(byte: u8) -> String {
        format!("0x{}", hex::encode(vec![byte; 32]))
    }

    fn make_nonce_hex(byte: u8) -> String {
        format!("0x{}", hex::encode(vec![byte; 32]))
    }

    /// PCA-0015: batch `merkle_root` is a SHA3-256 multihash on the wire.
    fn make_root_hex(bare_root: &[u8]) -> String {
        format!(
            "0x{}",
            hex::encode(crate::primitives::multihash_encode(
                crate::primitives::HashType::Sha3_256,
                bare_root
            ))
        )
    }

    fn compute_shielded(raw: &[u8], nonce: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(raw);
        input.extend_from_slice(nonce);
        HashType::Sha3_256.hash(&input)
    }

    #[test]
    fn single_leaf_match_passes() {
        use crate::primitives::merkle::batch_leaf_hash;
        use crate::primitives::HashType;

        let target_hash = make_hash_hex(0xAA);
        let raw_bytes = vec![0xAA; 32];
        let nonce = vec![0x11; 32];
        let nonce_hex = make_nonce_hex(0x11);
        let shielded = compute_shielded(&raw_bytes, &nonce);
        let leaf = batch_leaf_hash(&HashType::Sha3_256, &shielded);
        let root_hex = make_root_hex(&leaf);

        let payloads = serde_json::json!({
            "merkle_root": root_hex,
            "batch_tree_size": 1,
            "batch_leaf_index": 0,
            "merkle_proof": [],
            "shielding_nonce": nonce_hex
        });
        let result = verify_batch_inclusion(&payloads, &target_hash, "\t");
        assert!(
            result.is_ok(),
            "matching single-leaf should pass: {result:?}"
        );
        let logs = result.unwrap();
        assert!(logs.iter().any(|l| l.log.contains("single-leaf")));
    }

    #[test]
    fn batch_tree_size_zero_rejected() {
        let hash = make_hash_hex(0xAA);
        let payloads = serde_json::json!({
            "merkle_root": hash,
            "batch_tree_size": 0,
            "batch_leaf_index": 0,
            "merkle_proof": [],
            "shielding_nonce": make_nonce_hex(0x11)
        });
        let result = verify_batch_inclusion(&payloads, &hash, "\t");
        assert!(result.is_err());
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "BATCH_TREE_SIZE_ZERO");
    }

    #[test]
    fn missing_merkle_proof_fails() {
        let hash = make_hash_hex(0xAA);
        let payloads = serde_json::json!({
            "merkle_root": hash,
            "batch_tree_size": 1,
            "batch_leaf_index": 0
        });
        let result = verify_batch_inclusion(&payloads, &hash, "\t");
        assert!(result.is_err());
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "MERKLE_PROOF_MISSING");
    }

    #[test]
    fn single_leaf_mismatch_fails() {
        let hash_a = make_root_hex(&vec![0xAA; 32]);
        let hash_b = make_hash_hex(0xBB);
        let nonce_hex = make_nonce_hex(0x11);
        let payloads = serde_json::json!({
            "merkle_root": hash_a,
            "batch_tree_size": 1,
            "batch_leaf_index": 0,
            "merkle_proof": [],
            "shielding_nonce": nonce_hex
        });
        let result = verify_batch_inclusion(&payloads, &hash_b, "\t");
        assert!(result.is_err());
        let (valid, code, _) = result.unwrap_err();
        assert!(!valid);
        assert_eq!(code, "MERKLE_ROOT_MISMATCH");
    }

    #[test]
    fn missing_merkle_root_fails() {
        let payloads = serde_json::json!({ "timestamp": 1234567890 });
        let result = verify_batch_inclusion(&payloads, "0xdeadbeef", "\t");
        assert!(result.is_err());
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "MERKLE_ROOT_MISSING");
    }

    #[test]
    fn missing_batch_tree_size_fails() {
        let hash = make_hash_hex(0xAA);
        let payloads = serde_json::json!({
            "merkle_root": hash,
            "merkle_proof": [],
            "batch_leaf_index": 0
        });
        let result = verify_batch_inclusion(&payloads, &hash, "\t");
        assert!(result.is_err());
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "BATCH_TREE_SIZE_MISSING");
    }

    #[test]
    fn missing_batch_leaf_index_fails() {
        let hash = make_hash_hex(0xAA);
        let payloads = serde_json::json!({
            "merkle_root": hash,
            "merkle_proof": [],
            "batch_tree_size": 1
        });
        let result = verify_batch_inclusion(&payloads, &hash, "\t");
        assert!(result.is_err());
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "BATCH_LEAF_INDEX_MISSING");
    }

    #[test]
    fn missing_shielding_nonce_fails() {
        let hash = make_hash_hex(0xAA);
        let payloads = serde_json::json!({
            "merkle_root": hash,
            "batch_tree_size": 1,
            "batch_leaf_index": 0,
            "merkle_proof": []
        });
        let result = verify_batch_inclusion(&payloads, &hash, "\t");
        assert!(result.is_err());
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "SHIELDING_NONCE_MISSING");
    }

    // ── verify_batch_inclusion — multi-leaf batch ─────────────────────────────

    #[test]
    fn out_of_bounds_leaf_index_fails() {
        let hash = make_hash_hex(0xAA);
        let payloads = serde_json::json!({
            "merkle_root": hash,
            "batch_tree_size": 4,
            "batch_leaf_index": 4,   // == tree_size, out of bounds
            "merkle_proof": [],
            "shielding_nonce": make_nonce_hex(0x11)
        });
        let result = verify_batch_inclusion(&payloads, &hash, "\t");
        assert!(result.is_err());
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "MERKLE_LEAF_INDEX_OUT_OF_BOUNDS");
    }

    /// Build a real 2-leaf shielded Merkle tree and verify inclusion.
    ///
    /// Leaves are H(0x00 || H(raw || nonce)) per membership shielding + RFC 6962.
    #[test]
    fn two_leaf_valid_inclusion_proof_passes() {
        use crate::primitives::merkle::{batch_leaf_hash, inclusion_proof, merkle_root};
        use crate::primitives::HashType;

        let h0_raw: Vec<u8> = vec![0xAA; 32];
        let h1_raw: Vec<u8> = vec![0xBB; 32];
        let n0: Vec<u8> = vec![0x11; 32];
        let n1: Vec<u8> = vec![0x22; 32];

        let s0 = compute_shielded(&h0_raw, &n0);
        let s1 = compute_shielded(&h1_raw, &n1);
        let l0 = batch_leaf_hash(&HashType::Sha3_256, &s0);
        let l1 = batch_leaf_hash(&HashType::Sha3_256, &s1);
        let leaves = vec![l0, l1];

        let root = merkle_root(&leaves, &HashType::Sha3_256);
        let proof = inclusion_proof(&leaves, 0, &HashType::Sha3_256);

        let root_hex = make_root_hex(&root);
        let target_hex = format!("0x{}", hex::encode(&h0_raw));
        let nonce_hex = format!("0x{}", hex::encode(&n0));
        let proof_hexes: Vec<serde_json::Value> = proof
            .iter()
            .map(|p| serde_json::json!(format!("0x{}", hex::encode(p))))
            .collect();

        let payloads = serde_json::json!({
            "merkle_root": root_hex,
            "batch_tree_size": 2,
            "batch_leaf_index": 0,
            "merkle_proof": proof_hexes,
            "shielding_nonce": nonce_hex
        });

        let result = verify_batch_inclusion(&payloads, &target_hex, "\t");
        assert!(result.is_ok(), "valid 2-leaf proof should pass: {result:?}");
        let logs = result.unwrap();
        assert!(logs.iter().any(|l| l.log.contains("leaf 0 of 2")));
    }

    #[test]
    fn two_leaf_wrong_root_fails() {
        use crate::primitives::merkle::{batch_leaf_hash, inclusion_proof, merkle_root};
        use crate::primitives::HashType;

        let h0_raw: Vec<u8> = vec![0xAA; 32];
        let h1_raw: Vec<u8> = vec![0xBB; 32];
        let n0: Vec<u8> = vec![0x11; 32];
        let n1: Vec<u8> = vec![0x22; 32];

        let s0 = compute_shielded(&h0_raw, &n0);
        let s1 = compute_shielded(&h1_raw, &n1);
        let l0 = batch_leaf_hash(&HashType::Sha3_256, &s0);
        let l1 = batch_leaf_hash(&HashType::Sha3_256, &s1);
        let leaves = vec![l0, l1];

        let _root = merkle_root(&leaves, &HashType::Sha3_256);
        let proof = inclusion_proof(&leaves, 0, &HashType::Sha3_256);

        let bad_root_hex = make_root_hex(&vec![0xFF; 32]);
        let target_hex = format!("0x{}", hex::encode(&h0_raw));
        let nonce_hex = format!("0x{}", hex::encode(&n0));
        let proof_hexes: Vec<serde_json::Value> = proof
            .iter()
            .map(|p| serde_json::json!(format!("0x{}", hex::encode(p))))
            .collect();

        let payloads = serde_json::json!({
            "merkle_root": bad_root_hex,
            "batch_tree_size": 2,
            "batch_leaf_index": 0,
            "merkle_proof": proof_hexes,
            "shielding_nonce": nonce_hex
        });

        let result = verify_batch_inclusion(&payloads, &target_hex, "\t");
        assert!(result.is_err());
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "MERKLE_INCLUSION_FAILED");
    }

    // ── Membership shielding tests ──────────────────────────────────────────

    #[test]
    fn four_leaf_shielded_tree_round_trip() {
        use crate::primitives::merkle::{batch_leaf_hash, inclusion_proof, merkle_root};
        use crate::primitives::HashType;

        let raws: Vec<Vec<u8>> = (1u8..=4).map(|i| vec![i; 32]).collect();
        let nonces: Vec<Vec<u8>> = (0xA1u8..=0xA4).map(|i| vec![i; 32]).collect();

        let leaves: Vec<Vec<u8>> = raws
            .iter()
            .zip(nonces.iter())
            .map(|(r, n)| {
                let shielded = compute_shielded(r, n);
                batch_leaf_hash(&HashType::Sha3_256, &shielded)
            })
            .collect();

        let root = merkle_root(&leaves, &HashType::Sha3_256);
        let root_hex = make_root_hex(&root);

        for i in 0..4 {
            let proof = inclusion_proof(&leaves, i, &HashType::Sha3_256);
            let proof_hexes: Vec<serde_json::Value> = proof
                .iter()
                .map(|p| serde_json::json!(format!("0x{}", hex::encode(p))))
                .collect();
            let target_hex = format!("0x{}", hex::encode(&raws[i]));
            let nonce_hex = format!("0x{}", hex::encode(&nonces[i]));

            let payloads = serde_json::json!({
                "merkle_root": root_hex,
                "batch_tree_size": 4,
                "batch_leaf_index": i,
                "merkle_proof": proof_hexes,
                "shielding_nonce": nonce_hex
            });

            let result = verify_batch_inclusion(&payloads, &target_hex, "");
            assert!(
                result.is_ok(),
                "leaf {i}: shielded inclusion must pass: {result:?}"
            );
        }
    }

    #[test]
    fn wrong_nonce_fails_verification() {
        use crate::primitives::merkle::{batch_leaf_hash, inclusion_proof, merkle_root};
        use crate::primitives::HashType;

        let raws: Vec<Vec<u8>> = (1u8..=4).map(|i| vec![i; 32]).collect();
        let nonces: Vec<Vec<u8>> = (0xA1u8..=0xA4).map(|i| vec![i; 32]).collect();

        let leaves: Vec<Vec<u8>> = raws
            .iter()
            .zip(nonces.iter())
            .map(|(r, n)| {
                let shielded = compute_shielded(r, n);
                batch_leaf_hash(&HashType::Sha3_256, &shielded)
            })
            .collect();

        let root = merkle_root(&leaves, &HashType::Sha3_256);
        let root_hex = make_root_hex(&root);
        let proof = inclusion_proof(&leaves, 0, &HashType::Sha3_256);
        let proof_hexes: Vec<serde_json::Value> = proof
            .iter()
            .map(|p| serde_json::json!(format!("0x{}", hex::encode(p))))
            .collect();

        let target_hex = format!("0x{}", hex::encode(&raws[0]));
        let wrong_nonce = format!("0x{}", hex::encode(vec![0xFF; 32]));

        let payloads = serde_json::json!({
            "merkle_root": root_hex,
            "batch_tree_size": 4,
            "batch_leaf_index": 0,
            "merkle_proof": proof_hexes,
            "shielding_nonce": wrong_nonce
        });

        let result = verify_batch_inclusion(&payloads, &target_hex, "");
        assert!(result.is_err(), "wrong nonce must fail verification");
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "MERKLE_INCLUSION_FAILED");
    }

    #[test]
    fn no_sibling_matches_raw_leaf() {
        use crate::primitives::merkle::{batch_leaf_hash, inclusion_proof, merkle_root};
        use crate::primitives::HashType;

        let raws: Vec<Vec<u8>> = (1u8..=4).map(|i| vec![i; 32]).collect();
        let nonces: Vec<Vec<u8>> = (0xA1u8..=0xA4).map(|i| vec![i; 32]).collect();

        let leaves: Vec<Vec<u8>> = raws
            .iter()
            .zip(nonces.iter())
            .map(|(r, n)| {
                let shielded = compute_shielded(r, n);
                batch_leaf_hash(&HashType::Sha3_256, &shielded)
            })
            .collect();

        let raw_leaf_hashes: Vec<Vec<u8>> = raws
            .iter()
            .map(|r| batch_leaf_hash(&HashType::Sha3_256, r))
            .collect();

        for i in 0..4 {
            let proof = inclusion_proof(&leaves, i, &HashType::Sha3_256);
            for sibling in &proof {
                for raw_leaf in &raw_leaf_hashes {
                    assert_ne!(
                        sibling, raw_leaf,
                        "sibling in proof must not match any raw (unshielded) leaf"
                    );
                }
                for raw in &raws {
                    assert_ne!(
                        sibling, raw,
                        "sibling in proof must not match any raw revision hash"
                    );
                }
            }
        }

        let root = merkle_root(&leaves, &HashType::Sha3_256);
        for raw_leaf in &raw_leaf_hashes {
            assert_ne!(
                &root, raw_leaf,
                "merkle root must not match any raw leaf hash"
            );
        }
    }

    #[test]
    fn shielded_without_domain_separation_fails() {
        let raw = vec![0xAA; 32];
        let nonce = vec![0x11; 32];
        let nonce_hex = format!("0x{}", hex::encode(&nonce));

        let shielded = compute_shielded(&raw, &nonce);
        let bad_root = make_root_hex(&shielded);

        let payloads = serde_json::json!({
            "merkle_root": bad_root,
            "batch_tree_size": 1,
            "batch_leaf_index": 0,
            "merkle_proof": [],
            "shielding_nonce": nonce_hex
        });

        let target = format!("0x{}", hex::encode(&raw));
        let result = verify_batch_inclusion(&payloads, &target, "");
        assert!(
            result.is_err(),
            "shielded value without 0x00 domain prefix must fail"
        );
        let (_, code, _) = result.unwrap_err();
        assert_eq!(code, "MERKLE_ROOT_MISMATCH");
    }
}
