//! Domain-separated Merkle tree with HKDF salt derivation (RFC 6962 + RFC 5869).

use super::HashType;
use hkdf::Hkdf;
use sha3::Sha3_256;

/// HKDF application label for Aqua selective disclosure salt derivation.
const AQUA_SD_LABEL: &[u8] = b"AquaSD";

/// Domain separation prefixes per RFC 6962 Section 2.1 / PCA-0016 AD-20.
const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;
/// Inner domain tag for the path/label commitment (AD-20).
const LABEL_TAG: u8 = 0x03;
/// Inner domain tag for the salted value commitment (AD-20).
const VALUE_TAG: u8 = 0x02;

/// Derive the PRK (pseudo-random key) from the revision nonce.
/// PRK = HKDF-Extract(salt="AquaSD", IKM=nonce_bytes)
///
/// Always uses HKDF-SHA3-256 regardless of the revision's hash algorithm.
/// SD salt derivation is decoupled from revision hashing so the KDF spec
/// is a single path for all current and future hash algorithms.
pub fn derive_prk(nonce: &[u8]) -> Vec<u8> {
    let (prk, _) = Hkdf::<Sha3_256>::extract(Some(AQUA_SD_LABEL), nonce);
    prk.to_vec()
}

/// Derive a per-field salt from the PRK.
/// salt = HKDF-Expand(PRK, info=pointer_path, L=32)
///
/// Always uses HKDF-SHA3-256 regardless of the revision's hash algorithm.
pub fn derive_field_salt(prk: &[u8], pointer: &str) -> Vec<u8> {
    let hk = Hkdf::<Sha3_256>::from_prk(prk).expect("PRK length is valid for SHA3-256");
    let mut salt = vec![0u8; 32];
    hk.expand(pointer.as_bytes(), &mut salt)
        .expect("32 bytes is valid output length for SHA3-256");
    salt
}

/// Compute the path/label commitment (PCA-0016 AD-20).
/// `label = HASH(0x03 || pointer_bytes)`.
pub fn label_commit(hash_type: &HashType, pointer: &str) -> Vec<u8> {
    let mut pre = Vec::with_capacity(1 + pointer.len());
    pre.push(LABEL_TAG);
    pre.extend_from_slice(pointer.as_bytes());
    hash_type.hash(&pre)
}

/// Compute the salted value commitment (PCA-0016 AD-20).
/// `value_commit = HASH(0x02 || field_salt || value_display_bytes)`.
pub fn value_commit(hash_type: &HashType, salt: &[u8], value: &str) -> Vec<u8> {
    let mut pre = Vec::with_capacity(1 + salt.len() + value.len());
    pre.push(VALUE_TAG);
    pre.extend_from_slice(salt);
    pre.extend_from_slice(value.as_bytes());
    hash_type.hash(&pre)
}

/// Compute a domain-separated selective-disclosure leaf hash (PCA-0016 AD-20).
///
/// ```text
/// label        = HASH(0x03 || pointer)
/// value_commit = HASH(0x02 || salt || value_display_bytes)
/// leaf         = HASH(0x00 || label || value_commit)
/// ```
///
/// The path is authenticated: a Redacted leaf presents `(pointer, value_commit)`
/// and the verifier recomputes `label` from the cleartext pointer, so a path
/// relabel changes the leaf digest and fails root reconstruction.
pub fn leaf_hash(hash_type: &HashType, salt: &[u8], pointer: &str, value: &str) -> Vec<u8> {
    let label = label_commit(hash_type, pointer);
    let vcommit = value_commit(hash_type, salt, value);
    leaf_hash_from_commits(hash_type, &label, &vcommit)
}

/// Assemble a leaf digest from precomputed label and value commitments.
/// `leaf = HASH(0x00 || label || value_commit)`.
pub fn leaf_hash_from_commits(hash_type: &HashType, label: &[u8], value_commit: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + label.len() + value_commit.len());
    data.push(LEAF_PREFIX);
    data.extend_from_slice(label);
    data.extend_from_slice(value_commit);
    hash_type.hash(&data)
}

/// RFC 6962 domain-separated leaf hash for batch Merkle trees.
/// batch_leaf = HASH(0x00 || data)
pub fn batch_leaf_hash(hash_type: &HashType, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(data);
    hash_type.hash(&buf)
}

/// Compute a domain-separated internal node hash.
/// internal = HASH(0x01 || left || right)
pub fn internal_hash(hash_type: &HashType, left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + left.len() + right.len());
    data.push(INTERNAL_PREFIX);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    hash_type.hash(&data)
}

/// Compute the largest power of 2 strictly less than `n`.
/// Panics if n < 2 (undefined for fewer than 2 nodes).
fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k < n {
        k <<= 1;
    }
    k >> 1
}

/// Build a Merkle tree from leaf hashes and return the root.
/// Uses 0x01 domain-separated internal nodes. Odd nodes promoted (NOT duplicated).
pub fn merkle_root(leaves: &[Vec<u8>], hash_type: &HashType) -> Vec<u8> {
    if leaves.len() == 1 {
        return leaves[0].clone();
    }

    let mut current_level: Vec<Vec<u8>> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                next_level.push(internal_hash(
                    hash_type,
                    &current_level[i],
                    &current_level[i + 1],
                ));
                i += 2;
            } else {
                next_level.push(current_level[i].clone());
                i += 1;
            }
        }
        current_level = next_level;
    }

    current_level.into_iter().next().unwrap()
}

/// Generate an RFC 9162 Section 2.1.3.1 inclusion proof (PATH algorithm).
///
/// Returns the sibling hashes along the path from the leaf at `leaf_index` to
/// the root. An empty vec is returned for a single-leaf tree. The proof can be
/// verified with [`verify_inclusion`].
///
/// # Panics
/// Panics if `leaf_index >= leaves.len()`.
pub fn inclusion_proof(
    leaves: &[Vec<u8>],
    leaf_index: usize,
    hash_type: &HashType,
) -> Vec<Vec<u8>> {
    assert!(
        leaf_index < leaves.len(),
        "leaf_index {} out of range for {} leaves",
        leaf_index,
        leaves.len()
    );
    if leaves.len() == 1 {
        return vec![];
    }
    let k = largest_power_of_two_less_than(leaves.len());
    if leaf_index < k {
        let mut proof = inclusion_proof(&leaves[..k], leaf_index, hash_type);
        proof.push(merkle_root(&leaves[k..], hash_type));
        proof
    } else {
        let mut proof = inclusion_proof(&leaves[k..], leaf_index - k, hash_type);
        proof.push(merkle_root(&leaves[..k], hash_type));
        proof
    }
}

/// Verify an RFC 9162 Section 2.1.3.2 inclusion proof (iterative algorithm).
///
/// Returns `true` iff the `proof` path from `leaf_hash` at position `leaf_index`
/// in a tree of `tree_size` leaves produces `root`.
pub fn verify_inclusion(
    leaf_hash: &[u8],
    leaf_index: usize,
    tree_size: usize,
    proof: &[Vec<u8>],
    root: &[u8],
    hash_type: &HashType,
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    if tree_size == 1 {
        return proof.is_empty() && leaf_hash == root;
    }

    let mut fn_ = leaf_index;
    let mut sn = tree_size - 1;
    let mut r: Vec<u8> = leaf_hash.to_vec();

    for p in proof {
        if sn == 0 {
            return false;
        }
        if (fn_ & 1) == 1 || fn_ == sn {
            // Right child or rightmost node: merge proof || r
            r = internal_hash(hash_type, p, &r);
            // Consume completed right subtrees
            while (fn_ & 1) == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            // Left child: merge r || proof
            r = internal_hash(hash_type, &r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    sn == 0 && r == root
}

#[cfg(test)]
mod tests {
    use super::*;

    const HT: HashType = HashType::Sha3_256;

    // ── derive_prk / derive_field_salt ────────────────────────────────────

    #[test]
    fn test_derive_prk_deterministic() {
        let nonce = b"test-nonce-16bytes";
        let prk1 = derive_prk(nonce);
        let prk2 = derive_prk(nonce);
        assert_eq!(prk1, prk2, "same nonce must produce same PRK");
        assert_eq!(prk1.len(), 32, "PRK should be 32 bytes");
    }

    #[test]
    fn test_derive_prk_different_nonces() {
        let prk1 = derive_prk(b"nonce-a");
        let prk2 = derive_prk(b"nonce-b");
        assert_ne!(prk1, prk2, "different nonces must produce different PRKs");
    }

    #[test]
    fn test_derive_field_salt_deterministic() {
        let prk = derive_prk(b"test-nonce");
        let salt1 = derive_field_salt(&prk, "/name");
        let salt2 = derive_field_salt(&prk, "/name");
        assert_eq!(salt1, salt2);
        assert_eq!(salt1.len(), 32);
    }

    #[test]
    fn test_derive_field_salt_different_pointers() {
        let prk = derive_prk(b"test-nonce");
        let salt_a = derive_field_salt(&prk, "/name");
        let salt_b = derive_field_salt(&prk, "/email");
        assert_ne!(
            salt_a, salt_b,
            "different pointers must produce different salts"
        );
    }

    // ── leaf_hash / internal_hash domain separation ───────────────────────

    #[test]
    fn test_leaf_hash_has_leaf_prefix() {
        let salt = vec![0u8; 32];
        let h = leaf_hash(&HT, &salt, "/field", "value");
        assert_eq!(h.len(), 32);
        // Verify it's different from internal_hash with same data
        let ih = internal_hash(&HT, &salt, b"/field:value");
        assert_ne!(
            h, ih,
            "leaf and internal hashes must differ (domain separation)"
        );
    }

    // ── batch_leaf_hash ────────────────────────────────────────────────────

    #[test]
    fn test_batch_leaf_hash_deterministic() {
        let data = vec![0xAA; 32];
        let h1 = batch_leaf_hash(&HT, &data);
        let h2 = batch_leaf_hash(&HT, &data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_batch_leaf_hash_differs_from_raw() {
        let data = vec![0xAA; 32];
        let h = batch_leaf_hash(&HT, &data);
        assert_ne!(h, data, "domain-separated leaf must differ from raw data");
    }

    #[test]
    fn test_batch_leaf_hash_differs_from_internal() {
        let data = vec![0xAA; 32];
        let leaf = batch_leaf_hash(&HT, &data);
        let internal = internal_hash(&HT, &data, &[]);
        assert_ne!(
            leaf, internal,
            "batch leaf and internal hashes must differ (domain separation)"
        );
    }

    #[test]
    fn test_batch_leaf_hash_different_inputs() {
        let h1 = batch_leaf_hash(&HT, &[0xAA; 32]);
        let h2 = batch_leaf_hash(&HT, &[0xBB; 32]);
        assert_ne!(h1, h2);
    }

    /// PCA-0015 §6 batch single-leaf vector. Pins the two facts a from-scratch
    /// implementation most easily gets wrong: the seam preimage is the **34-byte
    /// multihash** (not the bare 32-byte digest), and `merkle_root` is itself a
    /// **multihash** whose inner digest equals the bare single leaf. Computed
    /// through the real `batch_leaf_hash` / `merkle_root` primitives.
    #[test]
    fn pca0015_batch_single_leaf_vector() {
        use crate::primitives::hash_type::multihash_encode;

        // Seam preimage = the target revision's full multihash bytes (§3.7) =
        // multihash("aqua"), 34 bytes — NOT the bare 32-byte digest.
        let seam_preimage = multihash_encode(HT, &HT.hash(b"aqua"));
        assert_eq!(
            seam_preimage.len(),
            34,
            "seam preimage must be the multihash"
        );

        // shielding_nonce = 32 zero bytes; shielded = SHA3-256(multihash || nonce).
        let nonce = [0u8; 32];
        let mut shielded_input = seam_preimage.clone();
        shielded_input.extend_from_slice(&nonce);
        let shielded = HT.hash(&shielded_input);
        assert_eq!(
            hex::encode(&shielded),
            "1fbb6176b3fdaf019360bf71ea503f2f23fb43eb380357f51b1f3dfd7bd67456"
        );

        // leaf = batch_leaf_hash(shielded) = SHA3-256(0x00 || shielded).
        let leaf = batch_leaf_hash(&HT, &shielded);
        assert_eq!(
            hex::encode(&leaf),
            "f4b2394287d1a4556c7c5be83818cc0dd87ebbeb036a8bff9be56d4d95df2b2a"
        );

        // Single leaf: bare root == leaf; the wire merkle_root is its multihash.
        let bare_root = merkle_root(&[leaf.clone()], &HT);
        assert_eq!(bare_root, leaf, "single-leaf root equals the leaf");
        let root_mh = multihash_encode(HT, &bare_root);
        assert_eq!(
            hex::encode(&root_mh),
            "1620f4b2394287d1a4556c7c5be83818cc0dd87ebbeb036a8bff9be56d4d95df2b2a"
        );
    }

    // ── leaf_hash (selective disclosure) ─────────────────────────────────

    #[test]
    fn test_leaf_hash_deterministic() {
        let salt = vec![1u8; 32];
        let h1 = leaf_hash(&HT, &salt, "/x", "42");
        let h2 = leaf_hash(&HT, &salt, "/x", "42");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_leaf_hash_different_values() {
        let salt = vec![1u8; 32];
        let h1 = leaf_hash(&HT, &salt, "/x", "a");
        let h2 = leaf_hash(&HT, &salt, "/x", "b");
        assert_ne!(h1, h2);
    }

    /// AD-20: same salt+value under two different paths produce different leaves.
    #[test]
    fn test_leaf_hash_path_authenticated() {
        let salt = vec![1u8; 32];
        let h1 = leaf_hash(&HT, &salt, "/previous_revision", "\"0xab\"");
        let h2 = leaf_hash(&HT, &salt, "/payloads/forged", "\"0xab\"");
        assert_ne!(
            h1, h2,
            "path must be bound into the leaf digest (AD-20 relabel defense)"
        );
        // Recomputing via commits with a relabeled path fails to match the original.
        let vcommit = value_commit(&HT, &salt, "\"0xab\"");
        let forged_label = label_commit(&HT, "/payloads/forged");
        let forged_leaf = leaf_hash_from_commits(&HT, &forged_label, &vcommit);
        assert_ne!(h1, forged_leaf);
        assert_eq!(h2, forged_leaf);
    }

    #[test]
    fn test_internal_hash_deterministic() {
        let left = vec![0xAA; 32];
        let right = vec![0xBB; 32];
        let h1 = internal_hash(&HT, &left, &right);
        let h2 = internal_hash(&HT, &left, &right);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_internal_hash_not_commutative() {
        let a = vec![0xAA; 32];
        let b = vec![0xBB; 32];
        let h1 = internal_hash(&HT, &a, &b);
        let h2 = internal_hash(&HT, &b, &a);
        assert_ne!(h1, h2, "internal_hash(a,b) != internal_hash(b,a)");
    }

    // ── merkle_root ──────────────────────────────────────────────────────

    #[test]
    fn test_merkle_root_single_leaf() {
        let leaf = vec![0x42; 32];
        let root = merkle_root(&[leaf.clone()], &HT);
        assert_eq!(root, leaf, "single leaf should be the root");
    }

    #[test]
    fn test_merkle_root_two_leaves() {
        let a = vec![0xAA; 32];
        let b = vec![0xBB; 32];
        let root = merkle_root(&[a.clone(), b.clone()], &HT);
        let expected = internal_hash(&HT, &a, &b);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_three_leaves_odd_promotion() {
        let a = vec![1; 32];
        let b = vec![2; 32];
        let c = vec![3; 32];
        let root = merkle_root(&[a.clone(), b.clone(), c.clone()], &HT);
        // Level 1: [internal(a,b), c_promoted]
        // Level 2: internal(internal(a,b), c)
        let ab = internal_hash(&HT, &a, &b);
        let expected = internal_hash(&HT, &ab, &c);
        assert_eq!(
            root, expected,
            "odd leaf should be promoted, not duplicated"
        );
    }

    #[test]
    fn test_merkle_root_four_leaves() {
        let leaves: Vec<Vec<u8>> = (1..=4).map(|i| vec![i; 32]).collect();
        let root = merkle_root(&leaves, &HT);
        let ab = internal_hash(&HT, &leaves[0], &leaves[1]);
        let cd = internal_hash(&HT, &leaves[2], &leaves[3]);
        let expected = internal_hash(&HT, &ab, &cd);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let leaves: Vec<Vec<u8>> = (0..5).map(|i| vec![i; 32]).collect();
        let r1 = merkle_root(&leaves, &HT);
        let r2 = merkle_root(&leaves, &HT);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_merkle_root_order_matters() {
        let a = vec![1; 32];
        let b = vec![2; 32];
        let r1 = merkle_root(&[a.clone(), b.clone()], &HT);
        let r2 = merkle_root(&[b, a], &HT);
        assert_ne!(r1, r2, "leaf order must affect the root");
    }

    // ── inclusion_proof ──────────────────────────────────────────────────────

    #[test]
    fn test_inclusion_proof_single_leaf() {
        let leaves = vec![vec![0x42u8; 32]];
        let proof = inclusion_proof(&leaves, 0, &HT);
        assert!(proof.is_empty(), "single leaf must produce empty proof");
    }

    #[test]
    fn test_inclusion_proof_two_leaves() {
        let a = vec![1u8; 32];
        let b = vec![2u8; 32];
        let leaves = vec![a.clone(), b.clone()];

        // Proof for leaf 0: sibling is b
        let proof0 = inclusion_proof(&leaves, 0, &HT);
        assert_eq!(proof0.len(), 1);
        assert_eq!(proof0[0], b, "proof for leaf 0 must be the sibling (b)");

        // Proof for leaf 1: sibling is a
        let proof1 = inclusion_proof(&leaves, 1, &HT);
        assert_eq!(proof1.len(), 1);
        assert_eq!(proof1[0], a, "proof for leaf 1 must be the sibling (a)");
    }

    #[test]
    fn test_inclusion_proof_three_leaves() {
        // n=3, k=2. RFC 9162 split: left=[L0,L1], right=[L2].
        // Root = internal(internal(L0,L1), L2).
        let leaves: Vec<Vec<u8>> = (1u8..=3).map(|i| vec![i; 32]).collect();
        let l0 = &leaves[0];
        let l1 = &leaves[1];
        let l2 = &leaves[2];

        // Leaf 0 (in left half [L0,L1]):
        //   recurse left: proof([L0,L1], 0) = [L1]
        //   append root of right half [L2] = L2
        //   proof = [L1, L2]
        let proof0 = inclusion_proof(&leaves, 0, &HT);
        assert_eq!(proof0.len(), 2);
        assert_eq!(proof0[0], *l1, "leaf 0 step 0 must be L1");
        assert_eq!(proof0[1], *l2, "leaf 0 step 1 must be root([L2])=L2");

        // Leaf 1 (in left half [L0,L1]):
        //   recurse left: proof([L0,L1], 1) = [L0]
        //   append root of right half = L2
        //   proof = [L0, L2]
        let proof1 = inclusion_proof(&leaves, 1, &HT);
        assert_eq!(proof1.len(), 2);
        assert_eq!(proof1[0], *l0, "leaf 1 step 0 must be L0");
        assert_eq!(proof1[1], *l2, "leaf 1 step 1 must be root([L2])=L2");

        // Leaf 2 (in right half [L2]):
        //   recurse right: proof([L2], 0) = []
        //   append root of left half = internal(L0,L1)
        //   proof = [internal(L0,L1)]
        let proof2 = inclusion_proof(&leaves, 2, &HT);
        let root_left = internal_hash(&HT, l0, l1);
        assert_eq!(proof2.len(), 1);
        assert_eq!(proof2[0], root_left, "leaf 2 step 0 must be root([L0,L1])");
    }

    #[test]
    fn test_inclusion_proof_four_leaves() {
        // n=4, k=2 (largest power of 2 < 4 = 2). Wait: k must be strictly less than n=4.
        // Powers of 2: 1,2,4. Largest strictly less than 4 is 2. Yes k=2.
        // Actually wait: let me recalculate. largest_power_of_two_less_than(4):
        // k starts at 1, shifts: 1->2->4, then 4 >= 4, so k=4, return k>>1=2.
        // So for n=4, k=2. Left=[L0,L1], right=[L2,L3].
        // Root = internal(internal(L0,L1), internal(L2,L3)).
        let leaves: Vec<Vec<u8>> = (1u8..=4).map(|i| vec![i; 32]).collect();
        let l0 = &leaves[0];
        let l1 = &leaves[1];
        let l2 = &leaves[2];
        let l3 = &leaves[3];

        let root_left = internal_hash(&HT, l0, l1);
        let root_right = internal_hash(&HT, l2, l3);

        // Leaf 0 in left [L0,L1]: proof([L0,L1],0)=[L1], append root_right
        let proof0 = inclusion_proof(&leaves, 0, &HT);
        assert_eq!(proof0.len(), 2);
        assert_eq!(proof0[0], *l1);
        assert_eq!(proof0[1], root_right);

        // Leaf 1 in left [L0,L1]: proof([L0,L1],1)=[L0], append root_right
        let proof1 = inclusion_proof(&leaves, 1, &HT);
        assert_eq!(proof1.len(), 2);
        assert_eq!(proof1[0], *l0);
        assert_eq!(proof1[1], root_right);

        // Leaf 2 in right [L2,L3] index 0: proof([L2,L3],0)=[L3], append root_left
        let proof2 = inclusion_proof(&leaves, 2, &HT);
        assert_eq!(proof2.len(), 2);
        assert_eq!(proof2[0], *l3);
        assert_eq!(proof2[1], root_left);

        // Leaf 3 in right [L2,L3] index 1: proof([L2,L3],1)=[L2], append root_left
        let proof3 = inclusion_proof(&leaves, 3, &HT);
        assert_eq!(proof3.len(), 2);
        assert_eq!(proof3[0], *l2);
        assert_eq!(proof3[1], root_left);
    }

    #[test]
    fn test_inclusion_proof_seven_leaves() {
        // n=7, k=4. Left=[L0..L3], right=[L4,L5,L6].
        // Test leaf 5 (index 5, in right half at index 1).
        // right=[L4,L5,L6]: n=3,k=2. index 1 in left=[L4,L5] at index 1.
        //   proof([L4,L5],1)=[L4], append root([L6])=L6.
        //   So proof([right],1) = [L4, L6].
        // Append root_left = root([L0..L3]).
        // Full proof for leaf 5 = [L4, L6, root_left].
        let leaves: Vec<Vec<u8>> = (1u8..=7).map(|i| vec![i; 32]).collect();
        let l4 = &leaves[4];
        let l6 = &leaves[6];
        let root_left = merkle_root(&leaves[..4], &HT);

        let proof5 = inclusion_proof(&leaves, 5, &HT);
        assert_eq!(proof5.len(), 3, "leaf 5 of 7 needs 3 proof elements");
        assert_eq!(proof5[0], *l4, "step 0 must be L4");
        assert_eq!(proof5[1], *l6, "step 1 must be L6");
        assert_eq!(proof5[2], root_left, "step 2 must be root of left half");
    }

    #[test]
    fn test_inclusion_proof_eight_leaves() {
        // n=8, k=4. Balanced. All proofs have length 3.
        let leaves: Vec<Vec<u8>> = (1u8..=8).map(|i| vec![i; 32]).collect();
        for i in 0..8 {
            let proof = inclusion_proof(&leaves, i, &HT);
            assert_eq!(
                proof.len(),
                3,
                "balanced 8-leaf tree: every proof must have 3 elements (got {} for leaf {})",
                proof.len(),
                i
            );
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn test_inclusion_proof_out_of_bounds() {
        let leaves = vec![vec![0u8; 32], vec![1u8; 32]];
        inclusion_proof(&leaves, 2, &HT); // index 2 >= len 2
    }

    // ── verify_inclusion ─────────────────────────────────────────────────────

    #[test]
    fn test_verify_inclusion_single_leaf() {
        let leaf = vec![0x42u8; 32];
        let leaves = vec![leaf.clone()];
        let root = merkle_root(&leaves, &HT);
        let proof = inclusion_proof(&leaves, 0, &HT);
        assert!(verify_inclusion(&leaf, 0, 1, &proof, &root, &HT));
    }

    #[test]
    fn test_verify_inclusion_two_leaves() {
        let a = vec![1u8; 32];
        let b = vec![2u8; 32];
        let leaves = vec![a.clone(), b.clone()];
        let root = merkle_root(&leaves, &HT);

        let proof0 = inclusion_proof(&leaves, 0, &HT);
        assert!(verify_inclusion(&a, 0, 2, &proof0, &root, &HT));

        let proof1 = inclusion_proof(&leaves, 1, &HT);
        assert!(verify_inclusion(&b, 1, 2, &proof1, &root, &HT));
    }

    #[test]
    fn test_verify_inclusion_roundtrip_all_positions() {
        for &size in &[3usize, 4, 5, 7, 8, 13, 16] {
            let leaves: Vec<Vec<u8>> = (0..size).map(|i| vec![i as u8; 32]).collect();
            let root = merkle_root(&leaves, &HT);
            for idx in 0..size {
                let proof = inclusion_proof(&leaves, idx, &HT);
                assert!(
                    verify_inclusion(&leaves[idx], idx, size, &proof, &root, &HT),
                    "round-trip failed: size={size} idx={idx}"
                );
            }
        }
    }

    #[test]
    fn test_verify_inclusion_wrong_leaf() {
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 32]).collect();
        let root = merkle_root(&leaves, &HT);
        let proof = inclusion_proof(&leaves, 0, &HT);
        let wrong_leaf = vec![0xFFu8; 32];
        assert!(!verify_inclusion(&wrong_leaf, 0, 4, &proof, &root, &HT));
    }

    #[test]
    fn test_verify_inclusion_wrong_index() {
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 32]).collect();
        let root = merkle_root(&leaves, &HT);
        let proof = inclusion_proof(&leaves, 0, &HT);
        // Claim leaf 0 is at index 1 — should fail
        assert!(!verify_inclusion(&leaves[0], 1, 4, &proof, &root, &HT));
    }

    #[test]
    fn test_verify_inclusion_wrong_root() {
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 32]).collect();
        let root = merkle_root(&leaves, &HT);
        let proof = inclusion_proof(&leaves, 0, &HT);
        let mut wrong_root = root.clone();
        wrong_root[0] ^= 0xFF;
        assert!(!verify_inclusion(
            &leaves[0],
            0,
            4,
            &proof,
            &wrong_root,
            &HT
        ));
    }

    #[test]
    fn test_verify_inclusion_index_out_of_range() {
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 32]).collect();
        let root = merkle_root(&leaves, &HT);
        let proof = inclusion_proof(&leaves, 0, &HT);
        // index 4 >= tree_size 4
        assert!(!verify_inclusion(&leaves[0], 4, 4, &proof, &root, &HT));
    }

    #[test]
    fn test_verify_inclusion_wrong_tree_size() {
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| vec![i; 32]).collect();
        let root = merkle_root(&leaves, &HT);
        let proof = inclusion_proof(&leaves, 0, &HT);
        // Claim tree_size is 5 instead of 4
        assert!(!verify_inclusion(&leaves[0], 0, 5, &proof, &root, &HT));
    }

    // ── BLAKE3-256 tests ─────────────────────────────────────────────────

    const BK: HashType = HashType::Blake3_256;

    #[test]
    fn test_blake3_hash_output_32_bytes() {
        let h = BK.hash(b"hello");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_blake3_hash_deterministic() {
        let h1 = BK.hash(b"aqua protocol");
        let h2 = BK.hash(b"aqua protocol");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_blake3_differs_from_sha3() {
        let input = b"same input, different algorithms";
        let sha3 = HT.hash(input);
        let blake3 = BK.hash(input);
        assert_ne!(
            sha3, blake3,
            "SHA3-256 and BLAKE3-256 must produce different outputs"
        );
        assert_eq!(sha3.len(), blake3.len(), "both must be 32 bytes");
    }

    #[test]
    fn test_blake3_sd_uses_same_kdf_as_sha3() {
        let nonce = b"same-nonce";
        let prk1 = derive_prk(nonce);
        let prk2 = derive_prk(nonce);
        assert_eq!(
            prk1, prk2,
            "KDF is hash-algorithm-independent; same nonce must produce same PRK"
        );
    }

    #[test]
    fn test_blake3_derive_field_salt() {
        let prk = derive_prk(b"nonce");
        let salt_a = derive_field_salt(&prk, "/name");
        let salt_b = derive_field_salt(&prk, "/email");
        assert_eq!(salt_a.len(), 32);
        assert_ne!(salt_a, salt_b);
    }

    #[test]
    fn test_blake3_leaf_hash() {
        let salt = vec![0xAB; 32];
        let h = leaf_hash(&BK, &salt, "/field", "value");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_blake3_merkle_root_and_inclusion() {
        let leaves: Vec<Vec<u8>> = (1u8..=4).map(|i| vec![i; 32]).collect();
        let root = merkle_root(&leaves, &BK);
        assert_eq!(root.len(), 32);

        for i in 0..4 {
            let proof = inclusion_proof(&leaves, i, &BK);
            assert!(
                verify_inclusion(&leaves[i], i, 4, &proof, &root, &BK),
                "BLAKE3 inclusion proof must verify for leaf {i}"
            );
        }
    }

    #[test]
    fn test_blake3_merkle_root_differs_from_sha3() {
        let leaves: Vec<Vec<u8>> = (1u8..=3).map(|i| vec![i; 32]).collect();
        let sha3_root = merkle_root(&leaves, &HT);
        let blake3_root = merkle_root(&leaves, &BK);
        assert_ne!(sha3_root, blake3_root);
    }
}
