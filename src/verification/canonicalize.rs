use crate::primitives::{Canonicalizable, HashType, Hashable, MethodError, RevisionLink};
use serde::Serialize;

fn canonical_link<T: Serialize + Hashable + Canonicalizable>(
    t: &T,
    hash_type: HashType,
) -> Result<RevisionLink, MethodError> {
    let method = t.method();
    let hash_bytes = method.compute_revision_hash(t, hash_type)?;
    Ok(RevisionLink::new(hash_bytes))
}

pub trait Linkable {
    /// Compute this revision's addressing [`RevisionLink`] (a full multihash,
    /// PCA-0015 §3.5) under the given algorithm. The algorithm is supplied by
    /// the caller — the builder at creation, or the code of the addressing
    /// multihash at verification — never read from the revision itself.
    fn calculate_link(&self, hash_type: HashType) -> Result<RevisionLink, MethodError>;
}

impl<T: Serialize + Hashable + Canonicalizable> Linkable for T {
    fn calculate_link(&self, hash_type: HashType) -> Result<RevisionLink, MethodError> {
        canonical_link(self, hash_type)
    }
}
