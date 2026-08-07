//! Single classifier for `revision_type` strings.
//!
//! Every revision in an Aqua tree carries a `revision_type` which is
//! always a hex-encoded 32-byte template hash (`"0x<hex>"`). Foundation
//! template hashes are published by [`TemplateMeta`], [`SignatureBase`],
//! [`AnchorTemplate`] and the algorithm-specific signature templates in
//! `crate::schema::templates`.
//!
//! [`resolve_revision_kind`] is the sole entry point that turns a
//! `revision_type` string into a [`RevisionKind`]. Downstream code
//! dispatches on the enum instead of pattern-matching on strings or
//! running ad-hoc `starts_with("0x")` heuristics.
//!
//! Legacy string literals (`"anchor"`, `"template"`) are no longer
//! accepted and resolve to [`RevisionKind::Unknown`].
//!
//! [`TemplateMeta`]: crate::schema::templates::TemplateMeta
//! [`SignatureBase`]: crate::schema::templates::SignatureBase
//! [`AnchorTemplate`]: crate::schema::templates::AnchorTemplate

use std::sync::LazyLock;

use super::hash_type::{multihash_decode, multihash_encode};
use super::unsupported::{TIMESTAMP_BASE_DIGEST, TIMESTAMP_EVM_DIGEST, TIMESTAMP_TSA_DIGEST};
use super::{HashType, RevisionLink};
use crate::schema::template::BuiltInTemplate;
use crate::schema::templates::{
    AnchorTemplate, SignatureBase, SignatureEd25519, SignatureEip191, SignatureP256,
    SignatureWebauthn, TemplateMeta,
};

/// Classification of a `revision_type` value.
///
/// All branch kinds (`Signature`, `Anchor`, `Timestamp`) are forks off
/// the main chain in the tree topology. `Object` covers every domain
/// object. `Template` covers template revisions (hash matches
/// `template_meta` or [`GENESIS_TYPE_HASH`]). `Unknown` is reserved
/// for unrecognized strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevisionKind {
    /// A signature revision. Hash matches `signature_base` or one of
    /// the built-in algorithm templates.
    Signature,
    /// An anchor revision. Hash matches `anchor_template`.
    Anchor,
    /// A timestamp revision. Hash matches `timestamp_base` or one of
    /// the built-in timestamp templates.
    Timestamp,
    /// A template revision. Hash matches `template_meta` or
    /// [`GENESIS_TYPE_HASH`].
    Template,
    /// A domain object whose `revision_type` is a template hash other
    /// than the recognized foundation hashes.
    Object,
    /// Unrecognized revision_type string. Conservatively treated as a
    /// non-branch; callers may surface this as a verification error.
    Unknown,
}

impl RevisionKind {
    /// Returns `true` for branch kinds (forks off the chain).
    ///
    /// Branch children trigger WASM domain re-evaluation on their
    /// owning object. Used by the daemon forest to classify children
    /// during insertion.
    pub fn is_branch(self) -> bool {
        matches!(
            self,
            RevisionKind::Signature | RevisionKind::Anchor | RevisionKind::Timestamp
        )
    }
}

/// Synthetic bootstrap hash for `template_meta.revision_type` in the
/// fully-unified wire format described in `Template_Logic_Unification.md`.
///
/// Two hashes refer to the template-template ("template_meta") concept
/// in this codebase, by design:
///
/// - [`TemplateMeta::TEMPLATE_LINK`] is the **content hash** of
///   `template_meta.json`. It is what every other template currently
///   declares in `derives_from` / `ancestry`, and what
///   `AnyRevision::get_revision_type()` returns for the `Template`
///   variant. Use this for classification, ancestry, and any code path
///   that touches a live tree today.
/// - `GENESIS_TYPE_HASH` is the **bootstrap self-reference** for the
///   future fully-unified wire format, where `template_meta` itself
///   needs a non-recursive `revision_type` value. Computed as
///   `SHA3-256("aqua:genesis:template_meta")`. Exposed only for forward
///   compatibility, the existing reachability tests below, and to keep
///   [`resolve_revision_kind`] accepting either form when the wire
///   format flips.
///
/// Both hashes resolve to [`RevisionKind::Template`] via
/// [`resolve_revision_kind`]. Do not introduce new producers of
/// `GENESIS_TYPE_HASH` until the wire-format migration lands.
pub static GENESIS_TYPE_HASH: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let hash = HashType::Sha3_256.hash(b"aqua:genesis:template_meta");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash);
    arr
});

/// Full multihash (always SHA3-256, code `0x16`, per PCA-0015 §3.9) of a
/// built-in template-id digest constant. Template ids are fixed-algorithm, so
/// the `TEMPLATE_LINK` constants stay bare 32-byte SHA3-256 digests and the
/// naming-value wire form is derived here.
pub fn template_id_multihash(link: &[u8; 32]) -> Vec<u8> {
    multihash_encode(HashType::Sha3_256, link)
}

/// [`GENESIS_TYPE_HASH`] expressed as a naming-value [`RevisionLink`] (full
/// multihash, PCA-0015 §3.3).
pub fn genesis_type_link() -> RevisionLink {
    RevisionLink::new(template_id_multihash(&GENESIS_TYPE_HASH))
}

/// Canonical naming-value hex string (full multihash) for the anchor
/// foundation template hash.
///
/// State builders and condition evaluators use this string as the
/// `StateNode.revision_type` for anchor branch nodes. Cheaper than
/// re-formatting `AnchorTemplate::TEMPLATE_LINK` on every access.
pub static ANCHOR_TEMPLATE_HEX: LazyLock<String> = LazyLock::new(|| {
    format!(
        "0x{}",
        hex::encode(template_id_multihash(&AnchorTemplate::TEMPLATE_LINK))
    )
});

/// Canonical naming-value hex string (full multihash) for the `template_meta`
/// foundation template hash.
pub static TEMPLATE_META_HEX: LazyLock<String> = LazyLock::new(|| {
    format!(
        "0x{}",
        hex::encode(template_id_multihash(&TemplateMeta::TEMPLATE_LINK))
    )
});

/// The `revision_type` value every template JSON must carry: the full
/// multihash of the `template_meta` foundation template.
///
/// Identical in value to [`TEMPLATE_META_HEX`], but a compile-time `&str`
/// rather than a lazily built `String`, so template authors can paste it into
/// a `const`, a test, or a generator instead of copying the 70-character
/// literal out of an existing template file (which is what everyone did
/// before, and how typos become new type identities).
///
/// ```rust
/// use aqua_rs_sdk_core::primitives::TEMPLATE_META_REVISION_TYPE;
///
/// let template_json = serde_json::json!({
///     "revision_type": TEMPLATE_META_REVISION_TYPE,
///     "nonce": "0x11223344556677889900aabbccddeeff",
///     "local_timestamp": 1754500000,
///     "version": "https://aqua-protocol.org/docs/v4/schema",
///     "method": "tree",
///     "schema": { "type": "object" }
/// });
/// assert!(template_json["revision_type"].as_str().unwrap().starts_with("0x1620"));
/// ```
///
/// The value is pinned by a test against `TemplateMeta::TEMPLATE_LINK`, so it
/// cannot drift from the constant the code resolves.
pub const TEMPLATE_META_REVISION_TYPE: &str =
    "0x1620f3040850a8836717dd73e87d046723e11f9e9870e3b2e246803ad842fbf01155";

/// Set of all foundation signature template ids (base plus per-algorithm), as
/// **full multihashes** (PCA-0015 §3.3 comparison rule).
///
/// Membership is the fast path for classification before any ancestry
/// walk. Per-algorithm templates derive from `signature_base`, but
/// `resolve_revision_kind` does not currently walk built-in template
/// ancestry, so each known hash is registered here directly.
static SIGNATURE_FOUNDATION_HASHES: LazyLock<std::collections::HashSet<Vec<u8>>> =
    LazyLock::new(|| {
        [
            SignatureBase::TEMPLATE_LINK,
            SignatureEip191::TEMPLATE_LINK,
            SignatureEd25519::TEMPLATE_LINK,
            SignatureP256::TEMPLATE_LINK,
            SignatureWebauthn::TEMPLATE_LINK,
        ]
        .iter()
        .map(template_id_multihash)
        .collect()
    });

/// Set of all foundation timestamp template ids (base plus per-provider), as
/// **full multihashes**.
static TIMESTAMP_FOUNDATION_HASHES: LazyLock<std::collections::HashSet<Vec<u8>>> =
    LazyLock::new(|| {
        [
            TIMESTAMP_BASE_DIGEST,
            TIMESTAMP_EVM_DIGEST,
            TIMESTAMP_TSA_DIGEST,
        ]
        .iter()
        .map(template_id_multihash)
        .collect()
    });

/// Classify a `revision_type` string into a [`RevisionKind`].
///
/// Compares the **full multihash byte string** (PCA-0015 §3.3): the value MUST
/// be a lowercase `0x`-hex encoding of a structurally valid registry multihash.
/// A foundation template id resolves to its branch/template kind; any other
/// valid multihash resolves to [`RevisionKind::Object`]; a value that is not a
/// valid registry multihash (bad hex, uppercase, unknown code, wrong length)
/// resolves to [`RevisionKind::Unknown`].
pub fn resolve_revision_kind(revision_type: &str) -> RevisionKind {
    let bytes = match decode_naming_hash(revision_type) {
        Some(b) => b,
        None => return RevisionKind::Unknown,
    };

    // A naming value MUST be a structurally valid registry multihash; anything
    // else is not classifiable (PCA-0015 §3.3, §3.11.6).
    if multihash_decode(&bytes).is_err() {
        return RevisionKind::Unknown;
    }

    if bytes == template_id_multihash(&GENESIS_TYPE_HASH)
        || bytes == template_id_multihash(&TemplateMeta::TEMPLATE_LINK)
    {
        return RevisionKind::Template;
    }
    if bytes == template_id_multihash(&AnchorTemplate::TEMPLATE_LINK) {
        return RevisionKind::Anchor;
    }
    if SIGNATURE_FOUNDATION_HASHES.contains(&bytes) {
        return RevisionKind::Signature;
    }
    if TIMESTAMP_FOUNDATION_HASHES.contains(&bytes) {
        return RevisionKind::Timestamp;
    }

    RevisionKind::Object
}

/// Decode a naming-value hex string (`0x`-prefixed, **lowercase**, PCA-0015
/// §3.11.7) into its raw multihash bytes. Returns `None` for a missing prefix,
/// any uppercase hex digit, or invalid hex.
fn decode_naming_hash(s: &str) -> Option<Vec<u8>> {
    let hex_str = s.strip_prefix("0x")?;
    if hex_str.contains(|c: char| c.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(hex_str).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_type_hash_is_deterministic() {
        let h1 = *GENESIS_TYPE_HASH;
        let h2 = HashType::Sha3_256.hash(b"aqua:genesis:template_meta");
        assert_eq!(h1.as_slice(), h2.as_slice());
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn genesis_type_link_roundtrips() {
        let link = genesis_type_link();
        // The link is now the full multihash; its inner digest is the bare hash.
        let (ht, digest) = multihash_decode(link.as_ref()).unwrap();
        assert_eq!(ht, HashType::Sha3_256);
        assert_eq!(digest.as_slice(), GENESIS_TYPE_HASH.as_slice());
    }

    #[test]
    fn legacy_literals_are_unknown() {
        assert_eq!(resolve_revision_kind("anchor"), RevisionKind::Unknown);
        assert_eq!(resolve_revision_kind("template"), RevisionKind::Unknown);
    }

    #[test]
    fn foundation_hashes_resolve() {
        let mh = |l: &[u8; 32]| format!("0x{}", hex::encode(template_id_multihash(l)));
        let anchor = mh(&AnchorTemplate::TEMPLATE_LINK);
        let tmpl = mh(&TemplateMeta::TEMPLATE_LINK);
        let sig_base = mh(&SignatureBase::TEMPLATE_LINK);
        let sig_ed = mh(&SignatureEd25519::TEMPLATE_LINK);
        let sig_eip = mh(&SignatureEip191::TEMPLATE_LINK);
        let sig_p256 = mh(&SignatureP256::TEMPLATE_LINK);
        let sig_wa = mh(&SignatureWebauthn::TEMPLATE_LINK);
        let ts_base = mh(&TIMESTAMP_BASE_DIGEST);
        let ts_evm = mh(&TIMESTAMP_EVM_DIGEST);
        let ts_tsa = mh(&TIMESTAMP_TSA_DIGEST);

        assert_eq!(resolve_revision_kind(&anchor), RevisionKind::Anchor);
        assert_eq!(resolve_revision_kind(&tmpl), RevisionKind::Template);
        assert_eq!(resolve_revision_kind(&sig_base), RevisionKind::Signature);
        assert_eq!(resolve_revision_kind(&sig_ed), RevisionKind::Signature);
        assert_eq!(resolve_revision_kind(&sig_eip), RevisionKind::Signature);
        assert_eq!(resolve_revision_kind(&sig_p256), RevisionKind::Signature);
        assert_eq!(resolve_revision_kind(&sig_wa), RevisionKind::Signature);
        assert_eq!(resolve_revision_kind(&ts_base), RevisionKind::Timestamp);
        assert_eq!(resolve_revision_kind(&ts_evm), RevisionKind::Timestamp);
        assert_eq!(resolve_revision_kind(&ts_tsa), RevisionKind::Timestamp);
    }

    #[test]
    fn user_template_hash_is_object() {
        // A custom template id is a valid SHA3-256 multihash, not a foundation hash.
        let user = format!("0x{}", hex::encode(template_id_multihash(&[0x11; 32])));
        assert_eq!(resolve_revision_kind(&user), RevisionKind::Object);
    }

    #[test]
    fn invalid_inputs_are_unknown() {
        assert_eq!(resolve_revision_kind(""), RevisionKind::Unknown);
        assert_eq!(resolve_revision_kind("garbage"), RevisionKind::Unknown);
        assert_eq!(resolve_revision_kind("0xZZZZ"), RevisionKind::Unknown);
        // Uppercase hex is rejected (PCA-0015 §3.11.7).
        let upper = format!(
            "0x{}",
            hex::encode(template_id_multihash(&[0xab; 32])).to_uppercase()
        );
        assert_eq!(resolve_revision_kind(&upper), RevisionKind::Unknown);
        // A bare 32-byte digest (no multihash prefix) is not a valid naming value.
        let bare = format!("0x{}", "ab".repeat(32));
        assert_eq!(resolve_revision_kind(&bare), RevisionKind::Unknown);
        // 16-byte hash (wrong length).
        let short = format!("0x{}", "ab".repeat(16));
        assert_eq!(resolve_revision_kind(&short), RevisionKind::Unknown);
    }

    #[test]
    fn branch_kinds_match_expected_set() {
        assert!(RevisionKind::Signature.is_branch());
        assert!(RevisionKind::Anchor.is_branch());
        assert!(RevisionKind::Timestamp.is_branch());
        assert!(!RevisionKind::Template.is_branch());
        assert!(!RevisionKind::Object.is_branch());
        assert!(!RevisionKind::Unknown.is_branch());
    }

    #[test]
    fn genesis_hex_constants_match_links() {
        assert_eq!(
            *ANCHOR_TEMPLATE_HEX,
            format!(
                "0x{}",
                hex::encode(template_id_multihash(&AnchorTemplate::TEMPLATE_LINK))
            )
        );
        assert_eq!(
            *TEMPLATE_META_HEX,
            format!(
                "0x{}",
                hex::encode(template_id_multihash(&TemplateMeta::TEMPLATE_LINK))
            )
        );
    }

    #[test]
    fn hex_constants_resolve_to_expected_kinds() {
        assert_eq!(
            resolve_revision_kind(&ANCHOR_TEMPLATE_HEX),
            RevisionKind::Anchor,
        );
        assert_eq!(
            resolve_revision_kind(&TEMPLATE_META_HEX),
            RevisionKind::Template,
        );
    }
}

#[cfg(test)]
mod template_meta_constant_tests {
    use super::*;

    #[test]
    fn template_meta_revision_type_matches_the_template_link() {
        // The pasted literal and the resolved constant are one value. If a
        // future template_meta change moves the hash, this fails here rather
        // than silently minting a wrong revision_type in authored templates.
        assert_eq!(
            TEMPLATE_META_REVISION_TYPE,
            format!(
                "0x{}",
                hex::encode(template_id_multihash(&TemplateMeta::TEMPLATE_LINK))
            ),
            "TEMPLATE_META_REVISION_TYPE drifted from TemplateMeta::TEMPLATE_LINK"
        );
        assert_eq!(TEMPLATE_META_REVISION_TYPE, *TEMPLATE_META_HEX);
    }

    #[test]
    fn template_meta_revision_type_parses_as_a_link() {
        use crate::primitives::RevisionLink;
        use std::str::FromStr;

        let link = RevisionLink::from_str(TEMPLATE_META_REVISION_TYPE).unwrap();
        assert_eq!(link.bare_digest(), Some(TemplateMeta::TEMPLATE_LINK));
        assert_eq!(
            link.hash_type().unwrap(),
            crate::primitives::HashType::Sha3_256
        );
    }

    #[test]
    fn every_shipped_template_declares_it() {
        // Every template JSON this crate ships carries exactly this string as
        // its revision_type, which is what makes the constant safe to paste.
        // The single exception is template_meta itself: being the
        // template-of-templates, it cannot name itself recursively and carries
        // the genesis bootstrap value instead (see GENESIS_TYPE_HASH).
        let bootstrap = format!(
            "0x{}",
            hex::encode(template_id_multihash(&GENESIS_TYPE_HASH))
        );
        let mut checked = 0usize;
        for (name, json, _) in crate::core::shipped_templates() {
            let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
            let declared = parsed["revision_type"].as_str().unwrap();
            if *name == "template_meta" {
                assert_eq!(declared, bootstrap, "template_meta lost its bootstrap");
            } else {
                assert_eq!(
                    declared, TEMPLATE_META_REVISION_TYPE,
                    "{name} declares a different revision_type"
                );
            }
            checked += 1;
        }
        assert_eq!(checked, 19, "expected every shipped template to be checked");
    }
}
