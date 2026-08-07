//! Object bounds — template-declared limits on Object subgraph structure.
//!
//! Each template declares how large and complex an Object of that type may become.
//! Bounds are part of the template JSON and therefore part of its SHA3-256 hash.
//!
//! **Inheritance**: Derived templates inherit parent bounds unless they explicitly
//! declare tighter bounds. Resolution walks the ancestry chain upward.
//!
//! See spec-object-model.md §3 for the full specification.

use serde::{Deserialize, Serialize};

// ── Protocol hard ceilings ──────────────────────────────────────────────────

/// No template can exceed these hard ceilings, regardless of what it declares.
pub const PROTOCOL_MAX_STRUCTURAL_LINKS_PER_ANCHOR: u8 = 64;
pub const PROTOCOL_MAX_COMPOSITIONAL_LINKS_PER_ANCHOR: u8 = 64;
pub const PROTOCOL_MAX_REFERENCE_LINKS_PER_ANCHOR: u8 = 64;
pub const PROTOCOL_MAX_CHAIN_DEPTH: u16 = 256;
pub const PROTOCOL_MAX_BRANCHES_PER_NODE: u16 = 256;
pub const PROTOCOL_MAX_REVISIONS_PER_OBJECT: u16 = 4096;

// ── ObjectBounds ────────────────────────────────────────────────────────────

/// Template-declared bounds on an Object's subgraph structure.
///
/// Enforced at write-time (`insert_node_atomic`) and eval-time
/// (`reconstruct_context`). Out-of-bounds Objects are incorrect per spec.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectBounds {
    /// Maximum chain depth (anchor → typed → ... → tip).
    pub max_chain_depth: u16,
    /// Structural link requirements in genesis/anchor revisions.
    pub structural_links: StructuralLinkSpec,
    /// Maximum signature branches per chain node.
    pub max_signature_branches: u8,
    /// Maximum timestamp branches per chain node.
    pub max_timestamp_branches: u8,
    /// Maximum compositional anchor branches per chain node.
    pub max_anchor_branches: u8,
    /// Hard ceiling on total revisions in the Object's subgraph.
    pub max_total_revisions: u16,
}

/// Structural link requirements for genesis/anchor revisions.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StructuralLinkSpec {
    /// MUST have at least this many structural links for WASM deps.
    pub required: u8,
    /// MAY have at most this many total (required ≤ max).
    pub max: u8,
}

impl ObjectBounds {
    /// Permissive default bounds for templates that don't declare specific limits.
    ///
    /// Used for vendor templates without explicit bounds and as the fallback
    /// when no template in an ancestry chain declares bounds.
    pub const fn permissive() -> Self {
        Self {
            max_chain_depth: 64,
            structural_links: StructuralLinkSpec {
                required: 0,
                max: 4,
            },
            max_signature_branches: 8,
            max_timestamp_branches: 4,
            max_anchor_branches: 4,
            max_total_revisions: 1024,
        }
    }
}

impl Default for ObjectBounds {
    fn default() -> Self {
        Self::permissive()
    }
}

// ── Resolution with inheritance ─────────────────────────────────────────────

/// Resolve bounds for a built-in template by hash, with ancestry inheritance.
///
/// 1. If the template's JSON declares `bounds`, return those.
/// 2. Otherwise, walk the ancestry chain upward looking for a parent with bounds.
/// 3. If no ancestor declares bounds, return `ObjectBounds::permissive()`.
pub fn resolve_bounds(template_hash: &[u8; 32]) -> ObjectBounds {
    use crate::core::resolve_builtin_template;
    use crate::primitives::RevisionLink;

    let link = RevisionLink::new(template_hash.to_vec());

    // Try the template itself first.
    if let Some(tmpl) = resolve_builtin_template(&link) {
        if let Some(b) = tmpl.raw_bounds() {
            return b.clone();
        }
        // Walk ancestry: try each ancestor from nearest to root.
        if let Some(ancestry) = tmpl.ancestry() {
            for ancestor_link in ancestry.iter().rev() {
                if let Some(ancestor_tmpl) = resolve_builtin_template(ancestor_link) {
                    if let Some(b) = ancestor_tmpl.raw_bounds() {
                        return b.clone();
                    }
                }
            }
        }
    }

    ObjectBounds::permissive()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_has_declared_bounds() {
        use crate::schema::template::BuiltInTemplate;
        use crate::schema::templates::File;
        let b = resolve_bounds(&File::TEMPLATE_LINK);
        assert_eq!(b.max_chain_depth, 64);
        assert_eq!(b.max_signature_branches, 4);
        assert_eq!(b.max_total_revisions, 1024);
    }

    #[test]
    fn identity_base_has_declared_bounds() {
        use crate::schema::template::BuiltInTemplate;
        use crate::schema::templates::IdentityBase;
        let b = resolve_bounds(&IdentityBase::TEMPLATE_LINK);
        assert_eq!(b.max_chain_depth, 2);
        assert_eq!(b.max_signature_branches, 1);
        assert_eq!(b.max_total_revisions, 6);
    }

    #[test]
    fn derived_audit_template_inherits_bounds() {
        use crate::schema::template::BuiltInTemplate;
        use crate::schema::templates::AuditUserPrompt;
        // AuditUserPrompt derives from audit_artifact and doesn't declare its
        // own bounds, so resolution must walk ancestry and inherit
        // audit_artifact's explicit bounds rather than falling through to
        // identity_base or the permissive default.
        let b = resolve_bounds(&AuditUserPrompt::TEMPLATE_LINK);
        assert_eq!(b.max_chain_depth, 2, "should inherit audit_artifact bounds");
        assert_eq!(b.max_anchor_branches, 4);
        assert_eq!(b.max_signature_branches, 6);
        assert_eq!(b.max_timestamp_branches, 4);
        assert_eq!(b.max_total_revisions, 16);
    }

    #[test]
    fn audit_family_declares_explicit_anchor_bounds() {
        use crate::schema::template::BuiltInTemplate;
        use crate::schema::templates::{AuditArtifact, AuditUserTurnMarker};
        // audit_artifact declares explicit bounds — without them, resolution
        // walks to identity_base and inherits max_anchor_branches: 0, which
        // rejects the round-seal anchor on audit trees.
        let b = resolve_bounds(&AuditArtifact::TEMPLATE_LINK);
        assert_eq!(b.max_anchor_branches, 4);
        assert_eq!(b.max_signature_branches, 6);
        assert_eq!(b.max_timestamp_branches, 4);
        assert_eq!(b.max_chain_depth, 2);
        assert_eq!(b.max_total_revisions, 16);
        // Every derived audit template inherits them (nearest-declaration-wins).
        let b = resolve_bounds(&AuditUserTurnMarker::TEMPLATE_LINK);
        assert_eq!(
            b.max_anchor_branches, 4,
            "T1 must inherit audit_artifact bounds, not identity_base's 0"
        );
        assert_eq!(b.max_total_revisions, 16);
    }

    #[test]
    fn timestamp_evm_inherits_timestamp_base() {
        use crate::schema::template::BuiltInTemplate;
        use crate::schema::templates::EvmTimestampPayload;
        let b = resolve_bounds(&EvmTimestampPayload::TEMPLATE_LINK);
        assert_eq!(b.max_chain_depth, 1);
        assert_eq!(b.max_total_revisions, 1);
    }

    #[test]
    fn unknown_template_returns_permissive() {
        let b = resolve_bounds(&[0xFF; 32]);
        assert_eq!(b, ObjectBounds::permissive());
    }

    #[test]
    fn protocol_ceilings_are_consistent() {
        // Walk every built-in template (rather than a hardcoded subset) so
        // this test tracks whichever templates core ships, and assert none
        // of them can exceed the protocol's hard ceilings once inheritance
        // is resolved.
        for hash in crate::core::builtin_templates().keys() {
            let b = resolve_bounds(hash);
            assert!(b.max_chain_depth <= PROTOCOL_MAX_CHAIN_DEPTH);
            assert!(b.max_total_revisions <= PROTOCOL_MAX_REVISIONS_PER_OBJECT);
            assert!(b.structural_links.max <= PROTOCOL_MAX_STRUCTURAL_LINKS_PER_ANCHOR);
        }
    }
}
