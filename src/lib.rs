//! # aqua-rs-sdk-core
//!
//! Minimal, WASM-free core of the [Aqua Protocol](https://aqua-protocol.org)
//! SDK: verifiable, portable data trees with anchors, typed objects,
//! templates, cryptographic signatures, and selective disclosure. A
//! compatible subset of the full `aqua-rs-sdk`: identical template hashes,
//! canonicalization, and verification semantics, proven by the repo's
//! `compat-tests` suite.
//!
//! Core capabilities:
//!
//! - **Data validation**: template JSON Schemas validate payload structure at
//!   object creation and at verification time.
//! - **Integrity and provenance**: revision hashing, Merkle proofs, tree
//!   linking via anchors, and signature verification (Ed25519, EIP-191,
//!   P-256, WebAuthn).
//! - **Auditable agents**: the t1-t8 audit template family records AI-agent
//!   turns as chains of signed, individually verifiable artifacts, with a
//!   pseudonymous selective-disclosure preset.
//! - **Self-descriptive exports**: [`Aquafier::export_tree`] embeds the
//!   templates a tree references (and their ancestry) by default, so exported
//!   artifacts are complete objects that verify with no side inputs.
//!   [`missing_templates`] reports what an incoming tree is still missing.
//!
//! Not included (see the README's conformance profile for exact behavior):
//! WASM compute execution, timestamping providers, the policy engine, the
//! daemon runtime, and the template registry.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use aqua_rs_sdk_core::Aquafier;
//! use aqua_rs_sdk_core::primitives::RevisionLink;
//!
//! let aquafier = Aquafier::new();
//!
//! // Create a typed object from a template
//! let template_hash = RevisionLink::from_bytes([0u8; 32]);
//! let payload = serde_json::json!({"name": "example"});
//! let tree = aquafier.create_object(template_hash, None, payload, None).unwrap();
//! ```
//!
//! See `examples/agent_audit_trail.rs` for the end-to-end agent
//! auditability walkthrough.
//!
//! ## Feature Flags
//!
//! | Flag | Purpose |
//! |------|---------|
//! | `native` (default) | Enables the EIP-191 secp256k1 signer |
//!
//! ## Architecture
//!
//! The entry point is [`Aquafier`], constructed via [`Aquafier::new()`] or
//! [`Aquafier::builder()`]. The SDK is stateless; signing keys are passed per
//! call as [`SigningCredentials`], and verification behavior is governed by a
//! [`VerificationPolicy`].

/// Data models: revision types, trees, templates, signatures, anchors, and file data.
pub mod schema;

/// Primitive types: [`RevisionLink`](primitives::RevisionLink), [`HashType`](primitives::HashType),
/// [`Method`](primitives::Method), [`Did`](primitives::Did), Merkle trees, and DID encoding.
pub mod primitives;

/// Canonicalization and verification helpers.
pub mod verification;

/// Core verification pipeline (L1-L3) and signing.
pub mod core;
pub mod utils;

use crate::core::{delete_last_revision_util, object::create_object_util_with_name};

use crate::core::{
    genesis::{
        create_genesis_revision, create_genesis_revision_from_metadata,
        create_minimal_genesis_revision,
    },
    link::link_aqua_tree_util,
    object::{
        create_object_util, create_object_validated_util, create_object_with_anchor_links_util,
    },
    template::create_template_util,
    verify_aqua_tree_util,
};

// Re-export VerificationResult for consumers
pub use crate::core::VerificationResult;

// Re-export verification policy types for consumers
pub use crate::core::{
    DecisionPoint, PolicyWarning, Severity, TemplateTrust, VerificationOutcome, VerificationPolicy,
    TEMPLATE_VENDOR_TRUST_DOMAIN,
};

use primitives::{HashType, Method, MethodError, RevisionLink};
// SignatureValue re-exported unconditionally at line 82 via schema::signature
use schema::{
    file_data::FileData,
    file_data::FileMetadata,
    template_descriptor::TemplateDescriptor,
    tree::Tree,
    {AquaOperationData, AquaTreeWrapper, SigningCredentials},
};
use std::collections::HashMap;

use crate::core::signature::sign_aqua_tree_util;

// Re-export Signer trait and signer types for consumers
pub use crate::core::signature::sign_did::Ed25519Signer;
#[cfg(feature = "native")]
pub use crate::core::signature::sign_eth::Secp256k1Signer;
pub use crate::core::signature::sign_p256::P256KeySigner;
pub use crate::core::signature::traits::{SignError, Signer};
// Re-export signing primitives needed by external Signer implementations
pub use crate::schema::signature::{PreSignature, Signature, SignatureValue};

// Re-export self-descriptive export types for consumers
pub use crate::core::export::{missing_templates, ExportOptions, ExportTreeError};

// Re-export the validated creation error and the key-generation helper
pub use crate::core::object::CreateObjectError;
pub use crate::core::signature::sign_did::generate_ed25519;

// Re-export selective disclosure types for consumers
pub use crate::core::disclosure::{
    export_selective_tree, redact_revision, verify_redacted_revision, verify_selective_tree,
    Directive, DisclosurePolicy, DisclosureProfile, DisclosureVerificationError, ExportError,
    RedactedLeaf, RedactedRevision, RedactionError, RevisionDisclosure, SelectiveRevision,
    SelectiveTree, SelectiveVerificationError,
};

pub use crate::primitives::{Did, DidError};

// Compile-time verification that Aquafier is Clone + Send + Sync.
// This is required for Arc<Aquafier> to be safe to share across threads
// in the daemon module.
const _: fn() = || {
    fn assert_clone_send_sync<T: Clone + Send + Sync>() {}
    assert_clone_send_sync::<Aquafier>();
};

/// Builder for constructing an [`Aquafier`] with explicit module injection.
pub struct AquafierBuilder {
    templates: HashMap<TemplateDescriptor, Tree>,
    object_method: Method,
    other_method: Method,
    hash_type: HashType,
    verification_policy: VerificationPolicy,
}

impl AquafierBuilder {
    fn new() -> Self {
        Self {
            templates: HashMap::new(),
            object_method: Method::Tree,
            other_method: Method::Scalar,
            hash_type: HashType::default(),
            verification_policy: VerificationPolicy::strict(),
        }
    }

    /// Set the default method for object revisions (default: Tree).
    pub fn default_object_method(mut self, method: Method) -> Self {
        self.object_method = method;
        self
    }

    /// Set the default method for non-object revisions — signatures, timestamps,
    /// anchors (default: Scalar).
    pub fn default_signature_method(mut self, method: Method) -> Self {
        self.other_method = method;
        self
    }

    /// Set the hash algorithm for new trees (default: SHA3-256).
    ///
    /// All revisions within a tree inherit this algorithm. Existing trees
    /// retain whatever algorithm they were created with.
    pub fn hash_type(mut self, hash_type: HashType) -> Self {
        self.hash_type = hash_type;
        self
    }

    /// Set the verification policy that governs how non-fatal decision points
    /// are treated (default: [`VerificationPolicy::strict`], all `Fail`).
    ///
    /// The policy only governs the relaxable decision points (missing template,
    /// unavailable timestamp, WASM execution failure, batch proof failure). L1
    /// structural and hash integrity always hard-fail regardless of policy.
    pub fn verification_policy(mut self, policy: VerificationPolicy) -> Self {
        self.verification_policy = policy;
        self
    }

    /// Consume the builder and produce an [`Aquafier`].
    pub fn build(self) -> Aquafier {
        Aquafier {
            templates: self.templates,
            object_method: self.object_method,
            other_method: self.other_method,
            hash_type: self.hash_type,
            verification_policy: self.verification_policy,
        }
    }
}

/// Central SDK facade for creating, signing, and verifying Aqua trees.
///
/// `Aquafier` is a stateless, `Clone + Send + Sync` handle safe to wrap in
/// `Arc` and share across threads. All external capabilities (blockchain hosts,
/// trust stores, signers) are injected at construction time via
/// [`Aquafier::builder()`].
///
/// # Construction
///
/// Use the builder pattern for full control:
///
/// ```rust,ignore
/// let aquafier = Aquafier::builder()
///     // .blockchain_host(host)
///     // .trust_store(store)
///     .build();
/// ```
///
/// Or use [`Aquafier::new()`] for a minimal instance with no hosts configured.
#[derive(Clone)]
pub struct Aquafier {
    templates: HashMap<TemplateDescriptor, Tree>,
    object_method: Method,
    other_method: Method,
    hash_type: HashType,
    verification_policy: VerificationPolicy,
}

impl Default for Aquafier {
    fn default() -> Self {
        Self::new()
    }
}

impl Aquafier {
    /// Create an Aquafier with default configuration (no hosts configured).
    /// Objects default to Tree method, all other revisions default to Scalar.
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
            object_method: Method::Tree,
            other_method: Method::Scalar,
            hash_type: HashType::default(),
            verification_policy: VerificationPolicy::strict(),
        }
    }

    /// Returns the hash algorithm configured for this Aquafier instance.
    pub fn hash_type(&self) -> HashType {
        self.hash_type
    }

    /// Returns the verification policy configured for this Aquafier instance.
    pub fn verification_policy(&self) -> &VerificationPolicy {
        &self.verification_policy
    }

    /// Create an Aquafier builder for explicit module injection.
    pub fn builder() -> AquafierBuilder {
        AquafierBuilder::new()
    }

    /// Create a genesis revision from file data.
    ///
    /// The genesis revision is the root of a new Aqua tree, containing the
    /// file's content hash, size, and name. Pass `None` for `method` to use
    /// the configured default (Tree).
    pub fn create_genesis_revision(
        &self,
        file_data: FileData,
        method: Option<Method>,
    ) -> Result<Tree, MethodError> {
        create_genesis_revision(file_data, method.unwrap_or(self.object_method))
    }

    /// Create a minimal genesis revision (content hash only, no file metadata).
    ///
    /// Use this for lightweight trees where full file metadata is not needed.
    pub fn create_minimal_genesis_revision(
        &self,
        file_data: FileData,
        method: Option<Method>,
    ) -> Result<Tree, MethodError> {
        create_minimal_genesis_revision(file_data, method.unwrap_or(self.object_method))
    }

    /// Create a genesis revision from pre-computed content hash and file size.
    ///
    /// Use this instead of `create_genesis_revision` when the caller already
    /// has the SHA3-256 hash of the file content (e.g. from content-addressed
    /// storage). Avoids a redundant hash pass and the ~N byte memory allocation.
    pub fn create_genesis_revision_from_metadata(
        &self,
        metadata: FileMetadata,
        method: Option<Method>,
    ) -> Result<Tree, MethodError> {
        create_genesis_revision_from_metadata(metadata, method.unwrap_or(self.object_method))
    }

    /// Sign the latest revision in an Aqua tree.
    ///
    /// Creates a new Signature branch revision pointing at the tree's tip.
    /// The `credentials` determine the signature algorithm (EIP-191, Ed25519, P-256).
    /// Pass `None` for `method` to use the configured default (Scalar).
    ///
    /// The optional `ident_character` is an application-level label included in
    /// the signature revision's metadata (e.g., for multi-signer workflows).
    pub async fn sign_aqua_tree(
        &self,
        aqua_tree: AquaTreeWrapper,
        credentials: &SigningCredentials,
        method: Option<Method>,
        ident_character: Option<String>,
    ) -> Result<AquaOperationData, MethodError> {
        sign_aqua_tree_util(
            &aqua_tree,
            credentials,
            method.unwrap_or(self.other_method),
            ident_character,
        )
        .await
    }

    /// Verify an Aqua tree through the full L1-L3 pipeline (async).
    ///
    /// Runs structural validation, hash verification, signature/timestamp
    /// verification (L2), and WASM template compute (L3) for every revision.
    /// Returns a [`VerificationResult`] whose [`outcome`](VerificationResult::outcome)
    /// is the single source of truth.
    ///
    /// Pass `file_objects` for trees that contain file genesis revisions
    /// requiring content hash verification.
    pub async fn verify_aqua_tree(
        &self,
        aqua_tree_wrapper: AquaTreeWrapper,
        file_objects: Vec<FileData>,
    ) -> Result<VerificationResult, MethodError> {
        verify_aqua_tree_util(
            &aqua_tree_wrapper,
            file_objects,
            &[],
            &self.verification_policy,
        )
        .await
    }

    /// Verify an Aqua tree with cross-tree dependencies (async).
    ///
    /// Same as [`verify_aqua_tree`](Aquafier::verify_aqua_tree) but also verifies
    /// `linked_trees` in topological order and resolves L3 cross-tree references
    /// (e.g., attestation templates that use `ctx_linked_tree_count()`).
    pub async fn verify_aqua_tree_with_linked_trees(
        &self,
        aqua_tree_wrapper: AquaTreeWrapper,
        linked_trees: Vec<AquaTreeWrapper>,
        file_objects: Vec<FileData>,
    ) -> Result<VerificationResult, MethodError> {
        verify_aqua_tree_util(
            &aqua_tree_wrapper,
            file_objects,
            &linked_trees,
            &self.verification_policy,
        )
        .await
    }

    /// Link one or more Aqua trees to the current tree via an Anchor revision.
    ///
    /// Creates a structural link from the current tree to each target tree,
    /// enabling cross-tree verification (L3). The anchor's `structural_links`
    /// contain the tip hashes of the linked trees.
    pub fn link_aqua_tree(
        &self,
        aqua_tree_wrapper: AquaTreeWrapper,
        link_aqua_tree_wrapper: Vec<AquaTreeWrapper>,
        method: Option<Method>,
    ) -> Result<Tree, MethodError> {
        link_aqua_tree_util(
            aqua_tree_wrapper,
            link_aqua_tree_wrapper,
            method.unwrap_or(self.other_method),
        )
    }

    /// Remove the last revision from an Aqua tree.
    ///
    /// Returns a new tree without the tip revision. Useful for undoing an
    /// unsigned operation before it has been shared.
    pub fn delete_last_revision(
        &self,
        aqua_tree_wrapper: AquaTreeWrapper,
    ) -> Result<Tree, MethodError> {
        delete_last_revision_util(aqua_tree_wrapper)
    }

    /// Create a new template definition and register it with this Aquafier.
    ///
    /// The `json_schema` defines the payload structure that objects of this
    /// template type must satisfy. The template's SHA3-256 hash becomes its
    /// type identifier. Set `enable_scalar` to allow Scalar-method objects
    /// for this template (in addition to Tree-method).
    pub fn create_template(
        &mut self,
        json_schema: serde_json::Value,
        template_name: String,
        enable_scalar: bool,
    ) -> Result<Tree, MethodError> {
        let template_result =
            create_template_util(json_schema, template_name.clone(), enable_scalar);

        if let Ok(template_tree) = &template_result {
            if let Some(genesis) = template_tree.get_genesis_revision() {
                let descriptor = TemplateDescriptor::default_with_hash(genesis.0);
                self.templates.insert(descriptor, template_tree.clone());
            }
        }

        template_result
    }

    /// Wrap an existing template definition as a one-revision Aqua tree, keyed
    /// by the template's **full multihash** link.
    ///
    /// This is the portable-template shape: the unit a template author
    /// publishes, an import store keeps, and
    /// [`export_tree`](Aquafier::export_tree) accepts as a template source. It
    /// is also what [`verify_aqua_tree_with_linked_trees`](Aquafier::verify_aqua_tree_with_linked_trees)
    /// resolves custom types from.
    ///
    /// The full multihash key is the load-bearing detail: verification
    /// recomputes every revision's hash from its own key, and template
    /// resolution looks up `revision_type` links, which are multihashes. The
    /// bare-digest keying used by this crate's internal built-in template
    /// trees is an implementation detail of the catalog and is **not** usable
    /// for a linked or embedded tree.
    ///
    /// `name` labels the revision in the tree's `file_index` (organizational
    /// metadata, never hashed). Pass `None` for the built-in name when the
    /// hash is known, or a `template_<hash prefix>` fallback.
    ///
    /// ```rust,ignore
    /// let template: Template = serde_json::from_str(MyTemplate::TEMPLATE_JSON)?;
    /// let source = aquafier.template_tree(&template, Some("my_template"))?;
    /// let portable = aquafier.export_tree(&tree, &[source], &ExportOptions::default())?;
    /// ```
    pub fn template_tree(
        &self,
        template: &schema::Template,
        name: Option<&str>,
    ) -> Result<Tree, MethodError> {
        crate::core::template::template_tree_util(template, name)
    }

    /// Create a typed object revision in an Aqua tree.
    ///
    /// The `template_hash` identifies the template whose JSON Schema the
    /// `payload` must satisfy. Pass `previous_tree` to append to an existing
    /// tree, or `None` to start a new tree. Pass `None` for `method` to use
    /// the configured default (Tree).
    pub fn create_object(
        &self,
        template_hash: RevisionLink,
        previous_tree: Option<Tree>,
        payload: serde_json::Value,
        method: Option<Method>,
    ) -> Result<Tree, MethodError> {
        create_object_util(
            template_hash,
            previous_tree,
            payload,
            method.unwrap_or(self.object_method),
            self.hash_type,
        )
    }

    /// Create a typed object revision, validating the payload against a
    /// template resolved from **explicit sources**.
    ///
    /// Use this for custom, imported, or registry-sourced types.
    /// [`create_object`](Aquafier::create_object) validates the payload only
    /// when the template is one of this crate's built-ins: it has no way to
    /// find a template it does not ship, so for every other type it creates
    /// the revision unvalidated and the mistake surfaces later, at the
    /// receiver's verification. This method closes that gap by making the
    /// caller say where the template lives.
    ///
    /// Resolution order is deliberately the one verification uses: the
    /// `previous_tree`'s own revisions, this crate's built-in catalog, then
    /// `template_sources` (one-revision template trees, as produced by
    /// [`template_tree`](Aquafier::template_tree)).
    ///
    /// Fails closed:
    ///
    /// - [`CreateObjectError::TemplateNotFound`] if no source supplies the
    ///   template (never a silent unvalidated create),
    /// - [`CreateObjectError::AncestorTemplateNotFound`] if the template
    ///   resolves but an ancestor in its `derives_from` chain does not, since
    ///   verification resolves the whole chain,
    /// - [`CreateObjectError::SchemaViolation`] with the per-field errors if
    ///   the payload does not satisfy the schema.
    ///
    /// The resulting tree is byte-identical to what
    /// [`create_object`](Aquafier::create_object) would have produced for the
    /// same inputs: this adds a gate, not a different construction.
    ///
    /// ```rust,ignore
    /// let source = aquafier.template_tree(&my_template, Some("my_template"))?;
    /// let tree = aquafier.create_object_validated(
    ///     my_template_link,
    ///     None,
    ///     serde_json::json!({ "field": "value" }),
    ///     None,
    ///     &[source],
    /// )?;
    /// ```
    pub fn create_object_validated(
        &self,
        template_hash: RevisionLink,
        previous_tree: Option<Tree>,
        payload: serde_json::Value,
        method: Option<Method>,
        template_sources: &[Tree],
    ) -> Result<Tree, CreateObjectError> {
        create_object_validated_util(
            template_hash,
            previous_tree,
            payload,
            method.unwrap_or(self.object_method),
            self.hash_type,
            template_sources,
        )
    }

    /// Create a typed object revision with a custom name in the file index.
    ///
    /// Same as [`create_object`](Aquafier::create_object) but registers
    /// `object_name` in the tree's `file_index` for the new revision.
    pub fn create_object_with_name(
        &self,
        template_hash: RevisionLink,
        previous_tree: Option<Tree>,
        payload: serde_json::Value,
        method: Option<Method>,
        object_name: String,
    ) -> Result<Tree, MethodError> {
        create_object_util_with_name(
            template_hash,
            previous_tree,
            payload,
            method.unwrap_or(self.object_method),
            object_name,
            self.hash_type,
        )
    }

    /// Create an object with custom genesis anchor links.
    ///
    /// Same as [`Aquafier::create_object`] but uses `anchor_links` for the genesis anchor's
    /// `structural_links` instead of `[template_hash]`.
    ///
    /// Use this to build attestation trees where the genesis anchor links to a
    /// claim signature hash rather than the template hash.
    pub fn create_object_with_anchor_links(
        &self,
        template_hash: RevisionLink,
        anchor_links: Vec<RevisionLink>,
        payload: serde_json::Value,
        method: Option<Method>,
    ) -> Result<Tree, MethodError> {
        create_object_with_anchor_links_util(
            template_hash,
            anchor_links,
            payload,
            method.unwrap_or(self.object_method),
            self.hash_type,
        )
    }

    /// Return all templates registered with this Aquafier instance.
    ///
    /// These are templates created via [`create_template`](Aquafier::create_template)
    /// during this instance's lifetime. Does not include SDK built-in templates
    /// (use [`builtin_templates`](Aquafier::builtin_templates) for those).
    pub fn get_available_templates(&self) -> HashMap<TemplateDescriptor, Tree> {
        self.templates.clone()
    }

    /// Return all SDK built-in templates, keyed by their 32-byte SHA3-256 hash.
    ///
    /// These are the templates bundled with the SDK (File, Timestamp, Attestation,
    /// MultiSigner, TrustAssertion, WalletIdentification, AccessGrant,
    /// PlatformIdentityClaim). They are parsed once and cached for the lifetime
    /// of the process.
    pub fn builtin_templates() -> &'static HashMap<[u8; 32], schema::Template> {
        crate::core::builtin_templates()
    }

    /// Get a built-in template as a properly structured Aqua-Tree.
    ///
    /// - L1 (root) templates: single Template revision
    /// - L2+ (derived) templates: Anchor(links=[parent_hash]) + Template
    pub fn builtin_template_tree(hash: &[u8; 32]) -> Option<schema::tree::Tree> {
        crate::core::builtin_template_tree(hash)
    }

    /// Return template trees for the given hash and all ancestors (root first).
    ///
    /// For a depth-2 template like GitHubClaim (IdentityBase → PlatformIdentityClaim → GitHubClaim),
    /// returns [IdentityBase_tree, PlatformIdentityClaim_tree, GitHubClaim_tree].
    pub fn builtin_template_tree_chain(hash: &[u8; 32]) -> Vec<schema::tree::Tree> {
        crate::core::builtin_template_tree_chain(hash)
    }

    /// Resolve a built-in template hash to its human-readable name.
    pub fn builtin_template_name(hash: &[u8; 32]) -> Option<&'static str> {
        crate::core::builtin_template_name(hash)
    }

    /// The verification catalog as data: `(name, bare 32-byte digest)` for
    /// every built-in template, sorted by name (`file` plus the four concrete
    /// signature templates).
    ///
    /// Same set as [`builtin_templates`](Aquafier::builtin_templates), without
    /// parsing the template bodies. See
    /// [`shipped_template_hashes`](Aquafier::shipped_template_hashes) for the
    /// 8 contract templates.
    pub fn builtin_template_hashes() -> &'static [(&'static str, [u8; 32])] {
        crate::core::builtin_template_hashes()
    }

    /// The 8 contract templates this crate ships, as `(name, bare 32-byte
    /// digest)` sorted by name: the machinery and signature templates.
    ///
    /// Superset of [`builtin_template_hashes`](Aquafier::builtin_template_hashes):
    /// it also lists `template_meta`, `anchor_template`, and `signature_base`,
    /// which ship but are not resolved as object types. The 11 audit identities
    /// are fixtures (see `tests/audit_template_hashes.txt`), not this set.
    pub fn shipped_template_hashes() -> &'static [(&'static str, [u8; 32])] {
        crate::core::shipped_template_hashes()
    }

    /// Resolve all template dependency trees for the given tree.
    ///
    /// Inspects the genesis anchor's `structural_links`, looks up each
    /// as a built-in template, and returns the full ancestor chains (root-first,
    /// deduplicated). Returns an empty Vec if no built-in template dependencies
    /// are found.
    pub fn resolve_dependency_trees(tree: &schema::tree::Tree) -> Vec<schema::tree::Tree> {
        crate::core::resolve_dependency_trees(tree)
    }

    /// Export a tree as a **self-descriptive** Aqua tree: embed every template
    /// it references, plus those templates' full ancestry chains, so the
    /// result verifies on its own.
    ///
    /// This is the primary way to hand a tree to someone else. A typed object
    /// names its type by hash only, so without the template body a receiver
    /// cannot validate the payload. Embedding is therefore the **default**
    /// ([`ExportOptions::default`]); callers opt out explicitly with
    /// [`ExportOptions::bare`].
    ///
    /// Template bodies are resolved in this order:
    ///
    /// 1. the tree's own revisions (templates already embedded),
    /// 2. this crate's built-in catalog,
    /// 3. `extra_template_sources`: any trees that carry template revisions,
    ///    for example the portable template trees an import store or registry
    ///    client hands out. Templates registered on this instance via
    ///    [`create_template`](Aquafier::create_template) are *not* consulted
    ///    automatically; pass them here if you want them (their trees come
    ///    from [`get_available_templates`](Aquafier::get_available_templates)).
    ///
    /// Each collected template is inserted under its canonical full multihash
    /// link (the portable-template pattern of `docs/template-authoring.md`
    /// section 6). Signature, anchor, and template revisions need no
    /// resolution (they dispatch on foundation hash constants), so only typed
    /// object revisions drive the walk.
    ///
    /// The input is never mutated, templates already present are left alone,
    /// and re-exporting an exported tree is a no-op.
    ///
    /// # Receiver-relative built-ins
    ///
    /// [`ExportOptions::include_builtin_templates`] also defaults to `true`:
    /// "built-in" describes the receiver, not the sender (this crate's audit
    /// templates are not resolvable in the current full `aqua-rs-sdk`), so a
    /// self-descriptive export carries them too.
    ///
    /// # Errors
    ///
    /// Fails closed with [`ExportTreeError::UnresolvedTemplates`] listing every
    /// hash that no source could supply. Nothing is embedded in that case: a
    /// partially self-descriptive tree would overstate what it carries. Use
    /// [`missing_templates`] to check a tree first.
    pub fn export_tree(
        &self,
        tree: &Tree,
        extra_template_sources: &[Tree],
        options: &ExportOptions,
    ) -> Result<Tree, ExportTreeError> {
        crate::core::export::export_tree_util(tree, extra_template_sources, options)
    }

    /// Verify an Aqua tree synchronously (no async runtime needed).
    ///
    /// Full L1-L3 verification pipeline using sync inner functions for
    /// signature/object verification and direct `run_wasm` for WASM compute.
    pub fn verify_tree_sync(
        &self,
        aqua_tree_wrapper: AquaTreeWrapper,
        file_objects: Vec<FileData>,
    ) -> Result<VerificationResult, MethodError> {
        crate::core::verify_sync::verify_aqua_tree_sync(
            &aqua_tree_wrapper,
            file_objects,
            &[],
            &self.verification_policy,
        )
    }

    /// Verify an Aqua tree with linked trees synchronously.
    pub fn verify_tree_sync_with_linked_trees(
        &self,
        aqua_tree_wrapper: AquaTreeWrapper,
        linked_trees: Vec<AquaTreeWrapper>,
        file_objects: Vec<FileData>,
    ) -> Result<VerificationResult, MethodError> {
        crate::core::verify_sync::verify_aqua_tree_sync(
            &aqua_tree_wrapper,
            file_objects,
            &linked_trees,
            &self.verification_policy,
        )
    }
}
