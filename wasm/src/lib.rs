//! wasm-bindgen exports for `aqua-rs-sdk-core`.
//!
//! Boundary conventions (shared with the TypeScript wrapper in `js-sdk/`):
//!
//! - Every structured value crosses as a JSON string in the serde shape of the
//!   corresponding core struct (`Tree`, `AquaTreeWrapper`, `AquaOperationData`,
//!   `VerificationResult`, `DisclosurePolicy`, ...). Byte payloads cross as
//!   `Uint8Array`.
//! - Errors are `JsError`s whose message is `"<context>: <source error>"`.
//! - Optional `Method` parameters take `"scalar"` / `"tree"` (bare or as a
//!   JSON string literal); omit, `null`, or `""` selects the Aquafier default.
//! - Hash type parameters take `"sha3_256"` / `"blake3_256"` or the wire names
//!   `"FIPS_202-SHA3-256"` / `"BLAKE3-256"`.
//! - Revision links cross as their wire form: the `"0x"`-prefixed hex of the
//!   full multihash (`0x1620<64 hex>` for SHA3-256).
//!
//! The whole surface is gated on `target_arch = "wasm32"`; on native targets
//! this crate is an empty library.

#[cfg(target_arch = "wasm32")]
pub mod bindings {
    use std::path::PathBuf;

    use aqua_rs_sdk_core::core::disclosure::{
        export_selective_tree, redact_revision, verify_redacted_revision, verify_selective_tree,
        DisclosurePolicy, RedactedRevision, SelectiveTree,
    };
    use aqua_rs_sdk_core::core::signature::sign_did::DIDSigner;
    use aqua_rs_sdk_core::core::signature::sign_p256::P256Signer;
    use aqua_rs_sdk_core::core::signature::verify_signature_sync;
    use aqua_rs_sdk_core::core::signature_template_hash;
    use aqua_rs_sdk_core::primitives::{
        did_key, merkle, multihash_decode, multihash_encode, HashType, Method, MethodError,
        RevisionLink,
    };
    use aqua_rs_sdk_core::schema::file_data::FileMetadata;
    use aqua_rs_sdk_core::schema::template::BuiltInTemplate;
    use aqua_rs_sdk_core::schema::templates::{
        AuditAgentResponse, AuditAgentThinking, AuditAgentToolCall, AuditApiResponse,
        AuditArtifact, AuditHitlApproval, AuditRoundAnchor, AuditSessionClose, AuditToolResult,
        AuditUserPrompt, AuditUserTurnMarker,
    };
    use aqua_rs_sdk_core::schema::tree::Tree;
    use aqua_rs_sdk_core::schema::{
        AnyRevision, AquaOperationData, AquaTreeWrapper, FileData, Object, PreSignature, Signature,
        SignatureValue, SigningCredentials, Template,
    };
    use aqua_rs_sdk_core::verification::Linkable;
    use aqua_rs_sdk_core::{missing_templates, Aquafier, ExportOptions, VerificationPolicy};
    use wasm_bindgen::prelude::*;

    // ── Module init ─────────────────────────────────────────────────────────

    /// Installs the panic hook so Rust panics surface as readable JS errors.
    /// Runs automatically when the module is instantiated; not exported.
    #[wasm_bindgen(start)]
    fn init_panic_hook() {
        console_error_panic_hook::set_once();
    }

    // ── Error and parsing helpers ───────────────────────────────────────────

    fn js_err(context: &str, e: impl std::fmt::Display) -> JsError {
        JsError::new(&format!("{context}: {e}"))
    }

    fn method_err(context: &str, e: MethodError) -> JsError {
        match e {
            MethodError::WithLogs(logs) => {
                let msg = logs
                    .iter()
                    .map(|l| l.log.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                JsError::new(&format!("{context}: {msg}"))
            }
            other => js_err(context, other),
        }
    }

    fn parse_json<T: serde::de::DeserializeOwned>(what: &str, json: &str) -> Result<T, JsError> {
        serde_json::from_str(json).map_err(|e| js_err(&format!("failed to parse {what}"), e))
    }

    fn to_json<T: serde::Serialize>(value: &T) -> Result<String, JsError> {
        serde_json::to_string(value).map_err(|e| js_err("failed to serialize result", e))
    }

    fn is_absent(s: &str) -> bool {
        let t = s.trim();
        t.is_empty() || t == "null" || t == "undefined"
    }

    fn parse_method(method_json: Option<String>) -> Result<Option<Method>, JsError> {
        let Some(raw) = method_json else {
            return Ok(None);
        };
        if is_absent(&raw) {
            return Ok(None);
        }
        let s = raw.trim();
        let name: String = if s.starts_with('"') {
            parse_json("method", s)?
        } else {
            s.to_string()
        };
        name.parse::<Method>().map(Some).map_err(|_| {
            JsError::new(&format!(
                "invalid method {name:?}: expected \"scalar\" or \"tree\""
            ))
        })
    }

    fn parse_hash_type(s: &str) -> Result<HashType, JsError> {
        match s.trim().trim_matches('"') {
            "sha3_256" | "sha3-256" | "SHA3_256" | "SHA3-256" | "FIPS_202-SHA3-256" => {
                Ok(HashType::Sha3_256)
            }
            "blake3_256" | "blake3-256" | "BLAKE3_256" | "BLAKE3-256" => Ok(HashType::Blake3_256),
            other => Err(JsError::new(&format!(
                "invalid hash type {other:?}: expected \"sha3_256\" or \"blake3_256\""
            ))),
        }
    }

    fn parse_link(what: &str, s: &str) -> Result<RevisionLink, JsError> {
        s.trim()
            .trim_matches('"')
            .parse::<RevisionLink>()
            .map_err(|e| js_err(&format!("invalid {what}"), e))
    }

    /// Accepts a full multihash link (`0x1620...`) or a bare 32-byte digest
    /// (`0x<64 hex>`), returning the bare digest the built-in catalog is keyed by.
    fn parse_digest(what: &str, s: &str) -> Result<[u8; 32], JsError> {
        let t = s.trim().trim_matches('"');
        let bytes = hex_bytes(what, t)?;
        if bytes.len() == 32 {
            return Ok(bytes.try_into().expect("length checked"));
        }
        parse_link(what, t)?
            .bare_digest()
            .ok_or_else(|| JsError::new(&format!("invalid {what}: not a 32-byte digest")))
    }

    fn hex_bytes(what: &str, s: &str) -> Result<Vec<u8>, JsError> {
        let t = s.trim().trim_matches('"');
        hex::decode(t.strip_prefix("0x").unwrap_or(t))
            .map_err(|e| js_err(&format!("invalid hex in {what}"), e))
    }

    fn hex0x(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn parse_tree(what: &str, json: &str) -> Result<Tree, JsError> {
        match serde_json::from_str::<Tree>(json) {
            Ok(t) => Ok(t),
            Err(tree_err) => match serde_json::from_str::<AquaTreeWrapper>(json) {
                Ok(w) => Ok(w.aqua_tree),
                Err(_) => Err(js_err(
                    &format!("failed to parse {what} (expected a Tree or an AquaTreeWrapper)"),
                    tree_err,
                )),
            },
        }
    }

    fn parse_optional_tree(what: &str, json: Option<String>) -> Result<Option<Tree>, JsError> {
        match json {
            Some(s) if !is_absent(&s) => parse_tree(what, &s).map(Some),
            _ => Ok(None),
        }
    }

    fn parse_wrapper(what: &str, json: &str) -> Result<AquaTreeWrapper, JsError> {
        match serde_json::from_str::<AquaTreeWrapper>(json) {
            Ok(w) => Ok(w),
            Err(wrap_err) => match serde_json::from_str::<Tree>(json) {
                Ok(t) => Ok(AquaTreeWrapper::new(t, None, None)),
                Err(_) => Err(js_err(
                    &format!("failed to parse {what} (expected an AquaTreeWrapper or a Tree)"),
                    wrap_err,
                )),
            },
        }
    }

    fn parse_trees(what: &str, json: &str) -> Result<Vec<Tree>, JsError> {
        if is_absent(json) {
            return Ok(Vec::new());
        }
        let items: Vec<serde_json::Value> = parse_json(what, json)?;
        items
            .iter()
            .enumerate()
            .map(|(i, v)| parse_tree(&format!("{what}[{i}]"), &v.to_string()))
            .collect()
    }

    fn parse_wrappers(what: &str, json: &str) -> Result<Vec<AquaTreeWrapper>, JsError> {
        if is_absent(json) {
            return Ok(Vec::new());
        }
        let items: Vec<serde_json::Value> = parse_json(what, json)?;
        items
            .iter()
            .enumerate()
            .map(|(i, v)| parse_wrapper(&format!("{what}[{i}]"), &v.to_string()))
            .collect()
    }

    fn parse_files(files_json: Option<String>) -> Result<Vec<FileData>, JsError> {
        match files_json {
            Some(s) if !is_absent(&s) => parse_json("files", &s),
            _ => Ok(Vec::new()),
        }
    }

    fn parse_export_options(options: &str) -> Result<ExportOptions, JsError> {
        let t = options.trim();
        if t.starts_with('{') {
            let v: serde_json::Value = parse_json("export options", t)?;
            let base = ExportOptions::default();
            return Ok(ExportOptions {
                include_templates: v
                    .get("include_templates")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(base.include_templates),
                include_builtin_templates: v
                    .get("include_builtin_templates")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(base.include_builtin_templates),
            });
        }
        match t.trim_matches('"') {
            "" | "default" | "self_descriptive" => Ok(ExportOptions::default()),
            "non_builtin_only" => Ok(ExportOptions::non_builtin_only()),
            "bare" => Ok(ExportOptions::bare()),
            other => Err(JsError::new(&format!(
                "invalid export options {other:?}: expected \"default\", \"self_descriptive\", \
                 \"non_builtin_only\", or \"bare\""
            ))),
        }
    }

    fn signature_target(wrapper: &AquaTreeWrapper) -> Result<RevisionLink, JsError> {
        if let Some(rev) = wrapper.revision.as_ref() {
            return Ok(rev.clone());
        }
        wrapper
            .aqua_tree
            .get_latest_revision_link()
            .ok_or_else(|| JsError::new("tree has no revisions to sign"))
    }

    // ── Aquafier ────────────────────────────────────────────────────────────

    /// Stateless SDK facade: create, sign, export, and verify Aqua trees.
    ///
    /// Construct with `new AquafierWasm()` for the defaults (objects use the
    /// tree method, signatures and anchors use scalar, SHA3-256 hashes, strict
    /// verification policy) or `AquafierWasm.withOptions(json)` to override.
    #[wasm_bindgen]
    pub struct AquafierWasm {
        inner: Aquafier,
    }

    impl Default for AquafierWasm {
        fn default() -> Self {
            Self::new()
        }
    }

    #[wasm_bindgen]
    impl AquafierWasm {
        /// Aquafier with default configuration.
        #[wasm_bindgen(constructor)]
        pub fn new() -> AquafierWasm {
            AquafierWasm {
                inner: Aquafier::new(),
            }
        }

        /// Aquafier configured from a JSON object. Every key is optional:
        ///
        /// ```json
        /// {
        ///   "default_object_method": "tree" | "scalar",
        ///   "default_signature_method": "scalar" | "tree",
        ///   "hash_type": "sha3_256" | "blake3_256",
        ///   "verification_policy": "default" | "strict" | "offline" | "debug"
        /// }
        /// ```
        ///
        /// `"default"` and `"strict"` are the same (all decision points fail);
        /// `"debug"` tolerates untrusted WASM and must never be used in production.
        #[wasm_bindgen(js_name = withOptions)]
        pub fn with_options(options_json: &str) -> Result<AquafierWasm, JsError> {
            let opts: serde_json::Value = if is_absent(options_json) {
                serde_json::Value::Object(Default::default())
            } else {
                parse_json("options", options_json)?
            };
            let str_opt = |key: &str| -> Result<Option<String>, JsError> {
                match opts.get(key) {
                    None | Some(serde_json::Value::Null) => Ok(None),
                    Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
                    Some(other) => Err(JsError::new(&format!(
                        "option {key:?} must be a string, got {other}"
                    ))),
                }
            };

            let mut builder = Aquafier::builder();
            if let Some(m) = parse_method(str_opt("default_object_method")?)? {
                builder = builder.default_object_method(m);
            }
            if let Some(m) = parse_method(str_opt("default_signature_method")?)? {
                builder = builder.default_signature_method(m);
            }
            if let Some(h) = str_opt("hash_type")? {
                builder = builder.hash_type(parse_hash_type(&h)?);
            }
            if let Some(p) = str_opt("verification_policy")? {
                let policy = match p.trim() {
                    "" | "default" | "strict" => VerificationPolicy::strict(),
                    "offline" => VerificationPolicy::offline(),
                    "debug" => VerificationPolicy::debug(),
                    other => {
                        return Err(JsError::new(&format!(
                            "invalid verification_policy {other:?}: expected \"default\", \
                             \"strict\", \"offline\", or \"debug\""
                        )))
                    }
                };
                builder = builder.verification_policy(policy);
            }
            Ok(AquafierWasm {
                inner: builder.build(),
            })
        }

        /// Hash algorithm this instance stamps on new trees, as its wire name
        /// (`"FIPS_202-SHA3-256"` or `"BLAKE3-256"`).
        #[wasm_bindgen(js_name = hashType)]
        pub fn hash_type(&self) -> String {
            self.inner.hash_type().to_string()
        }

        // ── Creation ────────────────────────────────────────────────────────

        /// Genesis revision from file bytes (content hash, size, and name).
        /// Returns the new `Tree` as JSON.
        #[wasm_bindgen(js_name = createGenesisRevision)]
        pub fn create_genesis_revision(
            &self,
            file_name: &str,
            file_content: &[u8],
            method_json: Option<String>,
        ) -> Result<String, JsError> {
            let file = FileData::new(
                file_name.to_string(),
                file_content.to_vec(),
                PathBuf::from(file_name),
            );
            let tree = self
                .inner
                .create_genesis_revision(file, parse_method(method_json)?)
                .map_err(|e| method_err("failed to create genesis revision", e))?;
            to_json(&tree)
        }

        /// Minimal genesis revision (content hash only, no file metadata).
        /// Returns the new `Tree` as JSON.
        #[wasm_bindgen(js_name = createMinimalGenesisRevision)]
        pub fn create_minimal_genesis_revision(
            &self,
            file_name: &str,
            file_content: &[u8],
            method_json: Option<String>,
        ) -> Result<String, JsError> {
            let file = FileData::new(
                file_name.to_string(),
                file_content.to_vec(),
                PathBuf::from(file_name),
            );
            let tree = self
                .inner
                .create_minimal_genesis_revision(file, parse_method(method_json)?)
                .map_err(|e| method_err("failed to create minimal genesis revision", e))?;
            to_json(&tree)
        }

        /// Genesis revision from a pre-computed SHA3-256 content hash.
        ///
        /// `metadata_json` is a `FileMetadata`:
        /// `{"file_name": string, "content_hash": number[] (32 bytes), "file_size": number, "path": string}`.
        /// Returns the new `Tree` as JSON.
        #[wasm_bindgen(js_name = createGenesisRevisionFromMetadata)]
        pub fn create_genesis_revision_from_metadata(
            &self,
            metadata_json: &str,
            method_json: Option<String>,
        ) -> Result<String, JsError> {
            let metadata: FileMetadata = parse_json("file metadata", metadata_json)?;
            let tree = self
                .inner
                .create_genesis_revision_from_metadata(metadata, parse_method(method_json)?)
                .map_err(|e| method_err("failed to create genesis revision from metadata", e))?;
            to_json(&tree)
        }

        /// Typed object revision. `template_link` is the template's multihash
        /// link; `previous_tree_json` (a `Tree`, or null) appends to an existing
        /// tree; `payload_json` is the object payload. The payload is validated
        /// only when the template is a built-in; use `createObjectValidated` for
        /// custom or registry templates. Returns the `Tree` as JSON.
        #[wasm_bindgen(js_name = createObject)]
        pub fn create_object(
            &self,
            template_link: &str,
            previous_tree_json: Option<String>,
            payload_json: &str,
            method_json: Option<String>,
        ) -> Result<String, JsError> {
            let template = parse_link("template link", template_link)?;
            let previous = parse_optional_tree("previous tree", previous_tree_json)?;
            let payload: serde_json::Value = parse_json("payload", payload_json)?;
            let tree = self
                .inner
                .create_object(template, previous, payload, parse_method(method_json)?)
                .map_err(|e| method_err("failed to create object", e))?;
            to_json(&tree)
        }

        /// Typed object revision validated against a template resolved from the
        /// previous tree, the built-in catalog, or `sources_json` (a JSON array
        /// of one-revision template `Tree`s, as produced by `templateTree`).
        /// Fails closed if the template or any ancestor cannot be resolved, or
        /// if the payload violates the schema. Returns the `Tree` as JSON.
        #[wasm_bindgen(js_name = createObjectValidated)]
        pub fn create_object_validated(
            &self,
            template_link: &str,
            previous_tree_json: Option<String>,
            payload_json: &str,
            method_json: Option<String>,
            sources_json: &str,
        ) -> Result<String, JsError> {
            let template = parse_link("template link", template_link)?;
            let previous = parse_optional_tree("previous tree", previous_tree_json)?;
            let payload: serde_json::Value = parse_json("payload", payload_json)?;
            let sources = parse_trees("template sources", sources_json)?;
            let tree = self
                .inner
                .create_object_validated(
                    template,
                    previous,
                    payload,
                    parse_method(method_json)?,
                    &sources,
                )
                .map_err(|e| js_err("failed to create validated object", e))?;
            to_json(&tree)
        }

        /// Like `createObject`, additionally recording `name` in the tree's
        /// `file_index` for the new revision. Returns the `Tree` as JSON.
        #[wasm_bindgen(js_name = createObjectWithName)]
        pub fn create_object_with_name(
            &self,
            template_link: &str,
            previous_tree_json: Option<String>,
            payload_json: &str,
            method_json: Option<String>,
            name: &str,
        ) -> Result<String, JsError> {
            let template = parse_link("template link", template_link)?;
            let previous = parse_optional_tree("previous tree", previous_tree_json)?;
            let payload: serde_json::Value = parse_json("payload", payload_json)?;
            let tree = self
                .inner
                .create_object_with_name(
                    template,
                    previous,
                    payload,
                    parse_method(method_json)?,
                    name.to_string(),
                )
                .map_err(|e| method_err("failed to create named object", e))?;
            to_json(&tree)
        }

        /// New tree whose genesis anchor carries `links_json` (a JSON array of
        /// multihash link strings) as structural links, followed by the typed
        /// object. Returns the `Tree` as JSON.
        #[wasm_bindgen(js_name = createObjectWithAnchorLinks)]
        pub fn create_object_with_anchor_links(
            &self,
            template_link: &str,
            links_json: &str,
            payload_json: &str,
            method_json: Option<String>,
        ) -> Result<String, JsError> {
            let template = parse_link("template link", template_link)?;
            let raw_links: Vec<String> = parse_json("anchor links", links_json)?;
            let links = raw_links
                .iter()
                .map(|l| parse_link("anchor link", l))
                .collect::<Result<Vec<_>, _>>()?;
            let payload: serde_json::Value = parse_json("payload", payload_json)?;
            let tree = self
                .inner
                .create_object_with_anchor_links(
                    template,
                    links,
                    payload,
                    parse_method(method_json)?,
                )
                .map_err(|e| method_err("failed to create object with anchor links", e))?;
            to_json(&tree)
        }

        /// Create a new template from a JSON Schema and register it on this
        /// instance (registration is unconditional in the core; registered
        /// templates are only consulted by `createTemplate` bookkeeping, pass
        /// the returned tree to `exportTree` / `createObjectValidated` as a
        /// source when you need it resolved). `enable_scalar` allows
        /// scalar-method objects of this type. Returns the template `Tree` as JSON.
        #[wasm_bindgen(js_name = createTemplate)]
        pub fn create_template(
            &mut self,
            schema_json: &str,
            name: &str,
            enable_scalar: bool,
        ) -> Result<String, JsError> {
            let schema: serde_json::Value = parse_json("template schema", schema_json)?;
            let tree = self
                .inner
                .create_template(schema, name.to_string(), enable_scalar)
                .map_err(|e| method_err("failed to create template", e))?;
            to_json(&tree)
        }

        /// Wrap a template definition (a `Template` revision JSON, e.g. a
        /// registry `definitions/<name>.json` body) as a one-revision tree keyed
        /// by its full multihash link: the portable shape that `exportTree`,
        /// `createObjectValidated`, and `verifyAquaTreeWithLinkedTrees` accept
        /// as a template source. `name` labels the revision in `file_index`.
        /// Returns the `Tree` as JSON.
        #[wasm_bindgen(js_name = templateTree)]
        pub fn template_tree(
            &self,
            template_json: &str,
            name: Option<String>,
        ) -> Result<String, JsError> {
            let template: Template = parse_json("template", template_json)?;
            let tree = self
                .inner
                .template_tree(&template, name.as_deref())
                .map_err(|e| method_err("failed to build template tree", e))?;
            to_json(&tree)
        }

        /// Link other trees to this one via an anchor revision whose structural
        /// links are the targets' tips. `link_wrappers_json` is a JSON array of
        /// `AquaTreeWrapper`. Returns the `Tree` as JSON.
        #[wasm_bindgen(js_name = linkAquaTree)]
        pub fn link_aqua_tree(
            &self,
            wrapper_json: &str,
            link_wrappers_json: &str,
            method_json: Option<String>,
        ) -> Result<String, JsError> {
            let wrapper = parse_wrapper("aqua tree", wrapper_json)?;
            let links = parse_wrappers("link trees", link_wrappers_json)?;
            let tree = self
                .inner
                .link_aqua_tree(wrapper, links, parse_method(method_json)?)
                .map_err(|e| method_err("failed to link aqua tree", e))?;
            to_json(&tree)
        }

        /// Remove the tip revision. Returns the `Tree` as JSON.
        #[wasm_bindgen(js_name = deleteLastRevision)]
        pub fn delete_last_revision(&self, wrapper_json: &str) -> Result<String, JsError> {
            let wrapper = parse_wrapper("aqua tree", wrapper_json)?;
            let tree = self
                .inner
                .delete_last_revision(wrapper)
                .map_err(|e| method_err("failed to delete last revision", e))?;
            to_json(&tree)
        }

        /// Self-descriptive export: embed every template the tree references
        /// (plus ancestry) under its canonical multihash link so the result
        /// verifies on its own. `sources_json` is a JSON array of template
        /// `Tree`s (from `templateTree`); `options` is `"default"`
        /// (= `"self_descriptive"`), `"non_builtin_only"`, `"bare"`, or a JSON
        /// object `{include_templates, include_builtin_templates}`. Fails closed
        /// listing unresolved template links. Returns the `Tree` as JSON.
        #[wasm_bindgen(js_name = exportTree)]
        pub fn export_tree(
            &self,
            tree_json: &str,
            sources_json: &str,
            options: &str,
        ) -> Result<String, JsError> {
            let tree = parse_tree("tree", tree_json)?;
            let sources = parse_trees("template sources", sources_json)?;
            let opts = parse_export_options(options)?;
            let exported = self
                .inner
                .export_tree(&tree, &sources, &opts)
                .map_err(|e| js_err("failed to export tree", e))?;
            to_json(&exported)
        }

        // ── Signing ─────────────────────────────────────────────────────────

        /// Sign the wrapper's target revision (`revision`, else the tip) with
        /// in-memory credentials. Resolves to `AquaOperationData` JSON.
        ///
        /// `credentials_json` is one of
        /// `{"did_key": "0x<32-byte Ed25519 secret>"}`,
        /// `{"p256_key": "0x<32-byte P-256 secret>"}`, or
        /// `{"secp256k1_key": "0x<32-byte secp256k1 secret>"}` (EIP-191).
        /// `ident` is an optional label copied into the log entries.
        #[wasm_bindgen(js_name = signAquaTree)]
        pub fn sign_aqua_tree(
            &self,
            wrapper_json: String,
            credentials_json: String,
            method_json: Option<String>,
            ident: Option<String>,
        ) -> js_sys::Promise {
            let aquafier = self.inner.clone();
            wasm_bindgen_futures::future_to_promise(async move {
                let wrapper = parse_wrapper("aqua tree", &wrapper_json)?;
                let credentials: SigningCredentials = parse_json("credentials", &credentials_json)?;
                let method = parse_method(method_json)?;
                let result = aquafier
                    .sign_aqua_tree(wrapper, &credentials, method, ident)
                    .await
                    .map_err(|e| method_err("failed to sign aqua tree", e))?;
                Ok(JsValue::from_str(&to_json(&result)?))
            })
        }

        /// Step 1 of external signing: build the pre-signature for the wrapper's
        /// target revision (`revision`, else the tip) and return exactly what the
        /// wallet must sign. Returns JSON:
        ///
        /// ```json
        /// {
        ///   "target_revision": "0x1620...",
        ///   "hash_type": "FIPS_202-SHA3-256",
        ///   "signature_type": "ed25519",
        ///   "signer": "did:key:z6Mk...",
        ///   "message": "<canonical pre-signature JSON>",
        ///   "message_hex": "0x..."
        /// }
        /// ```
        ///
        /// `message` is the canonical JSON the verifier recomputes from the
        /// stored revision (it already contains the nonce and timestamp, so it
        /// is single-use: pass the whole object back to `addExternalSignature`).
        /// What to sign, per `signature_type`:
        ///
        /// - `"ed25519"`: the raw UTF-8 bytes of `message`; 64-byte signature,
        ///   identifier = 32-byte public key. `signer` must be the matching
        ///   `did:key:z6Mk...` (see `didFromEd25519PublicKey`).
        /// - `"ecdsa:p256"`: ECDSA-SHA256 over the raw bytes of `message`
        ///   (WebCrypto `sign({name:"ECDSA", hash:"SHA-256"})`); 64-byte `r||s`
        ///   signature, identifier = 33-byte compressed SEC1 public key. `signer`
        ///   must be the matching `did:key:zDn...` (see `didFromP256PublicKey`).
        /// - `"ethereum:eip-191"`: `personal_sign` of the `message` string (the
        ///   wallet adds the `\x19Ethereum Signed Message:\n<len>` prefix);
        ///   65-byte signature, identifier = the 20-byte address. `signer` must
        ///   be `did:pkh:eip155:<chain>:0x<address>`.
        /// - `"webauthn:p256"`: challenge = SHA-256 of the raw bytes of
        ///   `message`; 64-byte `r||s` signature, identifier = 33-byte
        ///   compressed public key, plus `authenticator_data` and
        ///   `client_data_json` from the assertion. `signer` is the key's
        ///   `did:key:zDn...`.
        #[wasm_bindgen(js_name = prepareSignature)]
        pub fn prepare_signature(
            &self,
            wrapper_json: &str,
            signer: &str,
            signature_type: &str,
            method_json: Option<String>,
        ) -> Result<String, JsError> {
            if signature_template_hash(signature_type).is_none() {
                return Err(JsError::new(&format!(
                    "unknown signature_type {signature_type:?}: expected \"ed25519\", \
                     \"ecdsa:p256\", \"ethereum:eip-191\", or \"webauthn:p256\""
                )));
            }
            if signer.trim().is_empty() {
                return Err(JsError::new("signer DID must not be empty"));
            }
            let wrapper = parse_wrapper("aqua tree", wrapper_json)?;
            let target = signature_target(&wrapper)?;
            if !wrapper.aqua_tree.revisions.contains_key(&target) {
                return Err(JsError::new(&format!(
                    "target revision {target} is not in the tree"
                )));
            }
            let hash_type = target.hash_type().unwrap_or(HashType::Sha3_256);
            let method = parse_method(method_json)?.unwrap_or(Method::Scalar);
            let pre = PreSignature::new(target.clone(), method, hash_type, signer.to_string());
            let message = pre.canonical_json(signature_type);
            let message_str = String::from_utf8(message.clone())
                .map_err(|e| js_err("canonical json is not utf-8", e))?;
            to_json(&serde_json::json!({
                "target_revision": target.to_string(),
                "hash_type": hash_type.to_string(),
                "signature_type": signature_type,
                "signer": signer,
                "message": message_str,
                "message_hex": hex0x(&message),
            }))
        }

        /// Step 2 of external signing: attach a wallet-produced signature over
        /// the `message` returned by `prepareSignature`. `prepared_json` is that
        /// object verbatim; `signature_value_json` is the signature object in
        /// wire form:
        ///
        /// ```json
        /// {"signature_type": "ed25519", "signature": "0x<hex>", "signature_public_identifier": "0x<hex>"}
        /// ```
        ///
        /// (`ethereum:eip-191` takes the checksummed `0x` address as identifier;
        /// `webauthn:p256` adds `authenticator_data` and `client_data_json` as
        /// `0x` hex.) The revision is rebuilt from the prepared message so the
        /// verifier recomputes byte-identical input, then run through the core
        /// signature verifier (cryptographic check plus signer/key binding)
        /// before it is inserted: an invalid or mismatched signature throws and
        /// the tree is left untouched. Returns `AquaOperationData` JSON.
        #[wasm_bindgen(js_name = addExternalSignature)]
        pub fn add_external_signature(
            &self,
            wrapper_json: &str,
            prepared_json: &str,
            signature_value_json: &str,
        ) -> Result<String, JsError> {
            let wrapper = parse_wrapper("aqua tree", wrapper_json)?;
            let prepared: serde_json::Value = parse_json("prepared signature", prepared_json)?;
            let message = prepared
                .get("message")
                .and_then(|m| m.as_str())
                .ok_or_else(|| JsError::new("prepared signature is missing \"message\""))?;
            let mut fields: serde_json::Map<String, serde_json::Value> =
                parse_json("prepared message", message)?;

            let sig_value: SignatureValue = parse_json("signature value", signature_value_json)?;
            let declared_type = fields
                .remove("signature_type")
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or_else(|| JsError::new("prepared message is missing \"signature_type\""))?;
            if declared_type != sig_value.signature_type() {
                return Err(JsError::new(&format!(
                    "signature_type mismatch: prepared for {declared_type:?}, got {:?}",
                    sig_value.signature_type()
                )));
            }
            let hash_codec = fields
                .remove("hash_codec")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| JsError::new("prepared message is missing \"hash_codec\""))?;

            let target = fields
                .get("previous_revision")
                .and_then(|v| v.as_str())
                .map(|s| parse_link("previous_revision", s))
                .transpose()?
                .ok_or_else(|| JsError::new("prepared message is missing \"previous_revision\""))?;
            if !wrapper.aqua_tree.revisions.contains_key(&target) {
                return Err(JsError::new(&format!(
                    "target revision {target} is not in the tree"
                )));
            }
            let hash_type = target.hash_type().unwrap_or(HashType::Sha3_256);
            if u64::from(hash_type.multicodec()) != hash_codec {
                return Err(JsError::new(&format!(
                    "hash_codec mismatch: message says {hash_codec}, target revision uses {}",
                    hash_type.multicodec()
                )));
            }

            fields.insert(
                "signature".to_string(),
                serde_json::to_value(&sig_value)
                    .map_err(|e| js_err("failed to serialize signature value", e))?,
            );
            let signature: Signature = serde_json::from_value(serde_json::Value::Object(fields))
                .map_err(|e| js_err("failed to rebuild signature revision", e))?;

            let link = signature
                .calculate_link(hash_type)
                .map_err(|e| method_err("failed to compute signature revision hash", e))?;
            let revision = AnyRevision::Signature(signature);
            let (ok, mut logs) = verify_signature_sync(&revision, &link.to_string(), None);
            if !ok {
                let detail = logs
                    .iter()
                    .filter(|l| {
                        matches!(
                            l.log_type,
                            aqua_rs_sdk_core::primitives::log::LogType::Error
                                | aqua_rs_sdk_core::primitives::log::LogType::FinalError
                        )
                    })
                    .map(|l| l.log.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(JsError::new(&format!(
                    "external signature rejected by verifier: {detail}"
                )));
            }

            let mut aqua_tree = wrapper.aqua_tree;
            aqua_tree.revisions.insert(link, revision);
            logs.push(aqua_rs_sdk_core::primitives::log::LogData {
                log: "External signature added successfully".to_string(),
                log_type: aqua_rs_sdk_core::primitives::log::LogType::Success,
                ident: None,
            });
            to_json(&AquaOperationData {
                aqua_tree,
                aqua_trees: vec![],
                log_data: logs,
            })
        }

        // ── Verification ────────────────────────────────────────────────────

        /// Full L1-L3 verification, synchronous. `files_json` is an optional
        /// JSON array of `FileData`
        /// (`{"file_name": string, "file_content": number[], "path": string}`)
        /// for genesis content-hash checks. Returns `VerificationResult` JSON;
        /// read `outcome`: `{"result": "verified"}`,
        /// `{"result": "verified_with_warnings", "warnings": [...]}`, or
        /// `{"result": "failed", "errors": [...]}`.
        #[wasm_bindgen(js_name = verifyAquaTree)]
        pub fn verify_aqua_tree(
            &self,
            wrapper_json: &str,
            files_json: Option<String>,
        ) -> Result<String, JsError> {
            let wrapper = parse_wrapper("aqua tree", wrapper_json)?;
            let files = parse_files(files_json)?;
            let result = self
                .inner
                .verify_tree_sync(wrapper, files)
                .map_err(|e| method_err("verification error", e))?;
            to_json(&result)
        }

        /// Like `verifyAquaTree`, additionally verifying `linked_wrappers_json`
        /// (a JSON array of `AquaTreeWrapper`) in dependency order and resolving
        /// cross-tree references. Only linked trees reachable from the main
        /// tree's anchor `structural_links` are kept; the rest are pruned. That
        /// suits root templates and anchor-linked trees, but a derived
        /// template's ancestor supplied only as a linked tree is dropped and
        /// verification fails with `ANCESTOR_TEMPLATE_NOT_FOUND`. For derived
        /// template chains (the audit family), make the tree self-descriptive
        /// with `exportTree` first and verify it with `verifyAquaTree`.
        #[wasm_bindgen(js_name = verifyAquaTreeWithLinkedTrees)]
        pub fn verify_aqua_tree_with_linked_trees(
            &self,
            wrapper_json: &str,
            linked_wrappers_json: &str,
            files_json: Option<String>,
        ) -> Result<String, JsError> {
            let wrapper = parse_wrapper("aqua tree", wrapper_json)?;
            let linked = parse_wrappers("linked trees", linked_wrappers_json)?;
            let files = parse_files(files_json)?;
            let result = self
                .inner
                .verify_tree_sync_with_linked_trees(wrapper, linked, files)
                .map_err(|e| method_err("verification error", e))?;
            to_json(&result)
        }
    }

    // ── Free functions: version and keys ────────────────────────────────────

    /// Crate version (kept in lockstep with `aqua-rs-sdk-core`).
    #[wasm_bindgen]
    pub fn version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Fresh Ed25519 keypair from the host CSPRNG. Returns JSON
    /// `{"secret": "0x<64 hex>", "did": "did:key:z6Mk..."}`; `secret` is the
    /// `did_key` value for `signAquaTree` credentials.
    #[wasm_bindgen(js_name = generateEd25519)]
    pub fn generate_ed25519() -> Result<String, JsError> {
        let (secret, did) = aqua_rs_sdk_core::generate_ed25519();
        to_json(&serde_json::json!({ "secret": hex0x(&secret), "did": did }))
    }

    /// `did:key:z6Mk...` for a 32-byte Ed25519 public key.
    #[wasm_bindgen(js_name = didFromEd25519PublicKey)]
    pub fn did_from_ed25519_public_key(public_key: &[u8]) -> Result<String, JsError> {
        let key: &[u8; 32] = public_key.try_into().map_err(|_| {
            JsError::new(&format!(
                "Ed25519 public key must be 32 bytes (got {})",
                public_key.len()
            ))
        })?;
        Ok(did_key::encode_ed25519(key))
    }

    /// `did:key:zDn...` for a 33-byte compressed SEC1 P-256 public key.
    #[wasm_bindgen(js_name = didFromP256PublicKey)]
    pub fn did_from_p256_public_key(public_key: &[u8]) -> Result<String, JsError> {
        let key: &[u8; 33] = public_key.try_into().map_err(|_| {
            JsError::new(&format!(
                "P-256 compressed public key must be 33 bytes (got {})",
                public_key.len()
            ))
        })?;
        Ok(did_key::encode_p256(key))
    }

    /// `did:key:z6Mk...` derived from a 32-byte Ed25519 secret key (the DID
    /// `signAquaTree` will record for `{"did_key": ...}` credentials).
    #[wasm_bindgen(js_name = didFromEd25519SecretKey)]
    pub fn did_from_ed25519_secret_key(secret_key: &[u8]) -> Result<String, JsError> {
        DIDSigner::new()
            .derive_did(secret_key)
            .map_err(|e| js_err("failed to derive Ed25519 DID", e))
    }

    /// `did:key:zDn...` derived from a 32-byte P-256 secret scalar (the DID
    /// `signAquaTree` will record for `{"p256_key": ...}` credentials).
    #[wasm_bindgen(js_name = didFromP256SecretKey)]
    pub fn did_from_p256_secret_key(secret_key: &[u8]) -> Result<String, JsError> {
        P256Signer::new()
            .derive_did(secret_key)
            .map_err(|e| js_err("failed to derive P-256 DID", e))
    }

    /// Decode a `did:key` into JSON `{"algorithm": "ed25519" | "p256", "public_key": "0x..."}`.
    #[wasm_bindgen(js_name = decodeDidKey)]
    pub fn decode_did_key(did: &str) -> Result<String, JsError> {
        let (alg, bytes) = did_key::decode(did).map_err(|e| js_err("invalid did:key", e))?;
        let algorithm = match alg {
            did_key::KeyAlgorithm::Ed25519 => "ed25519",
            did_key::KeyAlgorithm::P256 => "p256",
        };
        to_json(&serde_json::json!({ "algorithm": algorithm, "public_key": hex0x(&bytes) }))
    }

    // ── Free functions: templates ───────────────────────────────────────────

    /// Template links a tree references but does not carry and that are not
    /// built-in here: what a receiver still needs before it can verify.
    /// Returns a JSON array of multihash link strings (empty = self-descriptive).
    #[wasm_bindgen(js_name = missingTemplates)]
    pub fn missing_templates_of(tree_json: &str) -> Result<String, JsError> {
        let tree = parse_tree("tree", tree_json)?;
        let links: Vec<String> = missing_templates(&tree)
            .iter()
            .map(|l| l.to_string())
            .collect();
        to_json(&links)
    }

    fn hashes_json(rows: &[(&str, [u8; 32])]) -> Result<String, JsError> {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|(name, digest)| {
                serde_json::json!({
                    "name": name,
                    "link": RevisionLink::from_bytes(*digest).to_string(),
                })
            })
            .collect();
        to_json(&rows)
    }

    /// Built-in templates resolvable as object types, as JSON
    /// `[{"name": string, "link": "0x1620..."}]` sorted by name.
    #[wasm_bindgen(js_name = builtinTemplateHashes)]
    pub fn builtin_template_hashes() -> Result<String, JsError> {
        hashes_json(Aquafier::builtin_template_hashes())
    }

    /// All 8 contract templates this crate ships (superset of
    /// `builtinTemplateHashes`: adds `template_meta`, `anchor_template`, and
    /// `signature_base`), as JSON `[{"name": string, "link": "0x1620..."}]`.
    /// The 11 audit identities are fixtures, not part of this set.
    #[wasm_bindgen(js_name = shippedTemplateHashes)]
    pub fn shipped_template_hashes() -> Result<String, JsError> {
        hashes_json(Aquafier::shipped_template_hashes())
    }

    /// One-revision tree for a built-in template, or `null` if `link` is not
    /// built-in. Accepts a multihash link or a bare 32-byte digest hex. Note
    /// the returned tree is keyed by the BARE 32-byte digest (`0x<64 hex>`),
    /// the catalog's internal form: it is not usable as a linked or embedded
    /// template source (those must be keyed by the full multihash; use
    /// `templateTree` on the template body for that). Returns `Tree` JSON.
    #[wasm_bindgen(js_name = builtinTemplateTree)]
    pub fn builtin_template_tree(link: &str) -> Result<Option<String>, JsError> {
        let digest = parse_digest("template link", link)?;
        Aquafier::builtin_template_tree(&digest)
            .map(|t| to_json(&t))
            .transpose()
    }

    /// Root-first ancestry chain of trees for a built-in template (empty array
    /// if `link` is not built-in). Returns a JSON array of `Tree`.
    #[wasm_bindgen(js_name = builtinTemplateTreeChain)]
    pub fn builtin_template_tree_chain(link: &str) -> Result<String, JsError> {
        let digest = parse_digest("template link", link)?;
        to_json(&Aquafier::builtin_template_tree_chain(&digest))
    }

    /// Name of a built-in template, or `null` if `link` is not built-in.
    #[wasm_bindgen(js_name = builtinTemplateName)]
    pub fn builtin_template_name(link: &str) -> Result<Option<String>, JsError> {
        let digest = parse_digest("template link", link)?;
        Ok(Aquafier::builtin_template_name(&digest).map(str::to_owned))
    }

    /// Full ancestor chains (root-first, deduplicated) of every built-in
    /// template named in the tree's genesis anchor `structural_links`.
    /// Returns a JSON array of `Tree`.
    #[wasm_bindgen(js_name = resolveDependencyTrees)]
    pub fn resolve_dependency_trees(tree_json: &str) -> Result<String, JsError> {
        let tree = parse_tree("tree", tree_json)?;
        to_json(&Aquafier::resolve_dependency_trees(&tree))
    }

    macro_rules! audit_templates {
        ($( $name:literal => $ty:ident ),* $(,)?) => {
            const AUDIT_TEMPLATE_NAMES: &[&str] = &[$($name),*];

            fn audit_fixture(name: &str) -> Option<&'static str> {
                match name {
                    $($name => Some(<$ty as BuiltInTemplate>::TEMPLATE_JSON),)*
                    _ => None,
                }
            }

            fn audit_digest(name: &str) -> Option<[u8; 32]> {
                match name {
                    $($name => Some(<$ty as BuiltInTemplate>::TEMPLATE_LINK),)*
                    _ => None,
                }
            }

            fn audit_validate_typed(name: &str, payload_json: &str) -> Result<(), JsError> {
                match name {
                    $($name => {
                        let payload: $ty = parse_json(concat!($name, " payload"), payload_json)?;
                        payload
                            .validate()
                            .map_err(|e| js_err(concat!("invalid ", $name, " payload"), e))
                    })*
                    other => Err(JsError::new(&format!("unknown audit template {other:?}"))),
                }
            }
        };
    }

    audit_templates! {
        "audit_artifact" => AuditArtifact,
        "audit_user_turn_marker" => AuditUserTurnMarker,
        "audit_user_prompt" => AuditUserPrompt,
        "audit_agent_thinking" => AuditAgentThinking,
        "audit_agent_tool_call" => AuditAgentToolCall,
        "audit_api_response" => AuditApiResponse,
        "audit_tool_result" => AuditToolResult,
        "audit_hitl_approval" => AuditHitlApproval,
        "audit_agent_response" => AuditAgentResponse,
        "audit_round_anchor" => AuditRoundAnchor,
        "audit_session_close" => AuditSessionClose,
    }

    fn unknown_audit(name: &str) -> JsError {
        JsError::new(&format!(
            "unknown audit template {name:?}: expected one of {}",
            AUDIT_TEMPLATE_NAMES.join(", ")
        ))
    }

    /// The 11 audit template names (`audit_artifact`, T1-T8, `audit_round_anchor`,
    /// `audit_session_close`), as a JSON array in family order.
    #[wasm_bindgen(js_name = auditTemplateNames)]
    pub fn audit_template_names() -> Result<String, JsError> {
        to_json(&AUDIT_TEMPLATE_NAMES)
    }

    /// The in-crate FIXTURE definition of an audit template (a `Template`
    /// revision JSON, byte-identical with `aqua-template-registry`
    /// `seed/audit-set-v1/definitions/<name>.json`).
    ///
    /// This is a test fixture, NOT a built-in: the audit family is
    /// registry-distributed and is not resolved by `createObject` or by
    /// verification on its own. Production code must fetch the definitions
    /// from the registry (`audit-set-v1`) and pass them through `templateTree`
    /// as explicit sources. The fixture is provided so tests and offline tools
    /// can exercise the same flow.
    #[wasm_bindgen(js_name = auditTemplateFixtureJson)]
    pub fn audit_template_fixture_json(name: &str) -> Result<String, JsError> {
        audit_fixture(name)
            .map(str::to_owned)
            .ok_or_else(|| unknown_audit(name))
    }

    /// Full multihash link (`0x1620...`) of an audit template: the
    /// `template_link` to pass to `createObjectValidated`.
    #[wasm_bindgen(js_name = auditTemplateLink)]
    pub fn audit_template_link(name: &str) -> Result<String, JsError> {
        audit_digest(name)
            .map(|d| RevisionLink::from_bytes(d).to_string())
            .ok_or_else(|| unknown_audit(name))
    }

    /// Validate a payload for an audit template: JSON Schema validation
    /// against the fixture definition, then the typed field rules
    /// (non-empty DIDs, decision enums, ...). Throws on the first violation;
    /// returns nothing on success.
    #[wasm_bindgen(js_name = validateAuditPayload)]
    pub fn validate_audit_payload(name: &str, payload_json: &str) -> Result<(), JsError> {
        let fixture = audit_fixture(name).ok_or_else(|| unknown_audit(name))?;
        let digest = audit_digest(name).ok_or_else(|| unknown_audit(name))?;
        let template: Template = parse_json("audit template fixture", fixture)?;
        let payload: serde_json::Value = parse_json("payload", payload_json)?;
        let object = Object::genesis(RevisionLink::from_bytes(digest), Method::Tree, payload);
        template
            .validate_object(&object)
            .map_err(|e| js_err(&format!("{name} payload violates the template schema"), e))?;
        audit_validate_typed(name, payload_json)
    }

    // ── Free functions: selective disclosure ────────────────────────────────

    /// The canonical `pseudonymous` `DisclosurePolicy` for a tree: audit
    /// revisions T2-T8 become `FieldRedacted`, disclosing structural and
    /// metadata fields (`signer_did`, ids, timestamps, hashes) while sealing
    /// content fields such as `prompt_text`; T1 markers, signatures, anchors,
    /// and non-audit revisions stay `Full`. Returns JSON to pass to
    /// `exportSelectiveTree`.
    #[wasm_bindgen(js_name = pseudonymousPolicy)]
    pub fn pseudonymous_policy(tree_json: &str) -> Result<String, JsError> {
        let tree = parse_tree("tree", tree_json)?;
        to_json(&DisclosurePolicy::pseudonymous(&tree))
    }

    /// The `full` `DisclosurePolicy` (every revision disclosed). The tree is
    /// accepted for symmetry with `pseudonymousPolicy`.
    #[wasm_bindgen(js_name = fullPolicy)]
    pub fn full_policy(tree_json: &str) -> Result<String, JsError> {
        let tree = parse_tree("tree", tree_json)?;
        to_json(&DisclosurePolicy::full(&tree))
    }

    /// Apply a `DisclosurePolicy` to a tree. Returns `SelectiveTree` JSON.
    #[wasm_bindgen(js_name = exportSelectiveTree)]
    pub fn export_selective_tree_of(tree_json: &str, policy_json: &str) -> Result<String, JsError> {
        let tree = parse_tree("tree", tree_json)?;
        let policy: DisclosurePolicy = parse_json("disclosure policy", policy_json)?;
        let selective = export_selective_tree(&tree, &policy)
            .map_err(|e| js_err("failed to export selective tree", e))?;
        to_json(&selective)
    }

    /// Verify a `SelectiveTree` (chain continuity plus every redacted
    /// revision's Merkle root). Throws on failure; returns nothing on success.
    #[wasm_bindgen(js_name = verifySelectiveTree)]
    pub fn verify_selective_tree_of(selective_json: &str) -> Result<(), JsError> {
        let selective: SelectiveTree = parse_json("selective tree", selective_json)?;
        verify_selective_tree(&selective)
            .map_err(|e| js_err("selective tree verification failed", e))
    }

    /// Field-level redaction of one tree-method revision. `revision_json` is
    /// the `AnyRevision` body, `link` its revision hash (multihash link), and
    /// `paths_json` a JSON array of JSON Pointer paths to disclose (`/nonce` is
    /// refused). Returns `RedactedRevision` JSON.
    #[wasm_bindgen(js_name = redactRevision)]
    pub fn redact_revision_of(
        revision_json: &str,
        link: &str,
        paths_json: &str,
    ) -> Result<String, JsError> {
        let revision: AnyRevision = parse_json("revision", revision_json)?;
        let link = parse_link("revision link", link)?;
        let paths: Vec<String> = parse_json("disclosed paths", paths_json)?;
        let redacted = redact_revision(&revision, &link, &paths)
            .map_err(|e| js_err("failed to redact revision", e))?;
        to_json(&redacted)
    }

    /// Verify a `RedactedRevision` against its declared revision hash. Throws
    /// on failure; returns nothing on success.
    #[wasm_bindgen(js_name = verifyRedactedRevision)]
    pub fn verify_redacted_revision_of(redacted_json: &str) -> Result<(), JsError> {
        let redacted: RedactedRevision = parse_json("redacted revision", redacted_json)?;
        verify_redacted_revision(&redacted)
            .map_err(|e| js_err("redacted revision verification failed", e))
    }

    // ── Free functions: hashing and Merkle ──────────────────────────────────

    /// Digest of `bytes` under `hash_type`, as `0x` hex.
    #[wasm_bindgen(js_name = hashBytes)]
    pub fn hash_bytes(bytes: &[u8], hash_type: &str) -> Result<String, JsError> {
        Ok(hex0x(&parse_hash_type(hash_type)?.hash(bytes)))
    }

    /// RFC 6962 leaf hash `HASH(0x00 || bytes)` for batch Merkle trees, as `0x` hex.
    #[wasm_bindgen(js_name = batchLeafHash)]
    pub fn batch_leaf_hash(bytes: &[u8], hash_type: &str) -> Result<String, JsError> {
        Ok(hex0x(&merkle::batch_leaf_hash(
            &parse_hash_type(hash_type)?,
            bytes,
        )))
    }

    /// RFC 9162 Merkle root of `leaves_json` (a JSON array of `0x` hex leaf
    /// hashes, already leaf-hashed), as `0x` hex. Throws on an empty array.
    #[wasm_bindgen(js_name = merkleRoot)]
    pub fn merkle_root(leaves_json: &str, hash_type: &str) -> Result<String, JsError> {
        let raw: Vec<String> = parse_json("leaves", leaves_json)?;
        let leaves = raw
            .iter()
            .map(|l| hex_bytes("leaf", l))
            .collect::<Result<Vec<_>, _>>()?;
        merkle::try_merkle_root(&leaves, &parse_hash_type(hash_type)?)
            .map(|r| hex0x(&r))
            .ok_or_else(|| JsError::new("merkle root of zero leaves is undefined"))
    }

    /// Aqua-profile multihash (`varint(code) || varint(len) || digest`) of a
    /// `0x` hex digest, as `0x` hex. Requires a full-length digest.
    #[wasm_bindgen(js_name = multihashEncode)]
    pub fn multihash_encode_hex(digest_hex: &str, hash_type: &str) -> Result<String, JsError> {
        let ht = parse_hash_type(hash_type)?;
        let digest = hex_bytes("digest", digest_hex)?;
        if digest.len() != ht.output_len() {
            return Err(JsError::new(&format!(
                "digest must be {} bytes for {ht} (got {})",
                ht.output_len(),
                digest.len()
            )));
        }
        Ok(hex0x(&multihash_encode(ht, &digest)))
    }

    /// Decode a `0x` hex multihash. Returns JSON
    /// `{"hash_type": "FIPS_202-SHA3-256" | "BLAKE3-256", "digest": "0x..."}`;
    /// throws on non-minimal varints, unknown codes, or length mismatches.
    #[wasm_bindgen(js_name = multihashDecode)]
    pub fn multihash_decode_hex(multihash_hex: &str) -> Result<String, JsError> {
        let bytes = hex_bytes("multihash", multihash_hex)?;
        let (ht, digest) = multihash_decode(&bytes).map_err(|e| js_err("invalid multihash", e))?;
        to_json(&serde_json::json!({ "hash_type": ht.to_string(), "digest": hex0x(&digest) }))
    }
}

#[cfg(target_arch = "wasm32")]
pub use bindings::*;
