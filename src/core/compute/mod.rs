use serde::{Deserialize, Serialize};

// aqua-rs-sdk-core: this module is the types-only subset of the full
// SDK's compute module. The wasmi runtime, host functions, and plugin
// API are not part of core; the serde types below are wire format
// (Template.verification) and must stay byte-compatible.

#[derive(thiserror::Error, Debug)]
pub enum ComputeError {
    #[error("WASM hash mismatch: expected {expected}, got {actual}")]
    WasmHashMismatch { expected: String, actual: String },
    #[error("missing host dependency: {0}")]
    MissingHostDependency(String),
    #[error("WASM compilation error: {0}")]
    WasmCompilation(String),
    #[error("WASM execution error: {0}")]
    WasmExecution(String),
    #[error("compute verification failed: {0}")]
    VerificationFailed(String),
    // Static compute-section validation errors (TemplateVerification::
    // validate_compute_section). Raised at template verification time,
    // before (and independently of) any WASM execution.
    #[error("computation {index}: wasm exceeds {max} bytes (got {bytes})")]
    ModuleTooLarge {
        index: usize,
        bytes: usize,
        max: usize,
    },
    #[error("computation {index}: source.code exceeds {max} bytes (got {bytes})")]
    SourceTooLarge {
        index: usize,
        bytes: usize,
        max: usize,
    },
    #[error(
        "computation {index}: source.hash mismatch (declared {declared}, computed {computed})"
    )]
    SourceHashMismatch {
        index: usize,
        declared: String,
        computed: String,
    },
    #[error("computation {index}: wasm_hash mismatch (declared {declared}, computed {computed})")]
    TemplateWasmHashMismatch {
        index: usize,
        declared: String,
        computed: String,
    },
    #[error("computation {index}: wasm is not valid hex: {error}")]
    MalformedWasmHex { index: usize, error: String },
    // Authoring-time error (retained for error-string compatibility;
    // core has no authoring feature).
    #[error("WAT compilation failed: {error}")]
    WatCompileFailed { error: String },
}

/// Context passed to WASM verification modules.
/// Serialized to JSON and written into WASM linear memory.
/// Also accessible via host API functions (ctx_* family).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct VerificationContext {
    /// The current revision being verified.
    pub revision: serde_json::Value,
    /// Ancestor chain from genesis to current revision (inclusive), following
    /// `previous_revision` links through content revisions. Ordered root-first.
    pub chain: Vec<serde_json::Value>,
    /// Parallel to `chain`. `branches[i]` contains all revisions whose
    /// `previous_revision` equals `chain[i]` but which are NOT `chain[i+1]`
    /// (i.e., signature/anchor forks). Sorted by revision hash for determinism.
    pub branches: Vec<Vec<serde_json::Value>>,
    /// Resolved revisions from trees referenced via anchor `structural_links`.
    pub linked_trees: Vec<serde_json::Value>,
    /// Computed lifecycle state string for each linked tree, one entry per tree.
    /// Parallel to the logical set of linked trees (NOT parallel to `linked_trees`,
    /// which is a flat revision list). Index 0 = first linked tree's state, etc.
    /// Used by `ctx_linked_tree_state()` and `ctx_linked_tree_count()`.
    pub linked_tree_states: Vec<String>,
    /// Object payloads from each linked tree, parallel to `linked_tree_states`.
    /// Used by `ctx_linked_tree_payload_str()` for cross-tree payload inspection
    /// (e.g., attestation WASM reading the claim's `signer_did`).
    pub linked_tree_payloads: Vec<serde_json::Value>,
    /// Position of the current revision within the chain array.
    pub self_index: usize,
    /// Unix timestamp (seconds) injected by the host. WASM MUST NOT read the
    /// system clock — use `ctx_current_time()` instead.
    pub current_time: i64,
    /// State name produced by the immediately preceding (parent) module in the
    /// ancestor verification chain, or `None` for the root module (no parent).
    /// Exposed to WASM via `ctx_parent_state()`. See spec-object-model §6.5.
    #[serde(default)]
    pub parent_state: Option<String>,
    /// Accumulated `wasm_output` of the ancestor chain entering this module
    /// (later keys override earlier, matching the chain merge semantics). Empty
    /// for the root module. Exposed via `ctx_parent_wasm_output_str()`. §6.5.
    #[serde(default)]
    pub parent_wasm_output: std::collections::HashMap<String, serde_json::Value>,
}

/// Protocol bound on the compiled WASM module size, hex-decoded (D-2,
/// DRAFT-ICP-self-contained-templates §5).
pub const MAX_WASM_MODULE_BYTES: usize = 2 * 1024 * 1024;

/// Protocol bound on embedded human-readable source code (D-2,
/// DRAFT-ICP-self-contained-templates §5).
pub const MAX_SOURCE_CODE_BYTES: usize = 512 * 1024;

/// Embedded in a Template to declare WASM-based verification.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct TemplateVerification {
    pub computations: Vec<ComputeModule>,
    #[serde(default)]
    pub host_dependencies: Vec<String>,
    /// Declares the set of states this template's WASM may output.
    /// WASM returns a non-negative index into this array for valid trees,
    /// or a negative value for structural rejection.
    /// REQUIRED by spec — empty vec only for legacy test modules.
    #[serde(default)]
    pub states: Vec<String>,
    /// States that are terminal (non-overridable by child WASM in a derivation chain).
    /// When a parent module returns a terminal state, child modules are NOT executed.
    /// Populated by SDK for built-in templates; custom templates declare via JSON.
    /// See spec-object-model.md §6: WASM Compositional Monotonicity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terminal_states: Vec<String>,
}

impl TemplateVerification {
    /// Fail-closed internal consistency check of the compute section.
    ///
    /// Checks, for every computation:
    /// 1. the hex-decoded `wasm` stays within [`MAX_WASM_MODULE_BYTES`]
    ///    (size gate runs before decoding, so oversized modules are
    ///    rejected without allocation);
    /// 2. `wasm` is valid hex and its SHA3-256 matches the declared
    ///    `wasm_hash`. Standalone template trees never execute WASM, so the
    ///    runtime's execution-time hash check does not cover them; this is
    ///    the static counterpart, same argument as `source.hash`;
    /// 3. when `source` is present, `source.code` stays within
    ///    [`MAX_SOURCE_CODE_BYTES`] and its SHA3-256 matches the declared
    ///    `source.hash`.
    ///
    /// `source` and `build` are never required for execution (spec): a
    /// module carrying neither field skips check 3 entirely.
    /// Hash comparison matches the runtime convention: strip an optional
    /// `0x` prefix on both sides, then compare case-insensitively.
    /// See DRAFT-ICP-self-contained-templates §5.
    pub fn validate_compute_section(&self) -> Result<(), ComputeError> {
        for (i, module) in self.computations.iter().enumerate() {
            validate_compute_module(i, module)?;
        }
        Ok(())
    }
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn sha3_hex(bytes: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// The single fail-closed consistency check for one compute module: static
/// wasm-size bound, `wasm_hash` recomputation, and (when present) source-size
/// bound plus `source.hash` recomputation. Shared by
/// [`TemplateVerification::validate_compute_section`] (one check per module
/// already embedded in a template) and [`ComputeModule::from_wasm_with_source`]
/// (one check on a module being freshly authored), so there is exactly one
/// place that defines what "internally consistent" means for a compute module.
fn validate_compute_module(index: usize, module: &ComputeModule) -> Result<(), ComputeError> {
    let wasm_hex = strip_0x(&module.wasm);
    let wasm_len = wasm_hex.len() / 2;
    if wasm_len > MAX_WASM_MODULE_BYTES {
        return Err(ComputeError::ModuleTooLarge {
            index,
            bytes: wasm_len,
            max: MAX_WASM_MODULE_BYTES,
        });
    }
    let wasm_bytes = hex::decode(wasm_hex).map_err(|e| ComputeError::MalformedWasmHex {
        index,
        error: e.to_string(),
    })?;
    let computed_wasm = sha3_hex(&wasm_bytes);
    if !computed_wasm.eq_ignore_ascii_case(strip_0x(&module.wasm_hash)) {
        return Err(ComputeError::TemplateWasmHashMismatch {
            index,
            declared: module.wasm_hash.clone(),
            computed: format!("0x{computed_wasm}"),
        });
    }
    if let Some(source) = &module.source {
        if source.code.len() > MAX_SOURCE_CODE_BYTES {
            return Err(ComputeError::SourceTooLarge {
                index,
                bytes: source.code.len(),
                max: MAX_SOURCE_CODE_BYTES,
            });
        }
        let computed = sha3_hex(source.code.as_bytes());
        if !computed.eq_ignore_ascii_case(strip_0x(&source.hash)) {
            return Err(ComputeError::SourceHashMismatch {
                index,
                declared: source.hash.clone(),
                computed: format!("0x{computed}"),
            });
        }
    }
    Ok(())
}

/// Output from WASM verification: the resolved state plus any structured output
/// written by the module via `output_set_str` / `output_set_int`.
#[derive(Clone, Debug, PartialEq)]
pub struct VerificationOutput {
    /// Index into the template's `states` array.
    pub state_index: usize,
    /// The state name from `states[state_index]`.
    pub state_name: String,
    /// Key-value data written by the WASM module via output_set_str/output_set_int.
    /// Queryable by the policy engine via `wasm/<key>` paths on StateNode.
    pub wasm_output: std::collections::HashMap<String, serde_json::Value>,
}

/// Human-readable source for a compute module (spec-core-protocol "Verification Field").
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ComputeSource {
    /// Complete source code, inline (the Aqua-Tree is self-contained).
    pub code: String,
    /// SHA3-256 of the UTF-8 source bytes, 0x-prefixed.
    pub hash: String,
    /// Source language identifier: "wat", "assemblyscript", "rust", "c".
    pub language: String,
}

/// Build recipe for reproducing `wasm` from `source`.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ComputeBuild {
    /// Compiler name and version (e.g. "wat 1.250.0").
    pub toolchain: String,
    /// Exact command that produces the WASM binary from source.
    pub command: String,
    /// Runtime environment; SHOULD be a digest-pinned image reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

/// A single WASM module embedded in a template.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ComputeModule {
    pub wasm: String,
    pub wasm_hash: String,
    /// Human-readable source (spec: templates carry source alongside compiled WASM).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<ComputeSource>,
    /// Build recipe reproducing `wasm` from `source`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<ComputeBuild>,
    /// Free-text description of what this module computes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ComputeModule {
    /// Build a fully self-contained module from prebuilt WASM bytes plus the
    /// human-readable source it was compiled from (e.g. Rust or WAT compiled
    /// out-of-band with a digest-pinned recipe).
    ///
    /// Computes `wasm_hash` and `source.hash` from the given bytes, then runs
    /// [`validate_compute_module`], the same fail-closed consistency check the
    /// verification pipelines apply. Because both hashes are computed here
    /// from the actual bytes, hash mismatches are unreachable on this path;
    /// the meaningful gate the validation adds is the protocol size bounds
    /// ([`MAX_WASM_MODULE_BYTES`], [`MAX_SOURCE_CODE_BYTES`]), so an
    /// oversized module cannot be authored.
    ///
    /// This does NOT verify that `code` actually compiles to `wasm_bytes`;
    /// that claim belongs to the reproducible-build attestation layer (see
    /// `wasm_build_attestation` in `aqua-example-templates/payments`), which
    /// independently rebuilds the bytes and compares hashes out of band. Here
    /// we only guarantee the module's own fields are self-consistent: the
    /// declared hashes match the declared bytes.
    pub fn from_wasm_with_source(
        wasm_bytes: &[u8],
        code: &str,
        language: &str,
        description: Option<String>,
        build: Option<ComputeBuild>,
    ) -> Result<Self, ComputeError> {
        let module = ComputeModule {
            wasm: format!("0x{}", hex::encode(wasm_bytes)),
            wasm_hash: format!("0x{}", sha3_hex(wasm_bytes)),
            source: Some(ComputeSource {
                code: code.to_string(),
                hash: format!("0x{}", sha3_hex(code.as_bytes())),
                language: language.to_string(),
            }),
            build,
            description,
        };
        validate_compute_module(0, &module)?;
        Ok(module)
    }

    /// Compile WAT text and embed it as a self-contained module. Uses the same
    /// `wat::parse_str` path as the SDK's reproducible builder crate
    /// (`aqua-example-templates/payments/build/wat-build`). Bytes produced
    /// here match that builder because this crate pins the same `wat`
    /// version (`=1.250.0`) as the builder's committed lockfile, and the
    /// `from_wat_reproduces_shipped_module` test acts as a canary against
    /// toolchain drift.
    ///
    /// Requires the `authoring` feature. Like [`Self::from_wasm_with_source`],
    /// this only checks internal consistency of the resulting module; it does
    /// not, by itself, constitute a reproducible-build attestation.
    #[cfg(feature = "authoring")]
    pub fn from_wat(
        wat_source: &str,
        description: Option<String>,
        build: Option<ComputeBuild>,
    ) -> Result<Self, ComputeError> {
        let wasm_bytes =
            wat::parse_str(wat_source).map_err(|e| ComputeError::WatCompileFailed {
                error: e.to_string(),
            })?;
        Self::from_wasm_with_source(&wasm_bytes, wat_source, "wat", description, build)
    }
}
