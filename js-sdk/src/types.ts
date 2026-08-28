/**
 * Wire shapes of the aqua-rs-sdk-core structs as they cross the WASM
 * boundary (serde_json form). Every interface here mirrors a Rust struct in
 * `src/schema/`, `src/core/`, or `src/primitives/` of the core crate; the
 * comments name the source so drift can be checked against it.
 */

// ── Primitives ───────────────────────────────────────────────────────────

/** `primitives::Method`: `"scalar"` (canonical JSON hash) or `"tree"` (Merkle root). */
export type Method = "scalar" | "tree";

/** `primitives::HashType` wire names. */
export type HashType = "FIPS_202-SHA3-256" | "BLAKE3-256";

/**
 * What the wasm hash-type parameters accept: the wire names above or the
 * short builder names.
 */
export type HashTypeParam = HashType | "sha3_256" | "blake3_256";

/**
 * `primitives::RevisionLink`: a `0x`-prefixed hex multihash,
 * `0x1620<64 hex>` for SHA3-256 and `0x1e20<64 hex>` for BLAKE3-256.
 */
export type RevisionLink = string;

/** `primitives::Nonce`: `0x` + 32 hex characters (16 bytes). */
export type Nonce = string;

/** `primitives::Timestamp`: integer seconds since the Unix epoch. */
export type Timestamp = number;

/** `primitives::Version`: the only value the core accepts. */
export type Version = "https://aqua-protocol.org/docs/v4/schema";

export const VERSION_V4: Version = "https://aqua-protocol.org/docs/v4/schema";

/** `signature_type` discriminants of `schema::SignatureValue`. */
export type SignatureType = "ed25519" | "ecdsa:p256" | "ethereum:eip-191" | "webauthn:p256";

// ── Revisions (`schema::AnyRevision`, untagged) ──────────────────────────

/** Fields every revision type carries. */
export interface RevisionCommon {
  /** Absent on genesis revisions (serde skips `None`). */
  previous_revision?: RevisionLink;
  /** Full multihash of the type (template) this revision instantiates. */
  revision_type: RevisionLink;
  nonce: Nonce;
  local_timestamp: Timestamp;
  version: Version;
  method: Method;
}

/** `schema::Object` — a typed payload validated against a template. */
export interface ObjectRevision<P = unknown> extends RevisionCommon {
  payloads: P;
  /** Hex leaf hashes, present on tree-method revisions after creation. */
  leaves?: string[];
}

/** `core::compute::TemplateVerification`; the core rejects trees that carry one (`COMPUTE_UNSUPPORTED`). */
export interface TemplateVerification {
  computations: Array<{
    wasm: string;
    wasm_hash: string;
    source?: unknown;
    build?: unknown;
    description?: string;
  }>;
  host_dependencies?: string[];
  states?: string[];
  [key: string]: unknown;
}

/** `schema::bounds::StructuralLinkSpec`. */
export interface StructuralLinkSpec {
  required: number;
  max: number;
}

/** `schema::bounds::ObjectBounds`. */
export interface ObjectBounds {
  max_chain_depth: number;
  structural_links: StructuralLinkSpec;
  max_signature_branches: number;
  max_timestamp_branches: number;
  max_anchor_branches: number;
  max_total_revisions: number;
}

/** `schema::Template` — a type definition (JSON Schema plus derivation metadata). */
export interface TemplateRevision extends RevisionCommon {
  schema: Record<string, unknown>;
  verification?: TemplateVerification;
  derives_from?: RevisionLink;
  ancestry?: RevisionLink[];
  bounds?: ObjectBounds;
}

/** `schema::SignatureValue`, serialized with a uniform `signature_type` discriminant. */
export type SignatureValue =
  | {
      signature_type: "ed25519";
      /** `0x` + 64 bytes. */
      signature: string;
      /** `0x` + 32-byte public key. */
      signature_public_identifier: string;
    }
  | {
      signature_type: "ecdsa:p256";
      /** `0x` + 64 bytes (`r || s`). */
      signature: string;
      /** `0x` + 33-byte compressed SEC1 public key. */
      signature_public_identifier: string;
    }
  | {
      signature_type: "ethereum:eip-191";
      /** `0x` + 65 bytes (`r || s || v`, `v` = 27/28). */
      signature: string;
      /** `0x` + 20-byte address (EIP-55 checksummed on output; any case accepted on input). */
      signature_public_identifier: string;
    }
  | {
      signature_type: "webauthn:p256";
      signature: string;
      signature_public_identifier: string;
      /** `0x` hex of the authenticator data from the assertion. */
      authenticator_data: string;
      /** `0x` hex of the client data JSON from the assertion. */
      client_data_json: string;
    };

/** `schema::Signature` — a signature branch over `previous_revision`. */
export interface SignatureRevision extends RevisionCommon {
  previous_revision: RevisionLink;
  /** The signer's DID (`did:key:...` or `did:pkh:...`). */
  signer: string;
  signature: SignatureValue;
}

/** `schema::CompositionalLink`. */
export interface CompositionalLink {
  hash: RevisionLink;
  role: string;
}

/** `schema::Anchor` — a genesis anchor or a cross-tree link revision. */
export interface AnchorRevision extends RevisionCommon {
  structural_links: RevisionLink[];
  compositional_links?: CompositionalLink[];
  leaves?: string[];
}

export type AnyRevision = ObjectRevision | TemplateRevision | SignatureRevision | AnchorRevision;

export function isObjectRevision(rev: AnyRevision): rev is ObjectRevision {
  return "payloads" in rev;
}

export function isTemplateRevision(rev: AnyRevision): rev is TemplateRevision {
  return "schema" in rev;
}

export function isSignatureRevision(rev: AnyRevision): rev is SignatureRevision {
  return "signature" in rev && "signer" in rev;
}

export function isAnchorRevision(rev: AnyRevision): rev is AnchorRevision {
  return "structural_links" in rev;
}

// ── Trees and wrappers ───────────────────────────────────────────────────

/** `schema::tree::Tree`. */
export interface Tree {
  revisions: Record<RevisionLink, AnyRevision>;
  file_index: Record<RevisionLink, string>;
}

/** `schema::FileData` (content as a JSON byte array). */
export interface FileData {
  file_name: string;
  file_content: number[];
  path: string;
}

/** `schema::FileMetadata` (pre-computed SHA3-256 content hash). */
export interface FileMetadata {
  file_name: string;
  content_hash: number[];
  file_size: number;
  path: string;
}

/** `schema::AquaTreeWrapper`. */
export interface AquaTreeWrapper {
  aqua_tree: Tree;
  file_object: FileData | null;
  /** Target revision; `null` targets the tip. */
  revision: RevisionLink | null;
}

/** The wasm side accepts either form wherever a wrapper is expected. */
export type WrapperLike = Tree | AquaTreeWrapper;

/** `primitives::log::LogType` (snake_case on the wire). */
export type LogType =
  | "success"
  | "info"
  | "error"
  | "final_error"
  | "warning"
  | "hint"
  | "debug_data"
  | "arrow"
  | "file"
  | "link"
  | "signature"
  | "timestamp"
  | "form"
  | "scalar"
  | "empty"
  | "tree";

/** `primitives::log::LogData`. Note the camelCase `logType` key. */
export interface LogData {
  logType: LogType;
  log: string;
  ident?: string | null;
}

/** `schema::AquaOperationData`. */
export interface AquaOperationData {
  aqua_tree: Tree;
  aqua_trees: Tree[];
  log_data: LogData[];
}

// ── Signing ──────────────────────────────────────────────────────────────

/** `schema::SigningCredentials` (untagged; the key selects the algorithm). */
export type SigningCredentials =
  | { did_key: string }
  | { p256_key: string }
  | { secp256k1_key: string };

/** Return value of `AquafierWasm.prepareSignature`. */
export interface PreparedSignature {
  target_revision: RevisionLink;
  hash_type: HashType;
  signature_type: SignatureType;
  signer: string;
  /** Canonical pre-signature JSON: the exact string the verifier recomputes. */
  message: string;
  /** `0x` hex of the UTF-8 bytes of `message`. */
  message_hex: string;
}

/** Return value of `generateEd25519`. */
export interface Ed25519KeyPair {
  /** `0x` + 32-byte secret: the `did_key` credential value. */
  secret: string;
  did: string;
}

/** Return value of `decodeDidKey`. */
export interface DecodedDidKey {
  algorithm: "ed25519" | "p256";
  public_key: string;
}

// ── Verification ─────────────────────────────────────────────────────────

/** `core::verification_policy::DecisionPoint`. */
export type DecisionPoint =
  | "timestamp_unavailable"
  | "template_not_found"
  | "ancestor_template_not_found"
  | "wasm_execution_failed"
  | "batch_proof_failed"
  | "wasm_untrusted_signer"
  | "unsigned_template";

/** `core::verification_policy::PolicyWarning`. */
export interface PolicyWarning {
  decision_point: DecisionPoint;
  revision_hash: string;
  message: string;
}

/** `core::verification_policy::VerificationError`. */
export interface VerificationError {
  code: string;
  revision_hash: string;
  message: string;
}

/** `core::verification_policy::VerificationOutcome` (custom serde). */
export type VerificationOutcome =
  | { result: "verified" }
  | { result: "verified_with_warnings"; warnings: PolicyWarning[] }
  | { result: "failed"; errors: VerificationError[] };

/** `core::verification_policy::TemplateTrust` (`tag = "trust", content = "did"`). */
export type TemplateTrust =
  | { trust: "builtin" }
  | { trust: "trusted_signer"; did: string }
  | { trust: "unsigned_allowed" }
  | { trust: "untrusted_allowed"; did: string };

/** `core::VerificationResult`. */
export interface VerificationResult {
  outcome: VerificationOutcome;
  logs: LogData[];
  wasm_outputs: Record<string, unknown>;
  template_trust: Record<string, TemplateTrust>;
}

/** Mirror of `VerificationResult::is_verified`: verified with or without warnings. */
export function isVerified(result: VerificationResult): boolean {
  return result.outcome.result === "verified" || result.outcome.result === "verified_with_warnings";
}

/** Mirror of `VerificationResult::errors`. */
export function verificationErrors(result: VerificationResult): VerificationError[] {
  return result.outcome.result === "failed" ? result.outcome.errors : [];
}

/** Mirror of `VerificationResult::warnings`. */
export function verificationWarnings(result: VerificationResult): PolicyWarning[] {
  return result.outcome.result === "verified_with_warnings" ? result.outcome.warnings : [];
}

// ── Selective disclosure (`core::disclosure`) ────────────────────────────

/** `RevisionDisclosure` (externally tagged enum). */
export type RevisionDisclosure = "Full" | "Hidden" | { FieldRedacted: string[] };

/** `DisclosurePolicy`; revisions not listed default to `Full`. */
export interface DisclosurePolicy {
  revisions: Record<RevisionLink, RevisionDisclosure>;
}

/** `RedactedLeaf` (`tag = "type"`). Byte fields are `0x` hex. */
export type RedactedLeaf =
  | { type: "Disclosed"; index: number; path: string; value: string; salt: string }
  | { type: "Redacted"; index: number; path: string; value_commit: string };

/** `RedactedRevision`. */
export interface RedactedRevision {
  revision_hash: RevisionLink;
  leaf_count: number;
  leaves: RedactedLeaf[];
}

/** `SelectiveRevision` (`tag = "disclosure"`). */
export type SelectiveRevision =
  | { disclosure: "Full"; revision: AnyRevision }
  | { disclosure: "Redacted"; redacted: RedactedRevision }
  | { disclosure: "Hidden" };

/** `SelectiveTree`. */
export interface SelectiveTree {
  revisions: Record<RevisionLink, SelectiveRevision>;
  file_index: Record<RevisionLink, string>;
}

// ── Configuration ────────────────────────────────────────────────────────

/** Options accepted by `AquafierWasm.withOptions`. Every key is optional. */
export interface AquafierOptions {
  default_object_method?: Method;
  default_signature_method?: Method;
  hash_type?: HashTypeParam;
  /** `"default"` and `"strict"` are the same; `"debug"` is never for production. */
  verification_policy?: "default" | "strict" | "offline" | "debug";
}

/** `exportTree` options: a preset name or the explicit `core::ExportOptions` flags. */
export type ExportOptions =
  | "default"
  | "self_descriptive"
  | "non_builtin_only"
  | "bare"
  | { include_templates?: boolean; include_builtin_templates?: boolean };

/** Entry of `builtinTemplateHashes` / `shippedTemplateHashes`. */
export interface TemplateHashEntry {
  name: string;
  link: RevisionLink;
}

/** Return value of `multihashDecode`. */
export interface DecodedMultihash {
  hash_type: HashType;
  digest: string;
}

/** Byte-like inputs accepted by the wrapper; strings are UTF-8 encoded. */
export type Bytes = Uint8Array | string;
