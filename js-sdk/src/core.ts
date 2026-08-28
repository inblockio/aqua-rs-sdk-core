/**
 * `AquaSDK`: a typed facade over the `AquafierWasm` class. Every method
 * serializes its arguments to JSON, calls the corresponding wasm export, and
 * parses the JSON result into the interfaces of `types.ts`. Methods are
 * synchronous where the wasm export is synchronous (everything except
 * `signAquaTree`, which returns a Promise because the core's signer trait
 * is async).
 */

import type { InitInput, AquafierWasm } from "aqua-rs-sdk-core-wasm";
import { toByteArray, toBytes } from "./bytes.js";
import type { AquaSigner } from "./signing/signer.js";
import type {
  AquaOperationData,
  AquaTreeWrapper,
  AquafierOptions,
  Bytes,
  ExportOptions,
  FileData,
  FileMetadata,
  HashType,
  Method,
  PreparedSignature,
  RevisionLink,
  SignatureType,
  SignatureValue,
  SigningCredentials,
  TemplateRevision,
  Tree,
  VerificationResult,
  WrapperLike,
} from "./types.js";
import { ensureReady, fromJson, init, methodArg, optionalJson, toJson, type WasmModule } from "./wasm.js";

/** Build a `FileData` from a name and content (path defaults to the name). */
export function toFileData(fileName: string, content: Bytes | number[], path = fileName): FileData {
  return { file_name: fileName, file_content: toByteArray(content), path };
}

/** Build an `AquaTreeWrapper`; `revision` selects the target (default: the tip). */
export function wrap(
  tree: Tree,
  fileObject: FileData | null = null,
  revision: RevisionLink | null = null,
): AquaTreeWrapper {
  return { aqua_tree: tree, file_object: fileObject, revision };
}

/** The `Tree` inside either wrapper form. */
export function treeOf(input: WrapperLike): Tree {
  return "aqua_tree" in input ? input.aqua_tree : input;
}

/** Links of a tree's revisions in map order (genesis first is not guaranteed; use `tipOf` for the tip). */
export function revisionLinks(tree: Tree): RevisionLink[] {
  return Object.keys(tree.revisions);
}

/**
 * The tip of the content chain: the revision no other revision names as
 * `previous_revision`, preferring non-template revisions (mirrors
 * `Tree::get_last_revision`).
 */
export function tipOf(tree: Tree): RevisionLink | undefined {
  const referenced = new Set<string>();
  for (const rev of Object.values(tree.revisions)) {
    if (rev.previous_revision) referenced.add(rev.previous_revision);
  }
  let template: RevisionLink | undefined;
  for (const [link, rev] of Object.entries(tree.revisions)) {
    if (referenced.has(link)) continue;
    if ("schema" in rev) {
      template ??= link;
      continue;
    }
    return link;
  }
  return template;
}

export class AquaSDK {
  readonly options: Readonly<AquafierOptions>;
  private readonly aq: AquafierWasm;

  /**
   * Requires the wasm module to be initialized (`await init()`); prefer
   * `AquaSDK.load()` which does both. Options map onto the core's
   * `AquafierBuilder`; omit them for the defaults (objects `tree`,
   * signatures `scalar`, SHA3-256, strict verification).
   */
  constructor(options: AquafierOptions = {}) {
    const w = ensureReady();
    this.options = Object.freeze({ ...options });
    this.aq =
      Object.keys(options).length === 0
        ? new w.AquafierWasm()
        : w.AquafierWasm.withOptions(JSON.stringify(options));
  }

  /**
   * Initialize the wasm module (if needed) and construct an SDK. `input` is
   * the package's `InitInput` (URL, `Response`, bytes, or compiled module);
   * omit it to read the file from disk in Node or fetch it in browsers.
   */
  static async load(input?: InitInput | Promise<InitInput>, options: AquafierOptions = {}): Promise<AquaSDK> {
    await init(input);
    return new AquaSDK(options);
  }

  /** The raw generated bindings, for anything the wrapper does not cover. */
  get wasm(): WasmModule {
    return ensureReady();
  }

  /** Release the wasm-side `Aquafier`. The instance is unusable afterwards. */
  free(): void {
    this.aq.free();
  }

  /** Wire name of the hash algorithm this instance stamps on new trees. */
  hashType(): HashType {
    return this.aq.hashType() as HashType;
  }

  // ── Creation ───────────────────────────────────────────────────────────

  /** Genesis revision from file bytes (content hash, size, and name). */
  createGenesisRevision(fileName: string, content: Bytes, method?: Method | null): Tree {
    return fromJson(this.aq.createGenesisRevision(fileName, toBytes(content), methodArg(method)));
  }

  /** Genesis revision carrying only the content hash. */
  createMinimalGenesisRevision(fileName: string, content: Bytes, method?: Method | null): Tree {
    return fromJson(this.aq.createMinimalGenesisRevision(fileName, toBytes(content), methodArg(method)));
  }

  /** Genesis revision from a pre-computed SHA3-256 content hash. */
  createGenesisRevisionFromMetadata(
    metadata: Omit<FileMetadata, "content_hash"> & { content_hash: Bytes | number[] },
    method?: Method | null,
  ): Tree {
    const meta: FileMetadata = { ...metadata, content_hash: toByteArray(metadata.content_hash) };
    return fromJson(this.aq.createGenesisRevisionFromMetadata(JSON.stringify(meta), methodArg(method)));
  }

  /**
   * Typed object revision. Validation only happens for built-in templates;
   * use `createObjectValidated` for registry or custom templates.
   */
  createObject(
    templateLink: RevisionLink,
    previousTree: WrapperLike | null,
    payload: unknown,
    method?: Method | null,
  ): Tree {
    return fromJson(
      this.aq.createObject(templateLink, optionalJson(previousTree), JSON.stringify(payload), methodArg(method)),
    );
  }

  /**
   * Typed object revision validated against a template resolved from the
   * previous tree, the built-in catalog, or `sources` (template trees from
   * `templateTree`). Fails closed when the template cannot be resolved.
   */
  createObjectValidated(
    templateLink: RevisionLink,
    previousTree: WrapperLike | null,
    payload: unknown,
    sources: Tree[],
    method?: Method | null,
  ): Tree {
    return fromJson(
      this.aq.createObjectValidated(
        templateLink,
        optionalJson(previousTree),
        JSON.stringify(payload),
        methodArg(method),
        JSON.stringify(sources),
      ),
    );
  }

  /** Like `createObject`, additionally recording `name` in `file_index`. */
  createObjectWithName(
    templateLink: RevisionLink,
    previousTree: WrapperLike | null,
    payload: unknown,
    name: string,
    method?: Method | null,
  ): Tree {
    return fromJson(
      this.aq.createObjectWithName(
        templateLink,
        optionalJson(previousTree),
        JSON.stringify(payload),
        methodArg(method),
        name,
      ),
    );
  }

  /** New tree whose genesis anchor carries `links` as structural links, then the typed object. */
  createObjectWithAnchorLinks(
    templateLink: RevisionLink,
    links: RevisionLink[],
    payload: unknown,
    method?: Method | null,
  ): Tree {
    return fromJson(
      this.aq.createObjectWithAnchorLinks(templateLink, JSON.stringify(links), JSON.stringify(payload), methodArg(method)),
    );
  }

  /**
   * Create a template from a JSON Schema and register it on this instance.
   * `enableScalar` allows scalar-method objects of this type.
   */
  createTemplate(schema: Record<string, unknown>, name: string, enableScalar = false): Tree {
    return fromJson(this.aq.createTemplate(JSON.stringify(schema), name, enableScalar));
  }

  /**
   * Wrap a template definition (a registry `definitions/<name>.json` body,
   * parsed or as a string) as a one-revision tree keyed by its multihash:
   * the shape `exportTree`, `createObjectValidated`, and
   * `verifyAquaTreeWithLinkedTrees` accept as a template source.
   */
  templateTree(definition: TemplateRevision | string, name?: string | null): Tree {
    return fromJson(this.aq.templateTree(toJson(definition), name ?? null));
  }

  /** Link other trees to this one via an anchor revision over their tips. */
  linkAquaTree(wrapper: WrapperLike, linkTargets: WrapperLike[], method?: Method | null): Tree {
    return fromJson(this.aq.linkAquaTree(JSON.stringify(wrapper), JSON.stringify(linkTargets), methodArg(method)));
  }

  /** Remove the tip revision. */
  deleteLastRevision(wrapper: WrapperLike): Tree {
    return fromJson(this.aq.deleteLastRevision(JSON.stringify(wrapper)));
  }

  /**
   * Self-descriptive export: embed every referenced template (from the
   * built-in catalog or `sources`) so the result verifies on its own.
   * Fails closed listing unresolved template links.
   */
  exportTree(tree: WrapperLike, sources: Tree[] = [], options: ExportOptions = "default"): Tree {
    return fromJson(this.aq.exportTree(JSON.stringify(tree), JSON.stringify(sources), toJson(options)));
  }

  // ── Signing ────────────────────────────────────────────────────────────

  /**
   * Sign the wrapper's target revision (`revision`, else the tip) with
   * in-memory credentials inside the wasm module.
   */
  signAquaTree(
    wrapper: WrapperLike,
    credentials: SigningCredentials,
    method?: Method | null,
    ident?: string | null,
  ): Promise<AquaOperationData> {
    return this.aq
      .signAquaTree(JSON.stringify(wrapper), JSON.stringify(credentials), methodArg(method), ident ?? null)
      .then((json: unknown) => fromJson<AquaOperationData>(String(json)));
  }

  /**
   * Step 1 of external signing: the exact message a wallet must sign for
   * the wrapper's target revision. Single-use (it carries a fresh nonce and
   * timestamp): pass the whole object to `addExternalSignature`.
   */
  prepareSignature(
    wrapper: WrapperLike,
    signer: string,
    signatureType: SignatureType,
    method?: Method | null,
  ): PreparedSignature {
    return fromJson(this.aq.prepareSignature(JSON.stringify(wrapper), signer, signatureType, methodArg(method)));
  }

  /**
   * Step 2 of external signing: rebuild the signature revision from
   * `prepared` plus the wallet's `signatureValue`, verify it with the core
   * verifier, and insert it. Throws (tree untouched) on a bad signature.
   */
  addExternalSignature(
    wrapper: WrapperLike,
    prepared: PreparedSignature,
    signatureValue: SignatureValue,
  ): AquaOperationData {
    return fromJson(
      this.aq.addExternalSignature(JSON.stringify(wrapper), JSON.stringify(prepared), JSON.stringify(signatureValue)),
    );
  }

  /** `prepareSignature` → `signer.sign` → `addExternalSignature` in one call. */
  async signWith(signer: AquaSigner, wrapper: WrapperLike, method?: Method | null): Promise<AquaOperationData> {
    const prepared = this.prepareSignature(wrapper, signer.signer, signer.signatureType, method);
    const value = await signer.sign(prepared.message);
    if (value.signature_type !== signer.signatureType) {
      throw new Error(
        `signer produced ${value.signature_type} but declared ${signer.signatureType}`,
      );
    }
    return this.addExternalSignature(wrapper, prepared, value);
  }

  // ── Verification ───────────────────────────────────────────────────────

  /**
   * Full L1-L3 verification, synchronous. `files` supplies genesis content
   * for content-hash checks.
   */
  verifyAquaTree(wrapper: WrapperLike, files?: FileData[] | null): VerificationResult {
    return fromJson(this.aq.verifyAquaTree(JSON.stringify(wrapper), optionalJson(files)));
  }

  /**
   * Like `verifyAquaTree`, additionally verifying `linked` (template source
   * trees from `templateTree` belong here) and resolving cross-tree references.
   */
  verifyAquaTreeWithLinkedTrees(
    wrapper: WrapperLike,
    linked: WrapperLike[],
    files?: FileData[] | null,
  ): VerificationResult {
    return fromJson(
      this.aq.verifyAquaTreeWithLinkedTrees(JSON.stringify(wrapper), JSON.stringify(linked), optionalJson(files)),
    );
  }
}
