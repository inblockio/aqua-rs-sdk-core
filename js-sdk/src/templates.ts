/**
 * Template catalog helpers and `TemplateSource`, the first-class way to
 * turn registry template definitions into the source trees that
 * `createObjectValidated`, `exportTree`, and
 * `verifyAquaTreeWithLinkedTrees` accept.
 *
 * Audit templates (T1-T8 and friends) are NOT built into the core: they are
 * distributed through `aqua-template-registry` (`audit-set-v1`), and a
 * receiver can only verify an audit tree if the definitions travel with it
 * (`exportTree`) or are supplied as sources. The `auditTemplate*` functions
 * below expose the crate's in-tree FIXTURE copies of those definitions for
 * tests and offline tooling; production code must fetch the registry
 * bodies instead.
 */

import type { AquaSDK } from "./core.js";
import { wrap } from "./core.js";
import type {
  AquaTreeWrapper,
  RevisionLink,
  TemplateHashEntry,
  TemplateRevision,
  Tree,
  WrapperLike,
} from "./types.js";
import { ensureReady, fromJson } from "./wasm.js";

// ── Catalog queries ──────────────────────────────────────────────────────

/**
 * Template links a tree references but neither carries nor has built in:
 * what a receiver still needs before it can verify (empty = self-descriptive).
 */
export function missingTemplates(tree: WrapperLike): RevisionLink[] {
  return fromJson(ensureReady().missingTemplates(JSON.stringify(tree)));
}

/** Built-in templates resolvable as object types, sorted by name. */
export function builtinTemplateHashes(): TemplateHashEntry[] {
  return fromJson(ensureReady().builtinTemplateHashes());
}

/** All 8 contract templates the crate ships (built-ins plus `template_meta`, `anchor_template`, `signature_base`). */
export function shippedTemplateHashes(): TemplateHashEntry[] {
  return fromJson(ensureReady().shippedTemplateHashes());
}

/** One-revision tree for a built-in template, or `undefined` if `link` is not built-in. */
export function builtinTemplateTree(link: RevisionLink): Tree | undefined {
  const json = ensureReady().builtinTemplateTree(link);
  return json === undefined ? undefined : fromJson(json);
}

/** Root-first ancestry chain of trees for a built-in template (empty if not built-in). */
export function builtinTemplateTreeChain(link: RevisionLink): Tree[] {
  return fromJson(ensureReady().builtinTemplateTreeChain(link));
}

/** Name of a built-in template, or `undefined`. */
export function builtinTemplateName(link: RevisionLink): string | undefined {
  return ensureReady().builtinTemplateName(link);
}

/** Full ancestor chains of every built-in template named in the tree's genesis anchor. */
export function resolveDependencyTrees(tree: WrapperLike): Tree[] {
  return fromJson(ensureReady().resolveDependencyTrees(JSON.stringify(tree)));
}

// ── Audit family fixtures ────────────────────────────────────────────────

/** The 11 audit template names in family order. */
export function auditTemplateNames(): string[] {
  return fromJson(ensureReady().auditTemplateNames());
}

/**
 * FIXTURE, not a built-in: the crate's copy of the audit template
 * definition (byte-identical with the registry's
 * `seed/audit-set-v1/definitions/<name>.json`), as the raw JSON string.
 * Production code must fetch the definition from `aqua-template-registry`
 * (`audit-set-v1`) and pass it through `templateTree` / `TemplateSource`.
 */
export function auditTemplateFixtureJson(name: string): string {
  return ensureReady().auditTemplateFixtureJson(name);
}

/** `auditTemplateFixtureJson`, parsed. Same caveat: fixture, not built-in. */
export function auditTemplateFixture(name: string): TemplateRevision {
  return fromJson(auditTemplateFixtureJson(name));
}

/** Full multihash link of an audit template: the `templateLink` for `createObjectValidated`. */
export function auditTemplateLink(name: string): RevisionLink {
  return ensureReady().auditTemplateLink(name);
}

/**
 * Validate a payload for an audit template (JSON Schema, then the typed
 * field rules). Throws on the first violation.
 */
export function validateAuditPayload(name: string, payload: unknown): void {
  ensureReady().validateAuditPayload(name, JSON.stringify(payload));
}

// ── TemplateSource ───────────────────────────────────────────────────────

/** A registry definition body with an optional label for `file_index`. */
export interface TemplateDefinition {
  name?: string;
  definition: TemplateRevision | string;
}

/**
 * A set of template source trees. Feed it registry definition bodies (or
 * already-built template trees) and pass `trees` / `wrappers()` to the
 * SDK calls that resolve templates from explicit sources.
 */
export class TemplateSource {
  private readonly byLink = new Map<RevisionLink, Tree>();

  constructor(private readonly sdk: AquaSDK) {}

  /**
   * Sources from registry definition bodies: the production path for the
   * audit family (`GET .../audit-set-v1/definitions/<name>.json`).
   */
  static fromDefinitions(sdk: AquaSDK, definitions: Iterable<TemplateDefinition>): TemplateSource {
    const source = new TemplateSource(sdk);
    for (const d of definitions) source.add(d.definition, d.name);
    return source;
  }

  /**
   * Sources from the crate's in-tree audit FIXTURES (all 11 templates).
   * For tests and offline tooling only: these are not built-ins, and a
   * production deployment must fetch the same definitions from
   * `aqua-template-registry` (`audit-set-v1`) with `fromDefinitions`.
   */
  static auditFixtures(sdk: AquaSDK): TemplateSource {
    return TemplateSource.fromDefinitions(
      sdk,
      auditTemplateNames().map((name) => ({ name, definition: auditTemplateFixtureJson(name) })),
    );
  }

  /** Wrap one definition with `templateTree` and add it. Returns its tree. */
  add(definition: TemplateRevision | string, name?: string): Tree {
    return this.addTree(this.sdk.templateTree(definition, name));
  }

  /** Add an already-built template tree (e.g. from `createTemplate` or `builtinTemplateTree`). */
  addTree(tree: Tree): Tree {
    for (const link of Object.keys(tree.revisions)) this.byLink.set(link, tree);
    return tree;
  }

  /** The template links this source can resolve. */
  get links(): RevisionLink[] {
    return [...this.byLink.keys()];
  }

  /** Whether `link` is resolvable from this source. */
  has(link: RevisionLink): boolean {
    return this.byLink.has(link);
  }

  /** The source trees, for `createObjectValidated` / `exportTree`. */
  get trees(): Tree[] {
    return [...new Set(this.byLink.values())];
  }

  /** The source trees as wrappers, for `verifyAquaTreeWithLinkedTrees`. */
  wrappers(): AquaTreeWrapper[] {
    return this.trees.map((t) => wrap(t));
  }
}
