/**
 * Selective disclosure and field-level redaction (free wasm functions).
 */

import type {
  AnyRevision,
  DisclosurePolicy,
  RedactedRevision,
  RevisionLink,
  SelectiveTree,
  WrapperLike,
} from "./types.js";
import { ensureReady, fromJson } from "./wasm.js";

/**
 * The canonical `pseudonymous` policy for a tree (audit preset: signer
 * identities hidden, content disclosed).
 */
export function pseudonymousPolicy(tree: WrapperLike): DisclosurePolicy {
  return fromJson(ensureReady().pseudonymousPolicy(JSON.stringify(tree)));
}

/** The `full` policy (every revision disclosed). */
export function fullPolicy(tree: WrapperLike): DisclosurePolicy {
  return fromJson(ensureReady().fullPolicy(JSON.stringify(tree)));
}

/** Apply a policy to a tree. */
export function exportSelectiveTree(tree: WrapperLike, policy: DisclosurePolicy): SelectiveTree {
  return fromJson(ensureReady().exportSelectiveTree(JSON.stringify(tree), JSON.stringify(policy)));
}

/** Verify chain continuity and every redacted revision's Merkle root. Throws on failure. */
export function verifySelectiveTree(selective: SelectiveTree): void {
  ensureReady().verifySelectiveTree(JSON.stringify(selective));
}

/**
 * Field-level redaction of one tree-method revision: disclose only the
 * JSON Pointer `paths` (`/nonce` is refused).
 */
export function redactRevision(revision: AnyRevision, link: RevisionLink, paths: string[]): RedactedRevision {
  return fromJson(ensureReady().redactRevision(JSON.stringify(revision), link, JSON.stringify(paths)));
}

/** Verify a `RedactedRevision` against its declared revision hash. Throws on failure. */
export function verifyRedactedRevision(redacted: RedactedRevision): void {
  ensureReady().verifyRedactedRevision(JSON.stringify(redacted));
}
