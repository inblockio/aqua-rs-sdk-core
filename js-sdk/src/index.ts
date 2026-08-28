/**
 * aqua-core-js: TypeScript wrapper for aqua-rs-sdk-core compiled to WebAssembly.
 *
 * Usage: `const sdk = await AquaSDK.load();` then call the typed methods.
 * Free functions (`generateEd25519`, `hashBytes`, `missingTemplates`, the
 * disclosure helpers, ...) work once `init()` or `AquaSDK.load()` has run.
 */

export { init, initSync, isInitialized, readNodeWasm, type WasmModule } from "./wasm.js";
export { AquaSDK, toFileData, wrap, treeOf, tipOf, revisionLinks } from "./core.js";
export { version } from "./version.js";

export {
  generateEd25519,
  didFromEd25519PublicKey,
  didFromEd25519SecretKey,
  didFromP256PublicKey,
  didFromP256SecretKey,
  decodeDidKey,
} from "./did.js";

export { hashBytes, batchLeafHash, merkleRoot, multihashEncode, multihashDecode } from "./merkle.js";

export {
  pseudonymousPolicy,
  fullPolicy,
  exportSelectiveTree,
  verifySelectiveTree,
  redactRevision,
  verifyRedactedRevision,
} from "./disclosure.js";

export {
  missingTemplates,
  builtinTemplateHashes,
  shippedTemplateHashes,
  builtinTemplateTree,
  builtinTemplateTreeChain,
  builtinTemplateName,
  resolveDependencyTrees,
  auditTemplateNames,
  auditTemplateFixtureJson,
  auditTemplateFixture,
  auditTemplateLink,
  validateAuditPayload,
  TemplateSource,
  type TemplateDefinition,
} from "./templates.js";

export type { AquaSigner } from "./signing/signer.js";
export { Ed25519WebCryptoSigner, P256WebCryptoSigner } from "./signing/webcrypto.js";
export { CredentialsSigner } from "./signing/credentials.js";
export { MetaMaskSigner, type Eip1193Provider } from "./signing/metamask.js";

export { toBytes, toText, bytesToHex, hexToBytes, toByteArray } from "./bytes.js";

export * from "./types.js";
