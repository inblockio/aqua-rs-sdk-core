# aqua-core-js

TypeScript wrapper for [`aqua-rs-sdk-core`](../README.md) compiled to
WebAssembly. It creates, signs, exports, verifies, and selectively discloses
Aqua trees in Node and in browsers, with the same hashes and the same
verification outcomes as the Rust crate: every operation runs inside the
`aqua-rs-sdk-core-wasm` module, and the wrapper only types the JSON boundary.

*Experimental, Apache-2.0, provided as-is; breaking changes are expected.*

- Typed interfaces for every wire shape (`Tree`, `AnyRevision`,
  `AquaTreeWrapper`, `VerificationResult`, `DisclosurePolicy`, ...) derived
  from the Rust serde structs.
- One method per wasm export, synchronous where the export is synchronous.
- External signing without key material in the module: `prepareSignature`
  returns exactly what a wallet signs, `addExternalSignature` verifies before
  inserting. Signers ship for WebCrypto Ed25519 and P-256 and for EIP-191 via
  any EIP-1193 provider (MetaMask); nothing is hashed in JavaScript.
- `TemplateSource` turns registry template definitions into the source trees
  the validated-creation, export, and verification paths accept.

## Prerequisites

- Rust with the `wasm32-unknown-unknown` target and
  [`wasm-pack`](https://rustwasm.github.io/wasm-pack/).
- Node 20.6 or newer (Node 24 is what CI runs) and a package manager. The
  scripts are manager-agnostic; the committed lockfile is pnpm's.

## Build

From the repository root, build the wasm package, then the wrapper:

```
wasm-pack build wasm --target web --release --out-dir pkg
cd js-sdk
pnpm install
pnpm build        # tsc -> dist/
pnpm test         # vitest
```

`js-sdk/package.json` depends on the wasm package as `file:../wasm/pkg`, so
the wasm build must exist before `pnpm install`, and a rebuilt wasm package
needs another `pnpm install` to be picked up.

## Quick start

### File genesis, sign, verify

```ts
import { AquaSDK, generateEd25519, toFileData, wrap } from "aqua-core-js";

const sdk = await AquaSDK.load(); // Node: reads the .wasm from node_modules

const content = new TextEncoder().encode("hello world");
const genesis = sdk.createGenesisRevision("hello.txt", content);

const key = generateEd25519(); // { secret: "0x...", did: "did:key:z6Mk..." }
const signed = await sdk.signAquaTree(wrap(genesis), { did_key: key.secret });

const result = sdk.verifyAquaTree(wrap(signed.aqua_tree), [toFileData("hello.txt", content)]);
console.log(result.outcome.result); // "verified"
```

In a browser, pass the module location to `load` (or nothing, if the wasm
package's files are served next to each other):

```ts
const sdk = await AquaSDK.load(new URL("aqua_rs_sdk_core_wasm_bg.wasm", import.meta.url));
```

### External signer

The private key never enters the module. `signWith` runs
`prepareSignature`, hands the canonical message to the signer, and calls
`addExternalSignature`, which re-verifies the signature and the signer/key
binding before inserting the revision.

```ts
import { AquaSDK, Ed25519WebCryptoSigner, MetaMaskSigner } from "aqua-core-js";

const sdk = await AquaSDK.load();
const tree = sdk.createGenesisRevision("hello.txt", "hello world");

const ed = await Ed25519WebCryptoSigner.generate(); // WebCrypto Ed25519, did:key
const signed = await sdk.signWith(ed, tree);

// EIP-191 through an EIP-1193 provider (window.ethereum), did:pkh:eip155
const mm = await MetaMaskSigner.connect();
const signedByWallet = await sdk.signWith(mm, signed.aqua_tree);
```

Implement `AquaSigner` (`signatureType`, `signer`, `sign(message)`) for
other wallets; the doc comment on `prepareSignature` in the wasm package
lists what each algorithm signs.

### Audit trail with registry templates

The audit templates (T1-T8, `audit_round_anchor`, `audit_session_close`,
`audit_artifact`) are not built into the core. Fetch their definitions from
[`aqua-template-registry`](https://github.com/inblockio/aqua-template-registry)
(`audit-set-v1`), wrap them with `TemplateSource`, and pass the source trees
to validated creation and export. The exported tree carries the templates
and verifies on its own.

```ts
import { AquaSDK, TemplateSource, auditTemplateLink, missingTemplates, wrap } from "aqua-core-js";

const sdk = await AquaSDK.load();

// GET .../audit-set-v1/definitions/<name>.json for each name you use.
const sources = TemplateSource.fromDefinitions(sdk, [
  { name: "audit_artifact", definition: await fetchDefinition("audit_artifact") },
  { name: "audit_user_prompt", definition: await fetchDefinition("audit_user_prompt") },
]);

const payload = { signer_did: userDid, created_at: 1754500000, session_id: "s1", turn_id, prompt_text: "hi" };
const prompt = sdk.createObjectValidated(auditTemplateLink("audit_user_prompt"), null, payload, sources.trees);
const exported = sdk.exportTree(prompt, sources.trees);
console.log(missingTemplates(exported)); // []

const signed = await sdk.signAquaTree(wrap(exported), { did_key: userSecret });
console.log(sdk.verifyAquaTree(wrap(signed.aqua_tree)).outcome.result); // "verified"
```

`TemplateSource.auditFixtures(sdk)` and `auditTemplateFixtureJson(name)`
expose the crate's in-tree copies of the same definitions. They are test
fixtures, not built-ins: use them for tests and offline tooling, and fetch
from the registry in production.

### Selective disclosure

```ts
import { exportSelectiveTree, pseudonymousPolicy, verifySelectiveTree, redactRevision, verifyRedactedRevision } from "aqua-core-js";

const policy = pseudonymousPolicy(signed.aqua_tree); // audit preset: content redacted, metadata kept
const selective = exportSelectiveTree(signed.aqua_tree, policy);
verifySelectiveTree(selective); // throws on failure

// Field-level redaction of one tree-method revision
const redacted = redactRevision(revision, link, ["/payloads/session_id"]);
verifyRedactedRevision(redacted);
```

## API overview

| Area | Functions and methods |
|---|---|
| Loading | `init(input?)`, `initSync(module)`, `AquaSDK.load(input?, options?)`, `new AquaSDK(options?)`, `sdk.free()` |
| Creation | `createGenesisRevision`, `createMinimalGenesisRevision`, `createGenesisRevisionFromMetadata`, `createObject`, `createObjectValidated`, `createObjectWithName`, `createObjectWithAnchorLinks`, `createTemplate`, `templateTree`, `linkAquaTree`, `deleteLastRevision`, `exportTree` |
| Signing | `signAquaTree` (credentials in the module), `prepareSignature` + `addExternalSignature`, `signWith(signer, ...)`; `Ed25519WebCryptoSigner`, `P256WebCryptoSigner`, `MetaMaskSigner`, `CredentialsSigner` |
| Verification | `verifyAquaTree`, `verifyAquaTreeWithLinkedTrees`, `isVerified`, `verificationErrors`, `verificationWarnings` |
| Keys and DIDs | `generateEd25519`, `didFromEd25519PublicKey`, `didFromEd25519SecretKey`, `didFromP256PublicKey`, `didFromP256SecretKey`, `decodeDidKey` |
| Templates | `missingTemplates`, `builtinTemplateHashes`, `shippedTemplateHashes`, `builtinTemplateTree`, `builtinTemplateTreeChain`, `builtinTemplateName`, `resolveDependencyTrees`, `TemplateSource` |
| Audit fixtures | `auditTemplateNames`, `auditTemplateFixtureJson`, `auditTemplateFixture`, `auditTemplateLink`, `validateAuditPayload` |
| Disclosure | `pseudonymousPolicy`, `fullPolicy`, `exportSelectiveTree`, `verifySelectiveTree`, `redactRevision`, `verifyRedactedRevision` |
| Hashing | `hashBytes`, `batchLeafHash`, `merkleRoot`, `multihashEncode`, `multihashDecode`, `version` |
| Helpers | `wrap`, `toFileData`, `treeOf`, `tipOf`, `revisionLinks`, `toBytes`, `bytesToHex`, `hexToBytes`, revision type guards |

Every method mirrors one export of the wasm package; the parity test
(`tests/parity.test.ts`) parses the generated `.d.ts` and fails when an
export is added or renamed without a wrapper. Errors thrown by the module
are plain `Error`s whose message is `"<context>: <source error>"`.

Options for `AquaSDK`: `default_object_method`, `default_signature_method`
(`"scalar"` or `"tree"`), `hash_type` (`"sha3_256"` or `"blake3_256"`; file
genesis content hashing is always SHA3-256), `verification_policy`
(`"strict"` (default), `"offline"`, or `"debug"`, which is never for
production).

## Notes

- `verifyAquaTreeWithLinkedTrees` consults linked trees only when the main
  tree's anchors reach them. A derived template's ancestors supplied as
  separate source trees are therefore not found; export the tree with
  `exportTree` so the templates travel inside it. Root templates resolve from
  linked trees as expected.
- A file genesis is two revisions: a scalar anchor and the typed `file`
  object (the tip). Verifying it needs the file bytes (`FileData`).
- Example: `node examples/node-example.mjs` after `pnpm build`.

## License

Apache-2.0, same as the core crate.
