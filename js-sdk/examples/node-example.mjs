// Node example for aqua-core-js. Run after `pnpm build`:
//     node examples/node-example.mjs
//
// Covers: file genesis -> sign -> verify, an external WebCrypto signer, an
// audit-trail object with explicit template sources, and pseudonymous
// disclosure.

import {
  AquaSDK,
  Ed25519WebCryptoSigner,
  TemplateSource,
  auditTemplateLink,
  exportSelectiveTree,
  generateEd25519,
  isVerified,
  missingTemplates,
  pseudonymousPolicy,
  toFileData,
  validateAuditPayload,
  verifySelectiveTree,
  version,
  wrap,
} from "../dist/index.js";

const sdk = await AquaSDK.load(); // reads the .wasm from node_modules in Node
console.log("aqua-rs-sdk-core-wasm", version());

// 1. File genesis -> sign with an in-module Ed25519 key -> verify.
const content = new TextEncoder().encode("hello aqua");
const genesis = sdk.createGenesisRevision("hello.txt", content);
const key = generateEd25519();
const signed = await sdk.signAquaTree(genesis, { did_key: key.secret });
const result = sdk.verifyAquaTree(wrap(signed.aqua_tree), [toFileData("hello.txt", content)]);
console.log("file tree:", result.outcome.result, `(${Object.keys(signed.aqua_tree.revisions).length} revisions)`);

// 2. External signer: the private key stays in WebCrypto.
const signer = await Ed25519WebCryptoSigner.generate();
const external = await sdk.signWith(signer, signed.aqua_tree);
console.log("external signature by", signer.signer.slice(0, 24) + "...", "->",
  sdk.verifyAquaTree(external.aqua_tree, [toFileData("hello.txt", content)]).outcome.result);

// 3. Audit trail (T2 user prompt) with explicit template sources.
//    TemplateSource.auditFixtures uses the crate's in-tree FIXTURE copies of
//    the audit definitions. In production, fetch the same bodies from
//    aqua-template-registry (audit-set-v1) and use TemplateSource.fromDefinitions.
const sources = TemplateSource.auditFixtures(sdk);
const payload = {
  signer_did: key.did,
  created_at: Math.floor(Date.now() / 1000),
  session_id: "session-1",
  turn_id: "0x1620" + "01".repeat(32),
  prompt_text: "Summarize the quarterly report.",
};
validateAuditPayload("audit_user_prompt", payload);
const prompt = sdk.createObjectValidated(auditTemplateLink("audit_user_prompt"), null, payload, sources.trees);
const exported = sdk.exportTree(prompt, sources.trees);
console.log("audit object missing templates after export:", missingTemplates(exported));
const signedPrompt = await sdk.signAquaTree(exported, { did_key: key.secret });
console.log("audit tree:", sdk.verifyAquaTree(signedPrompt.aqua_tree).outcome.result);

// 4. Pseudonymous disclosure: audit content is redacted; metadata, anchors,
//    templates, and signatures stay so the selective tree still verifies.
const selective = exportSelectiveTree(signedPrompt.aqua_tree, pseudonymousPolicy(signedPrompt.aqua_tree));
verifySelectiveTree(selective);
const kinds = Object.values(selective.revisions).map((r) => r.disclosure);
console.log("selective tree verified; disclosure kinds:", kinds.join(", "));
console.log("prompt text present in selective export:", JSON.stringify(selective).includes(payload.prompt_text));

if (!isVerified(result)) process.exit(1);
