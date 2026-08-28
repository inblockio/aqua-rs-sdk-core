/**
 * Selective disclosure: pseudonymous policy -> exportSelectiveTree ->
 * verifySelectiveTree, and redactRevision -> verifyRedactedRevision.
 */

import { describe, expect, it } from "vitest";
import {
  TemplateSource,
  auditTemplateLink,
  exportSelectiveTree,
  fullPolicy,
  generateEd25519,
  isObjectRevision,
  isSignatureRevision,
  pseudonymousPolicy,
  redactRevision,
  verifyRedactedRevision,
  verifySelectiveTree,
} from "../src/index.js";
import type { SelectiveTree, Tree } from "../src/index.js";
import { sdk } from "./helpers.js";

async function signedAuditTree(): Promise<{ tree: Tree; did: string }> {
  const aq = await sdk();
  const key = generateEd25519();
  const sources = TemplateSource.auditFixtures(aq);
  const payload = {
    signer_did: key.did,
    created_at: 1754500000,
    session_id: "s1",
    turn_id: "0x1620" + "01".repeat(32),
    prompt_text: "secret prompt",
  };
  const tree = aq.createObjectValidated(auditTemplateLink("audit_user_prompt"), null, payload, sources.trees, "tree");
  const exported = aq.exportTree(tree, sources.trees);
  const signed = await aq.signAquaTree(exported, { did_key: key.secret });
  return { tree: signed.aqua_tree, did: key.did };
}

describe("selective trees", () => {
  it("pseudonymous policy redacts T2 content, keeps metadata and signatures, and verifies", async () => {
    const { tree, did } = await signedAuditTree();
    const policy = pseudonymousPolicy(tree);
    // Only the audit object gets an entry (FieldRedacted with the spec 7.6 paths);
    // anchors, templates, and signatures default to Full.
    const [objectLink] = Object.entries(tree.revisions).find(([, r]) => isObjectRevision(r) && r.method === "tree")!;
    expect(Object.keys(policy.revisions)).toEqual([objectLink]);
    const entry = policy.revisions[objectLink]!;
    expect(typeof entry === "object" && "FieldRedacted" in entry).toBe(true);
    if (typeof entry !== "object") throw new Error("unreachable");
    expect(entry.FieldRedacted).toContain("/payloads/signer_did");
    expect(entry.FieldRedacted).not.toContain("/payloads/prompt_text");
    expect(entry.FieldRedacted).not.toContain("/nonce");

    const selective = exportSelectiveTree(tree, policy);
    expect(() => verifySelectiveTree(selective)).not.toThrow();
    expect(Object.keys(selective.revisions).length).toBe(Object.keys(tree.revisions).length);

    const redacted = selective.revisions[objectLink]!;
    if (redacted.disclosure !== "Redacted") throw new Error(`expected Redacted, got ${redacted.disclosure}`);
    const byPath = new Map(redacted.redacted.leaves.map((l) => [l.path, l.type]));
    expect(byPath.get("/payloads/prompt_text")).toBe("Redacted");
    expect(byPath.get("/payloads/signer_did")).toBe("Disclosed");
    expect(byPath.get("/payloads/session_id")).toBe("Disclosed");
    expect(byPath.get("/nonce")).toBe("Redacted");
    expect(JSON.stringify(selective)).not.toContain("secret prompt");
    expect(JSON.stringify(selective)).toContain(did);
    expect(redacted.redacted.leaf_count).toBe(redacted.redacted.leaves.length);

    const signatureLink = Object.entries(tree.revisions).find(([, r]) => isSignatureRevision(r))![0];
    expect(selective.revisions[signatureLink]!.disclosure).toBe("Full");
  });

  it("full policy discloses every revision", async () => {
    const { tree } = await signedAuditTree();
    const selective = exportSelectiveTree(tree, fullPolicy(tree));
    expect(Object.values(selective.revisions).every((r) => r.disclosure === "Full")).toBe(true);
    verifySelectiveTree(selective);
  });

  it("detects a tampered redacted leaf", async () => {
    const { tree } = await signedAuditTree();
    const selective = exportSelectiveTree(tree, pseudonymousPolicy(tree));
    const tampered: SelectiveTree = structuredClone(selective);
    const redacted = Object.values(tampered.revisions).find((r) => r.disclosure === "Redacted");
    expect(redacted).toBeDefined();
    if (redacted?.disclosure !== "Redacted") throw new Error("unreachable");
    const leaf = redacted.redacted.leaves.find((l) => l.type === "Disclosed");
    if (leaf?.type !== "Disclosed") throw new Error("expected a disclosed leaf");
    leaf.value = JSON.stringify("tampered");
    expect(() => verifySelectiveTree(tampered)).toThrow();
  });
});

describe("field-level redaction", () => {
  it("redactRevision discloses only the requested paths and verifies", async () => {
    const { tree } = await signedAuditTree();
    const [link, revision] = Object.entries(tree.revisions).find(([, r]) => isObjectRevision(r) && r.method === "tree")!;
    const redacted = redactRevision(revision, link, ["/payloads/session_id", "/payloads/created_at"]);
    expect(redacted.revision_hash).toBe(link);
    expect(redacted.leaf_count).toBe(redacted.leaves.length);
    const disclosed = redacted.leaves.filter((l) => l.type === "Disclosed").map((l) => l.path);
    expect(disclosed.sort()).toEqual(["/payloads/created_at", "/payloads/session_id"]);
    expect(redacted.leaves.some((l) => l.type === "Redacted" && l.path === "/payloads/prompt_text")).toBe(true);
    expect(() => verifyRedactedRevision(redacted)).not.toThrow();

    const tampered = structuredClone(redacted);
    tampered.leaf_count = 1;
    expect(() => verifyRedactedRevision(tampered)).toThrow();
  });

  it("refuses to disclose the nonce", async () => {
    const { tree } = await signedAuditTree();
    const [link, revision] = Object.entries(tree.revisions).find(([, r]) => isObjectRevision(r) && r.method === "tree")!;
    expect(() => redactRevision(revision, link, ["/nonce"])).toThrow();
  });

  it("refuses to field-redact a scalar revision", async () => {
    const aq = await sdk();
    const key = generateEd25519();
    const signed = await aq.signAquaTree(aq.createGenesisRevision("f.txt", "x", "scalar"), { did_key: key.secret });
    const [link, revision] = Object.entries(signed.aqua_tree.revisions).find(([, r]) => r.method === "scalar")!;
    expect(() => redactRevision(revision, link, ["/version"])).toThrow();
  });
});
