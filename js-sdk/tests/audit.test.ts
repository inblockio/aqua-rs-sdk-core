/**
 * Audit-trail flow with the 11 fixture templates (stand-ins for the
 * registry's audit-set-v1 definitions): validate -> createObjectValidated
 * -> sign -> exportTree -> missingTemplates == [] -> verify.
 */

import { describe, expect, it } from "vitest";
import {
  TemplateSource,
  auditTemplateFixture,
  auditTemplateFixtureJson,
  auditTemplateLink,
  auditTemplateNames,
  builtinTemplateHashes,
  builtinTemplateName,
  builtinTemplateTree,
  builtinTemplateTreeChain,
  generateEd25519,
  isObjectRevision,
  isVerified,
  missingTemplates,
  resolveDependencyTrees,
  shippedTemplateHashes,
  validateAuditPayload,
  verificationErrors,
  wrap,
} from "../src/index.js";
import { revisionCount, sdk } from "./helpers.js";

const T1_LINK = "0x1620" + "01".repeat(32); // stands in for a turn marker hash in payloads

function promptPayload(did: string) {
  return { signer_did: did, created_at: 1754500000, session_id: "s1", turn_id: T1_LINK, prompt_text: "hi" };
}

describe("audit fixtures", () => {
  it("exposes the 11 names, links, and definitions", async () => {
    await sdk();
    const names = auditTemplateNames();
    expect(names).toHaveLength(11);
    expect(names[0]).toBe("audit_artifact");
    expect(names).toContain("audit_user_prompt");
    for (const name of names) {
      expect(auditTemplateLink(name)).toMatch(/^0x1620[0-9a-f]{64}$/);
      const def = auditTemplateFixture(name);
      expect(def.schema).toBeTypeOf("object");
      expect(JSON.stringify(def)).toBe(JSON.stringify(JSON.parse(auditTemplateFixtureJson(name))));
    }
    expect(() => auditTemplateLink("nope")).toThrow(/unknown audit template/);
  });

  it("audit templates are not built-ins (registry-distributed)", async () => {
    await sdk();
    const builtin = new Set(builtinTemplateHashes().map((e) => e.link));
    for (const name of auditTemplateNames()) {
      expect(builtin.has(auditTemplateLink(name)), name).toBe(false);
      expect(builtinTemplateName(auditTemplateLink(name))).toBeUndefined();
    }
    expect(shippedTemplateHashes().length).toBe(8);
    expect(builtinTemplateHashes().length).toBeLessThanOrEqual(8);
  });

  it("validateAuditPayload accepts a valid T2 payload and rejects a bad one", async () => {
    await sdk();
    const did = generateEd25519().did;
    expect(() => validateAuditPayload("audit_user_prompt", promptPayload(did))).not.toThrow();
    expect(() => validateAuditPayload("audit_user_prompt", { ...promptPayload(did), signer_did: "" })).toThrow();
    expect(() => validateAuditPayload("audit_user_prompt", { ...promptPayload(did), turn_id: "bad" })).toThrow(
      /violates the template schema/,
    );
  });
});

describe("audit trail: createObjectValidated -> sign -> exportTree -> verify", () => {
  it("round-trips a T2 user prompt with explicit template sources", async () => {
    const aq = await sdk();
    const key = generateEd25519();
    const sources = TemplateSource.auditFixtures(aq);
    expect(sources.trees).toHaveLength(11);
    expect(sources.has(auditTemplateLink("audit_user_prompt"))).toBe(true);

    const t2 = auditTemplateLink("audit_user_prompt");
    const payload = promptPayload(key.did);
    validateAuditPayload("audit_user_prompt", payload);

    const tree = aq.createObjectValidated(t2, null, payload, sources.trees);
    const object = Object.values(tree.revisions).find(isObjectRevision)!;
    expect(object.revision_type).toBe(t2);
    expect(object.payloads).toEqual(payload);

    // Without sources the receiver is missing the template and its parent.
    const missingBefore = missingTemplates(tree);
    expect(missingBefore).toContain(t2);

    const exported = aq.exportTree(tree, sources.trees, "default");
    expect(missingTemplates(exported)).toEqual([]);
    expect(revisionCount(exported)).toBeGreaterThan(revisionCount(tree));

    const signed = await aq.signAquaTree(wrap(exported), { did_key: key.secret });
    const result = aq.verifyAquaTree(wrap(signed.aqua_tree));
    expect(result.outcome.result, JSON.stringify(result.outcome)).toBe("verified");
    expect(isVerified(result)).toBe(true);
  });

  it("fails closed without template sources", async () => {
    const aq = await sdk();
    const key = generateEd25519();
    const t2 = auditTemplateLink("audit_user_prompt");
    expect(() => aq.createObjectValidated(t2, null, promptPayload(key.did), [])).toThrow();
    expect(() => aq.exportTree(aq.createObject(t2, null, promptPayload(key.did)), [], "default")).toThrow();
  });

  it("rejects an invalid payload at creation", async () => {
    const aq = await sdk();
    const sources = TemplateSource.auditFixtures(aq);
    const t2 = auditTemplateLink("audit_user_prompt");
    expect(() => aq.createObjectValidated(t2, null, { prompt_text: "only" }, sources.trees)).toThrow();
  });

  it("a bare (non-exported) audit tree fails closed, even with the sources as linked trees", async () => {
    const aq = await sdk();
    const key = generateEd25519();
    const sources = TemplateSource.auditFixtures(aq);
    const t2 = auditTemplateLink("audit_user_prompt");
    const tree = aq.createObjectValidated(t2, null, promptPayload(key.did), sources.trees);
    const signed = await aq.signAquaTree(tree, { did_key: key.secret });

    const alone = aq.verifyAquaTree(signed.aqua_tree);
    expect(alone.outcome.result).toBe("failed");
    expect(verificationErrors(alone).length).toBeGreaterThan(0);

    // Known core limitation (see docs/plans/2026-08-28-typescript-wrapper.md):
    // linked trees are only consulted when an anchor of the main tree reaches
    // them. The T2 anchor links audit_user_prompt, whose source tree does not
    // itself link its parent audit_artifact, so the ancestor is pruned and
    // verification fails with ANCESTOR_TEMPLATE_NOT_FOUND. Derived templates
    // must travel inside the tree via exportTree.
    const withSources = aq.verifyAquaTreeWithLinkedTrees(signed.aqua_tree, sources.wrappers());
    expect(withSources.outcome.result).toBe("failed");
    expect(verificationErrors(withSources).map((e) => e.code)).toContain("ANCESTOR_TEMPLATE_NOT_FOUND");

    // The exported tree verifies with or without the linked sources.
    const exported = aq.exportTree(tree, sources.trees);
    const signedExport = await aq.signAquaTree(exported, { did_key: key.secret });
    expect(aq.verifyAquaTreeWithLinkedTrees(signedExport.aqua_tree, sources.wrappers()).outcome.result).toBe("verified");
  });

  it("registry-style definitions build the same source trees as the fixtures", async () => {
    const aq = await sdk();
    // Simulate `GET .../audit-set-v1/definitions/<name>.json` bodies.
    const bodies = auditTemplateNames().map((name) => ({ name, definition: auditTemplateFixture(name) }));
    const fromRegistry = TemplateSource.fromDefinitions(aq, bodies);
    const fromFixtures = TemplateSource.auditFixtures(aq);
    expect(new Set(fromRegistry.links)).toEqual(new Set(fromFixtures.links));
    expect(fromRegistry.trees).toEqual(fromFixtures.trees);
  });
});

describe("built-in catalog helpers", () => {
  it("resolves built-in templates and their chains", async () => {
    const aq = await sdk();
    const entries = builtinTemplateHashes();
    expect(entries.length).toBeGreaterThan(0);
    const first = entries[0]!;
    expect(builtinTemplateName(first.link)).toBe(first.name);
    const tree = builtinTemplateTree(first.link)!;
    // The core keys built-in template trees by the bare 32-byte digest, not
    // the full multihash the catalog entry reports.
    const keys = Object.keys(tree.revisions);
    expect(keys).toHaveLength(1);
    expect(keys[0]).toBe("0x" + first.link.slice(6));
    expect(builtinTemplateTreeChain(first.link).length).toBeGreaterThanOrEqual(1);
    expect(builtinTemplateTree("0x1620" + "00".repeat(32))).toBeUndefined();
    const deps = resolveDependencyTrees(aq.createObjectWithAnchorLinks("0x1620" + "cd".repeat(32), [first.link], { a: 1 }));
    expect(deps.length).toBeGreaterThanOrEqual(1);
  });

  it("createTemplate produces a template tree usable as a source", async () => {
    const aq = await sdk();
    const schema = {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      properties: { note: { type: "string" } },
      required: ["note"],
      additionalProperties: false,
    };
    const template = aq.createTemplate(schema, "note_template", true);
    const link = Object.keys(template.revisions)[0]!;
    const tree = aq.createObjectValidated(link, null, { note: "hi" }, [template]);
    expect(Object.values(tree.revisions).some(isObjectRevision)).toBe(true);
    expect(() => aq.createObjectValidated(link, null, { note: 1 }, [template])).toThrow();
    const exported = aq.exportTree(tree, [template]);
    expect(missingTemplates(exported)).toEqual([]);

    // A root (non-derived) custom template resolves from linked trees during
    // verification: the object's anchor links the template revision directly.
    const key = generateEd25519();
    const signed = await aq.signAquaTree(tree, { did_key: key.secret });
    expect(aq.verifyAquaTree(signed.aqua_tree).outcome.result).toBe("failed");
    const linked = aq.verifyAquaTreeWithLinkedTrees(signed.aqua_tree, [wrap(template)]);
    expect(linked.outcome.result, JSON.stringify(linked.outcome)).toBe("verified");
  });
});
