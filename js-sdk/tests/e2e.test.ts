/**
 * End to end through the wrapper: genesis -> sign (Ed25519 did:key inside
 * the module) -> verify, plus the negative case.
 */

import { describe, expect, it } from "vitest";
import {
  AquaSDK,
  CredentialsSigner,
  generateEd25519,
  isSignatureRevision,
  isVerified,
  verificationErrors,
  version,
  wrap,
  tipOf,
} from "../src/index.js";
import type { ObjectRevision } from "../src/index.js";
import { isObjectRevision } from "../src/index.js";
import { HELLO, HELLO_NAME, helloFiles, revisionCount, sdk } from "./helpers.js";

describe("genesis -> sign -> verify", () => {
  it("reports the crate version", async () => {
    await sdk();
    expect(version()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("verifies a did:key-signed file tree", async () => {
    const aq = await sdk();
    const key = generateEd25519();
    expect(key.did).toMatch(/^did:key:z6Mk/);

    // Genesis = scalar anchor + typed `file` object; the object is the tip.
    const genesis = aq.createGenesisRevision(HELLO_NAME, HELLO);
    expect(revisionCount(genesis)).toBe(2);
    const tip = tipOf(genesis)!;
    expect(genesis.revisions[tip]!.previous_revision).toBeDefined();

    const signed = await aq.signAquaTree(wrap(genesis), { did_key: key.secret }, null, "vitest");
    expect(revisionCount(signed.aqua_tree)).toBe(3);
    expect(signed.log_data.some((l) => l.logType === "success")).toBe(true);
    expect(signed.log_data.every((l) => l.ident === "vitest" || l.ident == null)).toBe(true);

    const sig = Object.values(signed.aqua_tree.revisions).find(isSignatureRevision)!;
    expect(sig.signer).toBe(key.did);
    expect(sig.signature.signature_type).toBe("ed25519");
    expect(sig.previous_revision).toBe(tip);

    const result = aq.verifyAquaTree(wrap(signed.aqua_tree), helloFiles());
    expect(result.outcome.result).toBe("verified");
    expect(isVerified(result)).toBe(true);
    expect(verificationErrors(result)).toEqual([]);
  });

  it("CredentialsSigner derives the DID the module records", async () => {
    const aq = await sdk();
    const signer = CredentialsSigner.generateEd25519();
    const genesis = aq.createMinimalGenesisRevision(HELLO_NAME, HELLO);
    const signed = await signer.sign(aq, genesis);
    const sig = Object.values(signed.aqua_tree.revisions).find(isSignatureRevision)!;
    expect(sig.signer).toBe(signer.did);
    // Genesis content checks need the file bytes; without them verification fails closed.
    expect(isVerified(aq.verifyAquaTree(signed.aqua_tree))).toBe(false);
    expect(isVerified(aq.verifyAquaTree(signed.aqua_tree, helloFiles()))).toBe(true);
  });

  it("fails verification when a payload is tampered with", async () => {
    const aq = await sdk();
    const key = generateEd25519();
    const signed = await aq.signAquaTree(aq.createGenesisRevision(HELLO_NAME, HELLO), { did_key: key.secret });
    const tampered = structuredClone(signed.aqua_tree);
    const fileObject = Object.values(tampered.revisions).find(isObjectRevision) as ObjectRevision<Record<string, unknown>>;
    fileObject.payloads = { ...fileObject.payloads, file_name: "evil.txt" };

    const result = aq.verifyAquaTree(wrap(tampered), helloFiles());
    expect(result.outcome.result).toBe("failed");
    expect(verificationErrors(result).length).toBeGreaterThan(0);
  });

  it("honours builder options (BLAKE3 hash type, explicit methods)", async () => {
    await sdk();
    const blake = new AquaSDK({ hash_type: "blake3_256", default_object_method: "scalar" });
    try {
      expect(blake.hashType()).toBe("BLAKE3-256");
      // Typed objects follow the builder's hash type and default method.
      // Templates stay SHA3-addressed by spec, so the object needs a real
      // (here: custom) template to verify under the strict policy.
      const template = blake.createTemplate(
        { type: "object", properties: { a: { type: "integer" } }, required: ["a"] },
        "blake_template",
        true,
      );
      const templateLink = Object.keys(template.revisions)[0]!;
      expect(templateLink).toMatch(/^0x1620/);
      const tree = blake.createObjectValidated(templateLink, null, { a: 1 }, [template]);
      const link = tipOf(tree)!;
      expect(link).toMatch(/^0x1e20[0-9a-f]{64}$/);
      expect(tree.revisions[link]!.method).toBe("scalar");
      const key = generateEd25519();
      const signed = await blake.signAquaTree(blake.exportTree(tree, [template]), { did_key: key.secret });
      const sigLink = Object.entries(signed.aqua_tree.revisions).find(([, r]) => isSignatureRevision(r))![0];
      expect(sigLink).toMatch(/^0x1e20/);
      const result = blake.verifyAquaTree(signed.aqua_tree);
      expect(result.outcome.result, JSON.stringify(result.outcome)).toBe("verified");
      // File genesis content hashing is pinned to SHA3-256 in the core
      // (`core::genesis`), independent of the builder's hash type.
      const genesis = blake.createGenesisRevision(HELLO_NAME, HELLO);
      expect(tipOf(genesis)).toMatch(/^0x1620/);
    } finally {
      blake.free();
    }
  });

  it("deleteLastRevision removes the tip", async () => {
    const aq = await sdk();
    const key = generateEd25519();
    const signed = await aq.signAquaTree(aq.createGenesisRevision(HELLO_NAME, HELLO), { did_key: key.secret });
    const trimmed = aq.deleteLastRevision(signed.aqua_tree);
    expect(revisionCount(trimmed)).toBe(2);
    expect(Object.values(trimmed.revisions).some(isSignatureRevision)).toBe(false);
  });

  it("rejects invalid input with a readable error", async () => {
    const aq = await sdk();
    expect(() => aq.createObject("not-a-link", null, {})).toThrow();
    await expect(aq.signAquaTree(aq.createGenesisRevision(HELLO_NAME, HELLO), { did_key: "0x00" })).rejects.toThrow();
  });
});
