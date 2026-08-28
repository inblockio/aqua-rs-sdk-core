/**
 * Merkle / canonicalization oracle: recompute every revision hash the
 * wasm module produces with an independent TypeScript implementation
 * (pure-JS SHA3-256 and HKDF from @noble/hashes, RFC 6901 flattening,
 * RFC 9162 Merkle root with odd-node promotion) and compare.
 *
 * Ported from aqua-rs-sdk/js-sdk/tests/merkle_tree_test.ts, upgraded to the
 * core's actual tree-method leaf construction (PCA-0016 AD-20: HKDF salts
 * from the nonce, label/value commitments, domain-separated nodes).
 */

import { describe, expect, it } from "vitest";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { batchLeafHash, bytesToHex, hashBytes, hexToBytes, merkleRoot, multihashDecode, isObjectRevision } from "../src/index.js";
import type { AnyRevision, Method, RevisionLink, Tree } from "../src/index.js";
import { HELLO, HELLO_NAME, sdk, utf8 } from "./helpers.js";

// ── Independent implementation ───────────────────────────────────────────

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

/** RFC 6901 flattening matching the `jsonpointer_flatten` crate: containers emit an empty marker at their own path. */
function flatten(value: unknown, route: string[] = [], target: Record<string, unknown> = {}): Record<string, unknown> {
  const key = route.join("");
  if (value === null || typeof value !== "object") {
    target[key] = value;
  } else if (Array.isArray(value)) {
    target[key] = [];
    value.forEach((v, i) => flatten(v, [...route, "/" + i], target));
  } else {
    target[key] = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      flatten(v, [...route, "/" + k.replace(/~/g, "~0").replace(/\//g, "~1")], target);
    }
  }
  return target;
}

function flattenSorted(revision: AnyRevision): Array<[string, unknown]> {
  // The core filters `/leaves*` pointers out of the hashed set; the field is
  // populated after hashing on tree-method revisions.
  const { leaves: _leaves, ...rest } = revision as AnyRevision & { leaves?: string[] };
  const flat = flatten(rest);
  return Object.keys(flat)
    .filter((k) => !k.startsWith("/leaves"))
    .sort()
    .map((k) => [k, flat[k]]);
}

function scalarHash(revision: AnyRevision): string {
  const canonical = JSON.stringify(Object.fromEntries(flattenSorted(revision)));
  return "0x1620" + bytesToHex(sha3_256(utf8(canonical))).slice(2);
}

function treeLeaves(revision: AnyRevision): Uint8Array[] {
  const prk = extract(sha3_256, hexToBytes(revision.nonce), utf8("AquaSD"));
  return flattenSorted(revision).map(([pointer, value]) => {
    const salt = expand(sha3_256, prk, utf8(pointer), 32);
    const label = sha3_256(concat(new Uint8Array([0x03]), utf8(pointer)));
    const valueCommit = sha3_256(concat(new Uint8Array([0x02]), salt, utf8(JSON.stringify(value))));
    return sha3_256(concat(new Uint8Array([0x00]), label, valueCommit));
  });
}

function root(leaves: Uint8Array[], promote = true): Uint8Array {
  if (leaves.length === 0) throw new Error("empty");
  let level = leaves;
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = level[i + 1];
      if (right !== undefined) next.push(sha3_256(concat(new Uint8Array([0x01]), left, right)));
      else next.push(promote ? left : sha3_256(concat(new Uint8Array([0x01]), left, left)));
    }
    level = next;
  }
  return level[0]!;
}

function treeHash(revision: AnyRevision): string {
  return "0x1620" + bytesToHex(root(treeLeaves(revision))).slice(2);
}

function expectedHash(revision: AnyRevision): string {
  return revision.method === "scalar" ? scalarHash(revision) : treeHash(revision);
}

function checkTree(tree: Tree): void {
  for (const [link, rev] of Object.entries(tree.revisions)) {
    expect(expectedHash(rev), `${rev.method} hash of ${link}`).toBe(link);
    if (rev.method === "tree" && "leaves" in rev && rev.leaves) {
      const local = treeLeaves(rev).map(bytesToHex);
      expect(local, `leaves of ${link}`).toEqual(rev.leaves);
      // The stored leaves must also fold to the link under the wasm root.
      expect(merkleRoot(rev.leaves, "sha3_256")).toBe("0x" + link.slice(6));
    }
  }
}

// ── Fixtures ─────────────────────────────────────────────────────────────

// A syntactically valid multihash link no template is registered under:
// `createObject` accepts unknown (non-built-in) types unvalidated.
const UNKNOWN_TEMPLATE: RevisionLink = "0x1620" + "ab".repeat(32);

const SIMPLE = { name: "hello" };
const COMPLEX = { name: "test", count: 42, tags: ["a", "b"] };
const NESTED = { name: "nested", count: 7, tags: ["x", "y", "z"], meta: { id: 1, deep: { flag: true, none: null } } };
const ESCAPED = { "a/b": "slash", "c~d": "tilde", quote: 'say "hi"\n', "": "empty-key" };

describe("hash primitives against @noble/hashes", () => {
  it("hashBytes is SHA3-256", async () => {
    await sdk();
    expect(hashBytes("abc", "sha3_256")).toBe(bytesToHex(sha3_256(utf8("abc"))));
    expect(hashBytes(HELLO, "FIPS_202-SHA3-256")).toBe(bytesToHex(sha3_256(HELLO)));
  });

  it("batchLeafHash is HASH(0x00 || data)", async () => {
    await sdk();
    expect(batchLeafHash("abc")).toBe(bytesToHex(sha3_256(concat(new Uint8Array([0x00]), utf8("abc")))));
  });

  it("merkleRoot promotes odd nodes and uses 0x01-prefixed internal nodes", async () => {
    await sdk();
    const leaves = ["a", "b", "c", "d", "e"].map((s) => sha3_256(concat(new Uint8Array([0x00]), utf8(s))));
    const hex = leaves.map(bytesToHex);
    expect(merkleRoot(hex)).toBe(bytesToHex(root(leaves, true)));
    expect(merkleRoot(hex)).not.toBe(bytesToHex(root(leaves, false)));
    expect(merkleRoot([hex[0]!])).toBe(hex[0]);
    expect(() => merkleRoot([])).toThrow(/zero leaves/);
  });

  it("multihash round trip", async () => {
    await sdk();
    const digest = bytesToHex(sha3_256(utf8("x")));
    const decoded = multihashDecode("0x1620" + digest.slice(2));
    expect(decoded).toEqual({ hash_type: "FIPS_202-SHA3-256", digest });
  });
});

describe("revision hashes recomputed independently", () => {
  for (const method of ["scalar", "tree"] as Method[]) {
    it(`genesis revision (${method})`, async () => {
      const aq = await sdk();
      // A file genesis is a scalar anchor plus the typed `file` object.
      const tree = aq.createGenesisRevision(HELLO_NAME, HELLO, method);
      expect(Object.keys(tree.revisions)).toHaveLength(2);
      const [link, rev] = Object.entries(tree.revisions).find(([, r]) => isObjectRevision(r))!;
      expect(rev.method).toBe(method);
      expect(tree.file_index[link]).toBe(HELLO_NAME);
      checkTree(tree);
    });

    for (const [label, payload] of [
      ["simple", SIMPLE],
      ["complex", COMPLEX],
      ["nested", NESTED],
      ["escaped keys", ESCAPED],
      ["empty", {}],
    ] as const) {
      it(`createObject ${label} payload (${method})`, async () => {
        const aq = await sdk();
        const tree = aq.createObject(UNKNOWN_TEMPLATE, null, payload, method);
        const objects = Object.values(tree.revisions).filter(isObjectRevision);
        expect(objects).toHaveLength(1);
        expect(objects[0]!.payloads).toEqual(payload);
        checkTree(tree);
      });
    }
  }

  it("scalar and tree hashes of the same payload differ", async () => {
    const aq = await sdk();
    const s = Object.keys(aq.createObject(UNKNOWN_TEMPLATE, null, COMPLEX, "scalar").revisions);
    const t = Object.keys(aq.createObject(UNKNOWN_TEMPLATE, null, COMPLEX, "tree").revisions);
    expect(s).not.toEqual(t);
  });

  it("odd leaf count: promotion matches, duplication does not", async () => {
    const aq = await sdk();
    const tree = aq.createObject(UNKNOWN_TEMPLATE, null, COMPLEX, "tree");
    const [link, rev] = Object.entries(tree.revisions).find(([, r]) => isObjectRevision(r))!;
    const leaves = treeLeaves(rev);
    // Make the assertion meaningful: pick a payload whose leaf count is odd.
    expect(leaves.length % 2, `leaf count ${leaves.length}`).toBe(1);
    expect("0x1620" + bytesToHex(root(leaves, true)).slice(2)).toBe(link);
    expect("0x1620" + bytesToHex(root(leaves, false)).slice(2)).not.toBe(link);
  });

  it("chained object revisions keep earlier hashes intact", async () => {
    const aq = await sdk();
    const first = aq.createObject(UNKNOWN_TEMPLATE, null, { name: "first" }, "tree");
    const second = aq.createObject(UNKNOWN_TEMPLATE, first, { name: "second" }, "tree");
    expect(Object.keys(second.revisions).length).toBe(Object.keys(first.revisions).length + 1);
    for (const [link, rev] of Object.entries(first.revisions)) expect(second.revisions[link]).toEqual(rev);
    const added = Object.entries(second.revisions).find(([l]) => !(l in first.revisions))!;
    expect(added[1].previous_revision).toBeDefined();
    expect(added[1].previous_revision! in first.revisions).toBe(true);
    checkTree(second);
  });

  it("signature and anchor revisions hash the same way", async () => {
    const aq = await sdk();
    const { generateEd25519 } = await import("../src/index.js");
    const key = generateEd25519();
    const genesis = aq.createGenesisRevision(HELLO_NAME, HELLO, "tree");
    const signed = await aq.signAquaTree(genesis, { did_key: key.secret });
    const other = aq.createGenesisRevision("other.txt", utf8("other"));
    const linked = aq.linkAquaTree(signed.aqua_tree, [other]);
    const kinds = new Set(
      Object.values(linked.revisions).map((r) => ("signature" in r ? "signature" : "structural_links" in r ? "anchor" : "object")),
    );
    expect(kinds).toEqual(new Set(["object", "signature", "anchor"]));
    checkTree(linked);
  });

  it("flattening emits container markers and sorted pointers", async () => {
    const aq = await sdk();
    const tree = aq.createObject(UNKNOWN_TEMPLATE, null, NESTED, "tree");
    const rev = Object.values(tree.revisions).find(isObjectRevision)!;
    const flat = Object.fromEntries(flattenSorted(rev));
    expect(flat[""]).toEqual({});
    expect(flat["/payloads"]).toEqual({});
    expect(flat["/payloads/tags"]).toEqual([]);
    expect(flat["/payloads/tags/2"]).toBe("z");
    expect(flat["/payloads/meta/deep/none"]).toBeNull();
    const keys = Object.keys(flat);
    expect(keys).toEqual([...keys].sort());
    expect(keys.some((k) => k.startsWith("/leaves"))).toBe(false);
  });
});
