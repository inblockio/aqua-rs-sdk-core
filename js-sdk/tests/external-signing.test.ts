/**
 * External signing: keys held outside the module (WebCrypto, a simulated
 * EIP-1193 wallet) drive prepareSignature -> sign -> addExternalSignature,
 * and forged or mismatched signatures are refused before insertion.
 */

import { describe, expect, it } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  Ed25519WebCryptoSigner,
  MetaMaskSigner,
  P256WebCryptoSigner,
  bytesToHex,
  decodeDidKey,
  generateEd25519,
  hexToBytes,
  isSignatureRevision,
  isVerified,
  wrap,
} from "../src/index.js";
import type { Eip1193Provider, SignatureValue } from "../src/index.js";
import { HELLO, HELLO_NAME, helloFiles, revisionCount, sdk } from "./helpers.js";

describe("Ed25519 via WebCrypto", () => {
  it("signs, inserts, and verifies", async () => {
    const aq = await sdk();
    const signer = await Ed25519WebCryptoSigner.generate();
    expect(signer.signer).toMatch(/^did:key:z6Mk/);
    expect(decodeDidKey(signer.signer)).toEqual({ algorithm: "ed25519", public_key: bytesToHex(signer.publicKey) });

    const genesis = aq.createGenesisRevision(HELLO_NAME, HELLO);
    const result = await aq.signWith(signer, genesis);
    expect(revisionCount(result.aqua_tree)).toBe(revisionCount(genesis) + 1);
    expect(result.log_data.at(-1)?.log).toMatch(/External signature added/);
    const sig = Object.values(result.aqua_tree.revisions).find(isSignatureRevision)!;
    expect(sig.signer).toBe(signer.signer);
    expect(sig.signature.signature_public_identifier).toBe(bytesToHex(signer.publicKey));

    expect(isVerified(aq.verifyAquaTree(wrap(result.aqua_tree), helloFiles()))).toBe(true);
  });

  it("imports a raw secret and matches the module's DID derivation", async () => {
    const aq = await sdk();
    const key = generateEd25519();
    const signer = await Ed25519WebCryptoSigner.fromSecretKey(key.secret);
    expect(signer.signer).toBe(key.did);
    const result = await aq.signWith(signer, aq.createGenesisRevision(HELLO_NAME, HELLO));
    expect(isVerified(aq.verifyAquaTree(result.aqua_tree, helloFiles()))).toBe(true);
  });

  it("rejects a tampered signature before insertion", async () => {
    const aq = await sdk();
    const signer = await Ed25519WebCryptoSigner.generate();
    const genesis = aq.createGenesisRevision(HELLO_NAME, HELLO);
    const prepared = aq.prepareSignature(genesis, signer.signer, "ed25519");
    expect(prepared.signature_type).toBe("ed25519");
    expect(prepared.message_hex).toBe(bytesToHex(new TextEncoder().encode(prepared.message)));
    expect(JSON.parse(prepared.message)).toMatchObject({
      hash_codec: 22,
      previous_revision: prepared.target_revision,
      signature_type: "ed25519",
      signer: signer.signer,
    });

    const good = await signer.sign(prepared.message);
    const sig = hexToBytes(good.signature);
    sig[0]! ^= 0xff;
    const bad: SignatureValue = { ...good, signature: bytesToHex(sig) };
    expect(() => aq.addExternalSignature(genesis, prepared, bad)).toThrow(/rejected by verifier/);
    // The good signature over the same prepared message still works.
    expect(revisionCount(aq.addExternalSignature(genesis, prepared, good).aqua_tree)).toBe(revisionCount(genesis) + 1);
  });

  it("rejects a signature whose key does not match the declared signer DID", async () => {
    const aq = await sdk();
    const real = await Ed25519WebCryptoSigner.generate();
    const impostor = await Ed25519WebCryptoSigner.generate();
    const genesis = aq.createGenesisRevision(HELLO_NAME, HELLO);
    const prepared = aq.prepareSignature(genesis, real.signer, "ed25519");
    const value = await impostor.sign(prepared.message);
    expect(() => aq.addExternalSignature(genesis, prepared, value)).toThrow(/rejected by verifier/);
  });

  it("rejects a signature over a different message", async () => {
    const aq = await sdk();
    const signer = await Ed25519WebCryptoSigner.generate();
    const genesis = aq.createGenesisRevision(HELLO_NAME, HELLO);
    const prepared = aq.prepareSignature(genesis, signer.signer, "ed25519");
    const value = await signer.sign(prepared.message + " ");
    expect(() => aq.addExternalSignature(genesis, prepared, value)).toThrow(/rejected by verifier/);
  });

  it("refuses a signature_type mismatch between prepared and value", async () => {
    const aq = await sdk();
    const signer = await Ed25519WebCryptoSigner.generate();
    const genesis = aq.createGenesisRevision(HELLO_NAME, HELLO);
    const prepared = aq.prepareSignature(genesis, signer.signer, "ecdsa:p256");
    const value = await signer.sign(prepared.message);
    expect(() => aq.addExternalSignature(genesis, prepared, value)).toThrow(/signature_type mismatch/);
  });
});

describe("ECDSA P-256 via WebCrypto", () => {
  it("signs, inserts, and verifies", async () => {
    const aq = await sdk();
    const signer = await P256WebCryptoSigner.generate();
    expect(signer.signer).toMatch(/^did:key:zDn/);
    expect(signer.publicKey).toHaveLength(33);
    const result = await aq.signWith(signer, aq.createGenesisRevision(HELLO_NAME, HELLO));
    const sig = Object.values(result.aqua_tree.revisions).find(isSignatureRevision)!;
    expect(sig.signature.signature_type).toBe("ecdsa:p256");
    expect(isVerified(aq.verifyAquaTree(result.aqua_tree, helloFiles()))).toBe(true);
  });
});

/**
 * A minimal EIP-1193 wallet: one secp256k1 key, `personal_sign` implemented
 * exactly as MetaMask does (EIP-191 prefix, keccak-256, r||s||v with
 * v = 27 + recovery id).
 */
function fakeWallet(chainId = 1): { provider: Eip1193Provider; address: string } {
  const { secretKey, publicKey } = secp256k1.keygen();
  const uncompressed = secp256k1.Point.fromBytes(publicKey).toBytes(false);
  const address = bytesToHex(keccak_256(uncompressed.subarray(1)).subarray(12));
  const provider: Eip1193Provider = {
    async request({ method, params }) {
      switch (method) {
        case "eth_requestAccounts":
        case "eth_accounts":
          return [address];
        case "eth_chainId":
          return "0x" + chainId.toString(16);
        case "personal_sign": {
          const [hexMessage, from] = params as [string, string];
          if (from.toLowerCase() !== address.toLowerCase()) throw new Error("unknown account");
          const message = hexToBytes(hexMessage);
          const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${message.length}`);
          const digest = keccak_256(new Uint8Array([...prefix, ...message]));
          const rec = secp256k1.sign(digest, secretKey, { prehash: false, format: "recovered" });
          // noble's recovered layout is [recovery, r, s]; Ethereum wants r || s || (27 + recovery).
          const eth = new Uint8Array(65);
          eth.set(rec.subarray(1), 0);
          eth[64] = rec[0]! + 27;
          return bytesToHex(eth);
        }
        default:
          throw new Error(`unsupported method ${method}`);
      }
    },
  };
  return { provider, address };
}

describe("EIP-191 via an EIP-1193 provider (MetaMaskSigner)", () => {
  it("signs with personal_sign and verifies as did:pkh:eip155", async () => {
    const aq = await sdk();
    const { provider, address } = fakeWallet(1);
    const signer = await MetaMaskSigner.connect(provider);
    expect(signer.signer).toBe(`did:pkh:eip155:1:${address}`);

    const result = await aq.signWith(signer, aq.createGenesisRevision(HELLO_NAME, HELLO));
    const sig = Object.values(result.aqua_tree.revisions).find(isSignatureRevision)!;
    expect(sig.signature.signature_type).toBe("ethereum:eip-191");
    expect(sig.signer).toBe(signer.signer);
    // The core re-serializes the identifier as an EIP-55 checksum of the same bytes.
    expect(sig.signature.signature_public_identifier.toLowerCase()).toBe(address);
    expect(isVerified(aq.verifyAquaTree(result.aqua_tree, helloFiles()))).toBe(true);
  });

  it("rejects a wallet signature from a different account than the declared DID", async () => {
    const aq = await sdk();
    const a = fakeWallet(1);
    const b = fakeWallet(1);
    // Declare A's address but have B sign: a DID/key mismatch.
    const signer = new MetaMaskSigner(
      { request: (args) => b.provider.request(args.method === "personal_sign" ? { ...args, params: [args.params![0], b.address] } : args) },
      a.address,
      1,
    );
    const genesis = aq.createGenesisRevision(HELLO_NAME, HELLO);
    await expect(aq.signWith(signer, genesis)).rejects.toThrow(/rejected by verifier/);
  });

  it("isAvailable is false without an injected provider", () => {
    expect(MetaMaskSigner.isAvailable()).toBe(false);
  });
});
