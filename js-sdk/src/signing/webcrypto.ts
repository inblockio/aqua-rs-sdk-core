/**
 * WebCrypto-backed signers. Ed25519 needs a runtime with the Ed25519
 * WebCrypto algorithm (Node 20+, current Chrome/Firefox/Safari); P-256
 * ECDSA is available everywhere WebCrypto is.
 */

import { bytesToHex, toBytes } from "../bytes.js";
import { didFromEd25519PublicKey, didFromP256PublicKey } from "../did.js";
import type { Bytes, SignatureValue } from "../types.js";
import type { AquaSigner } from "./signer.js";

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) throw new Error("WebCrypto (globalThis.crypto.subtle) is not available");
  return c.subtle;
}

/**
 * Ed25519 signer over a WebCrypto key pair. The private key never leaves
 * WebCrypto; the DID is derived from the exported raw public key by the
 * wasm module.
 */
export class Ed25519WebCryptoSigner implements AquaSigner {
  readonly signatureType = "ed25519" as const;

  private constructor(
    private readonly privateKey: CryptoKey,
    readonly publicKey: Uint8Array,
    readonly signer: string,
  ) {}

  /** Generate a fresh (non-extractable private) key pair. */
  static async generate(): Promise<Ed25519WebCryptoSigner> {
    const pair = (await subtle().generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
    return Ed25519WebCryptoSigner.fromKeyPair(pair);
  }

  /** Wrap an existing WebCrypto Ed25519 key pair. */
  static async fromKeyPair(pair: CryptoKeyPair): Promise<Ed25519WebCryptoSigner> {
    const raw = new Uint8Array(await subtle().exportKey("raw", pair.publicKey));
    if (raw.length !== 32) throw new Error(`expected a 32-byte Ed25519 public key, got ${raw.length}`);
    return new Ed25519WebCryptoSigner(pair.privateKey, raw, didFromEd25519PublicKey(raw));
  }

  /** Import a 32-byte raw Ed25519 secret (PKCS#8-wrapped for WebCrypto). */
  static async fromSecretKey(secret: Bytes): Promise<Ed25519WebCryptoSigner> {
    const seed = typeof secret === "string" ? hexOrUtf8(secret) : secret;
    if (seed.length !== 32) throw new Error(`expected a 32-byte Ed25519 secret, got ${seed.length}`);
    // PKCS#8 PrivateKeyInfo for id-Ed25519 (RFC 8410) with a 32-byte CurvePrivateKey.
    const prefix = new Uint8Array([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    const pkcs8 = new Uint8Array(prefix.length + 32);
    pkcs8.set(prefix);
    pkcs8.set(seed, prefix.length);
    const privateKey = await subtle().importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
    // Derive the public key by round-tripping through JWK (WebCrypto exposes `x` on the private JWK).
    const jwk = await subtle().exportKey("jwk", privateKey);
    if (!jwk.x) throw new Error("WebCrypto did not expose the Ed25519 public key");
    const publicKey = base64UrlToBytes(jwk.x);
    return new Ed25519WebCryptoSigner(privateKey, publicKey, didFromEd25519PublicKey(publicKey));
  }

  async sign(message: Bytes): Promise<SignatureValue> {
    const sig = new Uint8Array(await subtle().sign({ name: "Ed25519" }, this.privateKey, new Uint8Array(toBytes(message))));
    return {
      signature_type: "ed25519",
      signature: bytesToHex(sig),
      signature_public_identifier: bytesToHex(this.publicKey),
    };
  }
}

/**
 * ECDSA P-256 signer over a WebCrypto key pair (`ecdsa:p256`). WebCrypto
 * returns the raw `r || s` form the core expects; the public identifier is
 * the 33-byte compressed SEC1 point.
 */
export class P256WebCryptoSigner implements AquaSigner {
  readonly signatureType = "ecdsa:p256" as const;

  private constructor(
    private readonly privateKey: CryptoKey,
    readonly publicKey: Uint8Array,
    readonly signer: string,
  ) {}

  static async generate(): Promise<P256WebCryptoSigner> {
    const pair = (await subtle().generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    return P256WebCryptoSigner.fromKeyPair(pair);
  }

  static async fromKeyPair(pair: CryptoKeyPair): Promise<P256WebCryptoSigner> {
    const raw = new Uint8Array(await subtle().exportKey("raw", pair.publicKey));
    if (raw.length !== 65 || raw[0] !== 0x04) throw new Error("expected an uncompressed P-256 public key");
    const compressed = new Uint8Array(33);
    compressed[0] = (raw[64]! & 1) === 0 ? 0x02 : 0x03;
    compressed.set(raw.subarray(1, 33), 1);
    return new P256WebCryptoSigner(pair.privateKey, compressed, didFromP256PublicKey(compressed));
  }

  async sign(message: Bytes): Promise<SignatureValue> {
    const sig = new Uint8Array(
      await subtle().sign({ name: "ECDSA", hash: "SHA-256" }, this.privateKey, new Uint8Array(toBytes(message))),
    );
    return {
      signature_type: "ecdsa:p256",
      signature: bytesToHex(sig),
      signature_public_identifier: bytesToHex(this.publicKey),
    };
  }
}

function hexOrUtf8(s: string): Uint8Array {
  if (/^0x[0-9a-fA-F]{64}$/.test(s)) {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(s.slice(2 + i * 2, 4 + i * 2), 16);
    return out;
  }
  return toBytes(s);
}

function base64UrlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
