/**
 * Byte and hex helpers shared by the wrapper and the signers. No hashing
 * lives here: every digest comes from the wasm module.
 */

import type { Bytes } from "./types.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** UTF-8 encode a string, or pass a `Uint8Array` through unchanged. */
export function toBytes(input: Bytes): Uint8Array {
  return typeof input === "string" ? encoder.encode(input) : input;
}

/** Decode UTF-8 bytes, or pass a string through unchanged. */
export function toText(input: Bytes): string {
  return typeof input === "string" ? input : decoder.decode(input);
}

/** `0x`-prefixed lowercase hex of `bytes`. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "0x";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Decode `0x`-prefixed (or bare) hex into bytes. Throws on odd length or non-hex input. */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`invalid hex string: ${hex}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** JSON byte-array form (`number[]`) used by `FileData` / `FileMetadata`. */
export function toByteArray(input: Bytes | number[]): number[] {
  return Array.isArray(input) ? input : Array.from(toBytes(input));
}

/** Concatenate byte arrays. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
