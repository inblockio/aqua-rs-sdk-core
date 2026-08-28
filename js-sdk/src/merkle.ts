/**
 * Hashing and Merkle helpers (free wasm functions). Every digest is computed
 * by the core crate; nothing here re-implements a hash in JavaScript.
 */

import { toBytes } from "./bytes.js";
import type { Bytes, DecodedMultihash, HashTypeParam } from "./types.js";
import { ensureReady, fromJson } from "./wasm.js";

/** Digest of `data` under `hashType`, as `0x` hex. */
export function hashBytes(data: Bytes, hashType: HashTypeParam = "sha3_256"): string {
  return ensureReady().hashBytes(toBytes(data), hashType);
}

/** RFC 6962 leaf hash `HASH(0x00 || data)` for batch Merkle trees. */
export function batchLeafHash(data: Bytes, hashType: HashTypeParam = "sha3_256"): string {
  return ensureReady().batchLeafHash(toBytes(data), hashType);
}

/**
 * RFC 9162 Merkle root of already leaf-hashed `0x` hex leaves (odd nodes
 * promoted, `HASH(0x01 || left || right)` internal nodes). Throws on an
 * empty array.
 */
export function merkleRoot(leaves: string[], hashType: HashTypeParam = "sha3_256"): string {
  return ensureReady().merkleRoot(JSON.stringify(leaves), hashType);
}

/** Aqua-profile multihash (`varint(code) || varint(len) || digest`) of a full-length `0x` digest. */
export function multihashEncode(digestHex: string, hashType: HashTypeParam = "sha3_256"): string {
  return ensureReady().multihashEncode(digestHex, hashType);
}

/** Decode a `0x` hex multihash into its algorithm and digest; throws on malformed input. */
export function multihashDecode(multihashHex: string): DecodedMultihash {
  return fromJson(ensureReady().multihashDecode(multihashHex));
}
