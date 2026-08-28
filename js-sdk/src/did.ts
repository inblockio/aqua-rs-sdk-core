/**
 * Key and DID helpers (free wasm functions). All require `init()`.
 */

import { toBytes } from "./bytes.js";
import type { Bytes, DecodedDidKey, Ed25519KeyPair } from "./types.js";
import { ensureReady, fromJson } from "./wasm.js";

/** Fresh Ed25519 keypair from the host CSPRNG; `secret` is the `did_key` credential. */
export function generateEd25519(): Ed25519KeyPair {
  return fromJson(ensureReady().generateEd25519());
}

/** `did:key:z6Mk...` for a 32-byte Ed25519 public key. */
export function didFromEd25519PublicKey(publicKey: Bytes): string {
  return ensureReady().didFromEd25519PublicKey(toBytes(publicKey));
}

/** `did:key:z6Mk...` for a 32-byte Ed25519 secret key. */
export function didFromEd25519SecretKey(secretKey: Bytes): string {
  return ensureReady().didFromEd25519SecretKey(toBytes(secretKey));
}

/** `did:key:zDn...` for a 33-byte compressed SEC1 P-256 public key. */
export function didFromP256PublicKey(publicKey: Bytes): string {
  return ensureReady().didFromP256PublicKey(toBytes(publicKey));
}

/** `did:key:zDn...` for a 32-byte P-256 secret scalar. */
export function didFromP256SecretKey(secretKey: Bytes): string {
  return ensureReady().didFromP256SecretKey(toBytes(secretKey));
}

/** Decode a `did:key` into its algorithm and `0x` public key. */
export function decodeDidKey(did: string): DecodedDidKey {
  return fromJson(ensureReady().decodeDidKey(did));
}
