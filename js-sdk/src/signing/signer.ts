/**
 * External signer contract for the two-step flow
 * `prepareSignature` → `sign` → `addExternalSignature`.
 *
 * The SDK hands the signer `prepared.message` (the canonical pre-signature
 * JSON). What each algorithm signs, per the wasm doc comments:
 *
 * - `ed25519`: the raw UTF-8 bytes of the message.
 * - `ecdsa:p256`: ECDSA-SHA256 over the raw bytes (`r || s`).
 * - `ethereum:eip-191`: `personal_sign` of the message string (the wallet
 *   adds the `\x19Ethereum Signed Message:\n<len>` prefix).
 * - `webauthn:p256`: an assertion whose challenge is SHA-256 of the raw bytes.
 *
 * The core verifier checks both the cryptographic signature and that
 * `signer` (a DID) binds to `signature_public_identifier`, so a signer must
 * report the DID of the key it actually signs with.
 */

import type { Bytes, SignatureType, SignatureValue } from "../types.js";

export interface AquaSigner {
  /** Wire `signature_type` of the values this signer produces. */
  readonly signatureType: SignatureType;
  /** The `signer` DID recorded on the revision (`did:key:...` or `did:pkh:eip155:...`). */
  readonly signer: string;
  /** Sign the prepared message and return the wire-form signature value. */
  sign(message: Bytes): Promise<SignatureValue>;
}
