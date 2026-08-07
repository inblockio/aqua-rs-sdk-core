# 04 — Signatures

A **signature revision** is a branch revision that cryptographically attests
to another revision in the same tree. This document specifies its wire form,
the signing pre-image, the four signature suites, signer identity encoding,
and the verification rules.

## 1. The signature revision

A signature revision carries exactly eight fields
([01](01-data-model.md) §1.2), all REQUIRED:

```json
{
  "previous_revision": "0x1620…",      // the target: the revision being signed
  "revision_type":     "0x1620…",      // the signature suite's template multihash
  "nonce":             "0x<32 hex>",
  "local_timestamp":   1783616148,
  "version":           "https://aqua-protocol.org/docs/v4/schema",
  "method":            "scalar",
  "signer":            "did:key:z6Mk…",
  "signature": {
    "signature_type":              "ed25519",
    "signature":                   "0x<hex>",
    "signature_public_identifier": "0x<hex>"
  }
}
```

- `previous_revision` is the **target**. A signature revision can never be
  genesis. The target MUST be present in the same tree, and the signature's
  `local_timestamp` MUST be greater than or equal to the target's
  ([01](01-data-model.md) §3.1).
- `revision_type` MUST be the full SHA3-256 multihash of the signature suite's
  template ([03](03-templates.md) §8). Producers MUST set it to the template
  matching `signature_type`.
- `method` SHOULD be `"scalar"`. A signature revision has no `leaves` field,
  and its fields are identity data with no meaningful per-field disclosure;
  `"tree"` gains nothing and SHOULD NOT be used.
- A signature revision is always a branch: it forks off its target rather
  than extending the chain. Nothing prevents a signature from targeting
  another signature revision (a counter-signature); the semantics of doing so
  are application-defined.

## 2. The signature value object

The `signature` object has a uniform shape; unknown members MUST be rejected:

| Member | Presence | Content |
|---|---|---|
| `signature_type` | REQUIRED | One of `"ed25519"`, `"ethereum:eip-191"`, `"ecdsa:p256"`, `"webauthn:p256"`. Any other value MUST be rejected. |
| `signature` | REQUIRED | `0x` + hex of the signature bytes. Exact length per suite (§5). |
| `signature_public_identifier` | REQUIRED | `0x` + hex of the verification key material per suite (§5). |
| `authenticator_data` | REQUIRED for `webauthn:p256`, absent otherwise | `0x` + hex of the WebAuthn authenticator data, at least 37 bytes. |
| `client_data_json` | REQUIRED for `webauthn:p256`, absent otherwise | `0x` + hex of the UTF-8 client data JSON, non-empty. |

Byte lengths per suite:

| Suite | `signature` | `signature_public_identifier` |
|---|---|---|
| `ed25519` | 64 bytes (`R‖S`) | 32-byte raw Ed25519 public key |
| `ethereum:eip-191` | 65 bytes (`r‖s‖v`) | 20-byte Ethereum address, EIP-55 mixed-case checksummed |
| `ecdsa:p256` | 64 bytes (`r‖s`, big-endian fixed width) | 33-byte compressed SEC1 point |
| `webauthn:p256` | 64 bytes (`r‖s`) | 33-byte compressed SEC1 point |

All hex is emitted lowercase with a `0x` prefix, with one exception:
producers MUST emit the EIP-191 `signature_public_identifier` as the EIP-55
mixed-case checksummed rendering of the address. Verifiers recover the 20
address bytes case-insensitively and canonicalize to the EIP-55 rendering
before hashing, so the revision hash commits to the checksummed form
regardless of the case supplied on the wire; the checksum itself is not
validated.

For the three suites other than `webauthn:p256`, the `authenticator_data`
and `client_data_json` members MUST NOT be emitted; a verifier ignores them
if present (they are not part of the revision's canonical form).

The revision hash of a signature revision covers the complete `signature`
object ([02](02-hashing-and-canonicalization.md) §4.3): the signature bytes
are tamper-evident like any other content.

## 3. The signing pre-image

Every suite signs (or, for WebAuthn, challenges over) the same message `M`:
a **flat JSON object with exactly nine members**, keys sorted lexicographically
(byte-wise), serialized compactly (no whitespace), UTF-8 encoded:

```json
{"hash_codec":22,
 "local_timestamp":1783616148,
 "method":"scalar",
 "nonce":"0x43b3b02ccc27e2d194d88e61ce008f2e",
 "previous_revision":"0x1620ce6f69b28e6dd3a1b02f107bc08a2316901dbd3c7d41d619bd7bb0bd49b7ce0b",
 "revision_type":"0x1620baf1d5d47eef50dcde3931956879bb30c5580064a92ce43ed4c6bd8b878b659a",
 "signature_type":"ed25519",
 "signer":"did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7",
 "version":"https://aqua-protocol.org/docs/v4/schema"}
```

(The nine keys are listed above in their sorted order. Line breaks are for
readability only; the real message has none.)

Member semantics:

- `hash_codec` — a JSON **number**: the decimal multicodec of the revision's
  hash algorithm, `22` (SHA3-256) or `30` (BLAKE3-256). It binds the
  signature to the algorithm; at verification it MUST be recovered from the
  signature revision's own addressing multihash, so a signature cannot be
  re-verified under a substituted algorithm. It is a pre-image-only member,
  never a wire field.
- `signature_type` — the suite string; hoisted into the pre-image because the
  `signature` object does not yet exist when the message is built.
- `previous_revision`, `revision_type`, `nonce`, `local_timestamp`, `method`,
  `signer`, `version` — copied verbatim from the revision.

What the pre-image implies:

- **A signature attests to a target hash**, not to the target's content
  directly: the target's fields never enter `M`. Content integrity flows
  through the target's own hash.
- **A signature covers no other signatures.** Two signatures on the same
  target are independent siblings with no ordering. Distinctness comes from
  each signature revision's fresh `nonce` and timestamp inside `M`.
- **Replay is impossible across targets and revisions**: the target hash and
  the fresh nonce are both signed.
- The pre-image binds `signature_type` and `revision_type` as *declared*.
  Producers MUST keep them consistent (§1); verifiers select the suite from
  `signature_type`.

## 4. Signer identity

`signer` is a DID. Four forms are recognized:

| DID form | Key material | Suite |
|---|---|---|
| `did:key:z6Mk…` | Ed25519 public key (multicodec prefix bytes `0xed 0x01`, 32-byte raw key, multibase base58btc) | `ed25519` |
| `did:key:zDn…` | P-256 public key (multicodec prefix bytes `0x80 0x24`, 33-byte compressed SEC1, multibase base58btc) | `ecdsa:p256`, `webauthn:p256` |
| `did:pkh:eip155:<chain_id>:0x<40 hex>` | 20-byte Ethereum address (CAIP-10) | `ethereum:eip-191` |
| `did:pkh:ed25519:0x<64 hex>` | 32-byte Ed25519 public key (alternate form of the same identity as `did:key:z6Mk…`) | `ed25519` |

A `did:key` MUST be encoded with multibase base58btc (`z` prefix); the
multicodec MUST be one of the two registered and the key length MUST match
the codec — anything else MUST be rejected. Identity binding (§4.1) compares
decoded key bytes, so alternative renderings of the same key denote the same
identity; producers MUST NOT emit alternative multibase encodings.

For `did:pkh:eip155`, identity binding uses only the address (the final
colon-separated segment, compared as raw bytes — EIP-55 case does not affect
binding). The chain id is carried but not verified: the same address on two
chains is the same protocol identity.

**Fail-closed rule:** a verifier that cannot resolve the `signer` DID to key
material — an unrecognized method, malformed encoding, or empty string — MUST
reject the signature. Unknown DID methods are never a pass.

### 4.1 Signer binding

After the cryptographic check (§5), the verifier MUST confirm that the key
material resolved from `signer` **byte-equals** the key material in
`signature_public_identifier` (for EIP-191: the address recovered from the
signature). A cryptographically valid signature whose declared signer is a
different key MUST be rejected.

Binding compares key bytes, not DID strings: `did:key:z6Mk…` and
`did:pkh:ed25519:0x…` carrying the same 32 key bytes are the same identity.
Cross-suite mismatches (for example an Ed25519 signature with an `eip155`
signer) fail the binding by construction.

## 5. The four suites

Let `M` be the pre-image bytes of §3.

### 5.1 `ed25519`

- **Sign:** Ed25519 (RFC 8032, PureEdDSA) over `M` directly. No pre-hashing.
- **Wire:** 64-byte `R‖S`; identifier = 32-byte raw public key.
- **Verify:** strict RFC 8032 verification (small-order and mixed-order
  public keys and signatures MUST be rejected) of `M` under the identifier
  key.

### 5.2 `ethereum:eip-191`

- **Sign:**
  1. `P = "\x19Ethereum Signed Message:\n" || decimal(len(M)) || M`, where
     `len(M)` is the **byte** length of `M`;
  2. `h = Keccak-256(P)` (Keccak-256, not SHA3-256);
  3. recoverable ECDSA over secp256k1 on `h`;
  4. wire signature = `r ‖ s ‖ v`, 65 bytes, with `v ∈ {27, 28}`.
- **Wire:** identifier = the 20-byte address
  `Keccak-256(uncompressed_pubkey[1..65])[12..32]`, EIP-55 checksummed.
- **Verify:** normalize `v` by subtracting 27 when `v ≥ 27`; the result MUST
  be a valid secp256k1 recovery identifier. Recover the public key from `h`,
  derive the address, and require exact byte equality with the identifier.
  `M` MUST be valid UTF-8 (it is by construction).

### 5.3 `ecdsa:p256`

- **Sign:** ECDSA over NIST P-256 with SHA-256 as the message digest of `M`;
  deterministic nonces (RFC 6979) RECOMMENDED.
- **Wire:** 64-byte fixed-width big-endian `r ‖ s`; identifier = 33-byte
  compressed SEC1 public key.
- **Verify:** standard ECDSA verification of `M` under the identifier key.
  Low-`s` normalization is not required by this profile; signature
  malleability cannot alter verification outcomes because the signature bytes
  are committed by the revision hash.

### 5.4 `webauthn:p256`

- **Sign (assertion):**
  1. `challenge = SHA-256(M)` (32 bytes);
  2. a WebAuthn authenticator produces `authenticator_data` and
     `client_data_json` with `clientDataJSON.challenge` =
     base64url-without-padding of the challenge;
  3. the authenticator's signature is ECDSA P-256 with SHA-256 over
     `authenticator_data || SHA-256(client_data_json)`.
- **Wire:** the 64-byte `r ‖ s` signature, the 33-byte compressed SEC1 key,
  plus `authenticator_data` and `client_data_json` as hex (§2).
- **Verify**, in order, each with a distinct failure:
  1. `authenticator_data` is at least 37 bytes;
  2. the User Present flag (bit 0 of byte 32) is set;
  3. `client_data_json` parses as JSON;
  4. its `type` member equals `"webauthn.get"`;
  5. its `challenge` member decodes (base64url, no padding) to exactly
     `SHA-256(M)`;
  6. ECDSA P-256/SHA-256 verification of
     `authenticator_data || SHA-256(client_data_json)` under the identifier
     key.

**Scope note.** This profile authenticates the *key and challenge*, not the
WebAuthn ceremony context: `rpIdHash`, `origin`, the User Verified flag, and
`signCount` are not verified — the wire format carries no expected relying
party to check against. Applications requiring RP binding must enforce it at
the application layer.

## 6. Verification procedure

Given a signature revision addressed by link `L` in a tree:

1. **Integrity.** `L` MUST be a well-formed Aqua multihash, and the recomputed
   revision hash MUST equal `L` ([07](07-verification.md) §3). This makes
   every field of the signature revision — including the signature bytes —
   tamper-evident before any cryptography runs.
2. **Pre-image reconstruction.** Rebuild `M` from the revision's fields, with
   `hash_codec` taken from `L`'s multicodec and `signature_type` taken from
   the `signature` object.
3. **Cryptographic check** per §5, selected by `signature_type`.
4. **Signer binding** per §4.1.

All four steps MUST pass. Signature verification failures are integrity
failures: they are never policy-relaxable
([07](07-verification.md) §7).

Signature revisions are not schema-validated against their suite templates;
the strict wire shape of §1–§2 is the enforced constraint, and the suite
templates exist as the identity anchors for `revision_type` and revision-kind
classification ([01](01-data-model.md) §1.3).

## 7. Signatures and disclosure

Because a signature attests to its target's *hash*, selective disclosure of
the target ([06](06-selective-disclosure.md)) does not invalidate the
signature: a verifier that confirms the redacted target still matches its
original hash retains the full force of the attestation. Disclosure policies
MUST keep signature revisions fully disclosed if the attestation is to remain
checkable; hiding or redacting a signature revision removes the evidence
rather than protecting it.
