# 02 — Hashing and canonicalization

This document specifies how a revision's hash is computed: the algorithm
registry, the Aqua multihash profile, Aqua Pointer Form canonicalization, and
the two hashing methods (`scalar` and `tree`). The Merkle construction defined
here is shared by tree-method hashing, selective disclosure
([06](06-selective-disclosure.md)), and batch inclusion proofs
([07](07-verification.md) §4.1).

## 1. Algorithm registry

Exactly two hash algorithms are registered:

| Algorithm | Multicodec | Digest length | Codec (decimal) |
|---|---|---|---|
| SHA3-256 (FIPS 202) | `0x16` | 32 bytes | 22 |
| BLAKE3-256 (default unkeyed 32-byte mode) | `0x1e` | 32 bytes | 30 |

SHA3-256 is the default. There is no fallback: a multihash carrying any other
codec MUST be rejected. Template identity is always computed with SHA3-256
regardless of the containing tree's algorithm ([03](03-templates.md) §2).

## 2. The Aqua multihash profile

A revision hash on the wire is a **multihash**:

```
multihash = varint(codec) || varint(length) || digest
```

with multiformats unsigned varints (LEB128). For both registered algorithms
each varint is a single byte, so every revision hash is 34 bytes:
`0x16 0x20 <32-byte digest>` or `0x1e 0x20 <32-byte digest>`.

**String form:** `0x` + lowercase hex of the 34 bytes → 70 characters.
Uppercase hex MUST be rejected on parse.

**Decoding rules.** A decoder MUST enforce, in this order of severity:

1. **Minimal varints** — re-encode each decoded varint and require byte
   equality; a non-minimal encoding MUST be rejected.
2. **Varint range** — each decoded varint value MUST be below 128 (both
   registered codecs and the length 32 are single-byte values); a larger
   value MUST be rejected as out of range.
3. **Registered codec** — an unregistered codec MUST be rejected (before any
   length check).
4. **Registry length** — the declared digest length MUST equal the registered
   length for the codec (32).
5. **Exact framing** — the declared length MUST equal the number of remaining
   bytes exactly: fewer is a truncation error, more is a trailing-bytes error.

**Test vectors** (informative):

- SHA3-256 of the ASCII string `aqua` =
  `0e45033cba286c7dc85255b5d9dfe4ebde65bc6d477a6250d1784f5c0d5c1aa4`;
  multihash `0x16200e45033cba286c7dc85255b5d9dfe4ebde65bc6d477a6250d1784f5c0d5c1aa4`.
- BLAKE3-256 multihash of `aqua` =
  `0x1e204a037f9e6c19d69462ead0049b51237a5da0c861e9edd7c0610e626ac093ddd5`.

### 2.1 Full multihash vs bare digest

Two hash renderings coexist in the protocol and MUST NOT be confused:

| Rendering | Length (hex chars after `0x`) | Used for |
|---|---|---|
| **Full multihash** | 68 | revision map keys, `previous_revision`, `revision_type`, `derives_from`, `ancestry` entries, anchor `structural_links`, compositional link `hash` values, template identity in the template-tree key |
| **Bare 32-byte digest** | 64 | entries of the `leaves` array, Merkle proof siblings, the zero sentinel ([01](01-data-model.md) §1.4), and many application-level payload hash fields (note that some payload fields carry full multihashes instead — for example audit turn ids and leaf-hash lists; each template's schema decides) |

A verifier encountering a bare digest where a full multihash is required (or
vice versa) MUST reject it.

### 2.2 Algorithm recovery

A revision does not carry an algorithm field. The algorithm used to verify a
revision MUST be recovered from the multicodec of the multihash that addresses
it (its key in the tree's revision map). Consequently the same revision content
addressed under a different codec is a different revision hash, and a revision
stored under a malformed multihash key is unverifiable and MUST be rejected.

## 3. Aqua Pointer Form (APF)

Canonicalization proceeds in three steps shared by both methods:

**Step 1 — Serialize.** Serialize the revision to JSON. Absent OPTIONAL fields
are omitted entirely (never `null`); an empty `compositional_links` array is
omitted. Non-ASCII characters are emitted as raw UTF-8, never `\uXXXX`
escapes.

**Step 2 — Flatten.** Flatten the JSON document into a single-level map from
RFC 6901 JSON Pointers to values:

- the root object contributes the key `""` with value `{}`;
- every nested object contributes its own pointer with value `{}` (a container
  marker);
- every array contributes its own pointer with value `[]`, and each element
  appears at `/<…>/<decimal index>`;
- every scalar (null, boolean, number, string) appears at its pointer with the
  scalar itself as value;
- member names are escaped per RFC 6901: `~` → `~0` first, then `/` → `~1`.

Container markers are full participants in hashing, exactly like scalar
entries.

**Step 3 — Sort.** Sort the map by key, byte-wise over the UTF-8 encoding of
the pointer strings. Note the consequence for arrays of ten or more elements:
`/a/10` sorts before `/a/2`. This is the canonical order.

## 4. The two hashing methods

### 4.1 `method: "scalar"`

```
bare_digest   = HASH( compact_json( sorted_pointer_map ) )
revision_hash = multihash( bare_digest )
```

The serialized form is the flat pointer map itself: a single JSON object
whose keys are the pointer strings and whose values are the flattened values
(container markers as literal empty objects/arrays), in sorted key order,
serialized with no whitespace and standard JSON string escaping. `HASH` is
the revision's algorithm (§2.2). The pointer map is hashed as one opaque
blob; a scalar revision therefore supports no per-field disclosure. See the
worked example in §7.

A scalar revision MUST NOT carry a `leaves` field
([01](01-data-model.md) §1.2). This is a producer obligation: verifiers do
not recompute per-field leaves for scalar revisions, and a `leaves` member
present on one would be hashed as ordinary content.

### 4.2 `method: "tree"`

The sorted pointer map is committed per entry and reduced to a Merkle root:

```
prk = HKDF-SHA3-256-Extract( salt = "AquaSD" (6 ASCII bytes),
                             ikm  = nonce_bytes (16) )          # 32 bytes

for each (pointer, value) in canonical order,
        excluding every key that begins with the string "/leaves":
    salt         = HKDF-SHA3-256-Expand( prk, info = utf8(pointer), length = 32 )
    value_str    = compact JSON rendering of the value
    label        = HASH( 0x03 || utf8(pointer) )
    value_commit = HASH( 0x02 || salt || utf8(value_str) )
    leaf         = HASH( 0x00 || label || value_commit )

bare_digest   = merkle_root( leaves )      # §5; the leaf list MUST be non-empty
revision_hash = multihash( bare_digest )
```

Normative details:

- **The KDF is always HKDF with SHA3-256**, even when the revision's hash
  algorithm is BLAKE3-256. Salt derivation is deliberately decoupled from the
  revision algorithm.
- `HASH` in the leaf construction is the revision's algorithm.
- `value_str` is the compact JSON rendering of the flattened value: strings
  keep their quotes and JSON escaping (`"foo"`), numbers are bare, booleans
  are `true`/`false`, null is `null`, container markers are the literal
  two-character strings `{}` and `[]`.
- The domain tags are single bytes: `0x00` leaf, `0x01` internal node,
  `0x02` value commitment, `0x03` label commitment. They ensure a leaf can
  never collide with an internal node and a value commitment can never
  collide with a label commitment.
- The `/leaves` exclusion makes the hash independent of the published
  `leaves` array, so the hash can be recomputed identically before and after
  the array is populated. The filter is a plain prefix match on the pointer
  string; no defined field set contains any other key beginning with
  `/leaves`, so the prefix match and an exact `/leaves`-or-descendant match
  coincide — implementations MUST use the prefix match to stay
  byte-compatible.
- An empty leaf set is a protocol error; every revision flattens to at least
  the root pointer `""`, so this arises only from a defective input.

**Producer ordering rule:** the revision hash MUST be computed while the
`leaves` field is absent; the `leaves` array (the bare leaf digests, in
canonical order, hex-encoded with `0x`) is populated afterwards. A verifier
independently recomputes the leaves and compares them against the published
array ([07](07-verification.md) §3).

### 4.3 What the revision hash covers

| Item | Covered? |
|---|---|
| all serialized revision fields, including `nonce`, `local_timestamp`, `version`, `method`, `revision_type`, `previous_revision` | yes |
| a signature revision's own `signature` object (type, bytes, public identifier, WebAuthn extras) | yes — the hash commits to the signature itself |
| the `leaves` array of a tree-method revision | no (excluded by construction) |
| the tree's `file_index` | no (tree-level metadata, never hashed) |
| the revision-map key | no — it *is* the hash |

## 5. The Merkle construction

One Merkle construction serves the whole protocol.

**Nodes:**

```
leaf     = HASH( 0x00 || data )                # data = label || value_commit for SD leaves,
                                               #        or a shielded digest for batch leaves
internal = HASH( 0x01 || left || right )       # order-sensitive: internal(a,b) ≠ internal(b,a)
```

**Root:** reduce the leaf list bottom-up, pairing left to right. A trailing
unpaired node is **promoted unchanged** to the next level — never duplicated.
A single-leaf list's root is that leaf itself, with no additional hashing.
The root of an empty list is undefined; producers MUST NOT construct one and
verifiers MUST reject inputs that would require one.

**Inclusion proofs** follow RFC 9162 §2.1.3: the proof path is generated by
recursive splitting at `k` = the largest power of two strictly less than `n`,
and verified with the iterative algorithm of RFC 9162 §2.1.3.2. A single-leaf
tree has an empty proof. Leaves, internal nodes, and proof siblings are all
**bare** 32-byte digests; revision hashes and batch roots on the wire are
multihash-wrapped ([07](07-verification.md) §4.1).

Inclusion proofs are used by batch timestamp verification
([07](07-verification.md) §4.1). Selective disclosure does not transmit
proofs — it transmits the full leaf vector and recomputes the root
([06](06-selective-disclosure.md) §3).

## 6. The signing pre-image is a different canonicalization

The message signed by a signature revision is **not** the pointer-flattened
form of §3. It is a flat nine-key JSON object, key-sorted and compact,
specified in [04 — Signatures](04-signatures.md) §3. The two canonical forms
serve different purposes and MUST NOT be conflated:

- **APF (this document)** answers "what bytes does a revision hash commit
  to" — it covers the whole revision.
- **The signing pre-image** answers "what bytes does a signer attest to" —
  it covers the signature revision's identity fields and its target hash,
  and it exists before the signature bytes do.

## 7. Worked example

A genesis anchor revision ([05](05-anchor-revisions-and-links.md) §4) with
`method: "scalar"`:

```json
{
  "revision_type": "0x1620479a304927c47f4308d027a858060ce287a9bdb45f2203f8130574a73511e899",
  "nonce": "0x1a5f49342762a8282bc53f736b96d580",
  "local_timestamp": 1783616147,
  "version": "https://aqua-protocol.org/docs/v4/schema",
  "method": "scalar",
  "structural_links": [
    "0x162000f3abb3d74fc9dfc2b961cea906b3211716188f4de6f588180fdfcbbfa3fe53"
  ]
}
```

Flattening (§3 step 2) and sorting (§3 step 3) produce this pointer map —
note the root marker `""`, the array marker at `/structural_links`, and the
array element at `/structural_links/0`. Serialized compactly (§4.1), the
exact hash pre-image is the following single line:

```
{"":{},"/local_timestamp":1783616147,"/method":"scalar","/nonce":"0x1a5f49342762a8282bc53f736b96d580","/revision_type":"0x1620479a304927c47f4308d027a858060ce287a9bdb45f2203f8130574a73511e899","/structural_links":[],"/structural_links/0":"0x162000f3abb3d74fc9dfc2b961cea906b3211716188f4de6f588180fdfcbbfa3fe53","/version":"https://aqua-protocol.org/docs/v4/schema"}
```

SHA3-256 of those bytes, multihash-wrapped (§2), yields the revision hash:

```
0x1620ce6f69b28e6dd3a1b02f107bc08a2316901dbd3c7d41d619bd7bb0bd49b7ce0b
```

which is the key this revision is stored under, the `previous_revision` of
its children, and the target hash a signature over it would attest to
(the same tree appears in the pre-image example of
[04](04-signatures.md) §3).
