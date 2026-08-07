# 01 — Data model

This document specifies the revision — the universal protocol object — and the
tree that contains revisions. Hashing is specified in
[02 — Hashing and canonicalization](02-hashing-and-canonicalization.md);
kind-specific semantics are specified in documents 03–06.

## 1. Revisions

A **revision** is a JSON object. Exactly four revision kinds exist on the wire:

- **Object** — typed application data ([03](03-templates.md) §6)
- **Template** — a type declaration ([03](03-templates.md))
- **Signature** — a cryptographic attestation over another revision
  ([04](04-signatures.md))
- **Anchor** — a structural fork point carrying links to other revisions
  ([05](05-anchor-revisions-and-links.md))

### 1.1 Common fields

Every revision carries these fields:

| Field | Wire type | Presence | Meaning |
|---|---|---|---|
| `previous_revision` | string — revision link (§1.4) | OPTIONAL for object, template, and anchor revisions (omitted entirely when absent, never `null`); REQUIRED for signature revisions | The parent revision this revision chains from. |
| `revision_type` | string — revision link | REQUIRED | The naming value: the full multihash of the template that types this revision (§1.3). |
| `nonce` | string — `0x` + exactly 32 lowercase hex characters (16 bytes) | REQUIRED | Per-revision random value. It makes the revision hash unpredictable and, for tree-method revisions, seeds the selective-disclosure salts ([02](02-hashing-and-canonicalization.md) §4). |
| `local_timestamp` | JSON number — unsigned integer, Unix seconds | REQUIRED | Producer-local creation time. Not trusted evidence of time (§3.4). |
| `version` | string | REQUIRED | MUST be exactly `https://aqua-protocol.org/docs/v4/schema`. A revision carrying any other value MUST be rejected at parse time. |
| `method` | string | REQUIRED | MUST be `"scalar"` or `"tree"`. Selects the hashing method ([02](02-hashing-and-canonicalization.md)). |

Every field of a revision contributes to the revision hash, with one
exception: a tree-method revision's `leaves` array is derived data excluded
from hashing ([02](02-hashing-and-canonicalization.md) §4.2). The
serialization order of fields is irrelevant to
the hash (canonicalization sorts), but the field *sets* below are strict:
**a revision carrying any field outside its kind's declared set MUST be
rejected.**

A revision does **not** carry a hash-algorithm field. The algorithm is carried
by the multihash that addresses the revision
([02](02-hashing-and-canonicalization.md) §2).

### 1.2 Per-kind field sets

**Object revision** — common fields plus:

| Field | Wire type | Presence | Meaning |
|---|---|---|---|
| `payloads` | any JSON value | REQUIRED | The typed content, validated against the template named by `revision_type`. |
| `leaves` | array of strings (`0x` + hex, bare digests) | OPTIONAL | Published per-field leaf hashes. MUST be present when `method` is `"tree"`. Producers MUST NOT emit it when `method` is `"scalar"` (verifiers recompute leaves only for tree-method revisions, [07](07-verification.md) §3). Omitted entirely when absent, never `null`. |

**Template revision** — common fields plus:

| Field | Wire type | Presence | Meaning |
|---|---|---|---|
| `schema` | JSON object | REQUIRED | A JSON Schema (draft 2020-12) constraining the `payloads` of object revisions of this type. |
| `verification` | JSON object | OPTIONAL | A compute declaration ([03](03-templates.md) §7). |
| `derives_from` | string — revision link | OPTIONAL | The direct parent template's identity (full multihash). |
| `ancestry` | array of revision links | OPTIONAL | The derivation chain within the template's family, `[root, …, parent]`, root first ([03](03-templates.md) §4). Its last element MUST equal `derives_from`. MUST NOT exceed 3 entries (maximum derivation depth 4). |
| `bounds` | JSON object | OPTIONAL | Declared shape limits for trees of this type ([03](03-templates.md) §5). |

A template revision has no `leaves` field.

**Signature revision** — common fields plus:

| Field | Wire type | Presence | Meaning |
|---|---|---|---|
| `signer` | string — a DID | REQUIRED | The claimed signer identity ([04](04-signatures.md) §4). |
| `signature` | JSON object | REQUIRED | The signature value object ([04](04-signatures.md) §2). |

All eight fields of a signature revision are REQUIRED (including
`previous_revision` — the revision being signed). A signature revision has no
`leaves` field.

**Anchor revision** — common fields plus:

| Field | Wire type | Presence | Meaning |
|---|---|---|---|
| `structural_links` | array of revision links | REQUIRED (MAY be empty) | Verification-relevant dependencies; a verifier MUST resolve every entry ([05](05-anchor-revisions-and-links.md) §3). |
| `compositional_links` | array of `{ "hash": <revision link>, "role": <string> }` | OPTIONAL (omitted when empty) | Application-level references; carried, never interpreted by the protocol. |
| `leaves` | array of strings | OPTIONAL | As for object revisions: present iff `method` is `"tree"`. |

### 1.3 Kind discrimination

A decoder determines a revision's kind from two independent signals, both
normative:

**(a) The field set.** The presence of `payloads` makes it an object revision;
`schema` makes it a template; `signer` + `signature` make it a signature;
`structural_links` makes it an anchor. The field sets are disjoint, and the
strict-field rule of §1.1 makes the discrimination unambiguous. When a decoder
tries the kinds in order, the normative order is: object, template, signature,
anchor.

**(b) The naming value.** `revision_type` semantically classifies the revision
by which foundation template it names:

| `revision_type` names… | Classification |
|---|---|
| the `template_meta` template, or the genesis bootstrap hash (§1.5) | Template |
| the `anchor_template` template | Anchor |
| any of the five signature templates (`signature_base`, `signature_eip191`, `signature_ed25519`, `signature_p256`, `signature_webauthn`) | Signature |
| any of the three timestamp foundation templates (`timestamp_base`, `timestamp_evm`, `timestamp_tsa`) | Timestamp (outside the core profile; see [07](07-verification.md) §4.1) |
| any other structurally valid multihash | Object |
| anything else | Unknown |

Classification MUST require a structurally valid, `0x`-prefixed, lowercase-hex
full multihash ([02](02-hashing-and-canonicalization.md) §2). In particular a
classifier MUST NOT accept uppercase hex, a bare 32-byte digest without the
multihash prefix, or the legacy literal strings `"anchor"` and `"template"` —
all of these classify as Unknown.

Signature, anchor, and timestamp revisions are the **branch kinds** — a
classification of the naming value used by disclosure presets and traversal
metadata. Branch-kind membership is independent of tree position: topologically
a revision of any kind can sit on or off the chain (§3.2). Template, object,
and unknown revisions are not branch kinds.

### 1.4 Revision links

A **revision link** is the string form of a revision hash: `0x` followed by the
lowercase hex encoding of the full multihash
([02](02-hashing-and-canonicalization.md) §2). For the registered algorithms
this is 70 characters. Parsers MUST reject uppercase hex.

A distinguished **zero sentinel** exists: 32 zero bytes, rendered
`0x0000…0000` (64 hex characters). It is *not* a valid multihash and is legal
in exactly one position: as an entry of an anchor's `structural_links`, where
it denotes a deliberately headless attestation
([05](05-anchor-revisions-and-links.md) §3.1). It MUST NOT appear anywhere
else a revision link is expected.

### 1.5 Genesis

A revision is a **genesis revision** iff it has no `previous_revision` *and*
its kind admits genesis. Only object and anchor revisions can be genesis.
Template and signature revisions are never genesis, even when
`previous_revision` is absent (for templates it is routinely absent — a
template tree is a single free-standing revision, [03](03-templates.md) §2).

Two genesis shapes are produced by the protocol:

1. **Anchor genesis (the normal form for typed trees).** The tree begins with
   an anchor revision (no `previous_revision`) whose `structural_links` name
   the tree's type template (or other caller-chosen targets); the first object
   revision then chains from that anchor. Templates are referenced, never
   embedded, at creation time ([03](03-templates.md) §6.2).
2. **Minimal genesis.** A single object revision with no `previous_revision`.

The **genesis bootstrap type hash** is the SHA3-256 digest of the ASCII string
`aqua:genesis:template_meta`, wrapped as a multihash:

```
0x162087ea911a93f2698563b68b860f33fd7a568ca2391d4a227b532812d496039e74
```

It is the naming value that the `template_meta` template itself declares
(a template-of-templates cannot reference its own content hash), and it
classifies as Template. See [03](03-templates.md) §3.

## 2. Trees

A **tree** is the container for revisions:

```json
{
  "revisions":  { "<revision link>": { …revision… }, … },
  "file_index": { "<revision link>": "<name>", … }
}
```

- `revisions` maps each revision's link to the revision itself. **The key is
  normative:** a verifier recomputes each revision's hash and compares it to
  the key under which the revision is stored ([07](07-verification.md) §3).
  Map ordering, where it matters (§3.3), is byte-wise over the decoded
  multihash bytes.
- `file_index` is organizational metadata: display names keyed by revision
  link. It is **never hashed**, carries no integrity guarantee, and MAY
  contain keys that are not revisions of this tree (for example the tips of
  linked trees). Verifiers MUST NOT rely on it for any protocol decision.

## 3. Structure and ordering

### 3.1 The revision graph

Each revision has at most one parent (`previous_revision`), so a tree's
revisions form a forest of in-trees. Multiple children of one parent are
legal.

Normative structural rules, enforced at verification (acyclicity and
reference existence in [07](07-verification.md) §2; timestamp monotonicity in
[07](07-verification.md) §4):

- **Acyclicity.** Walking `previous_revision` backward from any revision MUST
  NOT revisit a revision.
- **Reference existence.** Every `previous_revision` MUST name a revision
  present in the same tree.
- **Timestamp monotonicity.** For every revision whose parent is in the tree,
  `child.local_timestamp >= parent.local_timestamp`. Equal timestamps are
  allowed; a decrease is a hard failure.

### 3.2 Chain, branches, tips

- The **chain** is the linear spine walked from a genesis revision by
  repeatedly following child links. The walk is kind-agnostic: where a
  revision has several children, the canonical traversal picks the child
  whose revision link is lowest in byte order of the decoded multihash,
  whatever its kind; when several genesis revisions exist, the one with the
  lowest link starts the chain. A genesis anchor is therefore the chain's
  head, and a signature that is its parent's only child sits on the chain.
  The tie-breaking rule makes traversal deterministic across
  implementations; it carries no semantic weight.
- A **branch** is any revision not on that spine — the non-preferred children
  at each fork. This topological notion is distinct from the *branch kinds*
  of §1.3: a signature commonly ends up a branch (its target usually has a
  content successor that wins the tie-break), but nothing guarantees it.
- A **tip** is a revision that no other revision names as its
  `previous_revision`. Multiple tips are normal (every signature is typically
  a tip).
- The **content tip** is the tip that is an object or template revision, with
  object preferred — the natural target for extending the tree.

### 3.3 Determinism

Given the same revision set, every conforming implementation MUST derive the
same chain, the same branch assignment, and the same traversal order, using
the byte-order tie-breaks above. A tree without any genesis revision has no
defined chain; verification of the individual revisions is unaffected.

### 3.4 The meaning of `local_timestamp`

`local_timestamp` is the producer's clock at creation, in Unix seconds. It is
hashed (so it cannot be altered after the fact) and it is ordered (§3.1), but
it is **not** evidence of real time: nothing in the core profile ties it to an
external clock. Trusted time requires timestamp revisions anchored to external
systems, which are outside the core profile ([07](07-verification.md) §4.1).

### 3.5 Well-formedness summary

A tree is well-formed when:

1. every revision parses under its kind's strict field set (§1.1–§1.2) — a
   parse-level obligation discharged before the staged verification
   procedure begins ([07](07-verification.md) §1);
2. every map key equals the recomputed hash of its revision
   ([07](07-verification.md) §3);
3. the structural rules of §3.1 hold;
4. every anchor's structural links resolve
   ([05](05-anchor-revisions-and-links.md) §3).

Everything beyond well-formedness — schema validity, signature validity,
cross-tree verification, disclosure — is specified in the later documents.
