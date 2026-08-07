# Aqua Protocol — Core Profile Specification

**Status:** Draft
**Date:** 2026-08-07
**Wire schema version:** `https://aqua-protocol.org/docs/v4/schema`

This is an independent specification of the Aqua protocol subset implemented by
`aqua-rs-sdk-core` (the *core profile*). It specifies the protocol — data
formats, algorithms, and the rules a conforming producer or verifier must
follow — and deliberately says nothing about how any particular implementation
is organized. Where this document and an implementation disagree, that is a
defect in one of them and must be reconciled; this document states the intended
protocol.

## Scope

The core profile covers:

- **Revisions** — the universal unit of the protocol: typed object revisions,
  template revisions, signature revisions, and anchor revisions
  ([01 — Data model](01-data-model.md))
- **Hashing and canonicalization** — content addressing, the Aqua multihash
  profile, Aqua Pointer Form, and the scalar and tree hashing methods
  ([02 — Hashing and canonicalization](02-hashing-and-canonicalization.md))
- **Templates** — hash-identified types, template derivation and narrowing,
  schema validation, and self-descriptive artifacts
  ([03 — Templates](03-templates.md))
- **Signatures** — the signature revision, the signing pre-image, the four
  signature suites, and signer identity binding
  ([04 — Signatures](04-signatures.md))
- **Anchor revisions** — structural and compositional links, genesis anchors,
  and cross-tree references
  ([05 — Anchor revisions and links](05-anchor-revisions-and-links.md))
- **Selective disclosure** — field-level redaction with salted commitments,
  selective trees, and the disclosure presets
  ([06 — Selective disclosure](06-selective-disclosure.md))
- **Verification** — the normative verification procedure, error codes, and
  the verification policy
  ([07 — Verification](07-verification.md))

Outside the core profile (and outside this specification) are: execution of
template compute (WASM) sections, timestamping providers, identity
verification beyond raw key material, and policy evaluation over stateful
trees. The core profile's obligations at
each of these boundaries are specified where they arise; the governing rule is
that a core-profile verifier MUST fail closed — it never treats a capability it
lacks as implicitly satisfied.

## Conformance language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in these
documents are to be interpreted as described in RFC 2119.

Two conformance roles are used throughout:

- a **producer** creates revisions and trees;
- a **verifier** checks them.

A statement without an explicit role binds both.

## Terminology

| Term | Meaning |
|---|---|
| **Revision** | The atomic protocol object: a JSON object of one of four kinds (object, template, signature, anchor), content-addressed by its revision hash. |
| **Revision hash / link** | The multihash of a revision's canonical form, rendered as a `0x`-prefixed lowercase hex string. Used both to address a revision and to reference it from other revisions. |
| **Tree** | A set of revisions keyed by revision hash, together with an informational file index. Structurally a forest of in-trees (each revision has at most one parent); colloquially "an Aqua tree". |
| **Chain** | The linear spine of a tree walked parent-to-child from a genesis revision. |
| **Branch** | A revision not on the chain's spine. Distinct from the *branch kinds* (signature, anchor, timestamp) — a classification by naming value, independent of tree position. |
| **Genesis revision** | A revision with no `previous_revision`. Only object and anchor revisions can be genesis. |
| **Template** | A revision that declares a type: a JSON Schema for payloads plus optional derivation metadata, identified by its own content hash. |
| **Naming value** | The value of a revision's `revision_type` field: the full multihash of the template that gives the revision its type. |
| **Structural link** | An anchor field naming a revision that is a verification-relevant dependency; a verifier must resolve it. |
| **Compositional link** | An anchor field naming a revision for application purposes; the protocol carries it but never interprets it. |
| **Selective disclosure** | Replacing a revision by per-field openings and salted commitments such that the original revision hash remains checkable. |

## Protocol constants

| Constant | Value |
|---|---|
| Wire schema version (the only legal `version` value) | `https://aqua-protocol.org/docs/v4/schema` |
| Hash algorithms | SHA3-256 (multicodec `0x16`), BLAKE3-256 (multicodec `0x1e`), both 32-byte digests |
| Nonce | 16 random bytes |
| Selective-disclosure KDF | HKDF with SHA3-256, extract salt `"AquaSD"` (ASCII) |
| Merkle domain tags | `0x00` leaf, `0x01` internal node, `0x02` value commitment, `0x03` label commitment |
| Template identity hash | Always SHA3-256, regardless of the tree's algorithm |
| Genesis bootstrap type hash | SHA3-256 of the ASCII string `aqua:genesis:template_meta` |

The catalog of shipped template hashes is normative and appears in
[03 — Templates](03-templates.md).
