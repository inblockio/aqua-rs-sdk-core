# 07 — Verification

This document specifies the normative verification procedure for a tree
(optionally with linked trees), the error vocabulary, and the verification
policy. It composes the per-topic rules of documents 01–06 into one ordered
procedure.

## 1. Outcomes

Verification reduces to one of three outcomes:

| Outcome | Meaning |
|---|---|
| `verified` | every check passed |
| `verified_with_warnings` | every non-relaxable check passed; one or more policy-governed conditions were tolerated as warnings (§7) |
| `failed` | at least one error |

Any error makes the outcome `failed`; otherwise any warning makes it
`verified_with_warnings`; otherwise it is `verified`. A result reports its
outcome together with its error codes (for errors) and decision-point
identifiers (for warnings), plus diagnostic logs.

Verification operates on parsed input. A document that violates the
wire-form rules — a kind's strict field set, the fixed `version` string,
unknown members ([01](01-data-model.md) §1.1) — MUST be rejected at parse:
a tree that does not parse fails verification as a whole, before the staged
procedure below begins.

## 2. Stage 0 — Structural verification

Runs first, in linear time, with no cryptography, and is **never
policy-governed**. Any failure short-circuits the whole verification with
`STRUCTURAL_VALIDATION_FAILED`.

1. **Anchor link resolution.** Every structural link of every anchor MUST
   resolve ([05](05-anchor-revisions-and-links.md) §3).
2. **Acyclicity.** No `previous_revision` walk may revisit a revision
   ([01](01-data-model.md) §3.1).
3. **Reference existence.** Every `previous_revision` MUST name a revision in
   the tree.

### 2.1 Linked trees

When linked trees are supplied ([05](05-anchor-revisions-and-links.md) §6):

1. Build the cross-tree dependency graph from anchor structural links; a
   cycle fails with `CROSS_TREE_CYCLE_DETECTED`.
2. Verify participating linked trees in topological order, dependencies
   first, each by this full procedure recursively.
3. Any participating linked tree that fails makes the main verification fail
   with `LINKED_TREE_RESOLUTION_FAILED`.

Neither condition is policy-relaxable. Warnings do not aggregate across
trees: a linked tree that verifies with warnings counts as verified for the
linking tree, and each tree's result carries its own warnings.

## 3. Stage 1 — Integrity

For every revision, keyed by link `L`. Never policy-governed; any failure
yields the tree-level code `HASH_VERIFICATION_FAILED`. The per-revision
conditions named below are diagnostic identifiers — they say in logs what
failed — not separately reported codes:

1. **Key well-formedness.** `L` MUST decode under the strict multihash rules
   ([02](02-hashing-and-canonicalization.md) §2); failure:
   `INVALID_REVISION_HASH_ENCODING`. The decoded codec supplies the
   algorithm for this revision.
2. **Hash equality.** Recompute the revision hash
   ([02](02-hashing-and-canonicalization.md) §4) and require byte equality
   with `L`. A computation failure is `HASH_COMPUTE_FAILED`; an inequality is
   `HASH_MISMATCH`.
3. **Leaf integrity** — for object and anchor revisions with
   `method: "tree"`:
   - the `leaves` field MUST be present (`LEAVES_MISSING`);
   - every entry MUST be a **bare** digest of exactly the algorithm's output
     length — a multihash-shaped leaf is rejected
     (`LEAF_NOT_BARE_DIGEST`);
   - recompute the leaves and require count equality
     (`LEAVES_COUNT_MISMATCH`) and value equality (`LEAVES_MISMATCH`);
     a computation failure is `LEAVES_COMPUTE_FAILED`.

   Signature and template revisions carry no leaves and skip this check.

## 4. Stage 2 — Types and order

Aggregated under the tree-level code `SCHEMA_OR_CHAIN_FAILED`:

1. **Schema validation** — for every object revision: resolve its template
   ([03](03-templates.md) §6.2) and require the type binding and payload
   conformance of [03](03-templates.md) §6.1. An unresolvable template is
   `TEMPLATE_NOT_FOUND` (policy-governed, §7); a resolved template with a
   non-conforming payload is `SCHEMA_VALIDATION_FAILED` (never
   policy-governed). When `TEMPLATE_NOT_FOUND` is tolerated by policy, the
   affected revision is excused from the remainder of the per-revision
   procedure — batch inclusion (§4.1), the compute boundary (§5), and
   type-specific verification (§6): its structure and hash are already
   verified, and without a template there is nothing further to evaluate.
2. **Timestamp monotonicity** — the ordering rule of
   [01](01-data-model.md) §3.1. Never policy-governed.

### 4.1 Batch inclusion (timestamp-typed revisions)

A revision whose naming value classifies as Timestamp
([01](01-data-model.md) §1.3) carries a batch inclusion proof in its payload,
binding the revision it timestamps (its `previous_revision`) into an external
Merkle batch. Although timestamp *creation* is outside the core profile, a
core verifier MUST check the proof when it can:

Required payload fields: `merkle_root`, `batch_tree_size`,
`batch_leaf_index`, `merkle_proof` (array), `shielding_nonce`. Missing fields
fail with `MERKLE_ROOT_MISSING`, `BATCH_TREE_SIZE_MISSING`,
`BATCH_LEAF_INDEX_MISSING`, `MERKLE_PROOF_MISSING`,
`SHIELDING_NONCE_MISSING`; a zero tree size is `BATCH_TREE_SIZE_ZERO`.

Encoding rules: `merkle_root` is a **SHA3-256 multihash** (any other codec:
`MERKLE_ROOT_BAD_CODEC` / `MERKLE_ROOT_BAD_MULTIHASH`); `merkle_proof`
siblings are **bare** 32-byte digests; `merkle_root`, `shielding_nonce`, and
every sibling MUST be lowercase hex (`MERKLE_HEX_NOT_LOWERCASE`,
`MERKLE_HEX_DECODE_FAILED`).

The leaf construction is always SHA3-256, regardless of the revision's own
algorithm:

```
raw      = the 34 multihash bytes of the timestamped revision's link
           (the timestamp revision's previous_revision, hex-decoded)
shielded = SHA3-256( raw || shielding_nonce_bytes )
leaf     = SHA3-256( 0x00 || shielded )
```

The shielding nonce prevents third parties from confirming a known revision
hash's presence in a public batch; its length is not constrained by
verification, and producers SHOULD use at least 16 random bytes. Verify the
RFC 9162 inclusion proof
([02](02-hashing-and-canonicalization.md) §5) of `leaf` at
`batch_leaf_index` in a tree of `batch_tree_size` against the root
(`MERKLE_LEAF_INDEX_OUT_OF_BOUNDS`, `MERKLE_INCLUSION_FAILED`,
`MERKLE_ROOT_MISMATCH`). A `batch_tree_size` of 1 degenerates to
`leaf == root`.

Batch-proof failure is governed by the `batch_proof_failed` policy decision
(§7); a revision failing it skips compute.

## 5. Stage 3 — Compute boundary

For every object revision with a resolved template: collect the template
chain (ancestors root-first, then the template). Ancestors are enumerated
from the template's declared `ancestry`, each entry resolved by hash — an
entry that resolves is authentic by content address; an unresolvable
ancestor is `ANCESTOR_TEMPLATE_NOT_FOUND`. If the chain carries any compute
(`verification`) declaration, a core-profile verifier fails the revision with
`COMPUTE_UNSUPPORTED` ([03](03-templates.md) §7). A chain with no compute
declarations passes silently.

(Contrast the disclosure lineage walk of
[06](06-selective-disclosure.md) §5.3, which re-derives lineage step by step
from `derives_from`: there, a self-declared list that *shortens* a lineage
could relax a redaction rule, so the list is not trusted.)

## 6. Stage 4 — Type-specific verification

Never policy-governed; failures carry `VERIFICATION_FAILED` for the affected
revision.

- **Object revisions of the `file` template**: the referenced file content
  MUST be verified against the payload by **size and content hash** — never
  by filename. The `file` payload is
  `{ "type": "file", "hash": <0x + hex>, "hash_type": <algorithm name>,
  "descriptor": <string>, "size": <u64>, "content_type": <MIME string> }`,
  where `hash_type` names the digest algorithm (`FIPS_202-SHA3-256` or
  `BLAKE3-256`) and `hash` is the digest of the file bytes under that
  algorithm. Other object revisions pass (their schema was checked in
  Stage 2).
- **Template revisions**: static validation of any compute declaration
  ([03](03-templates.md) §7).
- **Signature revisions**: the full procedure of
  [04](04-signatures.md) §6 — pre-image reconstruction, cryptographic
  verification, signer binding.
- **Anchor revisions**: pass (their links were resolved in Stage 0 and their
  hash in Stage 1).

## 7. The verification policy

A **verification policy** assigns one of two decisions — **Fail** or
**Warn** — to each of seven decision points. Warn records a warning and
continues; Fail records an error. The policy can only *relax* the specific
conditions below; everything else in this document is non-negotiable.

| Decision point | Condition it governs | `strict` | `offline` | `debug` |
|---|---|---|---|---|
| `timestamp_unavailable` | a timestamp-typed revision's proof capability is unavailable (`COMPUTE_UNSUPPORTED` or a host-requirement condition on a timestamp-typed revision; a missing timestamp *template* is `template_not_found` like any other) | Fail | Warn | Warn |
| `template_not_found` | an object's template is unresolvable | Fail | Warn | Warn |
| `ancestor_template_not_found` | a resolved template's ancestor is unresolvable | Fail | **Fail** | Warn |
| `wasm_execution_failed` | compute could not be evaluated (`COMPUTE_UNSUPPORTED` in this profile) | Fail | Warn | Warn |
| `batch_proof_failed` | a batch inclusion proof failed (§4.1) | Fail | **Fail** | Warn |
| `wasm_untrusted_signer` | a compute template's vendor is untrusted (richer profiles) | Fail | **Fail** | Warn |
| `unsigned_template` | a compute template is unsigned (richer profiles) | Fail | **Fail** | Warn |

- `strict` is the default policy. Purpose-built profiles: `offline` tolerates
  conditions caused by working without network access or optional
  capabilities, while still refusing broken proofs and missing ancestors;
  `debug` tolerates everything tolerable for diagnostics.
- **Secure deserialization default:** the five original decision points
  (`timestamp_unavailable`, `template_not_found`, `wasm_execution_failed`,
  `batch_proof_failed`, `wasm_untrusted_signer`) are REQUIRED members of a
  serialized policy — omitting one MUST be a parse error. Decision points
  added to the vocabulary later (`ancestor_template_not_found`,
  `unsigned_template`) MUST deserialize as **Fail** when absent, so policies
  serialized before their introduction stay secure. Both contracts are
  fail-closed.
- The last two decision points exist for cross-profile parity; a core-profile
  verifier never itself produces their conditions (it has no compute
  execution), but MUST route the corresponding codes correctly when they
  appear in embedded results.
- Condition-to-decision routing for capability codes: `COMPUTE_UNSUPPORTED`
  and host-requirement conditions on a **timestamp-typed** revision route to
  `timestamp_unavailable`; on other revisions to `wasm_execution_failed`.

**What no policy can relax:** structural validity (Stage 0), cross-tree
cycles and linked-tree failures, hash and leaf integrity (Stage 1), schema
violations of a resolved template, timestamp monotonicity, and type-specific
verification (file content, compute static checks, signature validity). A
core-profile verifier under *any* policy is never more permissive than a
full-profile verifier under the same policy: unsupported capabilities surface
as governed conditions or hard failures, never as silent passes.

## 8. Error code vocabulary

**Tree-level:**
`STRUCTURAL_VALIDATION_FAILED`, `CROSS_TREE_CYCLE_DETECTED`,
`LINKED_TREE_RESOLUTION_FAILED`, `HASH_VERIFICATION_FAILED`,
`SCHEMA_OR_CHAIN_FAILED`.

**Per-revision:**
`INVALID_REVISION_HASH_ENCODING`, `HASH_COMPUTE_FAILED`, `HASH_MISMATCH`,
`LEAVES_MISSING`, `LEAF_NOT_BARE_DIGEST`, `LEAVES_COMPUTE_FAILED`,
`LEAVES_COUNT_MISMATCH`, `LEAVES_MISMATCH`, `TEMPLATE_NOT_FOUND`,
`SCHEMA_VALIDATION_FAILED`, `ANCESTOR_TEMPLATE_NOT_FOUND`,
`COMPUTE_UNSUPPORTED`, `VERIFICATION_FAILED`.

The Stage-1 integrity conditions (`INVALID_REVISION_HASH_ENCODING` through
`LEAVES_MISMATCH`) and `SCHEMA_VALIDATION_FAILED` are aggregated into their
tree-level codes in a reported result (§3, §4); they appear individually in
diagnostics.

**Batch inclusion:**
`MERKLE_ROOT_MISSING`, `BATCH_TREE_SIZE_MISSING`,
`BATCH_LEAF_INDEX_MISSING`, `MERKLE_PROOF_MISSING`,
`SHIELDING_NONCE_MISSING`, `BATCH_TREE_SIZE_ZERO`,
`MERKLE_HEX_NOT_LOWERCASE`, `MERKLE_HEX_DECODE_FAILED`,
`MERKLE_ROOT_BAD_CODEC`, `MERKLE_ROOT_BAD_MULTIHASH`,
`MERKLE_ROOT_MISMATCH`, `MERKLE_LEAF_INDEX_OUT_OF_BOUNDS`,
`MERKLE_INCLUSION_FAILED`.

**Reserved (produced by richer profiles, routed by policy here):**
`WEB_HOST_REQUIRED`, `BLOCKCHAIN_HOST_REQUIRED`, `IDENTITY_HOST_REQUIRED`,
`TRUST_STORE_REQUIRED`, `UNSIGNED_TEMPLATE`, `WASM_UNTRUSTED_SIGNER`.

## 9. Selective-artifact verification

Selective trees have their own integrity procedure
([06](06-selective-disclosure.md) §3–§4). It shares Stage-1 hash semantics
(algorithm recovery from the multihash, byte-equality of recomputed roots)
but replaces the content-dependent stages with the redaction proofs; the
degraded-scope rules of [06](06-selective-disclosure.md) §3.1 apply.
