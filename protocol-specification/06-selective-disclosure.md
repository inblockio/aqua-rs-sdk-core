# 06 — Selective disclosure

Selective disclosure lets a tree's holder reveal a verifiable subset of its
content: hidden fields are replaced by salted commitments, and a verifier
confirms — with no side channel and no trusted party — that what was disclosed
is exactly what the original revision hashes commit to.

Disclosure operates at two levels:

- **Field level:** a single tree-method revision is replaced by a **redacted
  revision** whose leaves are individually disclosed or sealed (§2–§3).
- **Tree level:** a whole tree is exported as a **selective tree** in which
  each revision is fully disclosed, field-redacted, or hidden (§4).

## 1. Precondition: tree method

Only revisions with `method: "tree"` support field-level redaction — the
per-field commitments of [02](02-hashing-and-canonicalization.md) §4.2 *are*
the disclosure mechanism. A scalar revision hashes as one opaque blob and can
only be disclosed in full or hidden; a request to field-redact it MUST be
rejected.

The disclosure unit is the **leaf**: one entry of the canonical pointer map
([02](02-hashing-and-canonicalization.md) §3), including the container-marker
leaves (the root `""`, every object node as `{}`, every array node as `[]`).
Subtree redaction is expressed by redacting every leaf under the subtree's
pointer prefix; whole-revision hiding is a tree-level directive (§4).

## 2. The redacted revision

```json
{
  "revision_hash": "0x1620…",
  "leaf_count":    19,
  "leaves": [
    { "type": "Disclosed", "index": 3, "path": "/payloads/signer_did",
      "value": "\"did:key:z6Mk…\"", "salt": "0x<64 hex>" },
    { "type": "Redacted",  "index": 5, "path": "/payloads/prompt_text",
      "value_commit": "0x<64 hex>" },
    …
  ]
}
```

| Field | Meaning |
|---|---|
| `revision_hash` | The original revision's full multihash. The hash algorithm is recovered from its multicodec; a redacted revision carries no algorithm field. |
| `leaf_count` | The total number of leaves of the original revision. MUST be at least 1. |
| `leaves` | One entry per leaf. Every leaf of the original MUST appear, disclosed or redacted. |

Leaf entries are discriminated by `type`:

- **`Disclosed`** — `index` (the leaf's zero-based position in canonical
  order), `path` (the RFC 6901 pointer), `value` (the compact JSON rendering
  of the flattened value, carried as a JSON string — a string value keeps its
  quotes, e.g. `"\"alice\""`; a number is bare, e.g. `"42"`; container
  markers are `"{}"` / `"[]"`), and `salt` (the 32-byte per-leaf salt,
  `0x` + lowercase hex).
- **`Redacted`** — `index`, `path` (**always cleartext**, including on
  redacted leaves), and `value_commit` = `HASH(0x02 ‖ salt ‖ value)`
  (32 bytes, `0x` + lowercase hex) — the value commitment from
  [02](02-hashing-and-canonicalization.md) §4.2, with the salt and value
  withheld.

Unknown members of the redacted-revision container MUST be rejected.

### 2.1 What redaction cannot hide

The pointer paths and `leaf_count` are cleartext by design (the path is
authenticated into the leaf hash, §6.2). A redacted revision therefore
necessarily reveals:

- the complete field-name structure of the revision;
- array cardinalities (element pointers are visible);
- which optional fields were populated (absent fields produce no pointer);
- the total leaf count.

Disclosure policies must treat field *presence* as public.

## 3. Verifying a redacted revision

A verifier MUST, in order:

1. **Count** — `leaves` has exactly `leaf_count` entries; reject `leaf_count`
   of 0.
2. **Index bijectivity** — the `index` values are exactly
   `0 … leaf_count − 1`: none out of range, none duplicated, none missing.
3. **Algorithm recovery** — decode `revision_hash` under the full multihash
   rules ([02](02-hashing-and-canonicalization.md) §2); rejection on any
   malformation.
4. **Leaf reconstruction** — for each entry, in `index` order:
   - Disclosed: `leaf = HASH(0x00 ‖ HASH(0x03 ‖ path) ‖ HASH(0x02 ‖ salt ‖ value))`;
   - Redacted: `leaf = HASH(0x00 ‖ HASH(0x03 ‖ path) ‖ value_commit)` — the
     label is recomputed from the cleartext path; the commitment is taken as
     supplied.
5. **Root equality** — reduce the leaves with the Merkle construction
   ([02](02-hashing-and-canonicalization.md) §5), wrap the root as a
   multihash, and require byte equality with `revision_hash`.

Any tampering — a changed value, salt, commitment, path, count, or index —
surfaces as a root mismatch or an index/count violation. There is no
finer-grained attribution, and none is needed: the guarantee is all-or-nothing
per revision.

### 3.1 What redacted verification cannot check

A redacted revision proves *hash integrity* only. The following checks are
impossible over it and are **not** silently assumed to pass; they are simply
outside what a selective artifact can prove:

- template resolution and schema validation of the payload (the payload is
  partly sealed; under some policies even the naming value is sealed);
- the published `leaves` array check of full verification;
- signature verification *of* the redacted revision itself (a redacted
  signature revision seals the signature bytes);
- compute, anchor resolution, and every other content-dependent stage.

Consumers MUST NOT present a selectively disclosed artifact as having passed
full verification; it proves integrity of the disclosed subset against the
original hashes, no more and no less.

## 4. Selective trees

```json
{
  "revisions": {
    "0x1620…a": { "disclosure": "Full",     "revision": { … } },
    "0x1620…b": { "disclosure": "Redacted", "redacted": { …§2… } },
    "0x1620…c": { "disclosure": "Hidden" }
  },
  "file_index": { "0x1620…a": "name" }
}
```

Each revision of the source tree maps to one of three disclosure states:

- **`Full`** — the revision verbatim.
- **`Redacted`** — the field-level form of §2.
- **`Hidden`** — a bare placeholder carrying no fields at all, for typed
  object and template revisions. Hidden **signature and anchor revisions are
  omitted from the map entirely** rather than leaving a placeholder.

### 4.1 Production rules

1. A revision not named by the disclosure policy defaults to **Full**.
2. Every field-redacted revision that has a `previous_revision` MUST disclose
   the `/previous_revision` leaf (the exporter adds it if the policy did
   not) — chain linkage stays verifiable.
3. `file_index` entries are retained only for Full revisions; redacted and
   hidden revisions lose their display names.
4. **Hidden placement.** A hidden object or template revision keeps its key
   in the map (its placeholder), so chain continuity through it remains
   checkable — the loss is content, not linkage. Hidden signature and anchor
   revisions are omitted entirely, so a producer MUST NOT hide an anchor or
   signature that any retained revision chains from: the dangling reference
   makes the artifact fail chain verification (hiding a genesis anchor is
   the canonical mistake). Signatures and anchors with no dependents are the
   intended Hidden targets.
5. Field-redaction of a signature revision, while mechanically possible for a
   tree-method signature, destroys its verifiability; disclosure policies
   MUST keep signature revisions Full (or Hidden as dead ends), and MUST
   keep anchor revisions Full.

### 4.2 Verifying a selective tree

Per entry:

- **Full** — recover the algorithm from the map key, recompute the revision
  hash ([02](02-hashing-and-canonicalization.md) §4), and require byte
  equality with the key. If the revision has a `previous_revision`, that link
  MUST be a key of the selective tree (chain continuity).
- **Redacted** — verify per §3. If a *disclosed* leaf with path exactly
  `/previous_revision` is present and its value parses as a revision link,
  that link MUST be a key of the selective tree. A genesis revision has no
  `/previous_revision` leaf at all — absent fields produce no pointer
  ([02](02-hashing-and-canonicalization.md) §3) — so genesis-ness manifests
  as the leaf's absence.
- **Hidden** — nothing is verified; the entry attests only that a revision
  with that hash existed at that position.

A missing parent is a chain-break failure. Signature revisions disclosed as
Full SHOULD additionally be verified cryptographically per
[04](04-signatures.md) §6 by consumers relying on the attestations; the
selective-tree integrity procedure above does not include it.

### 4.3 No completeness guarantee

A selective tree carries **no commitment to the revision set**: nothing proves
that all revisions of the source tree appear. An exporter can omit a
revision no disclosed revision references, and a verifier cannot detect the
omission. Consumers that need completeness must obtain it out of band (for
example, an application-level commitment such as an audit round anchor's leaf
list, [03](03-templates.md) §8.2).

## 5. Disclosure policies

A disclosure policy maps revision links to directives:

```json
{ "revisions": {
    "0x1620…": "Full",
    "0x1620…": { "FieldRedacted": ["/payloads/signer_did", "/payloads/created_at"] },
    "0x1620…": "Hidden"
} }
```

`FieldRedacted` lists the pointers to **disclose** (an allow-list); everything
else in that revision is sealed. A listed pointer that is not a leaf of the
revision is an error: the redaction — and with it the export — MUST fail.
(The presets and profiles below never produce such pointers: they intersect
their fixed path sets with the revision's actual leaves before redacting, so
an unset optional field is dropped from the list, not an error.) Policies are
exporter inputs; they are never serialized into, or committed by, the
artifact.

### 5.1 The `full` preset

The empty policy: every revision defaults to Full. The artifact is the whole
tree, merely in selective-tree form.

### 5.2 The `pseudonymous` preset

A fixed preset for audit trees ([03](03-templates.md) §8.2): reveal structure,
identity, and chronology; seal content. Per revision kind:

- Signature and anchor revisions: **Full** (attestations stay verifiable).
- T1 (`audit_user_turn_marker`): **Full** (the marker carries no sensitive
  content).
- Audit templates T2–T8, matched by naming value: **FieldRedacted** with the
  following allow-lists (all pointers under `/payloads/`):

| Template | Disclosed paths (beyond forced `/previous_revision`) |
|---|---|
| T2 `audit_user_prompt` | `signer_did`, `session_id`, `turn_id`, `created_at`, plus `attached_files/<i>/hash` for every present index `<i>` |
| T3 `audit_agent_thinking` | `signer_did`, `turn_id`, `seq_in_turn`, `created_at`, `model_name` |
| T4 `audit_agent_tool_call` | `signer_did`, `turn_id`, `tool_name`, `risk_level`, `created_at` |
| T5 `audit_api_response` | `signer_did`, `turn_id`, `method`, `endpoint`, `status_code`, `attested_origin`, `created_at`, `request_hash` |
| T6 `audit_tool_result` | `signer_did`, `turn_id`, `tool_name`, `success`, `created_at` |
| T7 `audit_hitl_approval` | `signer_did`, `turn_id`, `decision`, `created_at` |
| T8 `audit_agent_response` | `signer_did`, `turn_id`, `created_at`, `is_final`, `model_name` |

Everything not listed is sealed — including the revision's structural leaves
(`/nonce`, `/local_timestamp`, `/method`, `/version`, `/revision_type`, the
container markers) and the sensitive payload fields (prompt text, thinking
text, tool arguments and results, response bodies, HITL prompt text and
rationale, attachment names and sizes, token counts).

The T2 attachment rule is dynamic: every actual path matching
`/payloads/attached_files/<index>/hash` — where `<index>` is one non-empty
all-ASCII-digit segment — is disclosed, so attachments stay hash-referenced
while their names, sizes, and count-independent details stay sealed.

- Any other revision (non-audit content): **Full**. The preset takes no
  position on templates outside the audit family; holders of mixed trees
  should use a profile (§5.3).

### 5.3 Derivation-aware profiles

A **disclosure profile** generalizes the preset to a closed world with
template-derivation awareness:

- **Closed world.** An object revision whose template family is not named by
  the profile is *redacted*, not disclosed — disclosing unknown content is
  the failure mode being designed out. Its disclosed set is exactly
  `/revision_type` (plus the forced `/previous_revision`).
- **Lineage classification.** A revision is classified by walking its
  template's verified derivation lineage (self, parent, …, root), resolving
  each ancestor by hash ([03](03-templates.md) §6.2) from verified sources —
  never by trusting a template's self-declared ancestry. Resolution failure —
  or a lineage that cannot be fully resolved within the classifier's fixed
  resolution cap, which MUST be at least the protocol derivation bound
  ([03](03-templates.md) §4) — classifies the revision as unknown → sealed
  (fail-closed; this also neutralizes ancestry cycles).
- **Family rules dominate.** A disclosure rule attached to a template family
  applies to every descendant template; the nearest family rule in the
  lineage wins, and a per-revision Full directive cannot override an
  inherited family redaction rule.
- **Forced naming-value disclosure.** Every field-redacted object revision
  discloses `/revision_type` — it is a hash, not sensitive, and consumers
  need the type to interpret the artifact. `/nonce` is **never** disclosed
  (§6.1).
- **Patterns.** A family rule's disclose-list entries are exact pointers or
  pointers with `*` segments, where `*` matches exactly one non-empty
  all-ASCII-digit segment (an array index). Multiple `*` segments are
  permitted.
- Structural revisions (signature, anchor, template) are not classified by
  profiles; they remain Full. A scalar object revision matched by a
  field-redaction rule becomes Hidden (§1).

Profiles are exporter-side policy inputs, never part of the artifact.

## 6. Security considerations

### 6.1 Everything rests on the nonce

The per-leaf salts are derived from the revision's 16-byte `nonce`
([02](02-hashing-and-canonicalization.md) §4.2). Consequences:

- **The `/nonce` leaf MUST NOT be disclosed** in any redacted revision.
  Disclosing it yields every leaf's salt and makes every sealed value —
  many of which are low-entropy (booleans, enums, small integers, container
  markers, the fixed `version` and `method` strings) — trivially
  brute-forceable. This is an obligation on exporters and policy authors:
  the artifact format itself cannot prevent a defective policy from
  disclosing it.
- Guessing resistance for sealed values is bounded by the nonce's 128 bits.
- Disclosing one leaf's salt does not weaken the others: per-leaf salts are
  derived through a one-way expansion keyed by the pointer path.

### 6.2 Path authentication

The pointer path is bound into every leaf hash via the label commitment
(`HASH(0x03 ‖ path)`). A sealed value cannot be relabeled to a different
field while keeping its commitment: any relabeling changes the leaf and
therefore the root.

### 6.3 Domain separation

The four domain tags ([02](02-hashing-and-canonicalization.md) §4.2) make
leaves, internal nodes, value commitments, and label commitments mutually
non-collidable.

### 6.4 One-wayness and linkability

- Redaction is one-way with respect to the artifact: a sealed leaf carries
  neither salt nor value. It is *not* one-way with respect to the producer,
  who holds the original and can always re-disclose.
- Commitments are not a join key: the same value at the same path in two
  different revisions produces different commitments (different nonces), and
  the same value at two paths within one revision produces different
  commitments (path-keyed salts).
- Structural leakage (§2.1) is inherent and must be considered when deciding
  what to seal.

### 6.5 Verifier hygiene

Selective-tree inputs are attacker-controlled. Verifiers MUST reject a
`leaf_count` of 0 (an empty leaf list has no defined Merkle root), MUST
enforce the index bijectivity of §3, and MUST apply the strict multihash
decoding rules to `revision_hash` before hashing anything.
