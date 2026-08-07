# 05 — Anchor revisions and links

An **anchor revision** is a branch revision that carries references to other
revisions — inside its own tree, in other trees, or in template trees. Anchors
are the protocol's only linking construct: they declare a tree's type at
genesis, connect trees to one another, and mark deliberate attestation points.

## 1. Wire form

An anchor revision carries the common fields plus its link lists
([01](01-data-model.md) §1.2):

```json
{
  "previous_revision":   "0x1620…",            // absent for a genesis anchor
  "revision_type":       "0x1620479a304927c47f4308d027a858060ce287a9bdb45f2203f8130574a73511e899",
  "nonce":               "0x<32 hex>",
  "local_timestamp":     1783616147,
  "version":             "https://aqua-protocol.org/docs/v4/schema",
  "method":              "scalar",
  "structural_links":    [ "0x1620…", … ],
  "compositional_links": [ { "hash": "0x1620…", "role": "composition" }, … ]
}
```

- `revision_type` MUST be the full SHA3-256 multihash of the
  `anchor_template` ([03](03-templates.md) §8). The legacy literal string
  `"anchor"` is retired and classifies as Unknown.
- `structural_links` is REQUIRED and MAY be empty. It is also the wire
  discriminator that makes the revision an anchor
  ([01](01-data-model.md) §1.3).
- `compositional_links` is omitted when empty. Each entry pairs a full
  multihash with a free-form `role` string.
- When `method` is `"tree"`, the anchor carries `leaves` like an object
  revision; anchors participate in tree-method hashing and selective
  disclosure like any other revision.
- An anchor revision is always a branch ([01](01-data-model.md) §3.2), except
  when it is the genesis revision of its tree (§4).

Anchors have no payload. All semantic weight is in the two link lists.

## 2. The two link kinds

**Structural links** are verification-relevant dependencies. A verifier MUST
resolve every entry (§3); an unresolvable structural link fails the whole
tree. Producers use structural links to declare: "this content, by hash, is
required to interpret or verify this tree" — the type template at genesis, a
claim being attested, a dependency of a compute chain.

**Compositional links** are application data. The protocol carries them
(they are hashed like all revision content) but never resolves, checks, or
interprets them. Two conventional roles exist:

| Role | Convention |
|---|---|
| `"composition"` | the linked tree is bundled/composed with this one |
| `"reference"` | a citation or provenance pointer |

Roles are free-form; applications MAY define others. A verifier MUST NOT
reject an anchor because of an unknown role and MUST NOT attempt to resolve
compositional links.

## 3. Structural link resolution

For every anchor in a tree, every entry of `structural_links` MUST resolve to
one of the following, checked in any order:

1. **The zero sentinel** — 32 zero bytes (`0x` + 64 zero hex chars,
   [01](01-data-model.md) §1.4). It denotes a deliberately headless
   attestation ("no linked claim, by design") and passes resolution
   unconditionally.
2. **A revision in the same tree** — the hash is a key of the tree's own
   revision map.
3. **A revision in a supplied linked tree** — the hash is a key of any linked
   tree's revision map. Resolution is by **containment, not tip equality**: a
   template tree whose tip has grown (for example a vendor-signature branch)
   still resolves any of its contained revisions.
4. **A catalog template** — the hash is the identity of a template in the
   verifier's catalog ([03](03-templates.md) §8.1).

If an entry resolves to none of these, the anchor — and with it the tree —
MUST be rejected (`STRUCTURAL_VALIDATION_FAILED`,
[07](07-verification.md) §2). There is no partial or policy-relaxed outcome:
a verifier that was not given a required linked tree gets a hard failure, and
the zero sentinel is the only sanctioned way to declare "nothing linked".

### 3.1 The zero sentinel

The sentinel is a bare 32-byte zero value — deliberately not a valid
multihash, so it can never collide with a real revision. It is admissible
**only** as a `structural_links` entry. Anywhere else a revision link is
expected, it MUST be rejected.

## 4. Genesis anchors and typed trees

The normal shape of a typed tree is:

```
Anchor (genesis; structural_links = [ <template multihash> ])
  └── Object (revision_type = <template multihash>, payloads = …)
        └── … further revisions …
```

The genesis anchor declares the tree's type dependency before any content
exists; the first object revision chains from it. The tree's type is thereby
asserted twice — by the anchor's structural link and by the object's naming
value. Both are independently resolved; no rule requires the two to name the
same template.

Producers MAY substitute other targets for the default template link (for
example, an attestation tree whose genesis anchor structurally links the
claim-signature hash it attests). A genesis anchor's `local_timestamp` MUST
be at or before its child object's — this is the general monotonicity rule of
[01](01-data-model.md) §3.1, and a genesis anchor dated after its child fails
verification.

Templates themselves are never anchored: a template tree is a single
free-standing revision ([03](03-templates.md) §2).

## 5. Cross-tree links

A tree references another tree by anchoring a revision of it — normally its
tip — via a structural link (verification-relevant) or a compositional link
(application-level bundling):

- Links are **one-directional**, linking tree → linked tree, and
  content-addressed: nothing is written into the linked tree.
- When trees are linked for composition, each linked tree's tip is recorded
  as a compositional link with role `"composition"`, appended in a new anchor
  chained onto the linking tree's tip. The linked tree's display name MAY be
  recorded in the linking tree's `file_index` under the linked tip hash
  (informational only, [01](01-data-model.md) §2).
- What a structural link *claims* is containment: "the referenced revision
  exists in the linked tree, which is part of this verification context."
  Deeper semantics (state, payload interpretation) belong to richer profiles.

## 6. Cross-tree verification

When a tree is verified together with linked trees, the following rules apply
([07](07-verification.md) §2 places them in the overall procedure):

1. **Dependency ordering.** Build the dependency graph over {the main tree,
   the linked trees} from anchor structural links. Verify linked trees in
   topological order, dependencies first; each linked tree is verified by the
   **full verification procedure, recursively**, with the already-verified
   trees as its own linked context.
2. **Cycles are fatal.** A cycle in the cross-tree dependency graph
   (including through the main tree) MUST fail verification
   (`CROSS_TREE_CYCLE_DETECTED`).
3. **Reachability.** Only linked trees reachable from the main tree's
   structural links participate; supplied-but-unreferenced trees are ignored
   and not verified.
4. **Failure propagation.** If any participating linked tree fails its own
   verification, the main tree MUST fail
   (`LINKED_TREE_RESOLUTION_FAILED`). This is not policy-relaxable.

Note the two distinct failure surfaces: a structural link that resolves
nowhere is a *structural* failure of the main tree (§3), while a link that
resolves into a linked tree that itself fails verification is a *linked-tree*
failure. Both are fatal; they differ in what they tell the caller to fix.

## 7. Boundary: anchors are not timestamps

Anchoring in this profile is structural linking between trees. It is distinct
from **timestamp revisions** — branch revisions that commit a revision hash to
an external timestamping system. Timestamps are their own revision
classification ([01](01-data-model.md) §1.3) with their own foundation
templates, none of which the core profile ships; a core-profile verifier
treats a timestamp revision's unresolvable template as `TEMPLATE_NOT_FOUND`
under the `template_not_found` policy decision
([07](07-verification.md) §4 and §7). Anchor
revisions carry no timestamping semantics, and no anchor sub-kinds exist.

Similarly, the `audit_round_anchor` template ([03](03-templates.md) §8.2) is
*not* an anchor revision: it is an ordinary typed object revision whose
payload carries an application-level Merkle commitment. The word "anchor" in
its name refers to closing a turn, not to this document's revision kind.
