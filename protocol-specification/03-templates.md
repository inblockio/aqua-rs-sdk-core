# 03 — Templates

A **template** declares a type. It is itself a revision
([01](01-data-model.md) §1.2): a JSON Schema for the payloads of object
revisions of that type, plus optional derivation metadata, optional shape
bounds, and an optional compute declaration. Templates are identified by
content hash — there are no template names on the wire; names are a resolution
convenience only.

## 1. Template identity

The identity of a template — its **template hash** — is the hash of its own
canonical form ([02](02-hashing-and-canonicalization.md) §3–§4), computed
**always with SHA3-256**, regardless of any tree's algorithm and regardless of
the template's own `method` field. The identity is used in two renderings:

- the **bare digest** (32 bytes) in catalogs and ledgers;
- the **full multihash** (`0x1620…`) everywhere on the wire: as the naming
  value of object revisions, in `derives_from` and `ancestry`, in anchor
  structural links, and as the template's key in its own tree.

Because the identity is a content hash, *any* change to a template — schema,
bounds, description strings, `nonce`, `local_timestamp` — mints a new type.
Template authors MUST therefore pin `nonce` and `local_timestamp` to fixed
literals; a freshly generated value would create a new type identity on every
build.

## 2. Template trees

A template is distributed as a **single-revision tree**: one template revision
keyed by its full SHA3-256 multihash, with no anchor and no
`previous_revision`. Derivation hierarchy is expressed *inside* the template
(§4), never through chain structure — chaining a template to any parent
revision would change its content hash and destroy its identity.

A template revision keyed under a BLAKE3-256 multihash is invalid: identity is
SHA3-256 (§1), so hash verification fails.

## 3. `template_meta` and the bootstrap

`template_meta` is the template-of-templates. Every template revision declares
as its naming value (`revision_type`) the full multihash of `template_meta`:

```
0x1620f3040850a8836717dd73e87d046723e11f9e9870e3b2e246803ad842fbf01155
```

with exactly one exception: `template_meta` itself cannot name its own content
hash, so it declares the **genesis bootstrap hash** — the SHA3-256 multihash of
the ASCII string `aqua:genesis:template_meta`:

```
0x162087ea911a93f2698563b68b860f33fd7a568ca2391d4a227b532812d496039e74
```

Both values classify a revision as a template
([01](01-data-model.md) §1.3).

`template_meta`'s schema constrains the body of templates (their `schema`,
`verification`, `derives_from`, `ancestry` members).

## 4. Derivation

A template MAY derive from another template:

- `derives_from` = the parent's full multihash. A template MAY instead name
  `template_meta` itself as its `derives_from`; that marks it as a **family
  root**, not a derived template, and contributes nothing to ancestry.
- `ancestry` = the derivation chain within the template's family,
  `[root, …, parent]`, root first, where the family root is the nearest
  ancestor with no family parent (its own `derives_from` is absent or names
  `template_meta`). `template_meta` never appears in an ancestry. The last
  element MUST equal `derives_from`.
- `ancestry` MUST NOT exceed **3 entries** — the maximum derivation depth is 4
  (a family root plus three levels of children). Derivation depth is
  `len(ancestry)`; family roots have depth 0.

### 4.1 Narrowing

Narrowing is a **derivation-time discipline** for refinement templates: a
child derived under it admits only payloads its parent also admits. It is
checked when the child is produced, and it is *not* re-checked at
verification. On the wire, `derives_from`/`ancestry` assert **family
membership, not schema subsumption** — consumers MUST NOT infer payload
compatibility from lineage. In particular, the shipped signature and audit
families (§8) are *extension* families: their concrete members add
properties to a minimal abstract parent and were not produced under the
narrowing discipline.

Under the narrowing discipline, the rules are checked property-wise on the
two schemas:

1. **No new properties.** Every key in the child's `properties` MUST exist in
   the parent's `properties`.
2. **No dropped requirements.** Every entry of the parent's `required` MUST
   remain in the child's `required`, or — if relaxed to optional — MUST still
   appear in the child's `properties`.
3. **Constraint tightening**, for each property present in both schemas:
   - `maxLength`, `maximum`, `exclusiveMaximum`: the child's value MUST be
     less than or equal to the parent's.
   - `minLength`, `minimum`, `exclusiveMinimum`: the child's value MUST be
     greater than or equal to the parent's.
   - If the parent declares one of these keywords and the child omits it, the
     child MUST declare a `const` instead; otherwise the omission widens the
     constraint and is invalid. A keyword only the child declares is always a
     valid tightening.
   - `enum`: the child's enum MUST be a subset of the parent's. The child MAY
     replace `enum` with a `const` whose value is a member of the parent's
     enum. Dropping the enum without a qualifying `const` is invalid.
   - `const`: if the parent declares `const`, the child MUST declare the
     identical `const`.
   - `pattern`: the child MAY add a pattern; removing a parent's pattern is
     invalid unless the child declares a `const` instead.

Closed payload schemas are what keep types analyzable: template schemas
SHOULD declare `additionalProperties: false` at every object level whose
member set is fixed. Levels that deliberately carry open content (for
example, a member that holds an arbitrary JSON Schema document) are the
exception, and an open level defeats narrowing analysis for everything
beneath it.

## 5. Bounds

A template MAY declare **bounds** — shape limits for trees of its type:

```json
"bounds": {
  "max_chain_depth":         <u16>,
  "structural_links":        { "required": <u8>, "max": <u8> },
  "max_signature_branches":  <u8>,
  "max_timestamp_branches":  <u8>,
  "max_anchor_branches":     <u8>,
  "max_total_revisions":     <u16>
}
```

Bounds are part of the template body and therefore part of its identity hash.
When `bounds` is present, all six members MUST be present.

**Resolution** is nearest-declaration-wins: a template's effective bounds are
its own declaration if present; otherwise the nearest ancestor's declaration,
walking `ancestry` from the direct parent toward the root; otherwise the
permissive default:

```
max_chain_depth 64, structural_links {required 0, max 4},
max_signature_branches 8, max_timestamp_branches 4,
max_anchor_branches 4, max_total_revisions 1024
```

**Protocol ceilings** cap every declaration; no template can raise them:

| Ceiling | Value |
|---|---|
| structural links per anchor | 64 |
| compositional links per anchor | 64 |
| compositional links with role `reference` per anchor | 64 |
| chain depth | 256 |
| branches per node | 256 |
| revisions per object tree | 4096 |

**Enforcement status.** In the core profile, declared bounds and the ceilings
above are normative limits on producers, but their enforcement is
**advisory**: the core verification procedure ([07](07-verification.md)) does
not count revisions, branches, or links against them. Runtime environments
that admit revisions incrementally SHOULD enforce effective bounds at
admission time; verifiers MAY enforce bounds and ceilings and reject trees
that exceed them.

## 6. Typing object revisions

### 6.1 The type binding

An object revision claims its type through its naming value:
`revision_type` = the template's full multihash. Verification of an object
revision requires **both**:

1. the naming value equals the resolved template's identity (recomputed, not
   trusted); and
2. the object's `payloads` conforms to the template's `schema` (JSON Schema
   draft 2020-12).

### 6.2 Template resolution

Templates are resolved in this order, identical at creation and verification:

1. the tree's **own revisions** (an embedded template revision);
2. the verifier's **catalog** of built-in templates (keyed by bare SHA3-256
   digest, §8);
3. supplied **linked trees** / template sources.

At creation, typed trees reference their template (via the genesis anchor's
structural links, [05](05-anchor-revisions-and-links.md) §4) and do **not**
embed it; embedding happens only in export (§9).

If resolution fails, the outcome is the policy-governed condition
`TEMPLATE_NOT_FOUND` ([07](07-verification.md) §4 and §7). A verifier MAY
recognize the hash as a known template of a richer profile it does not
implement and say so in its diagnostics, but the machine-readable outcome MUST
remain `TEMPLATE_NOT_FOUND` — a verifier is never more permissive because the
missing template is *known*-missing.

If the template resolves but any of its **ancestors** does not, the outcome is
`ANCESTOR_TEMPLATE_NOT_FOUND`: a child MUST NOT silently bypass invariants
declared by a parent it cannot see. This condition fails under both the
strict and the offline policies; only the debug policy tolerates it
([07](07-verification.md) §7).

### 6.3 Schema violations

If the template resolves and the payload does not conform, the outcome is
`SCHEMA_VALIDATION_FAILED`. This is never policy-relaxable.

## 7. Compute declarations

A template MAY carry a `verification` member declaring computations to be
executed by a WASM runtime (state machines over tree content). Its wire
shape:

```json
"verification": {
  "computations": [
    {
      "wasm":        "<hex of the compiled WASM module bytes; 0x prefix optional>",
      "wasm_hash":   "<SHA3-256 digest of the WASM bytes>",
      "source":      {                                  // OPTIONAL
        "code":     "<complete inline source text>",
        "hash":     "<SHA3-256 digest of the UTF-8 source bytes>",
        "language": "<source language identifier, e.g. \"wat\", \"rust\">"
      },
      "build":       { … },                             // OPTIONAL build recipe
      "description": "<free text>"                      // OPTIONAL
    }
  ],
  "host_dependencies": [ "<capability name>", … ],      // MAY be empty
  "states":            [ "<state name>", … ],
  "terminal_states":   [ "<state name>", … ]            // omitted when empty
}
```

Unknown members MUST be rejected at every level of the declaration. The core
profile does not execute compute. Its obligations are:

- **Static validation.** Whenever a template carrying a `verification` member
  is itself verified as a revision, the declaration MUST be statically
  checked: each computation's hex-decoded `wasm` MUST NOT exceed 2 MiB
  (the size gate applies to the hex length before decoding) and its SHA3-256
  digest MUST equal the declared `wasm_hash`; when `source` is present, its
  `code` MUST NOT exceed 512 KiB and the SHA3-256 digest of its UTF-8 bytes
  MUST equal the declared `source.hash`. Digest comparisons tolerate an
  optional `0x` prefix and are case-insensitive.
- **Fail-closed refusal.** When verifying an *object* revision whose resolved
  template chain (ancestors root-first, then the template itself) carries any
  `verification` member, a core-profile verifier MUST fail that revision with
  `COMPUTE_UNSUPPORTED` — it has no runtime and refuses to guess. Verification
  of such trees requires a full-profile verifier.

No template in the shipped catalog (§8) carries a compute declaration, so this
rule fires only for third-party templates.

## 8. The shipped catalog

The core profile ships 8 machinery and signature templates. Their identities
(bare SHA3-256 digests) are normative:

| Template | Identity (bare digest) | Role |
|---|---|---|
| `template_meta` | `0xf3040850a8836717dd73e87d046723e11f9e9870e3b2e246803ad842fbf01155` | template-of-templates (§3) |
| `anchor_template` | `0x479a304927c47f4308d027a858060ce287a9bdb45f2203f8130574a73511e899` | naming value of anchor revisions |
| `file` | `0x00f3abb3d74fc9dfc2b961cea906b3211716188f4de6f588180fdfcbbfa3fe53` | file-content genesis payloads |
| `signature_base` | `0xbdc93b4152c0163e40d3bf8cb956e235f0150731c1e8c8b50d9c3b7abe50e4a7` | abstract parent of the signature suites |
| `signature_ed25519` | `0xbaf1d5d47eef50dcde3931956879bb30c5580064a92ce43ed4c6bd8b878b659a` | Ed25519 signature revisions |
| `signature_eip191` | `0x57090c9095a2e9af36e9b6cb4574196fa973c44a210e703bd15dab2623dbd370` | EIP-191 signature revisions |
| `signature_p256` | `0x23a2cdd4618224a67235321e2dfeffac9ab1809175549d8b5402dd5c5376d81c` | ECDSA P-256 signature revisions |
| `signature_webauthn` | `0x2cdea1604c08b4e23f5415d8fcf885cf86d0a3e017cf4b7989c41aa99f3f2188` | WebAuthn signature revisions |

The 11 audit-family identities are **not** part of this catalog. They are
listed in §8.2 as the registry-distributed family; their hashes are identical
to those of the full SDK.

### 8.1 Catalog membership

Of the 8, **5 are resolvable by naming value** in a core-profile verifier's
catalog: `file` and the four concrete signature templates. The remaining
three (`template_meta`, `anchor_template`, `signature_base`) are shipped and
hash-pinned but deliberately outside the resolution catalog: nothing resolves
an object's type through them by default.

### 8.2 The audit family

The eleven audit templates form one family rooted at `audit_artifact` (each
concrete template derives from it with an ancestry of exactly one entry). They
give AI-agent workflows verifiable, per-turn audit trails: T1 opens a turn and
its revision hash becomes the `turn_id` that T2–T8 payloads reference;
`audit_round_anchor` commits a closed turn's artifact hashes (its
`merkle_root` payload field is an application-defined commitment over the
listed `leaf_hashes` — shape-validated by schema, not recomputed by the core
verification procedure); `audit_session_close` records the end of a session.
These identities are the same as the full SDK's.

| Template | Identity (bare digest) | Role |
|---|---|---|
| `audit_artifact` | `0x431668e53b2181311ec43db30ff4d4cf738059051829a5a4f3398c22440a16f3` | abstract root of the audit family |
| `audit_user_turn_marker` (T1) | `0x9bf38992cb2cc1230edb6539a98e6d3c889c69aa09b1764a4b91b30cb6a36990` | opens a user turn; its revision hash is the turn id |
| `audit_user_prompt` (T2) | `0x80143d8018fa7a0fa959c115ff7bf7da0d3363192db5202f2904b4626559ecc7` | the user's prompt |
| `audit_agent_thinking` (T3) | `0xfe1d5fd50335d5d21f3f1976baadc9eab68a0506241ed5303bb8ad0a25a407f1` | agent reasoning |
| `audit_agent_tool_call` (T4) | `0x13d08a7ea2a0dc5f4d5a380d9dd9456ec10392bc752f152517dd227bb272592f` | a tool invocation |
| `audit_api_response` (T5) | `0x6d1e300bbb0145cedc1a2ff19fd1ad0e0dcfcfde6a4a9b0d6ea67c7d31c4a129` | an attested API response |
| `audit_tool_result` (T6) | `0xad46f51cfce3fd961acb2a3d9047b4c217c3da43c32addc41e8e11b84b5c4732` | a tool result |
| `audit_hitl_approval` (T7) | `0xcd588f6994409f3088eef84d231027ba69a1d9d7193fcb1bf0d07a1716ba6560` | a human-in-the-loop decision |
| `audit_agent_response` (T8) | `0xe36f3af11b2c6d5c94e2862e4a66db016ff8e8f5486fe72594daa7df480c5413` | the agent's response |
| `audit_round_anchor` | `0xf174f2f669d102d3d74efb80248a08485fe2c40d18b2df5ccc7d225e794b63e7` | Merkle commitment closing a turn |
| `audit_session_close` | `0x9069525103b9408f039a41454d25ed5ffc59aed9e46224cb19864f2e71e0c23b` | closes an audit session |

### 8.3 Distribution

The sanctioned distribution channel for the audit family is the template
registry (`aqua-template-registry`, set `audit-set-v1`). None of the 11
identities is catalog-resolved. Producers MUST NOT rely on any verifier's
catalog beyond the machinery templates; the interoperable way to ship a
tree is self-descriptive export (§9) or explicit template sources.

## 9. Self-descriptive artifacts

A tree can be exported as a **self-descriptive artifact**: a tree into which
every referenced template — and every ancestor of every referenced template —
is embedded as an ordinary template revision, keyed by its full multihash.

Normative rules:

1. **Closure.** The embedded set is the transitive closure over each typed
   revision's naming value plus each embedded template's
   `derives_from`/`ancestry`. Signature, anchor, and template revisions do not
   contribute naming values to the closure (they dispatch on machinery
   templates).
2. **Fail-closed.** If any template in the closure cannot be resolved, the
   export MUST fail with the unresolved identities; partial embedding is not
   permitted.
3. **Idempotence.** Exporting an already self-descriptive artifact MUST be a
   no-op (already-embedded templates are not duplicated).
4. **Receiver-relative built-ins.** "Built-in" is relative to the receiver,
   not the sender. A self-descriptive export embeds catalog templates too, so
   the artifact verifies on receivers with a different (or empty) catalog. An
   exporter MAY offer an opt-out that skips catalog templates, at the cost of
   that portability.
5. **The missing-templates lint.** The same closure walk, without embedding,
   yields the set of unresolvable template identities. Publishers SHOULD run
   it before shipping a tree; a non-empty result means receivers will hit
   `TEMPLATE_NOT_FOUND`.

Embedding changes no revision: templates enter the artifact under their own
identities, and every existing hash and signature remains valid.
