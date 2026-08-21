# Template API

The helpers this crate gives you for working with templates, the
creation-time validation rules, and how the agent (audit) templates are
distributed.

## Working with templates: what the API gives you

Small, boring helpers that publishers and consumers were previously writing
by hand (and getting wrong):

| Need | API |
|---|---|
| Convert a wire link (`0x1620...`) to the bare 64-hex digest used by ledgers, `TEMPLATE_LINK` constants, and `..._hash` payload fields | `RevisionLink::bare_digest()`, `bare_digest_hex()` |
| The contract template hashes as data instead of parsing `tests/audit_template_hashes.txt` | `Aquafier::shipped_template_hashes()` (8), `builtin_template_hashes()` (5), and `core::shipped_templates()` for `(name, JSON, digest)`. The 11 audit rows in the ledger are fixture pins, not these accessors. |
| A fresh signing identity | `generate_ed25519() -> ([u8; 32], String)` (secret plus its `did:key`) |
| Publish or ship a template | `Aquafier::template_tree(&template, name)` (one-revision tree, full multihash key) |
| The `revision_type` every template JSON must declare | `primitives::TEMPLATE_META_REVISION_TYPE` |
| A Merkle root over a possibly empty batch | `merkle::try_merkle_root` (`merkle_root` panics on empty input, by documented design) |

**Creation-time validation is only automatic for built-in templates.**
`create_object` validates the payload against the template's JSON Schema when
it can resolve the template, and it can only resolve this crate's built-ins.
For a custom, imported, or registry-sourced type it creates the revision
**unvalidated**, and the mistake surfaces later at the receiver. Use
`create_object_validated`, which takes explicit template sources and fails
closed if the template (or an ancestor in its `derives_from` chain) is not
among them. For the agent (audit) templates this is the required creation
path — with registry-retrieved sources, per the distribution requirement
below:

```rust,ignore
let source = aquafier.template_tree(&my_template, Some("my_template"))?;
let tree = aquafier.create_object_validated(
    my_template_link,
    None,
    serde_json::json!({ "field": "value" }),
    None,
    &[source],
)?;
```

## Distribution: registry retrieval is required

The 11 audit templates are published as the `audit-set-v1` set of the
companion
[`aqua-template-registry`](https://github.com/inblockio/aqua-template-registry)
project, and the registry is their **only sanctioned distribution channel** —
stated normatively in the protocol specification,
[03 — Templates, §8.3 Distribution](../protocol-specification/03-templates.md#83-distribution).
They are not part of this crate's built-in template contract. A consumer of
the agent templates must:

1. retrieve them through a registry subscription — pinned by hash and
   restricted to an allow-listed publisher DID (the trust model and the
   publisher identity are defined in the registry README), and
2. pass the retrieved bodies to this crate as explicit template sources:
   `create_object_validated` for creation, `export_tree`'s extra sources for
   export, and `verify_aqua_tree_with_linked_trees` /
   `verify_tree_sync_with_linked_trees` for verifying trees that do not embed
   their templates.

Receivers of a self-descriptive export need no registry access: `export_tree`
(the default, see [docs/exports.md](exports.md)) embeds every template the
tree uses. Everyone else resolves through the registry. A verifier that cannot
resolve an audit template hash fails closed under the `template_not_found`
policy decision, and the `missing_templates` lint names the hashes to fetch.

The in-crate JSON copies are **fixtures** (typed payload structs and
`verify-templates` pins). They do not resolve as built-ins. The machinery and
signature templates listed in the "What is included" table of
[docs/conformance.md](conformance.md) remain the built-in contract.

## Creating a typed object from a registry template

Typed objects work the same way as any other revision: retrieve the template,
provide a payload that matches its JSON Schema, and the SDK builds the tree.
Agent (audit) templates are **not** resolved implicitly: retrieve them from
the
[`aqua-template-registry`](https://github.com/inblockio/aqua-template-registry)
and pass them as explicit template sources.

```rust,ignore
use aqua_rs_sdk_core::primitives::RevisionLink;
use aqua_rs_sdk_core::schema::template::Template;

// Template body and pinned digest come from your aqua-template-registry
// subscription store (hash-pinned, publisher allow-listed).
let turn_marker: Template = serde_json::from_str(&registry_template_json)?;
let source = aquafier.template_tree(&turn_marker, Some("audit_user_turn_marker"))?;

let tree = aquafier.create_object_validated(
    RevisionLink::from_bytes(pinned_turn_marker_digest), // from your registry lockfile
    None, // no previous tree, this creates a typed genesis
    serde_json::json!({
        "signer_did": "did:key:z6MkExampleServer",
        "session_id": "session-1",
        "turn_index": 0,
        "opens_at": 1754500000
    }),
    None,
    &[source],
)?;
```

For authoring your own templates, see
[docs/template-authoring.md](template-authoring.md).
