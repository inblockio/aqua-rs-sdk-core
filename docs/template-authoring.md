# Template authoring guide

How to define, hash, and ship your own Aqua templates with
`aqua-rs-sdk-core`. This guide covers **data-only templates** (payloads
validated by JSON Schema). Templates carrying WASM verification are not
supported by this crate (they are rejected at verification time with
`COMPUTE_UNSUPPORTED`); author those against the full `aqua-rs-sdk`.

## 1. Concepts

A template is itself a revision: a `Template` value whose canonical SHA3-256
hash is the template's **type identity**. Every typed object revision carries
that hash as its `revision_type`. Change one byte of the template and you have
defined a new, different type. There is no template name on the wire, only the
hash; names are a resolution convenience.

The hash is computed over the template's canonical form, not the raw file
bytes: the JSON is parsed, flattened to RFC 6901 pointers, key-sorted,
serialized compactly, hashed with SHA3-256, and multihash-prefixed
(`0x1620...`). Whitespace and key order in your file therefore do not matter,
but every field value does, including `nonce` and `local_timestamp`.

## 2. Write the payload schema

The `schema` field holds a standard JSON Schema (draft 2020-12) describing
your payload. Rules:

- Always set `"additionalProperties": false` on every object level. The SDK
  deserializes templates with `deny_unknown_fields`, and open payloads defeat
  narrowing checks.
- Constrain everything you can: `pattern` for DIDs (`^did:(pkh|key):`),
  `minimum` for counters, `maxLength` for strings.

## 3. Write the template JSON

Create `my_template.json`:

```json
{
  "revision_type": "0x1620f3040850a8836717dd73e87d046723e11f9e9870e3b2e246803ad842fbf01155",
  "nonce": "0x11223344556677889900aabbccddeeff",
  "local_timestamp": 1754500000,
  "version": "https://aqua-protocol.org/docs/v4/schema",
  "method": "tree",
  "schema": { "...": "your JSON Schema here" }
}
```

Field notes:

- `revision_type` is always the `template_meta` multihash shown above; it marks
  this revision as a template.
- **Pin `nonce` and `local_timestamp` to fixed values.** Do not generate
  templates at runtime with random nonces or the current time: the hash would
  differ on every run and your type identity would never be stable. Pick the
  values once, commit the file, never touch it again.
- `method` is the default hashing method for objects of this type (`tree`
  enables field-level selective disclosure, `scalar` is cheaper).
- Optional: `bounds` (chain depth, branch, and revision count ceilings).

### Derived templates

A template may refine a parent by adding `derives_from` (the parent's full
multihash) and `ancestry` (root-first list of full multihashes, at most 3
entries, so hierarchies are at most 4 deep). A derived template must
**narrow** its parent: it may add required fields or tighten constraints, but
must still accept a subset of what the parent accepts. Use
`Aquafier::create_template` / `create_derived_template` flows to have the SDK
validate narrowing for you, or mirror the checks in `schema/narrowing.rs`.

## 4. Compute and pin the hash

Add a Rust wrapper so your code can reference the type:

```rust,ignore
use aqua_rs_sdk_core::schema::template::BuiltInTemplate;

pub struct MyTemplate;

impl BuiltInTemplate for MyTemplate {
    const TEMPLATE_JSON: &'static str = include_str!("my_template.json");
    // Fill with the real hash; the self-check test below tells you the value.
    const TEMPLATE_LINK: [u8; 32] = [0u8; 32];
}
```

And a self-check test that keeps the pinned hash honest forever:

```rust,ignore
#[test]
fn my_template_link_is_current() {
    use aqua_rs_sdk_core::primitives::HashType;
    use aqua_rs_sdk_core::schema::Template;
    use aqua_rs_sdk_core::verification::Linkable;

    let t: Template = serde_json::from_str(MyTemplate::TEMPLATE_JSON).unwrap();
    let link = t.calculate_link(HashType::Sha3_256).unwrap();
    assert_eq!(
        link,
        aqua_rs_sdk_core::primitives::RevisionLink::from_bytes(MyTemplate::TEMPLATE_LINK),
        "template hash drifted; update TEMPLATE_LINK to {link}"
    );
}
```

Run the test once, copy the printed hash into `TEMPLATE_LINK`, and you are
pinned. (Inside this repo the `verify-templates` binary automates exactly this
for the built-in catalog, including derivation cascades:
`cargo run --features native --bin verify-templates`.)

## 5. Create objects of your type

```rust,ignore
let tree = aquafier.create_object(
    RevisionLink::from_bytes(MyTemplate::TEMPLATE_LINK),
    None,                       // or Some(previous_tree) to append
    serde_json::json!({ "field": "value" }),
    None,                       // method override
)?;
```

Payloads are validated against your schema at creation time and again at
verification time.

## 6. Ship the template with your trees (portability)

Your template is not in this crate's built-in catalog, so a stranger's
verifier cannot resolve its hash out of thin air. Template resolution checks,
in order: the tree's own revisions, the built-in catalog, then linked trees.
So either:

- **Embed** the template revision in every exported tree:

  ```rust,ignore
  let template: Template = serde_json::from_str(MyTemplate::TEMPLATE_JSON)?;
  tree.revisions.insert(
      RevisionLink::from_bytes(MyTemplate::TEMPLATE_LINK),
      AnyRevision::Template(template),
  );
  ```

- or pass the template tree alongside via
  `verify_aqua_tree_with_linked_trees(...)`.

The two shipped-but-uncached built-ins (`audit_round_anchor`,
`audit_session_close`) use the same pattern; see
`examples/agent_audit_trail.rs` for it in action.

## 7. What core will not let you do

- A custom template whose JSON contains a `verification` (WASM) section will
  parse, and `validate_compute_section` will even check its internal
  consistency, but verification of objects of that type fails closed with
  `COMPUTE_UNSUPPORTED`. This is deliberate: core has no WASM runtime and no
  vendor trust evaluation, and it refuses to pretend otherwise. Author WASM
  templates against the full SDK.
- Renaming or "fixing up" a shipped template file. The hash is the identity;
  edits mint a new type and orphan every existing artifact of the old type.
