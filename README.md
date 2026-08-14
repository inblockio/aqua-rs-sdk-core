# aqua-rs-sdk-core
A minimal, WASM-free Rust implementation of the [Aqua Protocol](https://aqua-protocol.org) core: verifiable, portable data trees with anchors, typed objects, templates, cryptographic signatures, and selective disclosure.

## DISCLAIMER
This is an experimental, minimal community release of Aqua Protocol v4 under the Apache License 2.0.
It is provided “AS IS”, without warranty of any kind. Use at your own risk.
The software is under active development and currently receives only limited support and maintenance. Breaking changes are expected and may occur without notice.

### Implemented

- **Verification layer 1**: revision objects
- **Verification layer 2**: template-typed trees (without WASM compute)

### Not implemented

- **Verification layer 3**: intra-tree (stateful) verification
- **Verification layer 4**: policy evaluation of stateful tree objects

`aqua-rs-sdk-core` is a **compatible subset** of the full
[`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk). The templates it
shares with the full SDK are byte-identical (the 8 machinery and signature
templates, and the 11 audit identities), hashes and canonicalization are
bit-for-bit the same, and trees created and signed with this crate verify
in the full SDK (and vice versa). That compatibility is not aspirational: it is
enforced by an integration test suite (`compat-tests/`) that runs both crates
side by side.

## Why this crate exists

The full SDK bundles a WASM compute runtime, a policy engine, a daemon runtime,
and timestamping providers. Those parts are powerful but heavy, and the WASM
build machinery gets in the way of consumers who only need the core data model.
`aqua-rs-sdk-core` is the light-weight, dependency-lean cut for exactly one job:
creating and verifying tamper-evident, signed, linkable data trees, with
first-class support for **auditable AI-agent workflows** through the t1-t8
audit template family, distributed through the companion
[`aqua-template-registry`](https://github.com/inblockio/aqua-template-registry)
(agent templates are retrieved from the registry, not baked into consumers —
see below).

- No `wasm-bindgen`, no `wasmi`, no `cdylib`. Plain `rlib`, builds anywhere.
- 18 runtime dependencies (the full SDK has about 30).
- Apache-2.0.

## What is included

| Area | Contents |
|---|---|
| Primitives | revision links, multihash (SHA3-256, BLAKE3-256), canonicalization, Merkle trees, DID encoding (`did:key`, `did:pkh`) |
| Revisions | genesis, typed objects, templates, anchors (tree linking), signatures |
| Signatures | Ed25519 (`did:key`), EIP-191 secp256k1 (`did:pkh`), P-256, WebAuthn (verification) |
| Templates | template machinery (`template_meta`, `anchor_template`, `file`) and the base signature templates as built-ins; the eleven audit/agent templates (t1-t8 plus `audit_artifact`, `audit_round_anchor`, `audit_session_close`) are **registry-distributed, not built-in** (see "Auditable AI agents" below). Everything is data-only: **this crate ships zero WASM bytes** |
| Verification | the full L1-L3 pipeline (structure, hashes, schemas, signatures, cross-tree links), async and sync, governed by a configurable `VerificationPolicy` |
| Disclosure | selective disclosure and redaction, including the `pseudonymous` preset for audit artifacts |
| Export | `export_tree`: self-descriptive artifacts (referenced templates and their ancestry embedded by default), an explicit per-call opt-out, and the `missing_templates` lint |
| Protocol spec | [protocol-specification/](protocol-specification/README.md): an implementation-agnostic specification of the core profile (data model, hashing and canonicalization, templates, signatures, anchors, selective disclosure, the verification procedure) |

## What is not included (conformance profile)

This crate is honest about what it does not do. For every excluded capability
the behavior is explicit, and never silently permissive:

| Excluded | Behavior in core |
|---|---|
| WASM compute execution | No shipped template carries WASM (enforced by a unit test). Any template whose chain carries a `verification` section is **rejected** with `COMPUTE_UNSUPPORTED`: core has no WASM runtime and refuses to guess. Verify such trees with the full SDK. |
| Known full-SDK templates | Every template hash the full SDK publishes but core does not ship (timestamps, the identity family, claims, policy, registration, manifest, historical identity-rooted audit variants) is in a built-in lookup; a resolution miss answers with an explicit "not supported for verification by aqua-rs-sdk-core: it depends on <module>" message, governed by the `template_not_found` policy decision. The current audit-family hashes are fixtures, not that lookup: they fail closed as ordinary unknown types unless the caller supplies sources. |
| Timestamping | No timestamp creation, no TSA or EVM providers, and the timestamp templates are not shipped. Timestamp revisions in incoming trees are still classified (`RevisionKind::Timestamp`), and their templates answer through the unsupported lookup above: `strict()` rejects, `offline()` tolerates with a warning. The hostless full SDK reaches the same outcomes through its `timestamp_unavailable` decision, and the compat suite proves the parity. |
| Policy engine | Not included. (The `VerificationPolicy` decision points listed above are part of the verification pipeline, not the policy engine.) |
| Daemon / forest runtime | Not included. |
| Template registry | The registry client is not bundled. The agent (audit) templates are distributed **only** through the separate [`aqua-template-registry`](https://github.com/inblockio/aqua-template-registry) project: consumers subscribe by publisher DID, pin template hashes, and pass the retrieved templates to this crate as explicit template sources. |

The invariant behind this table: **core is never more permissive than the full
SDK under the same verification policy.**

## Install

```toml
[dependencies]
aqua-rs-sdk-core = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] } # for the async API
```

Releases are timed events, not merge side-effects. `Cargo.toml` = git tag
`vX.Y.Z` = crates.io. Use [`scripts/release.sh`](scripts/release.sh); see
[RELEASE.md](RELEASE.md).

The `native` feature (on by default) enables the EIP-191 secp256k1 signer.
There is also a fully synchronous verification path (`verify_tree_sync`) if you
prefer not to pull in an async runtime for verification.

## Quick start

```rust,no_run
use aqua_rs_sdk_core::schema::{AquaTreeWrapper, FileData, SigningCredentials};
use aqua_rs_sdk_core::Aquafier;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aquafier = Aquafier::new();

    // 1. Create a genesis revision for some content.
    let file = FileData::new(
        "hello.txt".to_string(),
        b"hello world".to_vec(),
        PathBuf::from("hello.txt"),
    );
    let tree = aquafier.create_genesis_revision(file.clone(), None)?;

    // 2. Sign it with an Ed25519 key (did:key identity).
    let secret: Vec<u8> = std::env::var("MY_ED25519_SECRET_HEX")
        .map(|h| hex::decode(h).unwrap())
        .unwrap_or_else(|_| (1..=32).collect()); // demo key, never do this in production
    let creds = SigningCredentials::Did { did_key: secret };
    let signed = aquafier
        .sign_aqua_tree(AquaTreeWrapper::new(tree, None, None), &creds, None, None)
        .await?;

    // 3. Verify the full pipeline (structure, hashes, schema, signature).
    let result = aquafier
        .verify_aqua_tree(
            AquaTreeWrapper::new(signed.aqua_tree, Some(file.clone()), None),
            vec![file],
        )
        .await?;
    assert!(result.is_verified());
    println!("verified: {}", result.is_verified());
    Ok(())
}
```

Typed objects work the same way: retrieve the template, provide a payload
that matches its JSON Schema, and the SDK builds the tree. Agent (audit)
templates are **not** resolved implicitly: retrieve them from the
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

## Auditable AI agents (t1-t8)

The audit template family records one agent "turn" as a chain of signed,
individually verifiable artifacts:

| Tag | Template | Signed by |
|---|---|---|
| T1 | `audit_user_turn_marker` | server key (its revision hash becomes the `turn_id`) |
| T2 | `audit_user_prompt` | user session key |
| T3 | `audit_agent_thinking` | agent key |
| T4 | `audit_agent_tool_call` | agent key |
| T5 | `audit_api_response` (attested third-party API response) | API attestor key |
| T6 | `audit_tool_result` | agent key |
| T7 | `audit_hitl_approval` | user key (human-in-the-loop decision) |
| T8 | `audit_agent_response` | agent key (`is_final` closes the turn) |

`audit_round_anchor` (a Merkle commitment over a turn's artifacts) and
`audit_session_close` (the session seal) complete the chain, and the
`pseudonymous` disclosure preset lets you share redacted audit trails that
still verify.

The family is rooted at `audit_artifact` and is pure data end to end (JSON
Schema validation only, no WASM state machines).

### Distribution: registry retrieval is required

The 11 audit templates are published as the `audit-set-v1` set of the
companion
[`aqua-template-registry`](https://github.com/inblockio/aqua-template-registry)
project, and the registry is their **only sanctioned distribution channel** —
stated normatively in the protocol specification,
[03 — Templates, §8.3 Distribution](protocol-specification/03-templates.md#83-distribution).
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
(the default, see below) embeds every template the tree uses. Everyone else
resolves through the registry. A verifier that cannot resolve an audit
template hash fails closed under the `template_not_found` policy decision,
and the `missing_templates` lint names the hashes to fetch.

The in-crate JSON copies are **fixtures** (typed payload structs and
`verify-templates` pins). They do not resolve as built-ins. The machinery
and signature templates in the table above remain the built-in contract.

Run the end-to-end example:

```
cargo run --example agent_audit_trail --features native
```

## Self-descriptive exports

A typed object names its type by hash only, so a tree of a custom or imported
type is meaningless to a receiver who does not already hold that template.
`export_tree` closes that gap, and does it **by default**: it walks every
typed revision's template plus the full `derives_from` ancestry and embeds
each template revision into a clone of the tree, under its canonical
multihash link.

```rust,ignore
use aqua_rs_sdk_core::{Aquafier, ExportOptions, missing_templates};

// Self-descriptive (the default): verifies with no linked trees.
let portable = aquafier.export_tree(&tree, &[my_template_tree], &ExportOptions::default())?;
assert!(missing_templates(&portable).is_empty());

// Opt out per call site: a plain clone, receiver must resolve the types.
let bare = aquafier.export_tree(&tree, &[], &ExportOptions::bare())?;
```

Template bodies resolve from the tree's own revisions, then the built-in
catalog, then the extra sources you pass (for example trees from a template
import store). The export **fails closed**: if any referenced template or
ancestor cannot be resolved it returns the missing hashes and embeds nothing.
`missing_templates(&tree)` is the same check as a lint, for receivers
triaging an incoming tree or for publishers in CI.

`include_builtin_templates` also defaults to `true`, because **"built-in" is
a property of the receiver, not the sender**. Set it to `false`
(`ExportOptions::non_builtin_only()`) when the receiver is known to share this
crate's catalog and the bytes matter. The cost of the default is template JSON
size per exported tree. Audit templates are never built-in here, so an export
of an audit tree always needs the registry (or fixture) sources and always
embeds the family.

The compat suite proves the round trip end to end: a core-signed T1 audit tree
created with fixture sources and run through `export_tree` verifies in the
**full SDK** with no linked trees. A bare (un-exported) core audit tree
verifies in the full SDK too (the hashes match and the family is still a
full-SDK built-in) and fails in core without sources.

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
above:

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

## Protocol specification

An independent, implementation-agnostic specification of the protocol this
crate implements — revisions, hashing and canonicalization, templates,
signatures, anchor revisions, selective disclosure, and the verification
procedure — lives in
[protocol-specification/](protocol-specification/README.md). The code is the
reference implementation; the specification states the protocol a conforming
producer or verifier must follow.

## Custom templates

See [docs/template-authoring.md](docs/template-authoring.md) for the full
authoring guide: writing the schema, pinning the template JSON, computing the
template hash, derivation and narrowing rules, and shipping templates so that
any verifier can resolve them (`export_tree` above is the primary path;
section 6 documents the embedding pattern underneath it). Data-only templates
(JSON Schema validation, no WASM) are fully supported and are the documented
default.

## Compatibility testing

The `compat-tests/` crate (not published) proves subset compatibility against
the full SDK. It requires a sibling checkout:

```
parent/
  aqua-rs-sdk/       git clone https://github.com/inblockio/aqua-rs-sdk
  aqua-rs-sdk-core/  this repo
```

It is deliberately **not** a workspace member — membership would make every
cargo invocation in this repo fail wherever the sibling is absent — so it is
run by manifest path:

```
cargo test                      # unit tests, standalone
cargo test --manifest-path compat-tests/Cargo.toml   # compat suite (needs the sibling)
cargo run --features native --bin verify-templates   # template hash cascade check
```

The suite asserts: identical template hashes and bytes for the 8 shared
machinery and signature templates **and** the 11 audit templates, identical
canonicalization output, cross-verification of signed trees in both
directions, identical outcomes on deterministic seed fixtures, per-policy
outcome parity for timestamped trees, and tamper rejection parity.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). This crate contains
code and template definitions extracted from
[aqua-rs-sdk](https://github.com/inblockio/aqua-rs-sdk).
