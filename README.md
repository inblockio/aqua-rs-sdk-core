# aqua-rs-sdk-core

A minimal, WASM-free Rust implementation of the [Aqua Protocol](https://aqua-protocol.org) core: verifiable, portable data trees with anchors, typed objects, templates, cryptographic signatures, and selective disclosure.

### Implemented

- **Verification layer 1** — revision objects
- **Verification layer 2** — template-typed trees (without WASM compute)

### Not implemented

- **Verification layer 3** — intra-tree (stateful) verification
- **Verification layer 4** — policy evaluation of stateful tree objects

`aqua-rs-sdk-core` is a **compatible subset** of the full
[`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk). Every template it
ships is byte-identical to the full SDK's copy, hashes and canonicalization are
bit-for-bit the same, and trees created and signed with this crate verify in the
full SDK (and vice versa). That compatibility is not aspirational: it is
enforced by an integration test suite (`compat-tests/`) that runs both crates
side by side.

## Why this crate exists

The full SDK bundles a WASM compute runtime, a policy engine, a daemon runtime,
and timestamping providers. Those parts are powerful but heavy, and the WASM
build machinery gets in the way of consumers who only need the core data model.
`aqua-rs-sdk-core` is the light-weight, dependency-lean cut for exactly one job:
creating and verifying tamper-evident, signed, linkable data trees, with
first-class support for **auditable AI-agent workflows** through the t1-t8
audit template family.

- No `wasm-bindgen`, no `wasmi`, no `cdylib`. Plain `rlib`, builds anywhere.
- 18 runtime dependencies (the full SDK has about 30).
- Apache-2.0.

## What is included

| Area | Contents |
|---|---|
| Primitives | revision links, multihash (SHA3-256, BLAKE3-256), canonicalization, Merkle trees, DID encoding (`did:key`, `did:pkh`) |
| Revisions | genesis, typed objects, templates, anchors (tree linking), signatures |
| Signatures | Ed25519 (`did:key`), EIP-191 secp256k1 (`did:pkh`), P-256, WebAuthn (verification) |
| Templates | template machinery (`template_meta`, `anchor_template`, `file`), the base signature templates, and the eleven audit templates (t1-t8 plus `audit_artifact`, `audit_round_anchor`, `audit_session_close`), all data-only: **this crate ships zero WASM bytes** |
| Verification | the full L1-L3 pipeline (structure, hashes, schemas, signatures, cross-tree links), async and sync, governed by a configurable `VerificationPolicy` |
| Disclosure | selective disclosure and redaction, including the `pseudonymous` preset for audit artifacts |
| Export | `export_tree`: self-descriptive artifacts (referenced templates and their ancestry embedded by default), an explicit per-call opt-out, and the `missing_templates` lint |

## What is not included (conformance profile)

This crate is honest about what it does not do. For every excluded capability
the behavior is explicit, and never silently permissive:

| Excluded | Behavior in core |
|---|---|
| WASM compute execution | No shipped template carries WASM (enforced by a unit test). Any template whose chain carries a `verification` section is **rejected** with `COMPUTE_UNSUPPORTED`: core has no WASM runtime and refuses to guess. Verify such trees with the full SDK. |
| Known full-SDK templates | Every template hash the full SDK publishes but core does not ship (timestamps, the identity family, claims, policy, registration, manifest, the identity-rooted audit variants) is in a built-in lookup; a resolution miss answers with an explicit "not supported for verification by aqua-rs-sdk-core: it depends on <module>" message, governed by the `template_not_found` policy decision. |
| Timestamping | No timestamp creation, no TSA or EVM providers, and the timestamp templates are not shipped. Timestamp revisions in incoming trees are still classified (`RevisionKind::Timestamp`), and their templates answer through the unsupported lookup above: `strict()` rejects, `offline()` tolerates with a warning. The hostless full SDK reaches the same outcomes through its `timestamp_unavailable` decision, and the compat suite proves the parity. |
| Policy engine | Not included. (The `VerificationPolicy` decision points listed above are part of the verification pipeline, not the policy engine.) |
| Daemon / forest runtime | Not included. |
| Template registry | Not included by design. See the separate `aqua-template-registry` project for registering and subscribing to templates by publisher DID. |

The invariant behind this table: **core is never more permissive than the full
SDK under the same verification policy.**

## Install

```toml
[dependencies]
aqua-rs-sdk-core = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] } # for the async API
```

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

Typed objects work the same way: pick a template, provide a payload that
matches its JSON Schema, and the SDK builds the tree.

```rust,ignore
use aqua_rs_sdk_core::schema::template::BuiltInTemplate;
use aqua_rs_sdk_core::schema::templates::AuditUserTurnMarker;
use aqua_rs_sdk_core::primitives::RevisionLink;

let tree = aquafier.create_object(
    RevisionLink::from_bytes(AuditUserTurnMarker::TEMPLATE_LINK),
    None, // no previous tree, this creates a typed genesis
    serde_json::json!({
        "signer_did": "did:key:z6MkExampleServer",
        "session_id": "session-1",
        "turn_index": 0,
        "opens_at": 1754500000
    }),
    None,
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
Schema validation only, no WASM state machines). These 11 templates are the
first template set published through the companion `aqua-template-registry`
project. The full SDK currently ships an older, identity-rooted variant of
the family; core answers those hashes through the unsupported lookup, and
the planned upstream migration reunifies the two.

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
a property of the receiver, not the sender**: this crate's audit templates are
built-in here and unresolvable in the current full SDK, so a genuinely
self-descriptive export carries them too. Set it to `false`
(`ExportOptions::non_builtin_only()`) when the receiver is known to share this
crate's catalog and the bytes matter. The cost of the default is template JSON
size per exported tree.

The compat suite proves the round trip end to end: a core-signed T1 audit tree
run through `export_tree` verifies in the **full SDK** with no linked trees,
while the same tree un-exported fails there.

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

```
cargo test --workspace          # unit tests + compat suite
cargo run --features native --bin verify-templates   # template hash cascade check
```

The suite asserts: identical template hashes and bytes for the 8 shared
machinery and signature templates, a deliberately bounded fork for the 11
audit templates (hashes differ, and the JSONs differ from the full SDK's
only in ancestry linkage and description strings, enforced by
`audit_family_divergence_is_intentional`), identical canonicalization
output, cross-verification of signed
trees in both directions, identical outcomes on deterministic seed fixtures,
per-policy outcome parity for timestamped trees, and tamper rejection parity.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). This crate contains
code and template definitions extracted from
[aqua-rs-sdk](https://github.com/inblockio/aqua-rs-sdk).
