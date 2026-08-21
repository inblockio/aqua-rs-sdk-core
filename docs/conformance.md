# Conformance profile

What `aqua-rs-sdk-core` implements, what it deliberately does not, and how
subset compatibility with the full [`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk)
is enforced.

## What is included

| Area | Contents |
|---|---|
| Primitives | revision links, multihash (SHA3-256, BLAKE3-256), canonicalization, Merkle trees, DID encoding (`did:key`, `did:pkh`) |
| Revisions | genesis, typed objects, templates, anchors (tree linking), signatures |
| Signatures | Ed25519 (`did:key`), EIP-191 secp256k1 (`did:pkh`), P-256, WebAuthn (verification) |
| Templates | template machinery (`template_meta`, `anchor_template`, `file`) and the base signature templates as built-ins; the eleven audit/agent templates (t1-t8 plus `audit_artifact`, `audit_round_anchor`, `audit_session_close`) are **registry-distributed, not built-in** (see [docs/template-api.md](template-api.md)). Everything is data-only: **this crate ships zero WASM bytes** |
| Verification | the full L1-L3 pipeline (structure, hashes, schemas, signatures, cross-tree links), async and sync, governed by a configurable `VerificationPolicy` |
| Disclosure | selective disclosure and redaction, including the `pseudonymous` preset for audit artifacts |
| Export | `export_tree`: self-descriptive artifacts (referenced templates and their ancestry embedded by default), an explicit per-call opt-out, and the `missing_templates` lint (see [docs/exports.md](exports.md)) |
| Protocol spec | [protocol-specification/](../protocol-specification/README.md): an implementation-agnostic specification of the core profile (data model, hashing and canonicalization, templates, signatures, anchors, selective disclosure, the verification procedure) |

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
