# aqua-rs-sdk-core

A minimal, WASM-free Rust implementation of the [Aqua Protocol](https://aqua-protocol.org) core: verifiable, portable data trees with anchors, typed objects, templates, cryptographic signatures, and selective disclosure.

*Experimental community release of Aqua Protocol v4, Apache-2.0, provided as-is; breaking changes are expected.*

- No `wasm-bindgen`, no `wasmi`, no `cdylib` in the core crate — a plain `rlib` with 18 runtime dependencies that builds anywhere. Browser and Node bindings live in a separate workspace crate ([TypeScript / WASM bindings](#typescript--wasm-bindings)).
- Ed25519 (`did:key`) and EIP-191 secp256k1 (`did:pkh`) signing; P-256 and WebAuthn verification.
- Selective disclosure and redaction, including the `pseudonymous` preset for audit trails.
- Self-descriptive exports: `export_tree` embeds every referenced template by default, so receivers verify with nothing else ([docs/exports.md](docs/exports.md)).
- A compatible subset of the full [`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk): shared templates (the 8 machinery and signature templates, the 11 audit identities) are byte-identical, hashes and canonicalization are bit-for-bit the same, and signed trees verify in both directions — enforced by an integration test suite ([docs/conformance.md](docs/conformance.md)).

## Install

```toml
[dependencies]
aqua-rs-sdk-core = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] } # for the async API
```

The `native` feature (on by default) enables the EIP-191 secp256k1 signer; the
synchronous verification path (`verify_tree_sync`) needs no async runtime.

## Quick start

```rust,no_run
use aqua_rs_sdk_core::schema::{AquaTreeWrapper, FileData, SigningCredentials};
use aqua_rs_sdk_core::{generate_ed25519, Aquafier};
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

    // 2. Sign it with a fresh Ed25519 key (did:key identity).
    let (secret, _did) = generate_ed25519();
    let creds = SigningCredentials::Did { did_key: secret.to_vec() };
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
    Ok(())
}
```

Typed objects work the same way: retrieve the template, provide a payload that
matches its JSON Schema, and the SDK builds the tree. See
[docs/template-api.md](docs/template-api.md) for the template helper APIs, the
validated-creation path, and a registry-sourced example.

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

The 11 audit templates are not built-ins: they are distributed only through
the companion [`aqua-template-registry`](https://github.com/inblockio/aqua-template-registry),
hash-pinned and passed to this crate as explicit template sources
([03 — Templates, §8.3 Distribution](protocol-specification/03-templates.md#83-distribution)).
[docs/template-api.md](docs/template-api.md) covers the retrieval and creation workflow.

Run the end-to-end example:

```
cargo run --example agent_audit_trail --features native
```

## Scope

The full SDK's heavy parts are deliberately not here:

- **WASM compute execution** — any template whose chain carries a
  `verification` section is rejected with `COMPUTE_UNSUPPORTED`.
- **Timestamping** — no timestamp creation or providers; timestamp revisions
  in incoming trees resolve through an explicit unsupported-template lookup
  (`strict()` rejects, `offline()` tolerates with a warning).
- **Policy engine / daemon runtime** — not included.

Everything excluded fails closed, never silently permissive: core is never
more permissive than the full SDK under the same verification policy. See
[docs/conformance.md](docs/conformance.md) for the full conformance profile
and the compatibility test suite.

## TypeScript / WASM bindings

The core crate itself stays a plain `rlib`; nothing changes for native
consumers. The `wasm/` workspace member (`aqua-rs-sdk-core-wasm`,
`crate-type = ["cdylib", "rlib"]`, not published to crates.io) wraps the
public API with `wasm-bindgen`, and `js-sdk/` (`aqua-core-js`) is the typed
TypeScript layer over it: the same hashes and verification outcomes in Node
and browsers, external signing through wallets or WebCrypto, and the
registry-template and disclosure workflows.

```
wasm-pack build wasm --target web --release --out-dir pkg
cd js-sdk && pnpm install && pnpm build && pnpm test
```

See [wasm/README.md](wasm/README.md) for the boundary conventions and
[js-sdk/README.md](js-sdk/README.md) for the wrapper's quick start and API.

## Links

- [Protocol specification](protocol-specification/README.md) — implementation-agnostic spec of the core profile.
- [Template authoring guide](docs/template-authoring.md)
- [Template API and registry workflow](docs/template-api.md)
- [Conformance profile and compat testing](docs/conformance.md)
- [Self-descriptive exports](docs/exports.md)
- [TypeScript wrapper](js-sdk/README.md) · [wasm bindings crate](wasm/README.md)
- [`aqua-template-registry`](https://github.com/inblockio/aqua-template-registry)
- [`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk) — the full SDK.
- [CHANGELOG](CHANGELOG.md) · [RELEASE.md](RELEASE.md)

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). This crate contains
code and template definitions extracted from
[aqua-rs-sdk](https://github.com/inblockio/aqua-rs-sdk).
