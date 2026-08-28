# aqua-rs-sdk-core-wasm

wasm-bindgen exports for `aqua-rs-sdk-core`. Every structured value crosses
the boundary as a JSON string (serde_json shapes of the core structs); byte
payloads cross as `Uint8Array`. Errors surface as JavaScript `Error`s whose
message is `"<context>: <source error>"`. The generated `pkg/*.d.ts` carries
the doc comments from `src/lib.rs` and is the reference for the TypeScript
wrapper in `../js-sdk/`.

Build (from this directory; output lands in `pkg/`, which is gitignored):

    wasm-pack build --target web --release --out-dir pkg

The crate compiles to an empty rlib on native targets, so
`cargo check -p aqua-rs-sdk-core-wasm` from the workspace root verifies only
that it links. The wasm32 build needs the `getrandom_backend="wasm_js"` cfg
from the workspace's `.cargo/config.toml`, which cargo applies automatically
when invoked from inside this repository.

External signing (hardware wallets, MetaMask, WebCrypto) is a two-step flow:
`prepareSignature` returns the exact canonical bytes the verifier will
recompute, and `addExternalSignature` rebuilds the signature revision from
those bytes plus the wallet's signature and runs the core verifier before
inserting it. See the doc comments on those two methods for what each
algorithm signs.
