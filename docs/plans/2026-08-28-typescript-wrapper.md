# WASM bindings and TypeScript wrapper

**Task:** Make `aqua-rs-sdk-core` usable from Node and browsers without
changing what native consumers get: a `wasm-bindgen` crate over the public
API and a typed TypeScript package over that, with the same hashes and the
same verification outcomes as the Rust crate.

Status: implemented on branch `typescript`, not committed (left for review).
Reference implementation imitated in spirit: `aqua-rs-sdk` (`pub mod wasm`
and `js-sdk/`), whose defects were deliberately not carried over (an
`any`-typed module handle, wrapper methods calling exports that do not
exist, a MetaMask "signature" over a 32-bit string hash, a jest script that
does not run).

## Logic model

### CONTEXT

- The core is a plain `rlib` (README bullet one) and its CHANGELOG promises
  a byte-identical subset of the full SDK. Any binding work must leave
  `crate-type`, default features, and the public API alone.
- `wasm32-unknown-unknown` has no OS entropy and no wall clock; both
  `getrandom` majors are in the dependency graph, and
  `src/primitives/timestamp.rs` already had a `js_sys::Date::now()` arm
  without the dependency.
- The audit family is registry-distributed (0.1.1, B11): the wrapper must
  make "fetch definitions, pass as sources" the first-class path and must
  not present the in-crate fixtures as built-ins.
- Tooling: rustc 1.97 from Nix (no rustup, no clippy in this toolchain),
  wasm-pack, Node 24, pnpm 11 aliased as `npm` in the developer shell.

### GOAL

One command builds `wasm/pkg`; `js-sdk` typechecks, builds, and passes a
vitest suite that (a) recomputes every revision hash independently,
(b) runs genesis, sign, verify end to end, (c) signs with keys the module
never sees, (d) runs the audit-trail flow with explicit template sources,
(e) exercises selective disclosure, and (f) fails when a wasm export is
added or renamed without a wrapper. CI runs all of it.

### INPUTS

- `wasm/src/lib.rs` and its generated `wasm/pkg/aqua_rs_sdk_core_wasm.d.ts`
  (32 exports: the `AquafierWasm` class plus 31 free functions, one of them
  the panic hook).
- Rust serde shapes in `src/schema/`, `src/core/`, `src/primitives/` for the
  TypeScript interfaces.
- `docs/plans/2026-08-21-readme-rewrite.md` for prose style;
  `.github/workflows/ci.yml` for job style.

### BOUNDARY CONDITIONS

- No edits under `src/` beyond the wasm32 fixes already landed
  (`Cargo.toml` target-specific deps, `verify_common.rs` wasm32 arm), and
  none under `wasm/src` from the TypeScript side.
- No JavaScript re-implementation of any hash or signature primitive in the
  shipped package; the merkle oracle in `tests/` is the only independent
  implementation and it exists to check the module, not to replace it.
- No fabricated capabilities: a signer is shipped only if the message
  contract is pinned down by the wasm doc comments and a test proves it.

## Hypothesis register

| ID | Hypothesis | Prediction if true | Assumption | Test |
|---|---|---|---|---|
| H1 | A JSON-string boundary (`&str` in, `String` out, bytes as `Uint8Array`) is enough to expose the whole facade without `serde-wasm-bindgen` | every core struct round-trips through `JSON.parse(JSON.stringify(x))` unchanged; `deny_unknown_fields` structs deserialize from wrapper-built objects | serde shapes are stable across the boundary | all suites; `tests/parity.test.ts` |
| H2 | The core's canonicalization can be reproduced from the spec and source alone | an independent TypeScript implementation (noble SHA3-256 + HKDF, RFC 6901 flattening, RFC 9162 root with promotion) matches every scalar and tree link the module produces, and the stored `leaves` byte for byte | `serde_json` `Display` of values equals `JSON.stringify` for the payloads used (integers, strings, arrays, objects, null) | `tests/merkle.test.ts` (21 tests) |
| H3 | External signing can be exact and verifier-checked: `prepareSignature` returns the canonical pre-signature JSON, `addExternalSignature` rebuilds the revision from it and runs `verify_signature_sync` before inserting | WebCrypto Ed25519 and P-256 signatures and a simulated `personal_sign` verify; a flipped byte, a wrong key, a wrong message, or a `signature_type` mismatch throws and leaves the tree untouched | the verifier's signer/key binding covers `did:key` and `did:pkh:eip155` | `tests/external-signing.test.ts` (10 tests) |
| H4 | The registry workflow works with explicit sources only | `createObjectValidated` + `exportTree` with the 11 fixture trees yields `missingTemplates == []` and `verified`; without sources both fail closed | fixtures are byte-identical with `audit-set-v1` (0.1.1 CHANGELOG) | `tests/audit.test.ts` (10 tests) |
| H5 | Disclosure presets and redaction are usable from JS as-is | `pseudonymousPolicy` → `exportSelectiveTree` → `verifySelectiveTree` passes; a tampered disclosed leaf fails; `redactRevision` refuses `/nonce` and scalar revisions | — | `tests/disclosure.test.ts` (7 tests) |
| H6 | Drift between Rust exports and the wrapper can be caught mechanically | parsing `wasm/pkg/*.d.ts` at test time and checking each name against `AquaSDK.prototype` / the barrel fails on any unwrapped export | wasm-bindgen's `.d.ts` layout (4-space class members, `export function`) stays parseable | `tests/parity.test.ts` (4 tests) |
| H7 | The Node loading path needs no bundler and no `fs` in browser code | `import.meta.resolve` + dynamic `node:fs/promises` locates the `.wasm` from `node_modules`; browsers pass a URL or nothing | Node ≥ 20.6 | `examples/node-example.mjs`, e2e suite |
| H8 | wasm-pack forwards `--locked` to cargo | `wasm-pack build wasm ... -- --locked` builds; `cargo check --locked --target wasm32-unknown-unknown -p aqua-rs-sdk-core-wasm` is clean | — | run locally (see process notes); CI `wasm-js` job |

## Acceptance criteria

| ID | Criterion | Hypotheses |
|---|---|---|
| AC1 | `js-sdk` typechecks (sources and tests), builds to `dist/` with declarations, and `pnpm test` is green | H1–H6 |
| AC2 | Every export in the generated `.d.ts` (minus `init_panic_hook`, `initSync`, `free`, `constructor`) has a wrapper, enforced by a test | H6 |
| AC3 | Hash oracle agreement on scalar and tree links, stored leaves, `hashBytes`, `batchLeafHash`, `merkleRoot`, odd-node promotion | H2 |
| AC4 | External signing: three signer implementations verified end to end, four rejection paths tested, no hashing in JavaScript | H3 |
| AC5 | Audit flow with explicit sources verifies; the fixture caveat is stated in code, README, and this document | H4 |
| AC6 | CI job builds wasm with `--locked`, installs with `--frozen-lockfile`, typechecks, builds, tests, runs the example | H8 |
| AC7 | Rust side untouched by this task: `cargo fmt --all --check` and `cargo check --locked` pass unchanged; core README positioning stays accurate | — |

## Decisions

- **D1 Separate workspace crate, not a feature.** `wasm/` is a member with
  `crate-type = ["cdylib", "rlib"]` and `publish = false`; the core keeps
  `crate-type = ["rlib"]`, its 18 runtime dependencies on native, and its
  public API. The README bullet now says "in the core crate" and points at
  the new section instead of dropping the claim.
- **D2 JSON strings across the boundary.** Every structured value crosses
  as a serde_json string and byte payloads as `Uint8Array`. Cost: one
  stringify/parse per call. Benefit: the wrapper's types are the serde
  shapes verbatim, `deny_unknown_fields` errors surface as readable
  `Error`s, and no `serde-wasm-bindgen` mapping can drift from serde.
- **D3 `prepareSignature` / `addExternalSignature` instead of exposing
  `add_external_signature_util`.** The core utility takes a finished
  `Signature`; a wallet needs to know what to sign first, and the nonce and
  timestamp must be the ones the verifier will recompute. The two-step
  design returns the canonical pre-signature JSON (single-use, carried back
  verbatim) and re-verifies before insertion, so a wrapper bug cannot
  insert an unverifiable revision. The TypeScript `AquaSigner` interface is
  the thin contract over that: `signatureType`, `signer` DID, `sign(message)`.
- **D4 Signers shipped.** `Ed25519WebCryptoSigner` and `P256WebCryptoSigner`
  (WebCrypto; the private key never leaves the platform), `MetaMaskSigner`
  (EIP-191 over any EIP-1193 `request`, no ethers dependency; tested with a
  simulated wallet built on `@noble/curves`), and `CredentialsSigner` for
  in-module signing with `SigningCredentials`. WebAuthn is typed
  (`SignatureValue` variant) but has no signer: it needs a browser
  authenticator and cannot be tested here.
- **D5 Fixtures are not built-ins.** `auditTemplate*` and
  `TemplateSource.auditFixtures` carry the caveat in their doc comments, the
  README, and the example; `TemplateSource.fromDefinitions` is the
  production path and the test proves both produce identical source trees.
- **D6 Workspace-wide release profile.** `[profile.release]` with
  `opt-level = "z"` and `lto = true` lives in the root `Cargo.toml` because
  cargo profiles are workspace-wide. Native release builds of the core and
  its two dev bins (`verify-templates`, `regen-unsupported`) inherit it;
  they are not performance-sensitive, CI builds them in the dev profile,
  and crates.io consumers set their own profiles. Recorded here so nobody
  wonders why `cargo build --release` optimizes for size.
- **D7 pnpm with a committed lockfile; scripts stay manager-agnostic**
  (`build: tsc`, `test: vitest run`, `typecheck`). The wasm package is a
  `file:../wasm/pkg` dependency, so `wasm-pack build` precedes
  `pnpm install`, and a rebuilt package needs a fresh install.
- **D8 Clippy is unavailable in this toolchain** (Nix rustc without the
  component); the CI `core` job still runs it on `ubuntu-latest`. The wasm
  crate is not added to that clippy step because it is empty on native
  (everything is `cfg(target_arch = "wasm32")`).
- **D9 Independent oracle only in tests.** `@noble/hashes` and
  `@noble/curves` are devDependencies. The shipped package has exactly one
  runtime dependency, the wasm package.

## Process notes

- Wire shapes were read from the Rust structs, not guessed. Two things the
  wasm doc comments say that the module does not do are recorded under
  "Known gaps" rather than papered over in the wrapper.
- A file genesis is two revisions (scalar anchor plus the typed `file`
  object); the first test draft assumed one. Genesis content hashing is
  pinned to SHA3-256 in `core::genesis` regardless of the builder's
  `hash_type`, while typed objects and signatures follow it; the e2e suite
  documents both.
- The `pseudonymous` preset for T2 discloses `signer_did`, `session_id`,
  `turn_id`, `created_at` and redacts `prompt_text`, with signatures `Full`
  (they must stay to verify). The wasm doc string on `pseudonymousPolicy`
  ("signer identities hidden, content disclosed") describes it backwards;
  the test pins the actual behaviour from `src/core/disclosure.rs`.
- Local verification (all from a clean state):
  `pnpm install` (75 packages resolved, wasm package linked from
  `file:../wasm/pkg`), `pnpm typecheck` (clean), `pnpm build` (clean),
  `pnpm test` (6 files, 58 tests passed), `node examples/node-example.mjs`
  (file tree verified, external signature verified, audit tree verified
  with `missingTemplates == []`, selective tree verified), `cargo check
  --locked --target wasm32-unknown-unknown -p aqua-rs-sdk-core-wasm`,
  `cargo fmt --all --check`, `cargo check --locked`, and `wasm-pack build
  wasm --target web --release --out-dir pkg -- --locked`.

## Known gaps

- **Linked-tree template resolution prunes unreachable trees.**
  `collect_linked_tree_order` (`src/core/structural.rs`) only verifies and
  consults linked trees reachable from the main tree's anchors. A derived
  template's ancestor (e.g. `audit_artifact` behind `audit_user_prompt`)
  supplied as a separate source tree is never reached, and verification
  fails with `ANCESTOR_TEMPLATE_NOT_FOUND`. The wasm doc comment on
  `verifyAquaTreeWithLinkedTrees` ("template source trees from
  `templateTree` belong here") is therefore only true for root templates.
  The wrapper documents `exportTree` as the path for derived templates and
  the audit suite pins the failing case. Core-side fix candidates: walk
  `ancestry` of resolved templates when building the dependency graph, or
  have `templateTree` emit an anchor that links the ancestry.
- **`builtinTemplateTree` keys by bare digest.** Its doc comment says
  "keyed by its full multihash link"; the core's `builtin_template_tree`
  returns a tree keyed by the 32-byte digest (`0x<64 hex>`), not
  `0x1620...`. The test pins the actual key; the wasm doc comment should be
  corrected on the Rust side.
- **No WebAuthn signer** (D4). **No `didFromSecp256k1SecretKey`**, so
  `CredentialsSigner.did` is `undefined` for `secp256k1_key` credentials;
  the DID is still recorded correctly by the module at signing time.
- The npm package is not published; `aqua-core-js` is a local name and the
  wasm dependency is a path. Publishing would need the wasm package
  published first (or bundled) and an `exports` map on it.
