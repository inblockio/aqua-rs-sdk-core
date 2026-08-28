# Changelog

All notable crates.io releases of `aqua-rs-sdk-core`. Version identity is
`Cargo.toml` = git tag `vX.Y.Z` = crates.io `X.Y.Z`. See [RELEASE.md](RELEASE.md).

## Unreleased

- WebAssembly bindings and a TypeScript wrapper, without touching the core's
  public API or crate type. New workspace member `wasm/`
  (`aqua-rs-sdk-core-wasm`, `publish = false`) exports the Aquafier surface,
  keys and DIDs, template catalog and audit fixtures, selective disclosure,
  and hashing over a JSON-string boundary; `js-sdk/` (`aqua-core-js`) types
  it, adds external signing (`prepareSignature` / `addExternalSignature`,
  WebCrypto Ed25519 and P-256 signers, an EIP-191 signer over EIP-1193
  providers), and `TemplateSource` for registry template definitions. CI
  gains a `wasm-js` job. See
  [docs/plans/2026-08-28-typescript-wrapper.md](docs/plans/2026-08-28-typescript-wrapper.md).
- Core changes limited to wasm32 support: `getrandom` JS backends and
  `js-sys` as wasm32-only dependencies, `current_time_secs()` reads
  `js_sys::Date::now()` on wasm32, and a workspace `[profile.release]`
  (`opt-level = "z"`, `lto = true`) that native release builds of the core
  and its two dev bins inherit. Native debug builds and tests are unchanged.

## 0.1.1 - 2026-08-14

- Audit family left the built-in verification catalog (B11). Agent templates
  are retrieved from `aqua-template-registry` (`audit-set-v1`) and passed as
  explicit sources to `create_object_validated` / `export_tree` / verify.
- Audit-family hashes reunified with `aqua-rs-sdk` (A1–A5). The 11 JSON
  files are byte-identical; core no longer catalog-resolves them.
- Spec §8 / §8.1 / §8.2 updated: catalog is the 8 machinery and signature
  templates; the audit identities are registry-distributed.

## 0.1.0 - 2026-08-08

- Initial crates.io release. WASM-free core profile: genesis, objects,
  templates, signatures (Ed25519, EIP-191, P-256, WebAuthn verify),
  selective disclosure, self-descriptive export.
