# Changelog

All notable crates.io releases of `aqua-rs-sdk-core`. Version identity is
`Cargo.toml` = git tag `vX.Y.Z` = crates.io `X.Y.Z`. See [RELEASE.md](RELEASE.md).

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
