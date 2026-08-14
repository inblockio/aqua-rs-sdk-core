# Release discipline

crates.io versions are immutable. Git tags are cheap. Humans forget.
Those three facts are the whole design.

The number in `Cargo.toml` **is** the crate. The git tag `vX.Y.Z` **is**
that crate at that commit. crates.io `X.Y.Z` **is** that crate on the
public index. If any two disagree, the release is wrong. There is no
fourth source of truth.

## When a release happens

A release is a **timed event**, not a side-effect of merging:

1. The work is already on `main`.
2. CI on `main` is green.
3. Compat against the current `aqua-rs-sdk` `main` is green
   (`cargo test --manifest-path compat-tests/Cargo.toml`).
4. Then — and only then — one person (or one agent under instruction)
   runs `scripts/release.sh X.Y.Z`.

Do not bump the version inside a feature PR. Do not `cargo publish` by
hand. Do not tag a version that is not in `Cargo.toml`. Do not publish a
version that is not tagged.

`scripts/release.sh` is the only publish path. It refuses a dirty tree, a
non-`main` branch, a version already on crates.io, a missing compat
sibling, and a CHANGELOG that does not mention the version.

## Version numbers (0.1 series)

This crate is experimental (see the README disclaimer). Default bump is
**`0.1.z+1`**. Stay on `0.1.z` until Tim opens `0.2.0` on purpose.

| Bump | Use |
|---|---|
| `0.1.z+1` | The default. Docs, catalog policy, additive APIs, and even behaviour changes we accept cargo will pull under `aqua-rs-sdk-core = "0.1"`. |
| `0.2.0` | Only when we want cargo to **stop** auto-updating existing `0.1` pins. A deliberate new series, not a reflex. |

`0.1.1` (2026-08-14) already shipped the B11 catalog cut under the `0.1`
caret. That is the policy, not an accident: experimental crates.io
consumers opted into `0.1`.

## Compatibility with aqua-rs-sdk

Core is a **strict subset**, not a fork and not a peer:

- Shared machinery and signature template JSONs stay **byte-identical**.
- Hashes and canonicalization stay bit-for-bit the same.
- Core is **never more permissive** than the full SDK under the same
  verification policy.
- The 11 audit identities match the full SDK; they are
  **registry-distributed here**, built-in there. That is a distribution
  difference, not a type-identity difference.
- Core ships **zero WASM**. Templates whose chain carries `verification`
  are rejected (`COMPUTE_UNSUPPORTED`). Verify those trees with the
  full SDK, or — later — with a registry that has grown a WASM runtime.

The release script records the `aqua-rs-sdk` commit SHA it tested
against in the release commit message. That is the subset-proof, not
the version number.

The full SDK is unpublished. There is no version to lock to. Compat
is always against that repo's `main` at release time.

## Coordinated publish (core, then registry)

```
# 1. core — waits until crates.io serves the new version
cd aqua-rs-sdk-core && ./scripts/release.sh 0.1.2

# 2. registry — only if this release needs the new core (new API,
#    or you want the declared pin to move). Bump the
#    aqua-rs-sdk-core version= pin in registry Cargo.toml first,
#    then:
cd aqua-template-registry && ./scripts/release.sh 0.1.1
```

The two crates do **not** share a version number. They are different
products. The registry's `version =` pin on `aqua-rs-sdk-core` is the
coupling, and it must name a version that already exists on crates.io.

The registry may later accept WASM-carrying templates. That is a
registry-series decision (`0.2` or a feature flag), not a reason to
put a WASM runtime in core.

## Command

```
./scripts/release.sh 0.1.2           # interactive confirm
./scripts/release.sh --dry-run 0.1.2 # verify only, no commit/tag/publish
./scripts/release.sh --yes 0.1.2     # no prompt (still refuses a dirty tree)
```
