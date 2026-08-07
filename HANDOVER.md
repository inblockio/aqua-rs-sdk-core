# Handover

Date: 2026-08-07. State of the aqua-rs-sdk-core and aqua-template-registry
projects after the extraction, essential-core, publication, trust, and
self-descriptiveness rounds. Written for whoever continues the work, human
or agent.

## What exists

1. **aqua-rs-sdk-core** (github.com/inblockio/aqua-rs-sdk-core). Apache-2.0,
   WASM-free compatible subset of the full aqua-rs-sdk. 19 data-only
   templates: 8 byte-identical with the full SDK (template_meta,
   anchor_template, the 5 signature templates, file) and the 11 audit
   templates (t1-t8 plus audit_artifact, audit_round_anchor,
   audit_session_close), deliberately re-rooted at audit_artifact and
   forked from the full SDK. Zero WASM bytes, unit-test enforced. The
   `primitives::unsupported` lookup answers every known full-SDK hash core
   does not ship with "not supported, depends on <module>". Self-descriptive
   exports via `Aquafier::export_tree` (embed-by-default, `ExportOptions::bare()`
   opt-out). Verification is policy-governed (strict/offline), always
   fail-closed, and never more permissive than the full SDK under equal
   policy.
2. **aqua-template-registry** (github.com/inblockio/aqua-template-registry).
   Standalone register/subscribe service keyed by publisher DID. Registration
   is submission of signed Aqua trees, verified with core before acceptance.
   Consumer side: subscribe CLI and library with a fail-closed trust layer
   (required publisher allow list, lockfile hash pins, PinnedOnly default,
   ApproveNew only as a CLI flag, WASM definitions rejected, hash-keyed
   inert store). Feed integrity: publisher-signed feed heads (custom
   `feed_head` template, Merkle commitment per the byte-exact definition in
   the README trust model); subscribers fail closed on mismatch, rollback,
   withholding, and equivocation.
3. **The published template set**: `seed/audit-set-v1/` in the registry repo.
   Vendor `inblockio`, publisher DID
   `did:key:z6MkqDxSY5Z3gMNR2qKzV9ZwZDLwUYi5DqevZWhR7vaDWLCN`, 12 signed
   registrations plus the signed feed head and the 11 template bodies.
   The publisher private key is at `~/.aqua-registry-publisher/inblockio.key`
   (mode 0600) on the build machine and exists in no repository.

## How to verify everything (exit codes, not grep counts)

    # core (needs a sibling checkout of the full aqua-rs-sdk for compat-tests)
    cd aqua-rs-sdk-core
    cargo test --workspace && echo OK
    cargo run --features native --bin verify-templates
    cargo run --example agent_audit_trail --features native

    # registry (needs ../aqua-rs-sdk-core; cross-SDK extras need ../aqua-rs-sdk)
    cd aqua-template-registry
    cargo test && echo OK
    cargo test --test cross_sdk -- --ignored
    cargo test --test audit_set -- --ignored

## Where decisions and evidence live

- Plans and audits (hypothesis registers, executed evidence, honest process
  notes): `docs/plans/2026-08-06-core-extraction.md`,
  `docs/plans/2026-08-07-core-extraction-audit.md`,
  `docs/plans/2026-08-07-essential-core.md` in the core repo.
- The canonical hash ledger: `tests/audit_template_hashes.txt` (regenerate
  with `verify-templates`).
- Trust model and feed-head wire definition: the registry README.

## The backlogs are the single source of open work

- Core: `BACKLOG.md` (this repo). **Section A tracks the upstream SDK
  changes and is deliberately execution-blocked from this side**: A1-A8 are
  ONE atomic migration inside the full aqua-rs-sdk (re-root, rename, scrub,
  cascade, spec updates) and must be executed by whoever owns that repo.
  Partial adoption would mint a third set of audit type identities. The
  acceptance signal is objective: core's compat test
  `audit_family_divergence_is_intentional` must flip to failing, after which
  the audit templates return to the byte-identical parity lists.
- Registry: `BACKLOG.md` in the registry repo (R-items).
- Both files carry status markers and dates; done items keep their evidence
  references.

## Open decisions for the maintainers

1. crates.io publication of aqua-rs-sdk-core (`cargo publish --dry-run`
   passes; compat-tests are excluded from the package).
2. The upstream A1-A8 migration window.
3. README layer taxonomy: the Implemented / Not implemented section (L1
   revision objects, L2 template-typed trees) and an older sentence
   describing "the full L1-L3 pipeline" use different layer numberings.
4. Whether the git history should be squashed before wider announcement
   (early commits contain the pre-rename T5 identifier).

## Gotchas that cost time once already

- Template hash = type identity. Never edit a shipped template JSON; forks
  are deliberate, cascade-fixed, and test-guarded.
- Linked or embedded template revisions must be keyed by the full multihash
  link, never the bare 32-byte digest.
- "Built-in" is receiver-relative: tests of template distribution against
  core built-ins are vacuously green; use synthesized templates plus a
  negative control.
- `BuiltInTemplate::TEMPLATE_JSON` defaults to the empty string; compare
  template files, not that constant.
- `merkle_root(&[])` panics (backlog B9); guard empty input until fixed.
- Verify with exit codes; shell pipelines through grep have masked two real
  failures in this project's history.
