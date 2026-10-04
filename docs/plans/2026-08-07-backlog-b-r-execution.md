# Plan: backlog execution round (B-items and R-items)

Date: 2026-08-07. Pipeline: process-pipeline, list mode. Approval: Tim
("B and R executions with subagents after handover"). Out of scope by
direction: A1-A8 (upstream SDK, backlog-tracked only, see [HANDOVER.md (archived)](https://github.com/inblockio/aqua-rs-sdk-core/blob/eed9275b2d712e3a78db00d49a3cd58e3849216c/HANDOVER.md)) and
B5 (spec-gated wire-format change, stays tracked).

## Scope and design constraints per item

Core (executor: the export-round agent, resumed; Opus-class):
- B1 `RevisionLink::bare_digest()`: additive accessor (multihash or bare in,
  bare 32-byte out; mirror template_digest_key semantics), rustdoc, tests.
- B2 `builtin_template_hashes()`: public accessor derived from the built-in
  catalog (name, bare digest), test asserts it matches the ledger file.
- B3 `generate_ed25519()` (or equivalent): keypair generation returning the
  32-byte secret usable with SigningCredentials::Did plus the derived DID.
- B4 `Aquafier::template_tree(&Template)`: single-revision tree keyed by the
  FULL multihash link (the verifiable form), rustdoc pointing at the
  portable-template pattern; export_tree may reuse it internally.
- B6: additive only. A validated creation path for custom templates given
  explicit template sources; the existing create_object behavior is
  unchanged; loud documentation in README and the authoring guide.
- B7: GitHub Actions workflow: standalone job (build, test, clippy,
  verify-templates, example) plus a compat job cloning the public
  inblockio/aqua-rs-sdk as sibling. Local verification = run the workflow's
  command list; the live CI run is checked after push.
- B8: committed regeneration script for primitives::unsupported with usage
  docs; running it now must be a no-op against the current full SDK.
- B9: NON-breaking: keep merkle_root as-is (verbatim-copy parity with
  upstream), add a checked variant (try_merkle_root returning Result or
  Option) plus rustdoc on the panic; tests for empty input.
- B10: TEMPLATE_META_REVISION_TYPE string constant (test-tied to
  TemplateMeta::TEMPLATE_LINK); merkle &HashType alignment ONLY if it stays
  non-breaking, otherwise document and skip with a note.

Registry (executor: the registry agent, resumed; Opus-class):
- R5: alias registrations for the audit set (short names), additive seed
  files, registry acceptance + resolution tests.
- R6: design note (SSE or webhooks) as a committed doc; no implementation.
- R7: write-path concurrency test (two simultaneous same-name submissions:
  exactly one accepted, one 409-equivalent, store consistent).
- R8: store versioning/migration note (documented policy, record version
  field if cheap and backward-compatible).
- R9: CI workflow (test with ../aqua-rs-sdk-core sibling clone; cross-SDK
  ignored job gated on the full SDK's availability).
- R11: provenance annotations in the trust config (per-DID: source,
  verified-by, date), backward compatible with existing config files
  (version handling explicit); shipped example updated.
- R12: DESIGN NOTE ONLY (key rotation needs continuity proofs signed by old
  and new keys and consumer pin migration; protocol-shaped, do not
  implement in this round; refine the backlog item with the design).
- R13: head freshness: subscriber-side max-age policy verified against a
  SIGNED timestamp of the head (use existing signed fields if sufficient;
  if a payload field is required, version the project-owned feed_head
  template explicitly as a new hash with both accepted during transition);
  fail closed on stale beyond policy; tests.
- R14: cross-registry corroboration: client compares a publisher's heads
  across N registry base URLs, flags equivocation and lag; CLI surface;
  test with two live registryd instances.

## Hypothesis register

| ID | If | Then | Verification |
|----|----|------|--------------|
| P1 | B1-B4, B6, B8-B10 land additively | core workspace green, clippy baseline unchanged, no template/hash/verification semantics change | cargo test --workspace exit 0; verify-templates; stash-compared clippy |
| P2 | B2 accessor derives from the catalog | accessor equals the ledger file entry-for-entry | dedicated test |
| P3 | B7/R9 workflows encode the real commands | every command in the workflows passes locally | scripted local run of workflow steps |
| P4 | R5, R7, R11, R13, R14 land | registry default suite green including new negatives (stale head, equivocating mirrors, concurrent writes) | cargo test exit 0; named negative tests |
| P5 | R11/R13 config changes are compatible | pre-existing trust configs and seed replay still pass | existing tests untouched and green |
| P6 | R6/R8/R12 are notes | committed docs, backlog refined, no code paths changed | git diff scope check |
| P7 | Both repos remain publishable | core publish dry-run passes; both trees clean, every commit compiles | cargo publish --dry-run; per-commit check |

## Acceptance criteria

AC1 all in-scope items marked [x] in the backlogs with dates and file refs
(B5, A1-A8, R12-implementation excluded by design). AC2 all suites green by
exit code in both repos, clippy baselines not worsened. AC3 orchestrator
independently re-runs the verification battery before pushing. AC4 audit
addendum appended to this file with the trace.

## Audit addendum: core side (2026-08-07)

Executed: B1, B2, B3, B4, B6, B7, B8, B9, B10. Out of scope by direction and
left open: B5 (spec-gated wire-format change) and A1-A8 (upstream).

| Item | Landed as | Evidence |
|---|---|---|
| B1 | `RevisionLink::bare_digest` / `bare_digest_hex` | `src/primitives/mod.rs`, 5 tests |
| B2 | `builtin_template_hashes`, `shipped_template_hashes`, `shipped_templates` | `src/core/verify_stages.rs`, 5 tests incl. ledger equality |
| B3 | `generate_ed25519` | `src/core/signature/sign_did.rs`, 3 tests |
| B4 | `Aquafier::template_tree` | `src/core/template.rs`, 3 tests |
| B6 | `Aquafier::create_object_validated` | `src/core/object.rs`, 6 tests |
| B7 | `.github/workflows/ci.yml` | every command run locally, all exit 0 |
| B8 | `src/bin/regen_unsupported.rs` | regeneration is a no-op against the current full SDK |
| B9 | `merkle::try_merkle_root` | `src/primitives/merkle.rs`, 3 tests |
| B10 | `primitives::TEMPLATE_META_REVISION_TYPE` | `src/primitives/revision_kind.rs`, 3 tests |

Hypothesis outcomes:

- **P1 holds.** All items are additive. No template JSON, hashing,
  canonicalization, signature, or verification-semantics path was modified;
  `verify-templates` reports "All 19 templates verified. No drift detected."
  `cargo test --workspace` exits 0 (404 lib, 10 bin, 11 compat, 5 doc).
  Clippy on `--lib --features native` stays at the inherited 14 warnings,
  confirmed by stash-comparing against the pre-round tree.
- **P2 holds, and is now enforced rather than asserted once.** The B2
  accessor is compared to `tests/audit_template_hashes.txt` entry for entry
  in both directions, and every row's digest is recomputed from its own
  template JSON, so neither the ledger nor the accessor can drift alone.
- **P3 holds for the core workflow.** Each of the twelve commands in
  `.github/workflows/ci.yml` was executed against this checkout; all exit 0.
  The live CI run is still unverified and depends on `inblockio/aqua-rs-sdk`
  being public, which the workflow file states plainly rather than hiding
  behind a skip.
- **P7 holds on the core side.** `cargo publish --dry-run` succeeds with the
  new binary inside the package; every commit compiles.

Deviation from the plan, recorded rather than silently dropped: B10's second
half (aligning `merkle`'s `&HashType` parameters with the by-value
convention) was NOT done. It is source-breaking for existing callers and
diverges a file that is a verbatim copy of the full SDK's. The plan gated it
on staying non-breaking, so it stays open in BACKLOG B10 with the reasoning
and the `impl Borrow<HashType>` alternative written down.

## Audit addendum: registry side + orchestrator verification (2026-08-07)

Registry: R5, R7, R8, R9, R11, R13, R14 implemented; R6 and R12 delivered as
design notes per plan; R12 backlog entry refined (dual-signed vendor_rotation
shape, out-of-band confirmation mandatory, key compromise explicitly
unsolvable cryptographically). New follow-ups recorded: R15 (corroboration in
sync proper), R16 (mirror independence is assumed, not checked), R17 (alias
repointing not expressible).

Hypothesis outcomes, registry side:
- P3 holds: all nine CI workflow commands executed locally, exit 0
  (caveats recorded in the workflow: fmt not repo-scoped with path deps,
  RUSTFLAGS -D warnings impossible against sibling warnings).
- P4 holds: default suite green by exit code (131 lib + 9 suites), named
  negatives for stale head, equivocating mirror, lag-vs-equivocation,
  unreachable mirror, and four admit-exactly-one concurrency races.
- P5 holds: audit-set-v1 byte-untouched; pre-existing trust configs and the
  seed replay pass unmodified.
- P6 holds: R6/R8/R12 changed docs only (plus the additive record_version).
- P7 holds: both trees clean, every commit compiles.

Notable honest correction by the executor: the initial R13 claim that a
signature revision's local_timestamp is malleable was DISPROVED by its own
probe test (core's pre-signature covers it); the doc comment records the
corrected reasoning. This is the desired failure mode: claims probed, not
assumed.

Orchestrator verification (independently re-run, all by exit code):
- core: workspace tests 0, example 0, verify-templates "All 19 templates
  verified. No drift detected.", publish --locked --dry-run 0,
  regen-unsupported --check 0. Stale rust-analyzer diagnostics on lib.rs
  disregarded after cargo confirmed the build.
- registry: default suite 0, cross-SDK --ignored 0, head_freshness 9/9,
  concurrency 6/6, alias seed present (13 files), both design notes present.

Pushed: core and registry mains advanced together after this addendum.
