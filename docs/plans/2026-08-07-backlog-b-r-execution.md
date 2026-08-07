# Plan: backlog execution round (B-items and R-items)

Date: 2026-08-07. Pipeline: process-pipeline, list mode. Approval: Tim
("B and R executions with subagents after handover"). Out of scope by
direction: A1-A8 (upstream SDK, backlog-tracked only, see HANDOVER.md) and
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
