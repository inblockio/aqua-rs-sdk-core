# Plan: essential core (round 2)

Date: 2026-08-07. Pipeline: process-pipeline. Approval: Tim, "Yes Execute
it!", with three directives: (1) remove identity_base and re-root the audit
family, (2) timestamp_evm/timestamp_tsa (and companions) become entries in a
known-but-unsupported hash lookup drawn from the SDK, answered with an
explicit "not supported, requires <module>" message, (3) the 11 re-rooted
audit templates become the first template set published with the registry.

## Goal (one sentence)

Core ships zero WASM bytes and only templates it fully verifies; every other
known SDK template hash gets an explicit unsupported answer; the audit set is
published through aqua-template-registry.

## Design decisions

- E-D1: `audit_artifact` becomes a root template (revision_type stays the
  template_meta multihash, no derives_from/ancestry); all ten derived audit
  templates get ancestry `[audit_artifact]`. identity_base.{json,rs} leaves
  core. All 11 audit hashes fork (deliberate, pre-crates.io; upstream
  migration = scrub + re-rooting in one move).
- E-D2: timestamp_base/evm/tsa templates leave core entirely. A new module
  `primitives::unsupported` carries a static lookup of known full-SDK
  template hashes (drawn from the full SDK's catalog: timestamps, identity
  family, claims, policy, registration, manifest, and the pre-fork T4/T5)
  with name + required module. Template resolution misses consult it and
  report code TEMPLATE_UNSUPPORTED with the explicit message, routed through
  the existing template_not_found policy decision (strict rejects, a
  tolerant policy may proceed). Timestamp classification constants move to
  this module; RevisionKind behavior is unchanged.
- E-D3: With no shipped template carrying WASM, the compute stub simplifies:
  any verification-carrying chain fails closed with COMPUTE_UNSUPPORTED. A
  unit test enforces "no shipped template has a verification section".
- E-D4: Cross-SDK audit compatibility becomes the portable-template pattern
  (embed the audit template revisions or pass them as linked trees); the
  compat suite proves core-produced audit trees still verify in the full
  SDK that way.
- E-D5: Registry publication: the existing registry agent (with its build
  context) adds a publisher tool + committed, signed seed set: one vendor
  registration plus 11 template registrations for the new audit hashes,
  template definition trees included, private key kept out of the repo.

## Hypothesis register

| ID | If | Then | Verification |
|----|----|------|--------------|
| E1 | Audit family re-rooted at audit_artifact | Audit trees verify data-only in core, no WASM anywhere in the chain, all suites green | cargo test --workspace; example run; verify-templates cascade |
| E2 | Only ancestry/derives_from (+ the two description scrubs) changed | Divergence vs full SDK is exactly that | extended t4_t5 divergence test covering all 11 |
| E3 | Embed-the-template pattern | Core-produced audit trees verify in the full SDK | updated compat cross-verification test |
| E4 | Unsupported lookup wired into resolution misses | Known SDK hashes yield the explicit message; strict rejects; core never more permissive than the full SDK on timestamp seeds | updated timestamp-seed compat test + lookup unit test |
| E5 | Timestamp/identity templates removed | Zero WASM bytes shipped: no template JSON contains a verification section | new unit test + grep |
| E6 | Registry publishes the audit set | Vendor + 11 registrations signed, stored, resolvable by publisher DID, replayable | registry tests + committed seed + replay |
| E7 | Packaging intact | publish dry-run passes; docs consistent | cargo publish --dry-run; README/profile updated |

## Boundaries

- Full SDK stays untouched; wire shapes of kept machinery unchanged; no new
  runtime dependencies; fail-closed everywhere; no private keys committed.

## Execution record (audit addendum, 2026-08-07)

| ID | Status | Evidence (actually run) |
|----|--------|--------------------------|
| E1 | Confirmed | `cargo test --workspace` exit 0: 367 lib + 10 bin + 11 compat + 1 doctest; example exit 0; `verify-templates`: "All 19 templates verified. No drift detected." |
| E2 | Confirmed | compat `audit_family_divergence_is_intentional`: all 11 pairs hash-differ AND are JSON-identical after removing derives_from/ancestry/descriptions. |
| E3 | Confirmed | compat `audit_turn_marker_cross_verifies`: core-signed re-rooted T1 tree with embedded T1 + audit_artifact template revisions returns Verified from the full SDK. |
| E4 | Confirmed | compat `timestamp_seeds_policy_parity`: strict rejects in both crates and core's log names "the timestamping module"; offline verifies-with-warnings in both (core via template_not_found, full SDK via timestamp_unavailable). |
| E5 | Confirmed | `no_shipped_template_carries_wasm` walks the templates dir; `cargo tree` has zero wasm crates; the lookup carries 53 known full-SDK hashes. |
| E6 | Confirmed | registry tip bc20866: 60 unit + 4 audit_set (+1 ignored staleness, run: pass) + 11 e2e + cross-sdk 4/4 ignored-run green, all exit 0; 12 signed seed registrations committed, no key file in any ref; all 11 manifest hashes equal core's ledger (verified independently by the orchestrator). |
| E7 | Confirmed | `cargo publish --dry-run` passes; README conformance profile rewritten (zero-WASM claim, unsupported-lookup row). |

New audit hashes are recorded in tests/audit_template_hashes.txt (root
audit_artifact 0x431668e5...; full list in the ledger).

Process notes (honest record): a mid-round splice truncated
verify_stages.rs (recovered from git HEAD with edits re-applied and the
function-set audit repeated), and one commit was pushed with a broken
test build because a shell pipeline masked the failure; it was fixed and
amended with force-with-lease within a minute (tip 14aa77d). Both
mistakes repeat a pattern from round 1: verify with exit codes, never
with grep counts.

Follow-ups: upstream aqua-rs-sdk migration now covers the re-rooting +
rename + scrubs in one move; the unsupported lookup should be
regenerated when upstream's catalog changes (script-assisted, see module
docs); registry seed set seed/audit-set-v1 (vendor `inblockio`, publisher DID
did:key:z6MkqDxSY5Z3gMNR2qKzV9ZwZDLwUYi5DqevZWhR7vaDWLCN, registry tip
bc20866) is the distribution channel for the new family. Registry-agent
findings fed back to the core backlog: a RevisionLink::bare_digest()
helper (the multihash-vs-bare-digest split is a live footgun), a
programmatic builtin_template_hashes() accessor (the ledger is a text
file under tests/ that publishers must parse by hand), and an
`abstract` marker for audit_artifact (nothing machine-readable
distinguishes it from instantiable templates).
