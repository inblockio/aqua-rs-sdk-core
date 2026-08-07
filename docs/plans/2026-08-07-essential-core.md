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
