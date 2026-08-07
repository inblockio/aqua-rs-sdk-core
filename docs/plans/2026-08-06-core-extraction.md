# Plan: aqua-rs-sdk-core extraction + standalone template registry

Date: 2026-08-06. Pipeline: process-pipeline (logic-model planning, subagent execution, hypothesis-traced audit).
Approval: Tim ordered end-to-end execution with integration-test verification (2026-08-06), waiving the interactive gate. Decision defaults recorded below.

## What this prompt serves (reflection, higher-order goal)

The higher-order goal is community adoption of the Aqua protocol on a timeline the full SDK cannot meet. The full aqua-rs-sdk carries WASM compute, a policy engine, a daemon, and timestamping providers that are still in active development and not ready to publish. The community (and agent builders specifically) need a small, auditable, Apache-2.0 crate today that can: create and verify anchor/object/template revisions, sign with the base algorithms, and record agent actions as verifiable audit trails (t1-t8). Publishing a compatible subset now builds the ecosystem while development continues; compatibility (byte-identical template hashes, identical canonicalization and verification semantics) guarantees artifacts flow between community core and full SDK in both directions. The one intentionally missing piece, template distribution, becomes its own standalone registry project so the community can register and subscribe to templates by publisher DID without waiting for the SDK's deferred "module ecosystem" work.

IF-THEN test: IF a developer can `cargo add aqua-rs-sdk-core` and produce/verify audit trails that the full SDK accepts, THEN the community can build on Aqua now, and nothing published constrains the unreleased components.

## Logic model

### CONTEXT (established by 4 exploration agents, reports in session record)
- `--no-default-features` build passes but does NOT approximate the core: compute/host/timestamp/identity/registry compile unconditionally. Manual extraction required.
- Clean cuts: core/timestamp (0 inbound edges), core/identity (0 edges), registry (one 4-line struct leak via template_registration, which core drops), policy/daemon (already feature-gated), WASM bindings (lib.rs only).
- Compute severs at a types-only boundary: copy `core/compute/mod.rs` (288 LOC serde types incl. wire-format field `Template.verification`), stub `verify_revision_compute`. The audit templates themselves have `verification: absent`, BUT their ancestry root `identity_base` carries an embedded WASM module (verified in identity_base.json), and `collect_ancestor_verifications` gathers the whole chain, so the full SDK executes WASM for every audit revision. Core therefore needs deliberate skip semantics (see D7), and pass/fail parity is an empirical claim the compat tests must prove.
- disclosure.rs (pseudonymous redaction) and the audit templates are bidirectionally coupled; extracted together.
- Template closure (23 files + mod.rs): 11 audit files (T1-T8 + audit_artifact + audit_round_anchor + audit_session_close), identity_base (ancestry root), template_meta, anchor_template, 5 signature templates, file (needed by core/genesis.rs and core/object.rs), plus timestamp_base/evm/tsa retained for classification only (revision_kind.rs references them unconditionally; trees from the full SDK contain timestamp forks). manifest is NOT needed (core/manifest.rs drops with it). audit_round_anchor and audit_session_close are deliberately absent from the original's builtin caches; core mirrors that exactly (D6) and documents the embed-the-template pattern.
- Minimal dep set: 18 runtime deps (drops wasmi, wasm-bindgen family, tracing, unicode-*, chrono, regex, bytes/futures, wat; tokio moves to dev-deps).
- Compat precedent: `verify-templates --fix` + `tests/audit_template_hashes.txt` golden file; deterministic test key `(1..=32).collect()`; seed fixtures in `src/tests/seed/`.
- Registry subgoal has a normative spec already: aqua-spec `extensions/spec-type-registry.md` (publisher-DID resolution §3.7) and `spec-module-ecosystem.md` §7-8 (registry API shape). SDK explicitly defers this. Greenfield.

### GOAL
One sentence: publish-ready `aqua-rs-sdk-core` crate (anchor/object/template primitives, base signatures, t1-t8 audit templates, WASM-free) proven hash- and verification-compatible with aqua-rs-sdk by integration tests, plus a scaffolded standalone template-registry project keyed by publisher DID.

### INPUTS
- Source: `~/aqua-rs-sdk` (read-only; never modified by this project).
- Specs: `~/aqua-spec` (canonicalization PCAs, type-registry and module-ecosystem extensions).
- Docs to adapt: README minimal-usage, REF-0001 (L1-L3 model), REF-0003 (template authoring).
- Deterministic fixtures: seed trees + audit_template_hashes.txt.
- Skills: core-developer (Tier 0 discipline for all protocol-path edits).

### BOUNDARY CONDITIONS (what must not happen)
- B1: Template JSON bytes are never edited. Template hash = type identity.
- B2: No behavioral edits to canonicalization, hashing, Merkle, DID, or signature code. Copy verbatim; only module-wiring edits allowed.
- B3: Fail closed, never silently pass: templates carrying WASM `verification` are rejected with a clear error; unsupported revision kinds report explicit status.
- B4: `~/aqua-rs-sdk` stays untouched.
- B5: Hard scope: no policy engine, no daemon, no WASM runtime/bindings, no timestamp creation or providers, no template registry inside core, no templates beyond the closure listed above (structural necessities documented as such).
- B6: No new dependencies in verification paths; publish metadata must be self-contained (no path deps in [dependencies]).
- B7: The example never names the customer product or any customer implementation.
- B8: Build artifacts on disk (repo target/), never in the tmpfs scratchpad.

### DECISION DEFAULTS (taken under Tim's end-to-end execution order)
- D1 (superseded 2026-08-07 by Tim): T5 ships as `audit_api_response`, renamed from its customer-derived historical identifier, and the customer-derived example strings were scrubbed from the T4 and T5 JSON descriptions. Both hashes deliberately forked before publication; upstream migration of the full SDK to the same definitions is the follow-up that reunifies the type identities.
- D2: timestamp_base/evm/tsa template JSONs are retained as built-ins for revision classification and structural (batch-inclusion Merkle) verification, matching the full SDK's local behavior. No timestamp creation API, no providers. Documented in the conformance profile.
- D3: Repo layout: this folder is a workspace: root package `aqua-rs-sdk-core` (publishable) + `compat-tests/` (publish = false, path deps on both SDKs).
- D4: Feature `native` retained with original semantics; `default = ["native"]` so EIP-191 signing works out of the box.
- D5: Registry project lives at `~/aqua-template-registry`, implemented by a standalone Opus agent spawning Sonnet subagents, against the shapes in spec-type-registry.md / spec-module-ecosystem.md.
- D6: Builtin cache membership mirrors the original exactly (audit_round_anchor / audit_session_close stay uncached; KNOWN_UNCACHED updated to the reduced set). Portability pattern (embed template revisions in exported trees) documented instead.
- D7: Compute stage semantics in core: if every WASM-carrying template in the resolved ancestor chain is a core built-in (identity_base, timestamp_evm, timestamp_tsa), skip execution and report an explicit compute-skipped status without failing the revision; if any non-built-in template carries `verification`, fail closed with a clear error code. Rationale: Tim's prompt accepts losing wasm-template execution in core; invariant preserved: core is never more permissive than the full SDK.
- D8: schema/timestamp.rs (TimestampValue conversions) drops with core/timestamp; the Evm/Tsa payload structs live in the kept template .rs files. core/manifest.rs and the manifest template drop (no kept-path references). Host traits (blockchain/web/identity/trust_store) drop; core verify entrypoints take no host parameters (API subset, wire-compat unaffected).

## Hypothesis register

| ID | If | Then | Assumptions | Verification |
|----|----|------|-------------|--------------|
| H1 | Kept modules are copied per the edge list and compute is reduced to types-only | `cargo check` passes; no wasmi/wasm-bindgen/js-sys/web-sys in the dep tree | Edge list from exploration is complete | `cargo check` + `cargo tree -e normal \| grep -cE 'wasmi\|wasm-bindgen\|js-sys\|web-sys'` = 0 |
| H2 | Template JSONs copied byte-identical | Every TEMPLATE_LINK constant equals the original's | Hash constants derive only from JSON bytes + fixed algorithm | sha256sum diff of JSON files; compat test comparing constants; verify-templates cascade over subset |
| H3 | Canonicalization/hash code copied unmodified | Identical construction yields identical revision hashes cross-crate | No hidden config divergence (Method, HashType defaults) | compat test: build identical trees in both crates, assert equal revision links and byte-equal canonical JSON |
| H4 | Signature code copied unmodified | Sign in core, verify in original, and vice versa (ed25519, eip191, p256, webauthn-verify) | Deterministic key fixtures valid | compat cross-verification tests + seed fixture sign_did_example verifies in core |
| H5 | verify_revision_compute replaced by a stub: built-in-only WASM chains skipped with explicit status, non-built-in WASM templates rejected with clear error | is_verified parity with the full SDK for the core template subset; core never more permissive than the full SDK | Full SDK with DefaultIdentityHost passes audit trees; wasm_state strings are metadata, not pass/fail | same-fixture verify parity original vs core (is_verified + error codes); negative test with a custom compute-carrying template |
| H6 | Timestamp templates retained as data-only built-ins | Trees with timestamp forks from the full SDK verify in core with identical local statuses | Local timestamp verification = structural + batch-inclusion only | seed fixtures timestamp_eth/tsa verified in both crates, statuses compared |
| H7 | Example uses only core public API | agent_audit_trail example compiles, runs a full turn (T1-T8 + round anchor + session close, 4 roles), verifies green | - | `cargo run --example agent_audit_trail` |
| H8 | Docs cover WASM-free build + template authoring | A developer can author a custom template and verify objects against it using core alone | create_template path has no WASM dependency | authoring test: create_template, create_object, verify |
| H9 | Registry reuses NameValidator rules + registration JSON shapes + spec §3.7 DID resolution | Its registration trees are ingestible/verifiable by the full SDK unchanged | spec shapes are current | registry integration test: construct trees, verify with SDK path dep |
| H10 | Publish metadata complete, no path deps in [dependencies] | `cargo publish --dry-run` succeeds | crates.io name availability not required for dry-run | `cargo publish --dry-run --allow-dirty` |

## Tasks

### Task 1: Scaffold repo (H10)
git init -b main; Apache-2.0 LICENSE + NOTICE; .gitignore; workspace Cargo.toml (root package + compat-tests member); dep versions copied from original Cargo.toml.

### Task 2: Mechanical extraction (H1, H2)
Copy: primitives/, verification/, utils/, schema top-level, schema/templates closure set, core kept files + signature/ + compute/mod.rs (types only), bin/verify_templates.rs. Byte-identical JSON copies (B1).

### Task 3: Adaptation edits, Tier 0 discipline (H1, H5, H6)
Trim: schema/templates/mod.rs, core/mod.rs, lib.rs facade (drop registry/policy/daemon/wasm/timestamp-creation/identity APIs), verify_stages builtin table to closure set, verify_common ResolvedHosts/compute plumbing, verify_revision_compute fail-closed, primitives/timestamp.rs native arm only, template_registration references removed. Each edit minimal and reviewed against the seven questions.

### Task 4: Green build + inline tests (H1)
cargo check/test/clippy; curate surviving inline #[cfg(test)] tests; port compatible src/tests subset (audit_template_disclosure, sign*, link, blake3_e2e where compilable).

### Task 5: Compat integration tests (H2, H3, H4, H5, H6)
compat-tests crate with path deps on both SDKs: template hash parity, canonical-JSON byte parity, revision hash parity, cross-verification both directions, seed fixtures, negative compute-rejection test, WASM-free tree check.

### Task 6: Golden template hashes + verify-templates port (H2)
Port bin; generate subset golden file; wire as test.

### Task 7: Docs (H8)
README (what it is, conformance profile: in/out, unsupported-kind behavior, quick start), docs/template-authoring.md (WASM-free path, adapted REF-0003), build instructions, LICENSE/NOTICE.

### Task 8: Agent auditability example (H7)
examples/agent_audit_trail.rs: generic assistant turn, 4 keys (server, user + session delegate, agent, api attestor), T1-T8 + round anchor + session close, disclosure preset demo, verify at end. Neutral naming (B7).

### Task 9: Registry subgoal via Opus agent (H9)
Launch after Task 4 (core API stable). Standalone Opus agent spawning Sonnet subagents; project at ~/aqua-template-registry; scope: register/subscribe templates by publisher DID, persistent index (DID -> vendors -> templates), serve full signed trees, NameValidator rules verbatim, spec-module-ecosystem §7-8 API shape; own README + tests.

### Task 10: Audit (all H)
Layer 1 hypothesis trace with actually-run commands; Layer 2 acceptance criteria; report to Tim; remediation loop if needed.

## Acceptance criteria

| # | Criterion | Hypotheses |
|---|-----------|------------|
| AC1 | Core builds WASM-free (no wasmi/wasm-bindgen family anywhere in dep tree) | H1 |
| AC2 | t1-t8 templates ship with byte-identical hashes | H2 |
| AC3 | Integration tests against original SDK pass (parity + cross-verification + seeds + fail-closed negative) | H3-H6 |
| AC4 | Plug-and-play docs: quick start, build, template authoring, conformance profile | H8 |
| AC5 | Generic agent-auditability example runs and verifies, no customer naming | H7 |
| AC6 | Standalone registry project exists with publisher-DID register/subscribe design, SDK-verifiable trees, tests green | H9 |
| AC7 | Apache-2.0 publish-ready (cargo publish dry-run) | H10 |
