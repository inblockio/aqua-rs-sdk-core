# Audit: aqua-rs-sdk-core extraction + aqua-template-registry

Date: 2026-08-07. Phase 3 of the process-pipeline run planned in
[2026-08-06-core-extraction.md](2026-08-06-core-extraction.md).
Every "Confirmed" cites a command that was actually run against the final
tree (core tip `git log --oneline | head -1`, registry tip `f5aaf4b`).

## Layer 1: Hypothesis trace

| ID | Hypothesis | Status | Evidence |
|----|-----------|--------|----------|
| H1 | Manual module cut yields a WASM-free build | Confirmed | `cargo test --workspace`: 370 lib + 10 bin + 10 compat + 1 doctest green. `cargo tree -p aqua-rs-sdk-core -e normal \| grep -cE 'wasmi\|wasm-bindgen\|js-sys\|web-sys'` = 0. |
| H2 | Byte-identical template JSONs give identical type identities | Confirmed | compat `template_files_byte_identical` (all 23 files byte-equal across repos), `template_hash_constants_match` (all 23 LINK constants equal), `verify-templates`: "All 23 templates verified. No drift detected." |
| H3 | Unmodified canonicalization yields identical hashes | Confirmed | compat `canonical_template_hash_parity`, `tampered_tree_fails_in_both`, plus cross-verification (H4): verification recomputes every hash. |
| H4 | Signatures interoperate both directions | Confirmed | compat `core_signed_file_tree_verifies_in_full_sdk`, `full_sdk_signed_file_tree_verifies_in_core`, `seed_sign_did_fixture_verifies_identically`. |
| H5 | Compute stub: skip built-in WASM, fail closed otherwise, is_verified parity | Confirmed | compat `audit_turn_marker_cross_verifies` (core logs explicit skip, full SDK executes identity_base WASM, both Verified) and `custom_wasm_template_rejected_fail_closed` (COMPUTE_UNSUPPORTED). |
| H6 | Timestamp revisions: per-policy outcome parity, never more permissive | Confirmed | compat `timestamp_seeds_policy_parity`: strict rejects in both crates, offline tolerates in both, for the EVM and TSA seed fixtures. |
| H7 | Example runs a full turn on public API only | Confirmed | `cargo run --example agent_audit_trail --features native`: "ALL ARTIFACTS VERIFIED (10 trees: T1-T8, round anchor, session close)" plus disclosure demo, exit 0. |
| H8 | WASM-free custom-template authoring works end to end | Confirmed | docs/template-authoring.md written; the registry project dogfoods the flow (vendored registration templates as custom templates, built + signed + verified via core); example demonstrates the portable-template pattern for the two uncached built-ins. |
| H9 | Registry reusing SDK shapes stays SDK-compatible | Confirmed | Registry: 58 unit + 11 e2e + 1 doctest green; `cargo test --test cross_sdk -- --ignored`: 4/4 pass (vendored hashes equal full-SDK TEMPLATE_LINK constants; trees Verified under the full SDK), re-run independently by the orchestrator. |
| H10 | Publish-ready packaging | Confirmed | `cargo publish --dry-run --allow-dirty -p aqua-rs-sdk-core` verifies and compiles the package. Apache-2.0 LICENSE + NOTICE present. |

## Layer 2: Acceptance criteria

| # | Criterion | Met? | Evidence | Hypotheses |
|---|----------|------|----------|------------|
| AC1 | Core builds WASM-free | Yes | H1 evidence | H1 |
| AC2 | t1-t8 ship with byte-identical hashes | Yes | H2 evidence | H2 |
| AC3 | Integration tests against the original SDK pass | Yes | 10/10 compat tests | H3-H6 |
| AC4 | Plug-and-play docs (quick start, build, authoring, conformance profile) | Yes | README.md, docs/template-authoring.md, crate docs | H8 |
| AC5 | Generic agent-auditability example, no customer naming | Yes | H7 evidence; exactly one occurrence of the string "Gusto" in the example: the aliased wire-type import (accepted deviation D1, unavoidable without forking the type identity) | H7 |
| AC6 | Standalone registry with publisher-DID register/subscribe | Yes | H9 evidence; ~/aqua-template-registry, 8 commits, HTTP API + feed subscription + reverse DID indexes | H9 |
| AC7 | Apache-2.0 publish-ready | Yes | H10 evidence | H10 |

## Discovered during execution

1. **identity_base carries an embedded WASM module**, so the full SDK executes
   WASM when verifying every audit revision (the two exploration agents
   contradicted each other; resolved by reading verify_stages.rs and
   identity_base.json). This forced decision D7 (skip built-in chains
   explicitly, fail closed on custom WASM) and made H5's parity claim
   empirical; the compat tests now prove it.
2. **Timestamp governance refinement**: the initial stub would have silently
   passed timestamp revisions that the hostless full SDK rejects under
   strict policy. Fixed before the compat suite was written: timestamp
   revisions route through the governed `timestamp_unavailable` decision.
3. **Automated test pruning overreach**: the pruning loop's containment check
   was too permissive and deleted two production helpers
   (`reject_uppercase_hex`, `decode_batch_merkle_root`) and the entire
   verify_common test module. All restored from the original; a systematic
   function-set diff against the original then verified no other
   non-test losses. Adapted replacements restored the typed-genesis,
   template-machinery, bounds, and batch-inclusion suites (370 lib tests
   vs 336 at first green).
4. **Broken intermediate commit** (found by the registry agent): the cleanup
   commit did not compile due to a dangling doc comment. History was
   rewritten (local, unpushed) and every commit now passes
   `cargo check --lib` (verified per-commit).
5. **TEMPLATE_JSON trait default is ""** and several impls do not override
   it; the original byte-parity assertion was trivially true for those.
   Replaced with a direct file-byte comparison of all 23 template files.
6. **Registry agent findings on core (backlog, not blocking)**:
   no keypair-generation helper (consumers hand-roll ed25519 key material);
   a `template_tree(&Template)` convenience for the portable-template flow
   would improve discoverability; `resolve_template` checks tree revisions
   before built-ins (content-addressed, unspoofable, but registries should
   still pin expected type hashes independently, as the registry does).
7. **Example agent finding**: linked template trees must be keyed by the
   full multihash link, not the bare 32-byte form, or revision-hash
   verification fails; documented in the example.
8. **Closure corrections vs exploration**: the `file` template is required
   (genesis/object path), `manifest` is not; agent A's "compute never runs
   for audit templates" claim was wrong (see 1).

## Deviations from the original plan

- D1 accepted: T5 ships as `audit_gusto_api_response` byte-identical; a
  rename remains possible later as a deliberate both-SDK migration.
- Inherited clippy lints (14) in files copied verbatim from the original
  are left untouched to keep the diff against upstream reviewable.
- `PreSignature` canonical-JSON byte parity is not tested directly (fields
  are private and nonce/timestamp are randomized); it is covered
  transitively by cross-crate signature verification, which fails if
  signing bytes diverge.

## Residual risks / follow-ups for the maintainers

1. The compat suite requires a sibling `../aqua-rs-sdk` checkout; CI for the
   public repo should either vendor fixtures or run compat in a private job.
2. `Aquafier::create_object` does not schema-validate payloads of
   non-built-in templates at creation time (validation happens at
   verification); inherited from the original, worth documenting upstream.
3. Backlog candidates from finding 6: `generate_ed25519()` helper,
   `template_tree()` helper.
4. The registry's plugin-registration template and domain-scoped trust store
   are deferred by design (need WASM or are consumer-side policy).
