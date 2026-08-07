# 2026-08-08 — Disclosure remediation (process-pipeline)

Remediate the two implementation findings surfaced by the protocol-specification
review (spec shipped at `cfab111`): the code must be brought up to the two rules
the spec deliberately tightened.

## Logic model

**CONTEXT.** `aqua-rs-sdk-core` is the published reference implementation; the
protocol spec in `protocol-specification/` is now normative. Two spots where the
spec tightened beyond the code: (F1) `verify_redacted_revision` panics on a
zero-leaf `RedactedRevision` (attacker-controlled input → DoS; spec 06 §3 step 1
and §6.5 say MUST reject), and (F2) `redact_revision` permits disclosing the
`/nonce` leaf (spec 06 §6.1 says MUST NOT — disclosing it makes every sealed
value in the revision brute-forceable). Hard constraint: `merkle_root` itself
stays byte-identical to the full SDK (deliberate panic documented; backlog B9) —
the guard belongs at the disclosure call sites, not in the shared primitive.
`try_merkle_root` already exists as the additive total variant. Crate is not yet
on crates.io, so additive error-enum variants are acceptable.

**GOAL.** The reference implementation enforces both spec rules: hostile
zero-leaf artifacts are rejected with an error (never a panic anywhere in the
selective-verification path), and the exporter/redaction layer refuses any
policy that discloses `/nonce`.

**INPUTS.** `src/core/disclosure.rs` (both fixes), `src/primitives/merkle.rs`
(read-only; `try_merkle_root`), spec 06, `BACKLOG.md` (B9 entry), existing test
suite (370 lib tests), sibling `../aqua-rs-sdk` for compat suite.

**ACTIVITIES.** Two Opus subagents, run **sequentially** (both edit
`src/core/disclosure.rs`; parallel edits of one file would conflict): T1 =
zero-leaf guard, T2 = nonce-disclosure guard. Orchestrator audits with fresh
test runs, then commits.

**BOUNDARY CONDITIONS.** No hashing-path change (no byte written into any
canonicalization/Merkle preimage changes); no change to `merkle_root`; no
public-behavior change beyond the two rejections; existing tests stay green
except the one test that asserts the now-forbidden behavior
(`test_nonce_can_be_explicitly_disclosed`), which flips to assert rejection;
compat suite stays green; spec and code end the round consistent.

## Hypothesis register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | `verify_redacted_revision` rejects `leaf_count == 0` before reconstruction and uses `try_merkle_root` | the hostile artifact `{revision_hash, leaf_count: 0, leaves: []}` returns an error; no panic reachable from `verify_selective_tree` | zero-leaf is unreachable from honest producers (creation errors on empty leaf sets) | new unit tests incl. a would-have-panicked input; `cargo test disclosure` |
| H2 | the F1 guard is verification-side only | no hash changes; all existing lib + compat tests pass unchanged | compat suite covers the shared byte paths | full `cargo test`; `cargo test --manifest-path compat-tests/Cargo.toml` |
| H3 | `redact_revision` rejects `/nonce` in disclosed paths | a defective policy fails closed through `export_selective_tree`; presets/profiles (which never emit `/nonce`) are unaffected | no non-test caller discloses `/nonce` | new negative tests; existing preset/profile tests pass |
| H4 | changes are additive error variants + guards | no API breakage for in-repo consumers (bins, examples, compat) | crate not yet published; exhaustive matches on these enums exist only in-repo | `cargo build --all-targets`; full test run |
| H5 | spec 06 §6.1 sharpened to name the exporter obligation | spec and code are consistent (no remaining "code permits it" gap) | — | re-read of the spec diff against new behavior |

## Task 1: Zero-leaf RedactedRevision guard (F1) — agent 1

**Hypotheses:** H1, H2, H4
**Files:** `src/core/disclosure.rs` (verify path + tests), `BACKLOG.md` (B9 note)

- [ ] Reject `leaf_count == 0` in `verify_redacted_revision` with a dedicated
      error variant (step-1 "Count" position, per spec 06 §3).
- [ ] Replace the panicking `merkle_root` call in the verification path with
      `try_merkle_root` + error mapping (defense in depth; creation path
      already errors upstream).
- [ ] Tests: zero-leaf artifact → error (this input panicked before);
      zero-count-with-nonempty-leaves stays `LeafCountMismatch`; the error
      surfaces through `verify_selective_tree` as `RedactionFailed`.
- [ ] Update the B9 entry in `BACKLOG.md`: the disclosure-verifier call site is
      now guarded; `merkle_root` itself deliberately unchanged.

## Task 2: /nonce disclosure guard (F2) — agent 2 (after Task 1)

**Hypotheses:** H3, H4, H5
**Files:** `src/core/disclosure.rs` (redaction path + tests),
`protocol-specification/06-selective-disclosure.md` (§6.1 sentence)

- [ ] `redact_revision` rejects a disclosed-path set containing `/nonce` with a
      dedicated `RedactionError` variant (message cites spec 06 §6.1).
- [ ] Flip `test_nonce_can_be_explicitly_disclosed` into a rejection test; keep
      `test_nonce_redacted_by_default`; add an `export_selective_tree`-level
      negative test.
- [ ] Sharpen spec 06 §6.1: exporters MUST reject a policy that lists `/nonce`
      (replacing "cannot prevent a defective policy" framing with the enforced
      obligation).
- [ ] Confirm presets/profiles unaffected (existing tests).

## Audit plan

Layer 1: hypothesis trace with fresh command output (orchestrator re-runs the
full lib suite and the compat suite; does not trust agent-reported results).
Layer 2: acceptance criteria — AC1: zero-leaf artifact returns an error, no
panic (H1); AC2: `/nonce` disclosure refused at redaction and export (H3);
AC3: everything else green incl. compat (H2, H4); AC4: spec/code consistent
(H5). Then commit + push (repo convention: direct on main, verified via
`git ls-remote`).

**Gate note:** plan-confirmation gate satisfied by the explicit user
instruction "Execute fixes for both / remediation for both using two subagents
(opus) with /process-pipeline" (unsupervised session, execution pre-approved).
