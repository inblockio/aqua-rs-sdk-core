# Plan: audit-family harmonisation (A1–A5, B6, B11)

Date: 2026-08-14. Pipeline: process-pipeline, list mode. Approval: Tim
("Execute end to end as an unsupervised marathon"; A6/A7/A8 excluded by
direction; B10 assessed by orchestrator).

Work lands on feature branches, not `main`:

- `aqua-rs-sdk`: `feat/audit-family-harmonisation`
- `aqua-rs-sdk-core`: `feat/audit-family-harmonisation`
- `aqua-template-registry`: `feat/audit-family-harmonisation` (only if
  tests or import path must change)

## Logic model

### CONTEXT

`aqua-rs-sdk-core` forked the 11-template audit family on 2026-08-07
(re-root at `audit_artifact`, drop `identity_base`, rename T5 to
`audit_api_response`, scrub customer-derived description strings). Hashes
are type identities; the 11 hashes differ. The registry already publishes
the re-rooted set as `seed/audit-set-v1`. The full SDK still ships the
identity-rooted, `audit_gusto_api_response` family. Shared machinery and
signature templates are still byte-identical. The full SDK has landed no
protocol code since extraction (last code commit 2026-07-22). Core already
has `create_object_validated`; the full SDK does not.

### GOAL

Reunify the audit family's type identities in the full SDK with core's
ledger, add the validated creation path to the full SDK, and stop treating
the audit family as a core built-in — consumers retrieve it from the
registry.

### INPUTS

- Core ledger: `aqua-rs-sdk-core/tests/audit_template_hashes.txt`
  (`audit_artifact` = `0x431668e5…`)
- Core audit JSON + `.rs` (the target bytes and type names)
- Full SDK audit JSON + `.rs`, `verify_stages.rs`, `disclosure.rs`,
  `src/tests/audit_template_disclosure.rs`, `tests/audit_template_hashes.txt`
- Core `src/core/object.rs` (`create_object_validated_util`, tests) and
  `Aquafier::create_object_validated` / `template_tree`
- Registry `seed/audit-set-v1/` and `src/import.rs` / `tests/full_loop.rs`
- Skills: core-developer (Tier 0 for template JSON), elon-method (A5, B10)

### BOUNDARY CONDITIONS

- **Excluded by Tim:** A6 (migration window for old identity-rooted
  artefacts), A7 (regen of core `unsupported` for historical hashes), A8
  (spec updates that only accompany A1–A3). No backward compatibility.
- **B10 verdict (orchestrator):** SKIP. Changing `merkle`'s `&HashType`
  parameters is a source-breaking signature change on a hashing-path
  primitive that is otherwise a verbatim copy. Cosmetic. Bundling it with
  a template-identity migration violates one-concern-per-change. The
  `impl Borrow<HashType>` alternative is the same shape change. Revisit
  only if a later change already rewrites both `merkle.rs` copies.
- **A5 verdict (orchestrator):** do NOT add identity-attested extension
  templates. The family is data-only and registry-distributed. Recoupling
  to `identity_base` is forbidden. Depth headroom remains if someone later
  wants an extension; that is a new item, not this migration. Record the
  decision; do not build.
- Do not edit hashing, canonicalization, Merkle construction, or DID
  encoding.
- Do not commit to `main` of either SDK. Do not touch untracked draft
  PCAs on the full SDK checkout.
- Template hash = type identity: never hand-edit a hash constant; copy
  core's JSON bytes, then `verify-templates --fix`.
- Core is never more permissive than the full SDK under equal policy.
- A6/A7 skipped means old identity-rooted hashes become ordinary unknown
  hashes after B11 (fail closed via `template_not_found`). That is the
  intended no-compat outcome.

## Hypothesis register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | Full SDK audit JSONs are replaced by core's 11 files (T5 renamed) and `verify-templates --fix` is run | Every audit `TEMPLATE_LINK` equals core's ledger exactly; `cmp` of the 11 JSON files is silent | Core ledger is the source of truth; `verify-templates` is the only writer of hash constants | `cmp` each pair; `verify-templates` (no `--fix`) exits 0 on the SDK branch; ledger rows match |
| H2 | All `AuditGusto*` / `audit_gusto_*` identifiers are renamed in the full SDK | The crate compiles; no leftover identifier; disclosure and tests use `AuditApiResponse` | Rename is mechanical; no third-party in-tree caller of the old type name | `rg AuditGusto\\|audit_gusto` empty under `src/` and `tests/`; `cargo test --features native,policy,daemon` |
| H3 | `audit_artifact` has no `derives_from`/`ancestry`; children have ancestry `[audit_artifact]` only | Identity WASM no longer runs for audit revisions; ancestry unit tests that pin `identity_base` are rewritten to pin `audit_artifact` | Full SDK compute stage only walks declared ancestry | Ancestry tests assert the new chain; an audit object verifies without an identity host |
| H4 | A5 is recorded as "no extension now" | No new template JSON is added | — | `git diff --stat` has no new `src/schema/templates/*.json` beyond the T5 rename |
| H5 | `create_object_validated` is ported additively | Custom-template payloads are schema-checked at creation; `create_object` is unchanged for unresolvable types | Resolution order matches verification | Ported unit tests pass; `create_object` still accepts a bad custom payload |
| H6 | After A1–A4, core's `audit_family_divergence_is_intentional` is inverted | The 11 audit files join `template_files_byte_identical` and `template_hash_constants_match` | Compat suite path-deps the sibling checkout on the feature branch | `cargo test --manifest-path compat-tests/Cargo.toml` |
| H7 | The 9 catalog-resolvable audit templates leave core's `BUILTIN_TEMPLATES` | `resolve_builtin_template` returns `None` for those hashes; `create_object` no longer schema-validates them; `create_object_validated` with sources still does | JSON + `.rs` stay on disk as fixtures | Dedicated negative test; `builtin_template_hashes().len()` drops by 9 |
| H8 | An object of an audit type is created from a registry import | The tree verifies in core when the imported definition trees are passed as sources; it fails closed without them | Registry seed bodies equal the fixture JSONs; import store yields `template_tree`s | New registry test: import `audit-set-v1` → `create_object_validated` → verify green; no-sources control fails |
| H9 | Example + authoring guide + spec §8.1 follow the registry path | `agent_audit_trail` still runs using explicit sources; spec no longer lists the 11 as catalog-resolvable | Seed definitions are reachable as a sibling path or via the import API | `cargo run --example agent_audit_trail --features native`; spec §8.1 wording |
| H10 | Neither hashing path nor the 8 shared templates change | `template_meta`/`file`/`signature_*`/`anchor_template` remain byte-identical | We do not touch those files | `cmp` the 8 files; compat `canonical_template_hash_parity` |

## Acceptance criteria

| # | Criterion | Hypotheses |
|---|-----------|------------|
| AC1 | Full SDK audit family is byte-identical to core's 11 JSONs; T5 is `audit_api_response`; hashes equal the core ledger | H1, H2, H3 |
| AC2 | No identity-attested extension templates added; A5 decision written down | H4 |
| AC3 | Full SDK has `Aquafier::create_object_validated` with fail-closed tests | H5 |
| AC4 | Compat suite: audit family on the shared parity lists; divergence test gone | H6, H10 |
| AC5 | Core catalog no longer resolves the 9 audit templates; fixtures remain | H7 |
| AC6 | Registry import of `audit-set-v1` creates and verifies a T1 (and preferably T4/T5) via `create_object_validated` | H8 |
| AC7 | Example, authoring guide, BACKLOG, spec §8.1/§8.2 updated; B10 skipped with rationale | H9 |
| AC8 | Both SDK branches compile and their test suites exit 0; no commit on `main` | H1–H10 |

## Tasks

### Task 1 — Full SDK: A1–A4 atomic migration + A5 decision record

**Hypotheses:** H1, H2, H3, H4, H10
**Repo:** `~/aqua-rs-sdk` on `feat/audit-family-harmonisation`
**Files:**
- Replace: `src/schema/templates/audit_*.json` (copy from
  `~/aqua-rs-sdk-core/src/schema/templates/`; T5 file is
  `audit_api_response.json`)
- Rename: `audit_gusto_api_response.rs` → `audit_api_response.rs`;
  `AuditGustoApiResponse` → `AuditApiResponse`; error type likewise
- Update: `src/schema/templates/mod.rs`, every audit `*.rs` ancestry
  doc + tests that pin `identity_base`, `src/core/verify_stages.rs`
  (name table + include_str), `src/core/disclosure.rs`,
  `src/tests/audit_template_disclosure.rs`,
  `tests/audit_template_hashes.txt`, `CHANGELOG.md`
- Create: short decision note in `CHANGELOG.md` and a paragraph in
  this plan's audit addendum for A5 (no new templates)

- [ ] Copy the 11 core audit JSON files over the full SDK copies.
      Delete `audit_gusto_api_response.json`. Add
      `audit_api_response.json`.
- [ ] Rename the T5 Rust module and types. Update `mod.rs`.
- [ ] Rewrite ancestry rustdoc and unit tests: `audit_artifact` is a
      root (no `derives_from`); every derived template has
      `ancestry == [audit_artifact]` only. Delete the
      `identity_base_hash` assertions.
- [ ] Neutralise remaining customer-derived *example strings in tests
      and rustdoc* that are not hash-covered (`gusto.employee.create`
      in test fixtures may stay as payload data — those are not type
      identity — but T4/T5 JSON descriptions must match core:
      `inventory.item.create` / `api.example.com`).
- [ ] Update `verify_stages.rs` name + cache entries
      (`audit_api_response`).
- [ ] Update `disclosure.rs` and `audit_template_disclosure.rs`.
- [ ] Run `cargo run --features native --bin verify-templates -- --fix`
      and then without `--fix`. Assert each audit bare digest equals
      the corresponding row in
      `~/aqua-rs-sdk-core/tests/audit_template_hashes.txt`.
- [ ] Update `tests/audit_template_hashes.txt`.
- [ ] CHANGELOG: breaking, one concern: audit family re-rooted, T5
      renamed, no dual-accept of old hashes.
- [ ] A5: CHANGELOG / this plan: "No identity-attested audit extension
      in this migration. If wanted later, derive from the re-rooted
      family; do not recouple to `identity_base`."
- [ ] `cargo test --features native,policy,daemon` exits 0.
      Do not touch the 8 shared machinery/signature JSONs.
- [ ] Commit on the feature branch (one or two commits, A1–A4 together
      because they are one type-identity event; A5 note can share the
      CHANGELOG commit).

### Task 2 — Full SDK: B6 `create_object_validated`

**Hypotheses:** H5
**Repo:** `~/aqua-rs-sdk` on the same branch, **after Task 1**
**Files:**
- Port from core: `CreateObjectError`, `resolve_template_for_creation`,
  `create_object_validated_util` into `src/core/object.rs`
- Port `template_tree_util` if missing (`src/core/template.rs`) — B6
  tests and callers need a one-revision template tree keyed by the
  full multihash. Keep it additive.
- Wire `Aquafier::create_object_validated` (and `template_tree`) in
  `src/lib.rs`; re-export `CreateObjectError`
- Port the 6 unit tests from core `object.rs`. The
  `validated_requires_the_ancestry_too` "sanity" arm that assumes
  `audit_round_anchor` is a built-in ancestor-resolver still works
  in the *full* SDK (audit stays a built-in there). Use a synthesised
  custom type for the negative ancestor case, as core does.

- [ ] Port the API additively. Do not change `create_object` behaviour.
- [ ] Tests: conforming payload matches `create_object` construction;
      schema violation; fail-closed without sources; ancestor missing;
      verified with the same sources.
- [ ] `cargo test --features native,policy,daemon object` and a
      targeted lib test run exit 0.
- [ ] Commit.

### Task 3 — Core: A4 follow-up + B11 catalog cut

**Hypotheses:** H6, H7, H9, H10
**Repo:** `~/aqua-rs-sdk-core` on `feat/audit-family-harmonisation`
**Depends on:** Task 1 (sibling `../aqua-rs-sdk` must be on the feature
branch so `cmp` and compat see the new files).

- [x] Compat: delete `audit_family_divergence_is_intentional`. Add the
      11 audit files to `template_files_byte_identical` (T5 filename is
      now `audit_api_response.json` on both sides). Add the 11
      `TEMPLATE_LINK` pairs to `template_hash_constants_match`.
- [x] B11: remove the 9 audit entries from `BUILTIN_TEMPLATE_NAMES` and
      `BUILTIN_TEMPLATES` in `src/core/verify_stages.rs`. Keep
      `audit_round_anchor` / `audit_session_close` out of the catalog
      (already). Keep the JSON + `.rs` modules on disk as fixtures and
      as typed payload structs.
- [x] Accessors: `builtin_template_hashes()` = verification catalog
      only (file + 4 concrete signature templates).
      `shipped_template_hashes()` / `shipped_templates()` = the 8
      contract templates (catalog + `template_meta`, `anchor_template`,
      `signature_base`). Audit hashes stay in
      `tests/audit_template_hashes.txt` as fixture pins for
      `verify-templates`, labelled as fixtures, not as the built-in
      contract. Update the B2 equality tests.
- [x] `KNOWN_UNCACHED` / `builtin_caches_are_complete`: the 11 audit
      files are now a third class — shipped-as-fixture, not catalog,
      not "forgotten uncached built-ins". Update the test so it does
      not demand they be in `BUILTIN_TEMPLATES`.
- [x] Fix every in-crate test that implicitly resolved an audit
      template (object.rs typed-genesis tests, export.rs, signature
      tests, example). They must pass sources via
      `template_tree` / `create_object_validated`, or load fixture JSON
      and wrap it.
- [x] Example `agent_audit_trail.rs`: load definitions from
      `../aqua-template-registry/seed/audit-set-v1/definitions/` (fail
      with a clear message if the sibling is absent). Create via
      `create_object_validated` with those sources. Export with the
      same sources.
- [x] Docs: finish the in-progress README / `docs/template-authoring.md`
      edits (registry path is required). Update BACKLOG: A1–A5 done
      (A6–A8 excluded), B6 done on both sides, B10 skipped, B11 done.
      Update `protocol-specification/03-templates.md` §8 / §8.1 / §8.2:
      catalog is the 8 machinery+signature templates; the 11 audit
      identities remain listed as the registry-distributed family
      (same hashes as the full SDK); drop the "deliberate fork"
      sentence. §8.3 already states the distribution rule.
- [x] `create_object` on an audit hash without sources must *not*
      schema-validate (catalog miss). Pin that with a test. The same
      payload via `create_object_validated` + fixture/registry sources
      must validate and verify.
- [x] `cargo test` and `cargo test --manifest-path compat-tests/Cargo.toml`
      and `cargo run --features native --bin verify-templates` and
      `cargo run --example agent_audit_trail --features native` all
      exit 0.
- [ ] Commit.

### Task 4 — Registry: import-path proof of B11

**Hypotheses:** H8
**Repo:** `~/aqua-template-registry` on `feat/audit-family-harmonisation`
**Depends on:** Task 3 (path-dep `../aqua-rs-sdk-core` must be the
feature branch).

- [ ] Add a test (default suite, not `--ignored`) that: builds an
      `ImportStore` from `seed/audit-set-v1` through the real import
      path (or the existing seed replay helper), fetches the T1 (and
      `audit_artifact`) definition trees, calls
      `Aquafier::create_object_validated` with those trees as
      `template_sources`, and verifies the resulting object with the
      same sources. A control with empty sources must fail
      (`TemplateNotFound` or verification `template_not_found`).
- [ ] Fix any existing registry test that assumed core still resolves
      audit hashes as built-ins (`create_object` of an audit type with
      no linked tree). Prefer switching those call sites to
      `create_object_validated` + imported trees rather than restoring
      implicit resolution.
- [ ] `cargo test` exits 0.
- [x] Commit. `b4d0fc2` on the registry branch.

## Orchestrator notes

- Execute via one subagent per task, sequential where the depends-on
  edge exists (1 → 2, 1 → 3 → 4). Task 2 and Task 3 ran in parallel
  after Task 1.
- Orchestrator re-ran the verification battery before declaring done.
- B10 is not a task (skipped).
- Do not push; do not merge to `main`. Report at the end for review.

## Audit addendum (2026-08-14)

Executed unsupervised. Branches only; nothing pushed or merged.

| Task | Repo | Commits | Agent |
|---|---|---|---|
| T1 A1–A5 | aqua-rs-sdk | `36a8b65` | 01a0006c |
| T2 B6 | aqua-rs-sdk | `1d8955a`, changelog `7b44885` | 01a00074-f861 |
| T3 A4+B11 | aqua-rs-sdk-core | `5bc449a` `0721dba` `79506d1`, handover `4e65964` | 01a00074-f861…34527 |
| T4 H8 | aqua-template-registry | `b4d0fc2` | 01a00082 |

### Hypothesis trace (orchestrator-verified)

| ID | Status | Evidence |
|----|--------|----------|
| H1 | Confirmed | `cmp` 11/11 silent; `verify-templates` “All 19 templates verified”; ledger rows match |
| H2 | Confirmed | `rg AuditGusto\|audit_gusto` empty under `src/`; only a ledger-header mention of the rename |
| H3 | Confirmed | Ancestry tests rewritten; example “compute-skip note: no” on all 10 trees |
| H4 | Confirmed | No new template JSON beyond the T5 rename; A5 in CHANGELOG |
| H5 | Confirmed | Full SDK `--lib` 1158 passed; 6 `validated` tests; `create_object` still skips custom types |
| H6 | Confirmed | Orchestrator: `cargo test --manifest-path compat-tests/Cargo.toml` — 10 passed, divergence test gone |
| H7 | Confirmed | Orchestrator: `audit_hashes_are_not_built_in`, `create_object_does_not_schema_validate_audit_hashes` pass; catalog 5 / shipped 8 |
| H8 | Confirmed | Orchestrator: `imported_audit_set_v1_creates_t1_via_create_object_validated` ok |
| H9 | Confirmed | Example loads registry seed; spec §8.1 is the 5-entry catalog; fork sentence deleted |
| H10 | Confirmed | `cmp` of 8 shared machinery/signature JSONs silent |

### Acceptance criteria

| # | Met? | Evidence |
|---|------|----------|
| AC1 | Yes | 11/11 `cmp`; T5 is `audit_api_response`; hashes = core ledger |
| AC2 | Yes | A5 recorded; no new templates |
| AC3 | Yes | `Aquafier::create_object_validated` on full SDK `1d8955a` |
| AC4 | Yes | compat 10/10; divergence test deleted |
| AC5 | Yes | catalog 5; fixtures remain; pin tests pass |
| AC6 | Yes | registry default-suite test via real import path |
| AC7 | Yes | example + authoring + BACKLOG + spec §8; B10 skipped with rationale |
| AC8 | Yes | suites exit 0; no commit on `main` |

### Discovered during execution

1. **`regen-unsupported --check` now drifts** (exit 1). That is A7, excluded by direction. Not in CI. Running the regen would drop the old identity-rooted hashes from `unsupported.rs` (they are no longer in the full SDK catalog) and would keep the new hashes out of the table (core still has fixture JSON, so they hash-match). Leave as-is until A7 is allowed.
2. **Merge order is load-bearing.** Core's new compat tests require the re-rooted full SDK. Merge `aqua-rs-sdk` first, then core, then the registry.
3. **B8a comment** still describes the pre-harmonisation reason `include_builtin_templates` defaults true. After B11 the audit family is not built-in, so the default no longer carries those templates; exports must pass sources. The example does. No behaviour bug.

### B10 verdict (orchestrator)

SKIP. Cosmetic hashing-path signature change. One-concern-per-change. Revisit only if both `merkle.rs` copies are being rewritten anyway.
