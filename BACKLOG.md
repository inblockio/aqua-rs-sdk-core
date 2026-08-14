# Backlog

Living backlog for aqua-rs-sdk-core and the ecosystem catch-up around it.
Sections are ordered; items within a section are ordered by priority.
Registry-side items live in the companion repo's
[aqua-template-registry BACKLOG.md](https://github.com/inblockio/aqua-template-registry/blob/main/BACKLOG.md).

Status legend: [ ] open, [~] in progress, [x] done (keep done items with a
date until the section is fully cleared, then archive them at the bottom).

## A. Upstream harmonisation (the full aqua-rs-sdk catches up)

TRACKING NOTE (2026-08-07): these SDK changes stay in this backlog by
direction and are NOT executed from the core side; they are one atomic
migration inside the full aqua-rs-sdk, owned by that repo's maintainers.
See HANDOVER.md.

Context: on 2026-08-07 core deliberately forked the audit template family
(re-rooted at `audit_artifact`, `identity_base` removed from ancestry,
`audit_gusto_api_response` renamed to `audit_api_response`, customer-derived
example strings scrubbed from the T4/T5 descriptions). All 11 hashes changed;
the canonical ledger is `tests/audit_template_hashes.txt` (root
`audit_artifact` bare digest `0x431668e5...`). Reunification is ONE upstream
migration that adopts all of it together; partial adoption would mint a third
set of type identities.

- [x] A1. Re-root the audit family in the full SDK: `audit_artifact` becomes
      a root template (drop `derives_from`/`ancestry`), the ten derived
      templates get ancestry `[audit_artifact]`. (2026-08-14, full SDK
      `36a8b65` on `feat/audit-family-harmonisation`.)
- [x] A2. Rename `audit_gusto_api_response` to `audit_api_response` (file,
      `AuditGustoApiResponse` type and error type, name tables, disclosure
      wiring). (2026-08-14, `36a8b65`.)
- [x] A3. Scrub the customer-derived description examples in
      `audit_agent_tool_call.json` and `audit_api_response.json` (use the
      neutral strings core ships). (2026-08-14, `36a8b65`.)
- [x] A4. Run `verify-templates --fix` upstream and assert the resulting
      TEMPLATE_LINKs equal core's ledger exactly. Acceptance check on the
      core side: the 11 audit files joined
      `template_hash_constants_match` and `template_files_byte_identical`;
      `audit_family_divergence_is_intentional` is deleted. (2026-08-14,
      `36a8b65` + this branch.)
- [x] A5. Decide the identity-attested audit extension: **no extension in
      this migration.** If wanted later, derive from the re-rooted family;
      do not recouple to `identity_base`. (2026-08-14, recorded in the plan
      and the SDK CHANGELOG.)
- [ ] A6. **Excluded by direction** (2026-08-14): no backward compatibility
      / dual-accept window for identity-rooted artefacts. Old hashes fail
      closed via `template_not_found` (or the existing unsupported lookup).
- [ ] A7. **Excluded by direction** (2026-08-14): do not regen
      `primitives::unsupported` to drop historical hashes.
- [ ] A8. **Excluded by direction** (2026-08-14): no spec-only pass
      accompanying A1–A3. Catalog-membership wording for B11 is updated on
      the core side in this change.

Note: the registry's published `seed/audit-set-v1` already carries the
re-rooted hashes, so harmonisation does NOT require a v2 of the set.

## B. Core API and tooling (from the extraction and registry audits)

- [x] B1. `RevisionLink::bare_digest()` (2026-08-07). Plus
      `bare_digest_hex()` for the `0x` + 64-hex form ledgers and
      `..._hash` payload fields use. Accepts either input form (bare 32-byte
      digest or any well-formed Aqua-profile multihash) and returns `None`
      rather than panicking on anything else. Deliberately algorithm-agnostic,
      since BLAKE3-256 revision links are legitimate; the SHA3-only rule for
      template ids stays in the template index, which is untouched.
      `src/primitives/mod.rs` (5 tests, including agreement with the template
      index key over every built-in digest in both forms).
- [x] B2. Programmatic template hash accessors (2026-08-07). Three views over
      one table built from the templates' own `BuiltInTemplate` constants:
      `builtin_template_hashes()` (the 14-entry verification catalog),
      `shipped_template_hashes()` (all 19 shipped), and `shipped_templates()`
      (`(name, JSON, digest)`, the publishing view). `src/core/verify_stages.rs`,
      re-exported from `core` and as `Aquafier::` associated functions.
      Drift is impossible in both directions: a test compares
      `shipped_template_hashes()` to `tests/audit_template_hashes.txt` entry for
      entry, another recomputes every row's digest from its own JSON, a third
      pins the catalog view to the resolution cache and the shipped view to
      exactly the five deliberate non-catalog templates.
- [x] B3. `generate_ed25519() -> ([u8; 32], String)` (2026-08-07). OS CSPRNG
      through this crate's own `ed25519-dalek`; returns the seed ready for
      `SigningCredentials::Did` plus the `did:key` it derives.
      `src/core/signature/sign_did.rs`, re-exported at the crate root. Tested
      by signing a real tree with a generated key and verifying it.
- [x] B4. `Aquafier::template_tree(&Template, Option<&str>)` (2026-08-07).
      Single-revision tree keyed by the FULL multihash link, with the
      built-in name or a hash fallback as its `file_index` label.
      `src/core/template.rs` (`template_tree_util`), used by the example and
      by `export_tree`'s naming helper. Tested by resolving a synthesized
      custom type through it as a linked tree.
- [ ] B5. Machine-readable abstract-template marker. `audit_artifact` is
      abstract by convention only; registries and verifiers cannot tell.
      Wire-format change, so this needs the upstream spec process first.
- [x] B6. Validated creation path (2026-08-07). Additive:
      `Aquafier::create_object_validated(..., template_sources)` resolves the
      template from the previous tree, the built-in catalog, then the caller's
      sources (verification's exact order) and fails closed with
      `TemplateNotFound`, `AncestorTemplateNotFound`, or `SchemaViolation`.
      `create_object` is untouched, and the gap it leaves is now pinned by a
      test and documented loudly in `README.md` and
      `docs/template-authoring.md` section 5. `src/core/object.rs` (6 tests).
      Full-SDK port is a sibling task on the same
      `feat/audit-family-harmonisation` branch (B6 on both sides).
- [x] B7. CI for the public repo (2026-08-07). `.github/workflows/ci.yml`:
      a `core` job (fmt for this package, build, `test --lib --bins`, doc
      tests, clippy, rustdoc, verify-templates, the example, publish dry run)
      and a `compat` job that clones `inblockio/aqua-rs-sdk` as a sibling and
      runs `cargo test --workspace`. Every command was run locally first.
      Two documented judgement calls: the compat job stays strict and fails
      while that repo is private (a silently skipped compat job is the
      "green because uncovered" failure mode), and clippy denies the
      correctness group rather than all warnings, because the lib carries 14
      warnings inherited from verbatim-copied files and a pinned total would
      break on every new lint.
- [x] B8a. Self-descriptive exports (2026-08-07). Shipped as
      `Aquafier::export_tree(&tree, &extra_template_sources, &ExportOptions)`
      in `src/core/export.rs`, re-exported from the crate root together with
      `ExportOptions`, `ExportTreeError`, and the lint
      `missing_templates(&tree) -> Vec<RevisionLink>`. Tim flipped the
      default: embedding is ON (`include_templates`) and so is
      `include_builtin_templates`, since "built-in" is receiver-relative
      (core's audit templates are unresolvable in the pre-harmonisation full
      SDK). `ExportOptions::bare()` is the per-call-site opt-out,
      `non_builtin_only()` the lean middle. The walk starts at every typed
      revision's `revision_type` and follows `derives_from` ancestry;
      signature/anchor/template revisions need no resolution. Bodies resolve
      from the tree, then the built-in catalog, then the extra sources; each
      is embedded under its canonical full multihash link. Fails closed on any
      unresolvable template, listing the hashes. Cost, as predicted: template
      JSON size per export.
      Evidence: 9 unit tests in `src/core/export.rs` (synthesized custom type
      verifies standalone after a JSON round trip, with the un-exported
      control failing; real opt-out; idempotency; no input mutation;
      fail-closed; lint; audit-family bounds), the cross-SDK proof in
      `compat-tests/tests/compat.rs::audit_turn_marker_cross_verifies` (with
      a non-vacuity control), `examples/agent_audit_trail.rs`,
      `README.md` ("Self-descriptive exports"), and
      `docs/template-authoring.md` section 6.
- [x] B9. `merkle::try_merkle_root` (2026-08-07). Non-breaking by direction:
      `merkle_root` keeps its bytes and its signature, because it is a
      byte-for-byte shared primitive with the full SDK and changing it there
      would fork a hashing path; it gains a `# Panics` section instead. The
      guard returns `Option` (one failure mode, fully described by the input
      being empty). `src/primitives/merkle.rs`, 3 tests: the panic is pinned,
      the `None` is asserted, and byte equality with `merkle_root` is checked
      for 1 to 17 leaves.
      Follow-up (2026-08-08): the one call site that fed the primitive
      attacker-controlled leaves is now guarded. `verify_redacted_revision` in
      `src/core/disclosure.rs` rejects a `leaf_count` of 0 in the spec's step-1
      "Count" position (`DisclosureVerificationError::EmptyLeafSet`, spec 06 §3
      and §6.5) and reconstructs the root through `try_merkle_root`, so a
      hostile `{leaf_count: 0, leaves: []}` artifact returns an error instead
      of unwinding through the verifier. `merkle_root` itself is deliberately
      unchanged — still byte-for-byte the full SDK's copy, still panicking on
      empty by design.
- [x] B10. Authoring papercuts (2026-08-07), partially: the constant landed,
      the `&HashType` alignment did not.
      `primitives::TEMPLATE_META_REVISION_TYPE` is a compile-time `&str`
      (unlike the lazily built `TEMPLATE_META_HEX`) in
      `src/primitives/revision_kind.rs`, tied by tests to
      `TemplateMeta::TEMPLATE_LINK`, to `TEMPLATE_META_HEX`, and to the
      `revision_type` of all 19 shipped template JSONs; documented in
      `docs/template-authoring.md` section 3.
      SKIPPED (2026-08-07 and reconfirmed 2026-08-14 by the orchestrator):
      changing `merkle`'s `&HashType` parameters to by-value is a
      source-breaking signature change on a hashing-path primitive that is
      otherwise a verbatim copy. Cosmetic. One-concern-per-change: do not
      bundle it with a template-identity migration. Revisit only if a later
      change already rewrites both `merkle.rs` copies.
- [x] B8. Regeneration binary for `primitives::unsupported` (2026-08-07).
      `src/bin/regen_unsupported.rs`, run as
      `cargo run --bin regen-unsupported --features native`, with `--check`
      as a read-only drift gate. It parses the full SDK's template JSONs with
      this crate's own `Template` and `calculate_link`, so hashes come from
      the pipeline under test, and decides support by digest rather than by
      name (the re-rooted audit family shares names across the repos and must
      stay listed). The editorial "requires <module>" strings live in an
      explicit name-keyed table that panics loudly on an unknown template.
      Running it now writes nothing, which is the proof it reproduces the ad
      hoc extraction. When to run it is documented in the module doc comment
      and in the binary header: every upstream template addition or removal,
      and after A1-A8.
- [x] B11. Registry-only distribution for the audit family (2026-08-14).
      The 9 catalog-resolvable audit templates left `BUILTIN_TEMPLATES` /
      `BUILTIN_TEMPLATE_NAMES`. Accessors: `builtin_template_hashes()` is
      the 5-entry verification catalog (`file` + 4 signature suites);
      `shipped_template_hashes()` / `shipped_templates()` are the 8
      contract templates (catalog + `template_meta` + `anchor_template` +
      `signature_base`). The 11 audit identities stay on disk as fixtures
      and ledger pins, matching the registry set / full SDK. Example,
      authoring guide, spec §8 / §8.1 / §8.2 / §8.3, and the compat suite
      follow the registry path. Bare audit trees fail closed under
      `template_not_found` unless sources are supplied.

## C. Pointers

- Registry end-to-end and template subscription/import work: see the
  registry repo's BACKLOG.md, section "End-to-end and subscription".
- Decision and evidence records for everything above:
  `docs/plans/2026-08-06-core-extraction.md`,
  `docs/plans/2026-08-07-core-extraction-audit.md`,
  `docs/plans/2026-08-07-essential-core.md`.
