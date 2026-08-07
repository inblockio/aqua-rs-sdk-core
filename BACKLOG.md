# Backlog

Living backlog for aqua-rs-sdk-core and the ecosystem catch-up around it.
Sections are ordered; items within a section are ordered by priority.
Registry-side items live in the companion repo's
[aqua-template-registry BACKLOG.md](https://github.com/inblockio/aqua-template-registry/blob/main/BACKLOG.md).

Status legend: [ ] open, [~] in progress, [x] done (keep done items with a
date until the section is fully cleared, then archive them at the bottom).

## A. Upstream harmonisation (the full aqua-rs-sdk catches up)

Context: on 2026-08-07 core deliberately forked the audit template family
(re-rooted at `audit_artifact`, `identity_base` removed from ancestry,
`audit_gusto_api_response` renamed to `audit_api_response`, customer-derived
example strings scrubbed from the T4/T5 descriptions). All 11 hashes changed;
the canonical ledger is `tests/audit_template_hashes.txt` (root
`audit_artifact` bare digest `0x431668e5...`). Reunification is ONE upstream
migration that adopts all of it together; partial adoption would mint a third
set of type identities.

- [ ] A1. Re-root the audit family in the full SDK: `audit_artifact` becomes
      a root template (drop `derives_from`/`ancestry`), the ten derived
      templates get ancestry `[audit_artifact]`.
- [ ] A2. Rename `audit_gusto_api_response` to `audit_api_response` (file,
      `AuditGustoApiResponse` type and error type, name tables, disclosure
      wiring).
- [ ] A3. Scrub the customer-derived description examples in
      `audit_agent_tool_call.json` and `audit_api_response.json` (use the
      neutral strings core ships).
- [ ] A4. Run `verify-templates --fix` upstream and assert the resulting
      TEMPLATE_LINKs equal core's ledger exactly. Acceptance check on the
      core side: the compat test `audit_family_divergence_is_intentional`
      must then FAIL (hashes equal); replace it by moving the 11 audit
      templates back into the shared byte-identical parity lists
      (`template_hash_constants_match`, `template_files_byte_identical`).
- [ ] A5. Decide the identity-attested audit extension: if identity
      lifecycle states are still wanted on audit artifacts, define extension
      templates deriving from the re-rooted family (depth headroom exists:
      root, parent, child fits the max-depth rule). Do not re-couple the base
      family to `identity_base`.
- [ ] A6. Migration policy for existing identity-rooted audit artifacts in
      deployed systems (audit emitters, portals): dual-accept window or
      re-emission. Until then the old hashes stay answerable through core's
      `primitives::unsupported` lookup.
- [ ] A7. After harmonisation, regenerate core's `primitives::unsupported`
      lookup from the upstream catalog (decide whether the old identity-rooted
      audit hashes stay listed for historical trees).
- [ ] A8. Spec updates accompanying A1-A3 (template hash tables, audit-trail
      spec sections that cite the old ancestry), per the one-concern-per-change
      and code-with-spec discipline.

Note: the registry's published `seed/audit-set-v1` already carries the
re-rooted hashes, so harmonisation does NOT require a v2 of the set.

## B. Core API and tooling (from the extraction and registry audits)

- [ ] B1. `RevisionLink::bare_digest()` helper. The multihash-versus-bare-
      digest split is a live footgun: `calculate_link` returns `0x1620...`
      multihash while `template_hash` fields and the ledger use the bare
      64-hex digest, and nothing converts between them.
- [ ] B2. Programmatic `builtin_template_hashes() -> &'static [(&str, [u8; 32])]`
      accessor. The ledger is a text file under `tests/` that publishers
      currently parse by hand.
- [ ] B3. Ed25519 keypair generation helper (`generate_ed25519()` or similar)
      so consumers stop hand-rolling key material against a possibly skewed
      `ed25519-dalek` version.
- [ ] B4. `Aquafier::template_tree(&Template)` convenience for the
      portable-template pattern (single-revision tree keyed by the full
      multihash link; the bare-digest keying of the internal builtin trees is
      not reusable for verifiable linked trees).
- [ ] B5. Machine-readable abstract-template marker. `audit_artifact` is
      abstract by convention only; registries and verifiers cannot tell.
      Wire-format change, so this needs the upstream spec process first.
- [ ] B6. Creation-time schema validation for non-built-in templates in
      `create_object` (currently validation happens only at verification;
      inherited from upstream). Fix both sides or document loudly in both.
- [ ] B7. CI for the public repo: the compat suite needs a sibling
      `../aqua-rs-sdk` checkout. Either a private CI job with both repos or
      vendored fixtures for the public job.
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
- [ ] B8. Commit a regeneration script for `primitives::unsupported`
      (currently an ad hoc extraction from the full SDK's catalog); document
      when to run it (every upstream template addition or removal).

## C. Pointers

- Registry end-to-end and template subscription/import work: see the
  registry repo's BACKLOG.md, section "End-to-end and subscription".
- Decision and evidence records for everything above:
  `docs/plans/2026-08-06-core-extraction.md`,
  `docs/plans/2026-08-07-core-extraction-audit.md`,
  `docs/plans/2026-08-07-essential-core.md`.
