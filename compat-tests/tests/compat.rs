//! Integration tests proving aqua-rs-sdk-core is a compatible subset of
//! aqua-rs-sdk (the full SDK).
//!
//! Assertion classes (plan hypotheses H2-H6,
//! ../docs/plans/2026-08-06-core-extraction.md):
//!  * template hash parity: every shared built-in template has an identical
//!    TEMPLATE_LINK constant in both crates (H2),
//!  * canonicalization parity: parsing the same template JSON yields the
//!    same computed hash in both crates (H3),
//!  * cross-verification: trees created and signed by core verify in the
//!    full SDK, and vice versa (H3, H4),
//!  * audit family: a t1 audit object signed by core verifies in both (H5),
//!    in the full SDK through a self-descriptive `export_tree`, with no
//!    linked trees supplied,
//!  * deterministic seed fixtures from the full SDK verify identically (H4),
//!  * timestamp trees: outcome parity per verification policy; core is
//!    never more permissive than the hostless full SDK (H6),
//!  * tamper detection parity (H3).
//!
//! Cross-crate transfer always goes through serde JSON, which is the wire
//! format; type-level reuse between the two crates is deliberately not
//! attempted.

use aqua_rs_sdk as full;
use aqua_rs_sdk_core as core_;

use std::path::PathBuf;

/// Deterministic Ed25519 seed used across the original SDK's test suite.
fn test_key() -> Vec<u8> {
    (1..=32).collect()
}

fn core_file_data(name: &str, content: &[u8]) -> core_::schema::FileData {
    core_::schema::FileData::new(name.to_string(), content.to_vec(), PathBuf::from(name))
}

fn full_file_data(name: &str, content: &[u8]) -> full::schema::FileData {
    full::schema::FileData::new(name.to_string(), content.to_vec(), PathBuf::from(name))
}

/// Move a tree across the crate boundary through its JSON wire form.
fn core_tree_to_full(tree: &core_::schema::tree::Tree) -> full::schema::tree::Tree {
    serde_json::from_value(serde_json::to_value(tree).unwrap()).unwrap()
}

fn full_tree_to_core(tree: &full::schema::tree::Tree) -> core_::schema::tree::Tree {
    serde_json::from_value(serde_json::to_value(tree).unwrap()).unwrap()
}

// ── H2: template hash parity ────────────────────────────────────────────

#[test]
fn template_hash_constants_match() {
    use core_::schema::template::BuiltInTemplate as C;
    use full::schema::template::BuiltInTemplate as F;

    macro_rules! pair {
        ($name:ident) => {
            assert_eq!(
                <core_::schema::templates::$name as C>::TEMPLATE_LINK,
                <full::schema::templates::$name as F>::TEMPLATE_LINK,
                concat!("TEMPLATE_LINK drift for ", stringify!($name))
            );
            // TEMPLATE_JSON is not compared here: the trait defaults it to
            // an empty string and not every impl overrides it. Byte identity
            // of the template files is asserted directly in
            // template_files_byte_identical below.
        };
    }

    pair!(TemplateMeta);
    pair!(AnchorTemplate);
    pair!(SignatureBase);
    pair!(SignatureEd25519);
    pair!(SignatureEip191);
    pair!(SignatureP256);
    pair!(SignatureWebauthn);
    pair!(File);
    // The audit family, identity_base, and the timestamp templates are NOT
    // compared: the audit templates are the deliberately re-rooted variants
    // (see audit_family_divergence_is_intentional) and identity_base plus
    // the timestamp templates left core entirely (unsupported-lookup, E-D2).
}

// ── H3: canonicalization parity on identical input ──────────────────────

#[test]
fn canonical_template_hash_parity() {
    use core_::schema::template::BuiltInTemplate;
    use core_::verification::Linkable as CL;
    use full::verification::Linkable as FL;

    let json = <core_::schema::templates::AuditUserTurnMarker as BuiltInTemplate>::TEMPLATE_JSON;
    let ct: core_::schema::Template = serde_json::from_str(json).unwrap();
    let ft: full::schema::Template = serde_json::from_str(json).unwrap();
    let ch = CL::calculate_link(&ct, core_::primitives::HashType::Sha3_256).unwrap();
    let fh = FL::calculate_link(&ft, full::primitives::HashType::Sha3_256).unwrap();
    assert_eq!(
        ch.to_string(),
        fh.to_string(),
        "flatten/sort/hash/multihash pipeline diverged between crates"
    );
}

// ── H3 + H4: cross-verification of signed file trees ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn core_signed_file_tree_verifies_in_full_sdk() {
    let content = b"compat test payload";
    let aq = core_::Aquafier::new();
    let tree = aq
        .create_genesis_revision(core_file_data("compat.txt", content), None)
        .unwrap();
    let signed = aq
        .sign_aqua_tree(
            core_::schema::AquaTreeWrapper::new(tree, None, None),
            &core_::schema::SigningCredentials::Did {
                did_key: test_key(),
            },
            None,
            None,
        )
        .await
        .unwrap();

    // Verify in core itself.
    let core_result = aq
        .verify_aqua_tree(
            core_::schema::AquaTreeWrapper::new(
                signed.aqua_tree.clone(),
                Some(core_file_data("compat.txt", content)),
                None,
            ),
            vec![core_file_data("compat.txt", content)],
        )
        .await
        .unwrap();
    assert!(
        core_result.is_verified(),
        "core-signed tree must verify in core: {:?}",
        core_result.logs
    );

    // Verify in the full SDK.
    let full_tree = core_tree_to_full(&signed.aqua_tree);
    let full_result = full::Aquafier::new()
        .verify_aqua_tree(
            full::schema::AquaTreeWrapper::new(
                full_tree,
                Some(full_file_data("compat.txt", content)),
                None,
            ),
            vec![full_file_data("compat.txt", content)],
        )
        .await
        .unwrap();
    assert!(
        full_result.is_verified(),
        "core-signed tree must verify in the full SDK: {:?}",
        full_result.logs
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn full_sdk_signed_file_tree_verifies_in_core() {
    let content = b"compat test payload reverse";
    let aq = full::Aquafier::new();
    let tree = aq
        .create_genesis_revision(full_file_data("compat2.txt", content), None)
        .unwrap();
    let signed = aq
        .sign_aqua_tree(
            full::schema::AquaTreeWrapper::new(tree, None, None),
            &full::schema::SigningCredentials::Did {
                did_key: test_key(),
            },
            None,
            None,
        )
        .await
        .unwrap();

    let core_tree = full_tree_to_core(&signed.aqua_tree);
    let core_result = core_::Aquafier::new()
        .verify_aqua_tree(
            core_::schema::AquaTreeWrapper::new(
                core_tree,
                Some(core_file_data("compat2.txt", content)),
                None,
            ),
            vec![core_file_data("compat2.txt", content)],
        )
        .await
        .unwrap();
    assert!(
        core_result.is_verified(),
        "full-SDK-signed tree must verify in core: {:?}",
        core_result.logs
    );
}

// ── H5: audit template family (identity_base WASM ancestry) ─────────────

#[tokio::test(flavor = "multi_thread")]
async fn audit_turn_marker_cross_verifies() {
    use core_::schema::template::BuiltInTemplate;

    let payload = serde_json::json!({
        "signer_did": "did:key:z6MkcompatTestServerKey",
        "session_id": "compat-session-1",
        "turn_index": 0,
        "opens_at": 1754500000u64,
    });
    let aq = core_::Aquafier::new();
    let tree = aq
        .create_object(
            core_::primitives::RevisionLink::from_bytes(
                core_::schema::templates::AuditUserTurnMarker::TEMPLATE_LINK,
            ),
            None,
            payload,
            None,
        )
        .unwrap();
    let signed = aq
        .sign_aqua_tree(
            core_::schema::AquaTreeWrapper::new(tree, None, None),
            &core_::schema::SigningCredentials::Did {
                did_key: test_key(),
            },
            None,
            None,
        )
        .await
        .unwrap();

    // Core: the re-rooted audit chain is pure data (no WASM anywhere), so
    // verification runs with no compute involvement at all.
    let core_result = aq
        .verify_aqua_tree(
            core_::schema::AquaTreeWrapper::new(signed.aqua_tree.clone(), None, None),
            vec![],
        )
        .await
        .unwrap();
    assert!(
        core_result.is_verified(),
        "t1 audit tree must verify in core: {:?}",
        core_result.logs
    );
    assert!(
        !core_result
            .logs
            .iter()
            .any(|l| l.log.contains("Compute verification skipped")),
        "re-rooted audit chain must not involve the compute stage at all"
    );

    // Non-vacuity control: shipped as-is, the same tree must FAIL in the full
    // SDK, whose catalog holds the old identity-rooted audit hashes instead.
    // Without this the export assertion below could pass for the wrong reason.
    let bare_result = full::Aquafier::new()
        .verify_aqua_tree(
            full::schema::AquaTreeWrapper::new(core_tree_to_full(&signed.aqua_tree), None, None),
            vec![],
        )
        .await
        .unwrap();
    assert!(
        !bare_result.is_verified(),
        "an un-exported core audit tree must not resolve in the full SDK"
    );

    // Full SDK: core's re-rooted templates are not full-SDK built-ins, so the
    // tree has to carry them. That is exactly what a self-descriptive export
    // is for: export_tree with defaults walks the T1 object's type and its
    // audit_artifact ancestry and embeds both template revisions under their
    // multihash links. "Built-in" is receiver-relative, which this assertion
    // is the live proof of: both templates are built-in to core and neither
    // resolves in the full SDK, so the export must ship them anyway.
    let portable = aq
        .export_tree(&signed.aqua_tree, &[], &core_::ExportOptions::default())
        .expect("core's own audit templates resolve from its catalog");
    assert_eq!(
        portable
            .revisions
            .values()
            .filter(|r| matches!(r, core_::schema::AnyRevision::Template(_)))
            .count(),
        2,
        "export must embed the T1 template and its audit_artifact root"
    );
    assert!(
        core_::missing_templates(&portable).is_empty(),
        "an exported tree must reference no unresolvable type"
    );
    let full_tree = core_tree_to_full(&portable);
    let full_result = full::Aquafier::new()
        .verify_aqua_tree(
            full::schema::AquaTreeWrapper::new(full_tree, None, None),
            vec![],
        )
        .await
        .unwrap();
    assert!(
        full_result.is_verified(),
        "core-signed re-rooted t1 audit tree must verify in the full SDK \
         via the portable-template pattern: {:?}",
        full_result.logs
    );
}

// ── H4: deterministic seed fixture from the full SDK ────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn seed_sign_did_fixture_verifies_identically() {
    let raw = include_str!("../../src/tests/seed/sign_did_example.aqua.json");

    // The seed's genesis references test.txt with the fixed content used
    // by the original SDK's seed generator (src/tests/aqua.rs).
    let seed_file = b"test content";

    let core_tree: core_::schema::tree::Tree = serde_json::from_str(raw).unwrap();
    let core_result = core_::Aquafier::new()
        .verify_aqua_tree(
            core_::schema::AquaTreeWrapper::new(
                core_tree,
                Some(core_file_data("test.txt", seed_file)),
                None,
            ),
            vec![core_file_data("test.txt", seed_file)],
        )
        .await
        .unwrap();

    let full_tree: full::schema::tree::Tree = serde_json::from_str(raw).unwrap();
    let full_result = full::Aquafier::new()
        .verify_aqua_tree(
            full::schema::AquaTreeWrapper::new(
                full_tree,
                Some(full_file_data("test.txt", seed_file)),
                None,
            ),
            vec![full_file_data("test.txt", seed_file)],
        )
        .await
        .unwrap();

    assert_eq!(
        core_result.is_verified(),
        full_result.is_verified(),
        "seed fixture outcome diverged: core={:?} full={:?}",
        core_result.outcome,
        full_result.outcome
    );
    assert!(
        core_result.is_verified(),
        "sign_did seed must verify: {:?}",
        core_result.logs
    );
}

// ── H6: timestamp trees, per-policy outcome parity ──────────────────────

async fn core_verify_with_policy(
    raw: &str,
    policy: core_::VerificationPolicy,
) -> core_::VerificationResult {
    // Timestamp seeds share the sign_did seed's genesis: test.txt with the
    // fixed content from the original SDK's seed generator.
    let tree: core_::schema::tree::Tree = serde_json::from_str(raw).unwrap();
    let aq = core_::Aquafier::builder().verification_policy(policy).build();
    aq.verify_aqua_tree(
        core_::schema::AquaTreeWrapper::new(
            tree,
            Some(core_file_data("test.txt", b"test content")),
            None,
        ),
        vec![core_file_data("test.txt", b"test content")],
    )
    .await
    .unwrap()
}

async fn full_verify_with_policy(
    raw: &str,
    policy: full::VerificationPolicy,
) -> full::VerificationResult {
    let tree: full::schema::tree::Tree = serde_json::from_str(raw).unwrap();
    let aq = full::Aquafier::builder().verification_policy(policy).build();
    aq.verify_aqua_tree(
        full::schema::AquaTreeWrapper::new(
            tree,
            Some(full_file_data("test.txt", b"test content")),
            None,
        ),
        vec![full_file_data("test.txt", b"test content")],
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn timestamp_seeds_policy_parity() {
    for (name, raw) in [
        (
            "timestamp_eth",
            include_str!("../../src/tests/seed/timestamp_eth_example.json"),
        ),
        (
            "timestamp_tsa",
            include_str!("../../src/tests/seed/timestamp_tsa_example.json"),
        ),
    ] {
        // Strict policy: the timestamp attestation is unverifiable in core
        // (no WASM runtime) and in the hostless full SDK (no blockchain or
        // web host). Both must reject; core is never more permissive.
        let core_strict = core_verify_with_policy(raw, core_::VerificationPolicy::strict()).await;
        let full_strict = full_verify_with_policy(raw, full::VerificationPolicy::strict()).await;
        assert_eq!(
            core_strict.is_verified(),
            full_strict.is_verified(),
            "{name}: strict outcome diverged: core={:?} full={:?}",
            core_strict.outcome,
            full_strict.outcome
        );
        assert!(
            !core_strict.is_verified(),
            "{name}: strict core must reject an unverifiable timestamp \
             attestation: {:?}",
            core_strict.logs
        );
        assert!(
            core_strict.logs.iter().any(|l| l
                .log
                .contains("is not supported for verification by aqua-rs-sdk-core")
                && l.log.contains("the timestamping module")),
            "{name}: core must explain WHICH module the unsupported template \
             needs: {:?}",
            core_strict.logs
        );

        // Offline policy tolerates the unavailable attestation with a warning
        // in both implementations.
        let core_off = core_verify_with_policy(raw, core_::VerificationPolicy::offline()).await;
        let full_off = full_verify_with_policy(raw, full::VerificationPolicy::offline()).await;
        assert_eq!(
            core_off.is_verified(),
            full_off.is_verified(),
            "{name}: offline outcome diverged: core={:?} full={:?}",
            core_off.outcome,
            full_off.outcome
        );
        assert!(
            core_off.is_verified(),
            "{name}: offline core must tolerate the unavailable timestamp \
             attestation: {:?}",
            core_off.logs
        );
    }
}

// ── H3: tamper detection parity ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn tampered_tree_fails_in_both() {
    let content = b"tamper target";
    let aq = core_::Aquafier::new();
    let tree = aq
        .create_genesis_revision(core_file_data("t.txt", content), None)
        .unwrap();
    let signed = aq
        .sign_aqua_tree(
            core_::schema::AquaTreeWrapper::new(tree, None, None),
            &core_::schema::SigningCredentials::Did {
                did_key: test_key(),
            },
            None,
            None,
        )
        .await
        .unwrap();

    // Corrupt a hash-covered payload field (the file size inside the object
    // revision's payloads); revision-hash verification must catch this in
    // both implementations. The auxiliary file_index is deliberately NOT the
    // tamper target: it is not covered by revision hashes.
    let mut v = serde_json::to_value(&signed.aqua_tree).unwrap();
    let mut tampered = false;
    if let Some(revisions) = v.get_mut("revisions").and_then(|r| r.as_object_mut()) {
        for (_, rev) in revisions.iter_mut() {
            if let Some(size) = rev
                .get_mut("payloads")
                .and_then(|p| p.get_mut("size"))
                .and_then(|s| s.as_u64())
            {
                rev["payloads"]["size"] = serde_json::json!(size + 1);
                tampered = true;
                break;
            }
        }
    }
    assert!(tampered, "no payload field found to tamper");
    let tampered_json = serde_json::to_string(&v).unwrap();

    let core_tree: core_::schema::tree::Tree = serde_json::from_str(&tampered_json).unwrap();
    let core_result = aq
        .verify_aqua_tree(
            core_::schema::AquaTreeWrapper::new(core_tree, None, None),
            vec![core_file_data("t.txt", content)],
        )
        .await
        .unwrap();
    assert!(
        !core_result.is_verified(),
        "core must reject the tampered tree"
    );

    let full_tree: full::schema::tree::Tree = serde_json::from_str(&tampered_json).unwrap();
    let full_result = full::Aquafier::new()
        .verify_aqua_tree(
            full::schema::AquaTreeWrapper::new(full_tree, None, None),
            vec![full_file_data("t.txt", content)],
        )
        .await
        .unwrap();
    assert!(
        !full_result.is_verified(),
        "full SDK must reject the tampered tree"
    );
}

// ── H5 fail-closed: custom WASM-carrying templates are rejected ─────────

#[tokio::test(flavor = "multi_thread")]
async fn custom_wasm_template_rejected_fail_closed() {
    use core_::schema::template::BuiltInTemplate;
    use core_::verification::Linkable;

    // Build a CUSTOM template (distinct nonce => distinct type identity)
    // that carries identity_base's real WASM verification section.
    let mut tmpl_json: serde_json::Value = serde_json::from_str(
        <core_::schema::templates::AuditUserTurnMarker as BuiltInTemplate>::TEMPLATE_JSON,
    )
    .unwrap();
    let identity_base: serde_json::Value = serde_json::from_str(include_str!(
        "../../../aqua-rs-sdk/src/schema/templates/identity_base.json"
    ))
    .unwrap();
    tmpl_json["verification"] = identity_base["verification"].clone();
    tmpl_json["nonce"] = serde_json::json!("0x000102030405060708090a0b0c0d0e0f");
    // A custom root template: no derivation baggage from the audit family.
    tmpl_json.as_object_mut().unwrap().remove("derives_from");
    tmpl_json.as_object_mut().unwrap().remove("ancestry");
    let template: core_::schema::Template = serde_json::from_value(tmpl_json).unwrap();
    let template_link = template
        .calculate_link(core_::primitives::HashType::Sha3_256)
        .unwrap();

    // Object of that custom type, template revision embedded in the tree
    // (the portable-template pattern), keyed by the full multihash link.
    let aq = core_::Aquafier::new();
    let mut tree = aq
        .create_object(
            template_link.clone(),
            None,
            serde_json::json!({
                "signer_did": "did:key:z6MkCustomWasmTest",
                "session_id": "s",
                "turn_index": 0,
                "opens_at": 1
            }),
            None,
        )
        .unwrap();
    tree.revisions.insert(
        template_link.clone(),
        core_::schema::AnyRevision::Template(template),
    );

    let result = aq
        .verify_aqua_tree(core_::schema::AquaTreeWrapper::new(tree, None, None), vec![])
        .await
        .unwrap();
    assert!(
        !result.is_verified(),
        "core must fail closed on a non-built-in WASM-carrying template"
    );
    assert!(
        result
            .errors()
            .iter()
            .any(|e| e.code == "COMPUTE_UNSUPPORTED"),
        "expected COMPUTE_UNSUPPORTED, got: {:?}",
        result.outcome
    );
}

// ── H2: template JSON files are byte-identical across the two repos ─────

#[test]
fn template_files_byte_identical() {
    macro_rules! file_pair {
        ($file:literal) => {
            assert_eq!(
                include_str!(concat!("../../src/schema/templates/", $file)).as_bytes(),
                include_str!(concat!(
                    "../../../aqua-rs-sdk/src/schema/templates/",
                    $file
                ))
                .as_bytes(),
                concat!("template file byte drift: ", $file)
            );
        };
    }
    file_pair!("template_meta.json");
    file_pair!("anchor_template.json");
    file_pair!("signature_base.json");
    file_pair!("signature_ed25519.json");
    file_pair!("signature_eip191.json");
    file_pair!("signature_p256.json");
    file_pair!("signature_webauthn.json");
    file_pair!("file.json");
}

// ── Deliberate divergence: the audit family forked from the full SDK ────
//
// 2026-08-07 (Tim): the audit family was re-rooted at audit_artifact
// (identity_base removed from ancestry), T5 was renamed to
// audit_api_response, and customer-derived example strings were scrubbed
// from the T4/T5 descriptions. Template hash = type identity, so all 11
// audit templates are new types. This test documents that the divergence
// is intentional and exactly bounded: hashes differ, and the JSONs differ
// from the full SDK's ONLY in derives_from/ancestry and descriptions.

#[test]
fn audit_family_divergence_is_intentional() {
    use core_::verification::Linkable;

    fn scrub(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(m) => {
                m.remove("description");
                m.remove("derives_from");
                m.remove("ancestry");
                for (_, x) in m.iter_mut() {
                    scrub(x);
                }
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(scrub),
            _ => {}
        }
    }
    macro_rules! forked_pair {
        ($core_file:literal, $full_file:literal) => {{
            let core_raw = include_str!(concat!("../../src/schema/templates/", $core_file));
            let full_raw = include_str!(concat!(
                "../../../aqua-rs-sdk/src/schema/templates/",
                $full_file
            ));
            // Hash fork: computed links must differ.
            let ct: core_::schema::Template = serde_json::from_str(core_raw).unwrap();
            let ft: core_::schema::Template = serde_json::from_str(full_raw).unwrap();
            assert_ne!(
                ct.calculate_link(core_::primitives::HashType::Sha3_256)
                    .unwrap(),
                ft.calculate_link(core_::primitives::HashType::Sha3_256)
                    .unwrap(),
                concat!($core_file, ": expected a deliberate hash fork")
            );
            // Bounded fork: identical after removing ancestry linkage and
            // description strings.
            let mut c: serde_json::Value = serde_json::from_str(core_raw).unwrap();
            let mut f: serde_json::Value = serde_json::from_str(full_raw).unwrap();
            scrub(&mut c);
            scrub(&mut f);
            assert_eq!(
                c, f,
                concat!($core_file, ": fork must be bounded to ancestry + descriptions")
            );
        }};
    }
    forked_pair!("audit_artifact.json", "audit_artifact.json");
    forked_pair!("audit_user_turn_marker.json", "audit_user_turn_marker.json");
    forked_pair!("audit_user_prompt.json", "audit_user_prompt.json");
    forked_pair!("audit_agent_thinking.json", "audit_agent_thinking.json");
    forked_pair!("audit_agent_tool_call.json", "audit_agent_tool_call.json");
    forked_pair!("audit_api_response.json", "audit_gusto_api_response.json");
    forked_pair!("audit_tool_result.json", "audit_tool_result.json");
    forked_pair!("audit_hitl_approval.json", "audit_hitl_approval.json");
    forked_pair!("audit_agent_response.json", "audit_agent_response.json");
    forked_pair!("audit_round_anchor.json", "audit_round_anchor.json");
    forked_pair!("audit_session_close.json", "audit_session_close.json");
}
