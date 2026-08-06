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
            assert_eq!(
                <core_::schema::templates::$name as C>::TEMPLATE_JSON,
                <full::schema::templates::$name as F>::TEMPLATE_JSON,
                concat!("TEMPLATE_JSON byte drift for ", stringify!($name))
            );
        };
    }

    pair!(TemplateMeta);
    pair!(AnchorTemplate);
    pair!(SignatureBase);
    pair!(SignatureEd25519);
    pair!(SignatureEip191);
    pair!(SignatureP256);
    pair!(SignatureWebauthn);
    pair!(IdentityBase);
    pair!(File);
    pair!(TimestampBase);
    pair!(EvmTimestampPayload);
    pair!(TsaTimestampPayload);
    pair!(AuditArtifact);
    pair!(AuditUserTurnMarker);
    pair!(AuditUserPrompt);
    pair!(AuditAgentThinking);
    pair!(AuditAgentToolCall);
    pair!(AuditGustoApiResponse);
    pair!(AuditToolResult);
    pair!(AuditHitlApproval);
    pair!(AuditAgentResponse);
    pair!(AuditRoundAnchor);
    pair!(AuditSessionClose);
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

    // Core: identity_base's WASM ancestry is skipped with an explicit log
    // (D7); everything else verifies fully.
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
        core_result
            .logs
            .iter()
            .any(|l| l.log.contains("Compute verification skipped")),
        "core must log the explicit compute skip for the identity_base chain"
    );

    // Full SDK: identity_base's WASM actually executes (DefaultIdentityHost).
    let full_tree = core_tree_to_full(&signed.aqua_tree);
    let full_result = full::Aquafier::new()
        .verify_aqua_tree(
            full::schema::AquaTreeWrapper::new(full_tree, None, None),
            vec![],
        )
        .await
        .unwrap();
    assert!(
        full_result.is_verified(),
        "core-signed t1 audit tree must verify in the full SDK \
         (WASM executed there): {:?}",
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
