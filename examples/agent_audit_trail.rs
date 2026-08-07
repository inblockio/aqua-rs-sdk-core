//! End-to-end auditability for an AI agent, using the t1-t8 audit templates.
//!
//! This example walks through one complete turn of a generic order-processing
//! assistant. Every step the agent takes (reading the user's prompt, thinking,
//! calling a third-party inventory API, obtaining human approval, answering)
//! is recorded as its own signed Aqua tree, causally linked to the others.
//! The result is a verifiable audit trail that any third party can check
//! without trusting the agent's operator.
//!
//! Four distinct signing identities participate (all Ed25519 did:key,
//! derived from deterministic seeds so the identities are reproducible):
//!
//!   1. server key        - trust anchor: opens turns, seals rounds/session
//!   2. user session key  - signs the user's prompt and the human approval
//!   3. agent key         - signs thinking, tool calls, tool results, answers
//!   4. api attestor key  - signs the observed third-party API response
//!
//! Run with:
//!
//!   cargo run --example agent_audit_trail --features native

use std::collections::BTreeMap;
use std::error::Error;

use aqua_rs_sdk_core::core::signature::sign_did::DIDSigner;
use aqua_rs_sdk_core::primitives::log::LogType;
use aqua_rs_sdk_core::primitives::{merkle, HashType, Method, RevisionLink};
use aqua_rs_sdk_core::schema::link::{Anchor, CompositionalLink};
use aqua_rs_sdk_core::schema::template::BuiltInTemplate;
use aqua_rs_sdk_core::schema::templates::{
    AuditAgentResponse, AuditAgentThinking, AuditAgentToolCall, AuditHitlApproval,
    AuditRoundAnchor, AuditSessionClose, AuditToolResult, AuditUserPrompt, AuditUserTurnMarker,
};
// The wire-level type name below is a historical identifier retained for
// template-hash compatibility; semantically this is the generic template for
// an attested third-party API response.
use aqua_rs_sdk_core::schema::templates::AuditApiResponse;
use aqua_rs_sdk_core::schema::tree::Tree;
use aqua_rs_sdk_core::schema::{AnyRevision, AquaTreeWrapper, SigningCredentials, Template};
use aqua_rs_sdk_core::verification::Linkable;
use aqua_rs_sdk_core::{
    redact_revision, verify_redacted_revision, Aquafier, DisclosurePolicy, RedactedLeaf,
    RevisionDisclosure,
};
use serde_json::json;

/// Compositional-link vocabulary used to relate audit artifacts.
const ROLE_IN_TURN: &str = "aqua:in_user_turn";
const ROLE_PREV: &str = "aqua:prev_artifact_in_turn";
const ROLE_USED: &str = "prov:used";
const ROLE_GENERATED_BY: &str = "prov:wasGeneratedBy";

const SESSION_ID: &str = "session-demo-0001";
/// Fixed base timestamp (unix seconds) so the printed narrative is stable.
const BASE_TIME: u64 = 1754500000;

/// A named signing identity with a deterministic Ed25519 seed.
struct Identity {
    name: &'static str,
    seed: [u8; 32],
    did: String,
}

impl Identity {
    fn new(name: &'static str, seed: [u8; 32]) -> Result<Self, Box<dyn Error>> {
        let did = DIDSigner.derive_did(&seed)?;
        Ok(Self { name, seed, did })
    }

    fn credentials(&self) -> SigningCredentials {
        SigningCredentials::Did {
            did_key: self.seed.to_vec(),
        }
    }
}

/// The bare 32-byte template link of a built-in template.
fn builtin_link<T: BuiltInTemplate>() -> RevisionLink {
    RevisionLink::from_bytes(T::TEMPLATE_LINK)
}

/// Attach role-tagged compositional links via an Anchor revision, then sign
/// the tip once. Shape: Genesis Anchor -> Object -> [Anchor(links)] -> Signature.
/// Compositional links are application-level provenance edges; the SDK stores
/// them but does not resolve them, so linking across trees needs no extra
/// verification inputs.
async fn attach_and_sign(
    aquafier: &Aquafier,
    mut tree: Tree,
    links: Vec<CompositionalLink>,
    signer: &Identity,
) -> Result<Tree, Box<dyn Error>> {
    if !links.is_empty() {
        let tip = tree
            .get_latest_revision_link()
            .ok_or("unsigned tree has no revisions")?;
        let mut anchor = Anchor::with_links(tip, Method::Scalar, Vec::new(), links);
        let anchor_hash = anchor.calculate_link(HashType::Sha3_256)?;
        anchor.populate_leaves(HashType::Sha3_256)?;
        tree.revisions
            .insert(anchor_hash, AnyRevision::Anchor(anchor));
    }

    let signed = aquafier
        .sign_aqua_tree(
            AquaTreeWrapper::new(tree, None, None),
            &signer.credentials(),
            None,
            None,
        )
        .await?;
    Ok(signed.aqua_tree)
}

/// Create one audit artifact as its own Aqua tree:
/// object from template + payload, compositional links, one signature.
/// Returns the signed tree and the object revision hash (the artifact's
/// stable content identity, used for cross-artifact links and Merkle leaves).
async fn emit_artifact(
    aquafier: &Aquafier,
    template_link: RevisionLink,
    payload: serde_json::Value,
    links: Vec<CompositionalLink>,
    signer: &Identity,
) -> Result<(Tree, RevisionLink), Box<dyn Error>> {
    let tree = aquafier.create_object(template_link, None, payload, None)?;
    let object_hash = tree
        .get_latest_revision_link()
        .ok_or("created tree has no tip")?;
    let signed = attach_and_sign(aquafier, tree, links, signer).await?;
    Ok((signed, object_hash))
}

/// Portable custom-template pattern.
///
/// audit_round_anchor and audit_session_close are NOT in the SDK's built-in
/// verification cache (this mirrors the full SDK). A verifier can only check
/// objects of such templates if the template revision itself is made
/// resolvable. We build a one-revision template tree, keyed by the template's
/// canonical SHA3-256 multihash link, and hand it to
/// verify_aqua_tree_with_linked_trees at verification time. This is exactly
/// what third-party template authors must ship alongside their trees.
fn portable_template(
    name: &str,
    template_json: &str,
) -> Result<(RevisionLink, AquaTreeWrapper), Box<dyn Error>> {
    let template: Template = serde_json::from_str(template_json)?;
    let link = template.calculate_link(HashType::Sha3_256)?;

    let mut revisions = BTreeMap::new();
    let mut file_index = BTreeMap::new();
    revisions.insert(link.clone(), AnyRevision::Template(template));
    file_index.insert(link.clone(), name.to_string());

    let tree = Tree {
        revisions,
        file_index,
    };
    Ok((link, AquaTreeWrapper::new(tree, None, None)))
}

/// Verify one tree through the full pipeline; print outcome and dump error
/// logs on failure. Returns (verified, saw_compute_skip_note).
async fn verify_tree(
    aquafier: &Aquafier,
    label: &str,
    tree: &Tree,
    linked: Vec<AquaTreeWrapper>,
) -> Result<(bool, bool), Box<dyn Error>> {
    let wrapper = AquaTreeWrapper::new(tree.clone(), None, None);
    let result = if linked.is_empty() {
        aquafier.verify_aqua_tree(wrapper, vec![]).await?
    } else {
        aquafier
            .verify_aqua_tree_with_linked_trees(wrapper, linked, vec![])
            .await?
    };

    let compute_skipped = result
        .logs
        .iter()
        .any(|l| l.log.contains("Compute verification skipped"));
    println!(
        "  {:<24} verified: {:<5} compute-skip note: {}",
        label,
        result.is_verified(),
        if compute_skipped { "yes" } else { "no" }
    );
    if !result.is_verified() {
        for log in result
            .logs
            .iter()
            .filter(|l| matches!(l.log_type, LogType::Error))
        {
            eprintln!("    error: {}", log.log);
        }
    }
    Ok((result.is_verified(), compute_skipped))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let aquafier = Aquafier::new();

    println!("=== Agent audit trail: one verifiable turn of an order-processing assistant ===");
    println!();

    // ── Identities ─────────────────────────────────────────────────────
    // Deterministic seeds make the four DIDs reproducible across runs.
    // In production each seed would come from a key store or HSM.
    let server = Identity::new("server", [0x11; 32])?;
    let user = Identity::new("user_session", [0x22; 32])?;
    let agent = Identity::new("agent", [0x33; 32])?;
    let attestor = Identity::new("api_attestor", [0x44; 32])?;

    println!("Signing identities (Ed25519 did:key):");
    for id in [&server, &user, &agent, &attestor] {
        println!("  {:<14} {}", id.name, id.did);
    }
    println!();

    // ── T1: turn marker (server) ───────────────────────────────────────
    // The server opens the turn. The T1 object's revision hash IS the
    // turn_id that every later artifact carries, so the whole turn is
    // pinned to one content-addressed identifier.
    let (t1_tree, t1_hash) = emit_artifact(
        &aquafier,
        builtin_link::<AuditUserTurnMarker>(),
        json!({
            "signer_did": server.did,
            "session_id": SESSION_ID,
            "turn_index": 0,
            "opens_at": BASE_TIME,
        }),
        vec![],
        &server,
    )
    .await?;
    let turn_id = t1_hash.to_string();
    println!("T1 turn marker (server opens the turn)");
    println!("  turn_id = {turn_id}");

    // ── T2: user prompt (user session key) ─────────────────────────────
    // The user's own key signs what the user actually asked.
    let prompt_text = "Where is my order ORD-1042? If it has not shipped yet, \
                       please expedite it.";
    let (t2_tree, t2_hash) = emit_artifact(
        &aquafier,
        builtin_link::<AuditUserPrompt>(),
        json!({
            "signer_did": user.did,
            "session_id": SESSION_ID,
            "turn_id": turn_id,
            "prompt_text": prompt_text,
            "created_at": BASE_TIME + 1,
        }),
        vec![CompositionalLink::new(t1_hash.clone(), ROLE_IN_TURN)],
        &user,
    )
    .await?;
    println!("T2 user prompt (signed by the user's session key)");
    println!("  \"{prompt_text}\"");

    // ── T3: agent thinking (agent key) ─────────────────────────────────
    let (t3_tree, t3_hash) = emit_artifact(
        &aquafier,
        builtin_link::<AuditAgentThinking>(),
        json!({
            "signer_did": agent.did,
            "turn_id": turn_id,
            "seq_in_turn": 1,
            "thinking_text": "The user asks about order ORD-1042 and wants it \
                              expedited. I need the current shipment status from \
                              the inventory service first. Expediting changes the \
                              order, so it requires explicit human approval.",
            "claude_round_id": "round-1",
            "created_at": BASE_TIME + 2,
            "model_name": "example-model-1",
        }),
        vec![
            CompositionalLink::new(t1_hash.clone(), ROLE_IN_TURN),
            CompositionalLink::new(t2_hash.clone(), ROLE_PREV),
        ],
        &agent,
    )
    .await?;
    println!("T3 agent thinking (reasoning trace, signed by the agent key)");

    // ── T4: tool call (agent key) ──────────────────────────────────────
    let (t4_tree, t4_hash) = emit_artifact(
        &aquafier,
        builtin_link::<AuditAgentToolCall>(),
        json!({
            "signer_did": agent.did,
            "turn_id": turn_id,
            "seq_in_turn": 2,
            "tool_name": "inventory.order.status",
            "tool_args": { "order_id": "ORD-1042" },
            "risk_level": "low",
            "created_at": BASE_TIME + 3,
        }),
        vec![
            CompositionalLink::new(t1_hash.clone(), ROLE_IN_TURN),
            CompositionalLink::new(t3_hash.clone(), ROLE_PREV),
        ],
        &agent,
    )
    .await?;
    println!("T4 tool call: inventory.order.status(order_id: ORD-1042)");

    // ── T5: attested API response (api attestor key) ───────────────────
    // A separate attestor identity (for example a proxy in front of the
    // third-party API) signs what the API actually returned, so the agent
    // cannot later misrepresent the observation.
    let request_canonical = b"GET /v1/orders/ORD-1042";
    let request_hash = format!(
        "0x{}",
        hex::encode(HashType::Sha3_256.hash(request_canonical))
    );
    let response_body = json!({
        "order_id": "ORD-1042",
        "status": "picking",
        "warehouse": "AMS-2",
        "expedite_available": true,
    });
    let (t5_tree, t5_hash) = emit_artifact(
        &aquafier,
        builtin_link::<AuditApiResponse>(),
        json!({
            "signer_did": attestor.did,
            "turn_id": turn_id,
            "seq_in_turn": 3,
            "method": "GET",
            "endpoint": "/v1/orders/ORD-1042",
            "status_code": 200,
            "request_hash": request_hash,
            "response_body": response_body,
            "attested_origin": "api.inventory.example",
            "created_at": BASE_TIME + 4,
        }),
        vec![
            CompositionalLink::new(t1_hash.clone(), ROLE_IN_TURN),
            CompositionalLink::new(t4_hash.clone(), ROLE_PREV),
            CompositionalLink::new(t4_hash.clone(), ROLE_GENERATED_BY),
        ],
        &attestor,
    )
    .await?;
    println!("T5 attested API response (signed by the independent api attestor)");
    println!("  GET /v1/orders/ORD-1042 -> 200, status: picking, warehouse: AMS-2");

    // ── T6: tool result (agent key) ────────────────────────────────────
    // What the agent saw. The prov:used link ties it to the attested T5
    // observation, so divergence between the two is detectable.
    let (t6_tree, t6_hash) = emit_artifact(
        &aquafier,
        builtin_link::<AuditToolResult>(),
        json!({
            "signer_did": agent.did,
            "turn_id": turn_id,
            "seq_in_turn": 4,
            "tool_name": "inventory.order.status",
            "result_payload": {
                "order_id": "ORD-1042",
                "status": "picking",
                "warehouse": "AMS-2",
                "expedite_available": true,
            },
            "success": true,
            "created_at": BASE_TIME + 5,
        }),
        vec![
            CompositionalLink::new(t1_hash.clone(), ROLE_IN_TURN),
            CompositionalLink::new(t5_hash.clone(), ROLE_PREV),
            CompositionalLink::new(t5_hash.clone(), ROLE_USED),
        ],
        &agent,
    )
    .await?;
    println!("T6 tool result (the result the agent saw, linked to the attested T5)");

    // ── T7: human-in-the-loop approval (user session key) ──────────────
    // Expediting mutates the order, so the human approves before the agent
    // acts. The approval is signed with the user's key, not the agent's.
    let approval_prompt = "Order ORD-1042 is still in warehouse AMS-2 (status: \
                           picking). Expedite shipping for an extra fee?";
    let (t7_tree, t7_hash) = emit_artifact(
        &aquafier,
        builtin_link::<AuditHitlApproval>(),
        json!({
            "signer_did": user.did,
            "turn_id": turn_id,
            "decision": "approved",
            "prompt_shown": approval_prompt,
            "created_at": BASE_TIME + 6,
            "rationale": "Extra fee accepted.",
        }),
        vec![
            CompositionalLink::new(t1_hash.clone(), ROLE_IN_TURN),
            CompositionalLink::new(t6_hash.clone(), ROLE_PREV),
        ],
        &user,
    )
    .await?;
    println!("T7 human approval: \"approved\" (signed by the user's session key)");

    // ── T8: agent response (agent key, is_final closes the turn) ───────
    let response_text = "Your order ORD-1042 is still being picked in warehouse \
                         AMS-2. As you approved, expedited shipping has been \
                         applied; it will leave with today's priority batch.";
    let (t8_tree, t8_hash) = emit_artifact(
        &aquafier,
        builtin_link::<AuditAgentResponse>(),
        json!({
            "signer_did": agent.did,
            "turn_id": turn_id,
            "response_text": response_text,
            "is_final": true,
            "created_at": BASE_TIME + 7,
            "model_name": "example-model-1",
        }),
        vec![
            CompositionalLink::new(t1_hash.clone(), ROLE_IN_TURN),
            CompositionalLink::new(t7_hash.clone(), ROLE_PREV),
            CompositionalLink::new(t6_hash.clone(), ROLE_USED),
        ],
        &agent,
    )
    .await?;
    println!("T8 agent response (is_final: true, closes the turn)");
    println!();

    // ── Round anchor (server): Merkle commitment over the turn ─────────
    // The server closes the turn with a Merkle root over the seven artifact
    // hashes (T2..T8), computed with the SDK's domain-separated helpers
    // (RFC 6962 style: leaf = H(0x00 || data), node = H(0x01 || l || r)).
    let artifact_hashes = [
        &t2_hash, &t3_hash, &t4_hash, &t5_hash, &t6_hash, &t7_hash, &t8_hash,
    ];
    let leaf_hashes: Vec<String> = artifact_hashes.iter().map(|h| h.to_string()).collect();
    let leaves: Vec<Vec<u8>> = artifact_hashes
        .iter()
        .map(|h| merkle::batch_leaf_hash(&HashType::Sha3_256, h.as_ref()))
        .collect();
    let merkle_root = format!(
        "0x{}",
        hex::encode(merkle::merkle_root(&leaves, &HashType::Sha3_256))
    );

    // Typed payload structs exist for the audit templates; using one here
    // gets us compile-time field names plus the validate() pre-flight.
    let round_anchor = AuditRoundAnchor {
        signer_did: server.did.clone(),
        session_id: SESSION_ID.to_string(),
        turn_id: turn_id.clone(),
        turn_index: 0,
        artifact_count: artifact_hashes.len() as u64,
        leaf_hashes,
        merkle_root: merkle_root.clone(),
        closed_at: BASE_TIME + 8,
    };
    round_anchor.validate()?;

    let (round_template_link, round_template_wrapper) =
        portable_template("audit_round_anchor", AuditRoundAnchor::TEMPLATE_JSON)?;
    let (anchor_tree, anchor_hash) = emit_artifact(
        &aquafier,
        round_template_link,
        serde_json::to_value(&round_anchor)?,
        vec![CompositionalLink::new(t1_hash.clone(), ROLE_IN_TURN)],
        &server,
    )
    .await?;
    println!("Round anchor (server seals the turn)");
    println!("  merkle_root over 7 artifacts = {merkle_root}");

    // ── Session close (server) ─────────────────────────────────────────
    let session_close = AuditSessionClose {
        signer_did: server.did.clone(),
        session_id: SESSION_ID.to_string(),
        total_turns: 1,
        last_turn_id: turn_id.clone(),
        last_round_anchor_hash: anchor_hash.to_string(),
        reason: "user_ended".to_string(),
        closed_at: BASE_TIME + 9,
    };
    session_close.validate()?;

    let (close_template_link, close_template_wrapper) =
        portable_template("audit_session_close", AuditSessionClose::TEMPLATE_JSON)?;
    let (close_tree, _close_hash) = emit_artifact(
        &aquafier,
        close_template_link,
        serde_json::to_value(&session_close)?,
        vec![],
        &server,
    )
    .await?;
    println!("Session close (server seals the session, reason: user_ended)");
    println!();

    // ── Verification ───────────────────────────────────────────────────
    // Every artifact is verified independently through the full pipeline:
    // structure, hash integrity, template schema, and signatures.
    //
    // T1..T8 use built-in templates, so they verify self-contained. The
    // round anchor and session close use templates OUTSIDE the built-in
    // cache, so their portable template trees are passed as linked trees;
    // the pipeline verifies those template trees first, then resolves the
    // object's template from them.
    println!("Verifying all artifact trees:");
    let checks: Vec<(&str, &Tree, Vec<AquaTreeWrapper>)> = vec![
        ("T1 turn marker", &t1_tree, vec![]),
        ("T2 user prompt", &t2_tree, vec![]),
        ("T3 agent thinking", &t3_tree, vec![]),
        ("T4 tool call", &t4_tree, vec![]),
        ("T5 api response", &t5_tree, vec![]),
        ("T6 tool result", &t6_tree, vec![]),
        ("T7 hitl approval", &t7_tree, vec![]),
        ("T8 agent response", &t8_tree, vec![]),
        ("round anchor", &anchor_tree, vec![round_template_wrapper]),
        ("session close", &close_tree, vec![close_template_wrapper]),
    ];

    let mut all_verified = true;
    let mut any_compute_skip = false;
    for (label, tree, linked) in checks {
        let (verified, skipped) = verify_tree(&aquafier, label, tree, linked).await?;
        all_verified &= verified;
        any_compute_skip |= skipped;
    }
    println!();

    if any_compute_skip {
        println!("Note on the \"Compute verification skipped\" entries above:");
        println!("  every audit template derives from identity_base, whose WASM state");
        println!("  machine aqua-rs-sdk-core does not execute (core ships no WASM");
        println!("  runtime). The full aqua-rs-sdk executes it; the compat-tests suite");
        println!("  proves both implementations reach the same verification outcome.");
        println!();
    }

    if !all_verified {
        return Err("at least one artifact failed verification".into());
    }
    println!("ALL ARTIFACTS VERIFIED (10 trees: T1-T8, round anchor, session close)");
    println!();

    // ── Selective disclosure ───────────────────────────────────────────
    // An auditor may need proof that a prompt was signed and belongs to the
    // turn, without learning what the user wrote. Because object revisions
    // use the Tree method by default, each field is a salted Merkle leaf and
    // can be redacted independently while the revision hash stays provable.
    println!("=== Selective disclosure: pseudonymous view of the T2 prompt ===");
    println!();

    let policy = DisclosurePolicy::pseudonymous(&t2_tree);
    let disclosed_paths = match policy.revisions.get(&t2_hash) {
        Some(RevisionDisclosure::FieldRedacted(paths)) => paths.clone(),
        other => return Err(format!("unexpected T2 disclosure policy: {other:?}").into()),
    };
    let t2_revision = t2_tree
        .revisions
        .get(&t2_hash)
        .ok_or("T2 object revision missing from its tree")?;

    let redacted = redact_revision(t2_revision, &t2_hash, &disclosed_paths)?;

    println!(
        "Redacted T2 revision ({} Merkle leaves):",
        redacted.leaf_count
    );
    for leaf in &redacted.leaves {
        match leaf {
            RedactedLeaf::Disclosed { path, value, .. } => {
                let shown: String = value.chars().take(50).collect();
                println!("  disclosed {path} = {shown}");
            }
            RedactedLeaf::Redacted { path, .. } => {
                // The empty pointer is the revision's document-root leaf.
                let shown = if path.is_empty() { "(root)" } else { path };
                println!("  redacted  {shown} (salted commitment only)");
            }
        }
    }
    println!();

    let prompt_is_hidden = redacted.leaves.iter().any(
        |l| matches!(l, RedactedLeaf::Redacted { path, .. } if path == "/payloads/prompt_text"),
    );
    if !prompt_is_hidden {
        return Err("expected /payloads/prompt_text to be redacted".into());
    }

    verify_redacted_revision(&redacted)?;
    println!("The prompt text is no longer disclosed, yet the redacted revision");
    println!("still verifies against the original revision hash:");
    println!("  {t2_hash}");
    println!();
    println!("Done. Every claim about this agent's turn is now independently checkable.");

    Ok(())
}
