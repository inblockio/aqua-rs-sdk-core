//! Regenerate `primitives::unsupported::UNSUPPORTED_SDK_TEMPLATES` from the
//! full aqua-rs-sdk's template catalog.
//!
//! `aqua-rs-sdk-core` ships a curated subset of the full SDK's built-in
//! templates. A template the full SDK registers
//! (`src/schema/templates/mod.rs`) is "supported" here only if this crate
//! ships a byte-identical copy of the same JSON (hence the same hash);
//! everything else is "unsupported" and gets an entry in
//! `UNSUPPORTED_SDK_TEMPLATES` so a resolution miss can answer with an
//! explicit "not supported, requires <module>" explanation instead of a bare
//! not-found.
//!
//! ## Usage
//!
//! ```text
//! cargo run --bin regen-unsupported --features native
//! cargo run --bin regen-unsupported --features native -- --check
//! cargo run --bin regen-unsupported --features native -- /path/to/aqua-rs-sdk
//! AQUA_FULL_SDK_DIR=/path/to/aqua-rs-sdk cargo run --bin regen-unsupported --features native
//! ```
//!
//! - Positional arg (optional): path to the full aqua-rs-sdk checkout.
//!   Resolved in this order: the positional arg, then `$AQUA_FULL_SDK_DIR`,
//!   then the default `../aqua-rs-sdk` (a sibling checkout of this repo).
//! - `--check`: do not write; print the drift and exit 1 if the regenerated
//!   table would differ from what's on disk, exit 0 if it already matches
//!   (useful in CI to catch upstream catalog drift).
//!
//! This binary only *reads* the full SDK checkout, as plain files by path.
//! The full SDK is NOT, and must not become, a Cargo dependency of this
//! crate.
//!
//! ## When to run it
//!
//! Any time the full SDK's template catalog changes shape: a template is
//! added to or removed from its `src/schema/templates/mod.rs`, or the
//! content of one of the 8 templates this crate ships byte-identically
//! (`template_meta`, `anchor_template`, `signature_base`,
//! `signature_ed25519`, `signature_eip191`, `signature_p256`,
//! `signature_webauthn`, `file`) changes upstream in a way that changes its
//! hash. In particular, run it after BACKLOG.md items A1-A8 (the upstream
//! audit-family re-rooting) land, since that changes which of the 11 audit
//! variants collide with core's own re-rooted hashes.
//!
//! It parses full-SDK template JSON with this crate's own `Template` type
//! and `Linkable::calculate_link`, reusing the exact canonicalization/hash
//! pipeline under test rather than reimplementing it elsewhere (e.g. in a
//! throwaway script in another language).
//!
//! The "requires `<module>`" strings are editorial, not derived from the
//! JSON: they live in `requires_for` below, keyed by template name. A
//! template the mapping doesn't recognize is a loud panic naming the
//! template, never a silently-emitted default; extend the mapping and
//! re-run.

use aqua_rs_sdk_core::primitives::{multihash_decode, HashType};
use aqua_rs_sdk_core::schema::Template;
use aqua_rs_sdk_core::verification::Linkable;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Start of the generated region: the array declaration line itself is
/// preserved verbatim; only what follows it is regenerated.
const START_MARKER: &str = "pub static UNSUPPORTED_SDK_TEMPLATES: &[([u8; 32], &str, &str)] = &[\n";

fn main() {
    let mut check_only = false;
    let mut full_sdk_arg: Option<String> = None;
    for arg in env::args().skip(1) {
        if arg == "--check" {
            check_only = true;
        } else {
            full_sdk_arg = Some(arg);
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let full_sdk_dir = full_sdk_arg
        .map(PathBuf::from)
        .or_else(|| env::var("AQUA_FULL_SDK_DIR").ok().map(PathBuf::from))
        .unwrap_or_else(|| manifest_dir.join("../aqua-rs-sdk"));
    let full_templates_dir = full_sdk_dir.join("src/schema/templates");
    let core_templates_dir = manifest_dir.join("src/schema/templates");
    let target_path = manifest_dir.join("src/primitives/unsupported.rs");

    let registered = read_registered_names(&full_templates_dir);
    if registered.is_empty() {
        panic!(
            "no `mod X;` declarations found in {}; is the full SDK path correct? \
             (positional arg, then $AQUA_FULL_SDK_DIR, then ../aqua-rs-sdk)",
            full_templates_dir.join("mod.rs").display()
        );
    }

    let core_hashes = hash_local_templates(&core_templates_dir);

    let mut entries: Vec<([u8; 32], String, &'static str)> = Vec::new();
    for name in &registered {
        let json_path = full_templates_dir.join(format!("{name}.json"));
        let digest = hash_template_file(&json_path, name);
        if core_hashes.contains(&digest) {
            // Byte-identical to a template this crate ships: supported, not listed.
            continue;
        }
        entries.push((digest, name.clone(), requires_for(name)));
    }
    entries.sort_by(|a, b| a.1.cmp(&b.1));

    let rendered_body = render_array_body(&entries);

    let current = fs::read_to_string(&target_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", target_path.display(), e));
    let new_content = splice(&current, &rendered_body, &target_path);

    if check_only {
        if new_content == current {
            println!(
                "OK: {} unsupported template(s), matches {}",
                entries.len(),
                target_path.display()
            );
        } else {
            eprintln!(
                "DRIFT: regenerated table differs from {}; run without --check to update.",
                target_path.display()
            );
            std::process::exit(1);
        }
        return;
    }

    if new_content == current {
        println!(
            "No change: {} unsupported template(s), already up to date in {}",
            entries.len(),
            target_path.display()
        );
    } else {
        fs::write(&target_path, &new_content)
            .unwrap_or_else(|e| panic!("cannot write {}: {}", target_path.display(), e));
        println!(
            "Wrote {} unsupported template entries to {}",
            entries.len(),
            target_path.display()
        );
    }
}

/// The curated "what verifying it requires" string for a full-SDK template
/// name. Editorial, not derived from the JSON. Grouped by the upstream
/// domain that actually owns the template (identity claims/attestations,
/// the template/plugin/vendor registry, the policy engine, the timestamping
/// module, or "the full aqua-rs-sdk" for everything else including the
/// identity-rooted audit variants this crate ships re-rooted equivalents
/// of). Unknown names fail loudly rather than guessing.
fn requires_for(name: &str) -> &'static str {
    match name {
        "address_claim" | "age_claim" | "attestation" | "birthdate_claim" | "delegation"
        | "dns_claim" | "document_claim" | "drivers_license_claim" | "email_claim"
        | "github_claim" | "google_claim" | "identity_base" | "key_association"
        | "key_rotation" | "key_rotation_commitment" | "name_claim" | "national_id_claim"
        | "passport_claim" | "phone_claim" | "platform_identity" | "service_claim"
        | "service_claim_agent" | "service_claim_api_attestor" | "service_claim_server"
        | "service_claim_user_session" | "trust_assertion" | "wallet_identification" => {
            "the identity module"
        }
        "alias_registration" | "plugin_registration" | "template_registration"
        | "vendor_registration" => "the template registry",
        "policy_base" | "policy_condition" => "the policy engine",
        "timestamp_base" | "timestamp_evm" | "timestamp_tsa" => "the timestamping module",
        "access_grant" | "aqua_certificate" | "aqua_sign" | "folder" | "manifest"
        | "multi_signer" => "the full aqua-rs-sdk",
        "audit_agent_response" | "audit_agent_thinking" | "audit_agent_tool_call"
        | "audit_artifact" | "audit_gusto_api_response" | "audit_hitl_approval"
        | "audit_round_anchor" | "audit_session_close" | "audit_tool_result"
        | "audit_user_prompt" | "audit_user_turn_marker" => {
            "the full aqua-rs-sdk (identity-rooted audit variant; this crate ships re-rooted equivalents)"
        }
        other => panic!(
            "regen_unsupported: template '{other}' has no curated \"requires\" mapping in \
             requires_for(). Add it there (see BACKLOG.md B8) before regenerating; this is a \
             loud failure by design so an unmapped template never gets a silent default."
        ),
    }
}

/// Parse `mod NAME;` declarations out of the full SDK's
/// `src/schema/templates/mod.rs` (the authoritative, upstream-maintained
/// list of registered templates). Sorted for determinism regardless of the
/// order they appear upstream.
fn read_registered_names(templates_dir: &Path) -> Vec<String> {
    let mod_path = templates_dir.join("mod.rs");
    let content = fs::read_to_string(&mod_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", mod_path.display(), e));
    let mut names: Vec<String> = content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("mod ")
                .and_then(|rest| rest.strip_suffix(';'))
                .map(|name| name.to_string())
        })
        .collect();
    names.sort();
    names
}

/// Hash every non-schema template JSON this crate ships locally, producing
/// the set of digests this crate already supports. Membership is by hash,
/// not name, deliberately: the audit family ships under the same names
/// upstream and locally but with different (re-rooted) hashes, so a name
/// match alone would wrongly mark them supported.
fn hash_local_templates(dir: &Path) -> HashSet<[u8; 32]> {
    let mut set = HashSet::new();
    let read_dir =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {}", dir.display(), e));
    for entry in read_dir {
        let entry =
            entry.unwrap_or_else(|e| panic!("cannot read entry in {}: {}", dir.display(), e));
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        if stem.ends_with("_schema") {
            continue;
        }
        set.insert(hash_template_file(&path, &stem));
    }
    set
}

/// Parse a template JSON file with this crate's own `Template` type and
/// compute its bare (unwrapped) 32-byte SHA3-256 digest via
/// `Linkable::calculate_link`, the same pipeline `verify-templates` and the
/// verification pipeline itself use.
fn hash_template_file(path: &Path, label: &str) -> [u8; 32] {
    let json_str = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {} ({label}): {}", path.display(), e));
    let template: Template = serde_json::from_str(&json_str).unwrap_or_else(|e| {
        panic!(
            "cannot parse {} ({label}) as a Template: {}",
            path.display(),
            e
        )
    });
    let link = template
        .calculate_link(HashType::Sha3_256)
        .unwrap_or_else(|e| panic!("cannot hash {label}: {e}"));
    let (_, bare) = multihash_decode(link.as_ref())
        .unwrap_or_else(|e| panic!("template link for {label} is not a valid multihash: {e}"));
    let len = bare.len();
    bare.try_into()
        .unwrap_or_else(|_| panic!("expected a 32-byte digest for {label}, got {len}"))
}

/// Render the entries in the exact on-disk style: one tuple per entry, the
/// 32-byte array on a single line, 4-space/8-space indentation, trailing
/// commas, no blank lines between entries.
fn render_array_body(entries: &[([u8; 32], String, &'static str)]) -> String {
    let mut out = String::new();
    for (digest, name, requires) in entries {
        out.push_str("    (\n        [");
        for (i, b) in digest.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&format!("0x{b:02x}"));
        }
        out.push_str("],\n");
        out.push_str(&format!("        \"{name}\",\n"));
        out.push_str(&format!("        \"{requires}\",\n"));
        out.push_str("    ),\n");
    }
    out
}

/// Replace only the array body between `START_MARKER` and the array's
/// closing `];` with `rendered_body`, leaving everything else in the file
/// (module doc comment, `unsupported_template_info`, the
/// `TIMESTAMP_*_DIGEST` constants) untouched.
fn splice(current: &str, rendered_body: &str, target_path: &Path) -> String {
    let start = current.find(START_MARKER).unwrap_or_else(|| {
        panic!(
            "could not find `{}` in {}",
            START_MARKER.trim_end(),
            target_path.display()
        )
    });
    let body_start = start + START_MARKER.len();
    let rel_end = current[body_start..].find("\n];\n").unwrap_or_else(|| {
        panic!(
            "could not find the closing `];` for UNSUPPORTED_SDK_TEMPLATES in {}",
            target_path.display()
        )
    });
    // rel_end points at the '\n' that terminates the last entry's "    ),"
    // line; keep that newline out of the suffix so rendered_body (which
    // already ends each entry, including the last, with its own '\n') lines
    // up with the following "];\n" without a blank line in between.
    let suffix_start = body_start + rel_end + 1;
    format!(
        "{}{}{}",
        &current[..body_start],
        rendered_body,
        &current[suffix_start..]
    )
}
