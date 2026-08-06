//! Deterministic template hash verifier with cascade-aware --fix.
//!
//! Reads all built-in template JSONs, computes their canonical SHA3-256 hash
//! using the SDK's own logic, and compares against the hardcoded TEMPLATE_LINK
//! constants in the corresponding .rs files. Also verifies derives_from and
//! ancestry fields in child templates reference correct parent hashes.
//!
//! In --fix mode, repairs the full cascade (PCA-0016 AD-21):
//!   0. Pins `revision_type` (genesis bootstrap for `template_meta`, else
//!      the `template_meta` content multihash)
//!   1. Fixes derives_from and ancestry as FULL multihashes (`0x1620 || digest`)
//!   2. Recomputes child hashes (since JSON changed)
//!   3. Repeats for grandchildren (topological order)
//!   4. Rewrites all stale TEMPLATE_LINK constants in .rs files
//!
//! Usage:
//!   cargo run --bin verify-templates --features native          # check mode
//!   cargo run --bin verify-templates --features native -- --fix # auto-repair
//!
//! Exit codes:
//!   0 = all hashes match
//!   1 = drift detected (or --fix applied repairs)

use aqua_rs_sdk_core::primitives::{multihash_encode, HashType};
use aqua_rs_sdk_core::schema::Template;
use aqua_rs_sdk_core::verification::Linkable;
use std::collections::HashMap;
use std::path::PathBuf;

/// Genesis bootstrap self-reference: `0x1620 || SHA3-256("aqua:genesis:template_meta")`.
const GENESIS_TYPE_MULTIHASH_HEX: &str =
    "0x162087ea911a93f2698563b68b860f33fd7a568ca2391d4a227b532812d496039e74";

/// Strip optional `0x` and optional SHA3-256 multihash prefix (`1620`) to bare digest hex.
fn to_bare_hex(hex_str: &str) -> String {
    let hex = hex_str
        .strip_prefix("0x")
        .unwrap_or(hex_str)
        .to_ascii_lowercase();
    if hex.len() == 68 && hex.starts_with("1620") {
        hex[4..].to_string()
    } else {
        hex
    }
}

/// Encode a bare 32-byte digest hex as a full SHA3-256 multihash wire string.
fn bare_to_multihash_hex(bare_hex: &str) -> String {
    let bare = hex::decode(bare_hex).expect("bare hex");
    assert_eq!(bare.len(), 32, "template id digests are 32 bytes");
    let mh = multihash_encode(HashType::Sha3_256, &bare);
    format!("0x{}", hex::encode(mh))
}

struct TemplateInfo {
    name: String,
    json_path: PathBuf,
    parent_name: Option<String>,
}

fn main() {
    let fix_mode = std::env::args().any(|a| a == "--fix");
    let templates_dir = find_templates_dir();

    // Discover all template JSON files
    let mut json_files: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(&templates_dir).expect("cannot read templates dir") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap().to_string();
        if stem.ends_with("_schema") {
            continue;
        }
        json_files.push((stem, path));
    }
    json_files.sort_by(|a, b| a.0.cmp(&b.0));

    // First pass: compute current hashes + read .rs TEMPLATE_LINK (old hashes).
    // We need both because after a parent JSON changes, children still reference
    // the OLD parent hash in their derives_from field.
    let mut current_hex_to_name: HashMap<String, String> = HashMap::new();
    let mut old_hex_to_name: HashMap<String, String> = HashMap::new();
    for (name, path) in &json_files {
        let hash_hex = compute_hash_from_file(path, name);
        current_hex_to_name.insert(hash_hex, name.clone());
        let rs_path = templates_dir.join(format!("{name}.rs"));
        if rs_path.exists() {
            let rs_content = std::fs::read_to_string(&rs_path).unwrap();
            if let Some(old_bytes) = extract_template_link_bytes(&rs_content) {
                old_hex_to_name.insert(hex::encode(&old_bytes), name.clone());
            }
        }
    }

    // Build TemplateInfo with parent relationships resolved by name.
    // Try current hash first, fall back to old (.rs) hash for cascade scenarios.
    let mut templates: Vec<TemplateInfo> = Vec::new();
    for (name, path) in &json_files {
        let raw = read_json_value(path);
        let parent_name = raw
            .get("derives_from")
            .and_then(|v| v.as_str())
            .and_then(|hex_str| {
                let bare = to_bare_hex(hex_str);
                current_hex_to_name
                    .get(&bare)
                    .or_else(|| old_hex_to_name.get(&bare))
                    .cloned()
            });
        templates.push(TemplateInfo {
            name: name.clone(),
            json_path: path.clone(),
            parent_name,
        });
    }

    // Topological sort (parents before children)
    let sorted = topological_sort(&templates);

    // Main loop: compute hashes in topo order, fix if needed
    let mut authoritative: HashMap<String, (Vec<u8>, String)> = HashMap::new();
    let mut json_fixes = 0;
    let mut rs_fixes = 0;
    let mut mismatches: Vec<String> = Vec::new();
    let mut derives_errors: Vec<String> = Vec::new();

    println!(
        "Verifying {} templates (topological order).\n",
        sorted.len()
    );

    // Force template_meta through the loop first so its multihash is available
    // for every other template's revision_type pin (AD-21 two-phase bootstrap).
    let mut sorted = sorted;
    if let Some(pos) = sorted.iter().position(|t| t.name == "template_meta") {
        let meta = sorted.remove(pos);
        sorted.insert(0, meta);
    }

    for info in &sorted {
        let name = &info.name;
        let json_path = &info.json_path;

        // Phase A0 (AD-21): pin revision_type
        // - template_meta: genesis bootstrap multihash
        // - every other template: template_meta content multihash
        {
            let expected_rt = if name == "template_meta" {
                GENESIS_TYPE_MULTIHASH_HEX.to_string()
            } else if let Some((_, meta_bare)) = authoritative.get("template_meta") {
                bare_to_multihash_hex(meta_bare)
            } else {
                // Should not happen once template_meta is forced first; fall back
                // so check-mode still reports rather than panicking.
                String::new()
            };
            if !expected_rt.is_empty() {
                let raw = read_json_value(json_path);
                let current_rt = raw
                    .get("revision_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if current_rt != expected_rt {
                    if fix_mode {
                        fix_json_revision_type(json_path, &expected_rt);
                        println!("  FIX-JSON {name}: revision_type -> {expected_rt}");
                        json_fixes += 1;
                    } else {
                        println!(
                            "  STALE {name}: revision_type is {current_rt}, expected {expected_rt}"
                        );
                        derives_errors
                            .push(format!("{name}: revision_type should be {expected_rt}"));
                    }
                }
            }
        }

        // Phase A: Check / fix derives_from + ancestry in JSON (FULL multihashes)
        if let Some(parent_name) = &info.parent_name {
            if let Some((_, parent_hex)) = authoritative.get(parent_name) {
                let raw = read_json_value(json_path);
                let current_derives = raw
                    .get("derives_from")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let expected_derives = bare_to_multihash_hex(parent_hex);

                let ancestry_ok = verify_ancestry(&raw, parent_name, &authoritative);

                if current_derives != expected_derives || !ancestry_ok {
                    if fix_mode {
                        fix_json_derives(json_path, parent_name, parent_hex, &authoritative);
                        println!(
                            "  FIX-JSON {name}: derives_from/ancestry updated to point to {parent_name}"
                        );
                        json_fixes += 1;
                    } else {
                        println!(
                            "  STALE {name}: derives_from is {current_derives}, expected {expected_derives} ({parent_name})"
                        );
                        derives_errors.push(format!(
                            "{name}: derives_from should be {expected_derives} ({parent_name})"
                        ));
                    }
                }
            }
        }

        // Phase B: Compute hash from (possibly fixed) JSON
        let hash_hex = compute_hash_from_file(json_path, name);
        let hash_bytes = hex::decode(&hash_hex).unwrap();
        authoritative.insert(name.clone(), (hash_bytes.clone(), hash_hex.clone()));

        // Phase C: Compare against .rs TEMPLATE_LINK
        let rs_path = templates_dir.join(format!("{name}.rs"));
        if !rs_path.exists() {
            println!("  SKIP {name} (no .rs file)");
            continue;
        }

        let rs_content = std::fs::read_to_string(&rs_path).unwrap();
        match extract_template_link_bytes(&rs_content) {
            Some(existing_bytes) => {
                if existing_bytes == hash_bytes {
                    println!("  OK   {name}");
                } else {
                    let existing_hex = hex::encode(&existing_bytes);
                    println!(
                        "  DRIFT {name}\n        expected: 0x{hash_hex}\n        found:    0x{existing_hex}"
                    );
                    if fix_mode {
                        let new_content = rewrite_template_link(&rs_content, &hash_bytes);
                        std::fs::write(&rs_path, new_content).unwrap();
                        println!("        FIXED {}", rs_path.display());
                        rs_fixes += 1;
                    } else {
                        mismatches.push(name.clone());
                    }
                }
            }
            None => {
                println!("  WARN {name} (could not parse TEMPLATE_LINK from .rs file)");
                mismatches.push(name.clone());
            }
        }
    }

    // Print derives_from link summary
    println!();
    for info in &sorted {
        if let Some(parent_name) = &info.parent_name {
            println!("  LINK {} --derives_from--> {parent_name}", info.name);
        }
    }

    // Summary
    println!();
    let total_fixes = json_fixes + rs_fixes;
    let total_errors = mismatches.len() + derives_errors.len();

    if fix_mode && total_fixes > 0 {
        println!(
            "Fixed {} JSON file(s) + {} TEMPLATE_LINK constant(s).",
            json_fixes, rs_fixes
        );
        println!("Run `cargo fmt` then re-run without --fix to verify.");
        std::process::exit(1);
    }

    if total_errors > 0 {
        println!("{total_errors} error(s) detected:");
        for m in &mismatches {
            println!("  - {m}: TEMPLATE_LINK mismatch");
        }
        for e in &derives_errors {
            println!("  - {e}");
        }
        println!("\nRun with --fix to auto-repair everything.");
        std::process::exit(1);
    }

    println!(
        "All {} templates verified. No drift detected.",
        authoritative.len()
    );
}

fn find_templates_dir() -> PathBuf {
    let candidates = [
        PathBuf::from("src/schema/templates"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/schema/templates"),
    ];
    for candidate in &candidates {
        if candidate.is_dir() {
            return candidate.clone();
        }
    }
    panic!("Cannot find templates directory. Tried: {:?}", candidates);
}

fn compute_hash_from_file(path: &PathBuf, name: &str) -> String {
    let json_str = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
    let template: Template = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("cannot parse {}: {}", path.display(), e));
    // Template ids are always SHA3-256 (PCA-0015 §3.9). calculate_link returns the
    // full multihash (0x1620 || digest); TEMPLATE_LINK constants stay BARE 32-byte
    // digests, so strip the multihash wrapper back to the inner digest.
    let link = template
        .calculate_link(HashType::Sha3_256)
        .unwrap_or_else(|e| panic!("cannot hash {name}: {e}"));
    let (_, bare) = aqua_rs_sdk_core::primitives::multihash_decode(link.as_ref())
        .unwrap_or_else(|e| panic!("template link for {name} is not a valid multihash: {e}"));
    hex::encode(bare)
}

fn read_json_value(path: &PathBuf) -> serde_json::Value {
    let s = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&s).unwrap()
}

fn topological_sort(templates: &[TemplateInfo]) -> Vec<&TemplateInfo> {
    let name_set: HashMap<&str, &TemplateInfo> =
        templates.iter().map(|t| (t.name.as_str(), t)).collect();
    let mut visited: HashMap<&str, bool> = HashMap::new();
    let mut result: Vec<&TemplateInfo> = Vec::new();

    fn visit<'a>(
        name: &'a str,
        name_set: &HashMap<&str, &'a TemplateInfo>,
        visited: &mut HashMap<&'a str, bool>,
        result: &mut Vec<&'a TemplateInfo>,
    ) {
        if visited.contains_key(name) {
            return;
        }
        visited.insert(name, true);
        let info = name_set[name];
        if let Some(parent) = &info.parent_name {
            visit(parent, name_set, visited, result);
        }
        result.push(info);
    }

    for t in templates {
        visit(&t.name, &name_set, &mut visited, &mut result);
    }
    result
}

fn fix_json_revision_type(json_path: &PathBuf, expected_rt: &str) {
    let mut raw = read_json_value(json_path);
    let obj = raw.as_object_mut().unwrap();
    obj.insert(
        "revision_type".to_string(),
        serde_json::Value::String(expected_rt.to_string()),
    );
    let formatted = serde_json::to_string_pretty(&raw).unwrap() + "\n";
    std::fs::write(json_path, formatted).unwrap();
}

fn fix_json_derives(
    json_path: &PathBuf,
    parent_name: &str,
    parent_hex: &str,
    authoritative: &HashMap<String, (Vec<u8>, String)>,
) {
    let mut raw = read_json_value(json_path);
    let obj = raw.as_object_mut().unwrap();

    // AD-21: derives_from / ancestry carry FULL multihashes.
    let new_derives = bare_to_multihash_hex(parent_hex);
    obj.insert(
        "derives_from".to_string(),
        serde_json::Value::String(new_derives),
    );

    // Build ancestry by walking up the parent chain to the first root-set value
    // (AD-18): include the root-set parent, do not continue past it. Root-set
    // names match the PCA-0016 D2 foundation table (leaf bases + template_meta
    // + anchor foundation).
    const ROOT_SET_NAMES: &[&str] = &[
        "template_meta",
        "signature_base",
        "timestamp_base",
        "anchor_template",
    ];
    let mut ancestry: Vec<String> = Vec::new();
    let mut current_parent = Some(parent_name.to_string());
    for _ in 0..10 {
        match current_parent {
            Some(ref pname) => {
                let (_, phex) = authoritative
                    .get(pname)
                    .unwrap_or_else(|| panic!("missing authoritative hash for '{pname}'"));
                ancestry.push(bare_to_multihash_hex(phex));
                // Stop at the first root-set value (AD-18).
                if ROOT_SET_NAMES.contains(&pname.as_str()) {
                    current_parent = None;
                    continue;
                }
                let parent_json_path = json_path.parent().unwrap().join(format!("{pname}.json"));
                if parent_json_path.exists() {
                    let parent_raw = read_json_value(&parent_json_path);
                    current_parent = parent_raw
                        .get("derives_from")
                        .and_then(|v| v.as_str())
                        .and_then(|hex_str| {
                            let bare = to_bare_hex(hex_str);
                            authoritative
                                .iter()
                                .find(|(_, (_, h))| h == &bare)
                                .map(|(n, _)| n.clone())
                        });
                } else {
                    current_parent = None;
                }
            }
            None => break,
        }
    }

    // Reverse: we built [parent, grandparent, root] but need [root, ..., parent]
    ancestry.reverse();
    let ancestry_json: Vec<serde_json::Value> = ancestry
        .into_iter()
        .map(serde_json::Value::String)
        .collect();
    obj.insert(
        "ancestry".to_string(),
        serde_json::Value::Array(ancestry_json),
    );

    let formatted = serde_json::to_string_pretty(&raw).unwrap() + "\n";
    std::fs::write(json_path, formatted).unwrap();
}

fn verify_ancestry(
    raw: &serde_json::Value,
    parent_name: &str,
    authoritative: &HashMap<String, (Vec<u8>, String)>,
) -> bool {
    let ancestry = match raw.get("ancestry").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return false,
    };

    let (_, parent_hex) = match authoritative.get(parent_name) {
        Some(v) => v,
        None => return false,
    };
    let expected_last = bare_to_multihash_hex(parent_hex);

    match ancestry.last().and_then(|v| v.as_str()) {
        Some(last) => last == expected_last,
        None => false,
    }
}

fn extract_template_link_bytes(source: &str) -> Option<Vec<u8>> {
    let start_marker = "const TEMPLATE_LINK: [u8; 32] = [";
    let start = source.find(start_marker)?;
    let after_marker = start + start_marker.len();
    let end = source[after_marker..].find(']')? + after_marker;
    let inner = source[after_marker..end].trim();

    // Repeat-expression form: `[VAL; N]` (e.g. `[0u8; 32]`, `[0; 32]`, `[0x00; 32]`).
    // Lets new templates ship a `[0u8; 32]` placeholder that `--fix` then populates.
    if !inner.contains(',') && inner.contains(';') {
        let mut parts = inner.splitn(2, ';');
        let val_part = parts.next()?.trim();
        let len_part = parts.next()?.trim();
        let val = parse_byte_literal(val_part)?;
        let len: usize = len_part.parse().ok()?;
        return if len == 32 { Some(vec![val; 32]) } else { None };
    }

    let bytes: Vec<u8> = inner
        .split(',')
        .filter_map(|s| parse_byte_literal(s.trim()))
        .collect();

    if bytes.len() == 32 {
        Some(bytes)
    } else {
        None
    }
}

fn parse_byte_literal(s: &str) -> Option<u8> {
    if s.is_empty() {
        return None;
    }
    // Strip Rust integer-literal type suffix and underscore separators
    // (e.g. `0u8`, `255_u8`, `1_0`).
    let mut s = s.trim_end_matches("u8");
    while let Some(stripped) = s.strip_suffix('_') {
        s = stripped;
    }
    let s: String = s.chars().filter(|c| *c != '_').collect();
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(hex_str, 16).ok()
    } else {
        s.parse::<u8>().ok()
    }
}

fn rewrite_template_link(source: &str, hash: &[u8]) -> String {
    let start_marker = "const TEMPLATE_LINK: [u8; 32] = [";
    let start = match source.find(start_marker) {
        Some(pos) => pos,
        None => return source.to_string(),
    };

    let after_marker = start + start_marker.len();
    let closing_bracket = match source[after_marker..].find("];") {
        Some(pos) => after_marker + pos,
        None => return source.to_string(),
    };
    let end = closing_bracket + 2;

    let formatted = format_hash_bytes(hash);
    let replacement = format!("const TEMPLATE_LINK: [u8; 32] = [\n{}\n    ];", formatted);

    let mut result = String::with_capacity(source.len());
    result.push_str(&source[..start]);
    result.push_str(&replacement);
    result.push_str(&source[end..]);
    result
}

fn format_hash_bytes(hash: &[u8]) -> String {
    let mut lines = Vec::new();
    for chunk in hash.chunks(16) {
        let formatted: Vec<String> = chunk.iter().map(|b| format!("0x{:02x}", b)).collect();
        lines.push(format!("        {}", formatted.join(", ")));
    }
    let last = lines.len() - 1;
    if !lines[last].ends_with(',') {
        lines[last].push(',');
    }
    lines.join(",\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explicit_32_byte_array(start: u8) -> String {
        let bytes: Vec<String> = (0..32)
            .map(|i| format!("0x{:02x}", start.wrapping_add(i)))
            .collect();
        format!(
            "const TEMPLATE_LINK: [u8; 32] = [\n    {},\n];",
            bytes.join(", ")
        )
    }

    #[test]
    fn parses_explicit_hex_array() {
        let src = explicit_32_byte_array(0x10);
        let bytes = extract_template_link_bytes(&src).expect("should parse");
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x10);
        assert_eq!(bytes[31], 0x2f);
    }

    #[test]
    fn parses_repeat_zero_u8_form() {
        let src = "const TEMPLATE_LINK: [u8; 32] = [0u8; 32];";
        let bytes = extract_template_link_bytes(src).expect("should parse [0u8; 32]");
        assert_eq!(bytes, vec![0u8; 32]);
    }

    #[test]
    fn parses_repeat_decimal_form() {
        let src = "const TEMPLATE_LINK: [u8; 32] = [0; 32];";
        let bytes = extract_template_link_bytes(src).expect("should parse [0; 32]");
        assert_eq!(bytes, vec![0u8; 32]);
    }

    #[test]
    fn parses_repeat_hex_form() {
        let src = "const TEMPLATE_LINK: [u8; 32] = [0xab; 32];";
        let bytes = extract_template_link_bytes(src).expect("should parse [0xab; 32]");
        assert_eq!(bytes, vec![0xabu8; 32]);
    }

    #[test]
    fn parses_repeat_with_suffix() {
        let src = "const TEMPLATE_LINK: [u8; 32] = [255u8; 32];";
        let bytes = extract_template_link_bytes(src).expect("should parse [255u8; 32]");
        assert_eq!(bytes, vec![255u8; 32]);
    }

    #[test]
    fn rejects_repeat_with_wrong_length() {
        let src = "const TEMPLATE_LINK: [u8; 32] = [0u8; 16];";
        assert!(extract_template_link_bytes(src).is_none());
    }

    #[test]
    fn rejects_repeat_with_out_of_range_byte() {
        let src = "const TEMPLATE_LINK: [u8; 32] = [256; 32];";
        assert!(extract_template_link_bytes(src).is_none());
    }

    #[test]
    fn rejects_missing_const() {
        let src = "fn main() {}";
        assert!(extract_template_link_bytes(src).is_none());
    }

    #[test]
    fn rejects_wrong_length_explicit() {
        let src = "const TEMPLATE_LINK: [u8; 32] = [0x01, 0x02, 0x03];";
        assert!(extract_template_link_bytes(src).is_none());
    }

    #[test]
    fn parse_byte_literal_handles_common_forms() {
        assert_eq!(parse_byte_literal("0"), Some(0));
        assert_eq!(parse_byte_literal("255"), Some(255));
        assert_eq!(parse_byte_literal("0u8"), Some(0));
        assert_eq!(parse_byte_literal("0x00"), Some(0));
        assert_eq!(parse_byte_literal("0xff"), Some(255));
        assert_eq!(parse_byte_literal("0xFF"), Some(255));
        assert_eq!(parse_byte_literal("255_u8"), Some(255));
        assert_eq!(parse_byte_literal(""), None);
        assert_eq!(parse_byte_literal("256"), None);
        assert_eq!(parse_byte_literal("abc"), None);
    }
}
