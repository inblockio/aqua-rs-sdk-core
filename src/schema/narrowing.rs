//! Schema narrowing validation for derived templates.
//!
//! A child template schema is a valid narrowing of its parent schema when every
//! JSON object that satisfies the child schema also satisfies the parent schema
//! (i.e., the child's set of valid objects is a subset of the parent's).
//!
//! Allowed narrowing operations:
//! - Make an optional field required (add to `required` array)
//! - Add `const`, `pattern`, `enum`, `minimum`, `maximum`, `minLength`,
//!   `maxLength` constraints to existing fields
//! - Tighten existing constraints (e.g., reduce `maxLength`, narrow `enum` set)
//! - Remove optional fields entirely from child schema (field elimination)
//!
//! Forbidden operations:
//! - Adding new properties not present in parent schema
//! - Widening constraints
//! - Removing required fields from parent

use serde_json::Value;
use thiserror::Error;

/// Errors produced by the narrowing validator.
#[derive(Debug, Error, PartialEq)]
pub enum NarrowingError {
    #[error("child schema adds new property '{0}' not present in parent")]
    NewProperty(String),
    #[error("child schema removes required field '{0}' from parent")]
    RemovedRequired(String),
    #[error("child schema widens constraint on field '{field}': {detail}")]
    WidenedConstraint { field: String, detail: String },
    #[error("child schema has invalid structure: {0}")]
    InvalidStructure(String),
}

/// Validate that `child_schema` is a valid narrowing of `parent_schema`.
///
/// Both must be JSON Schema draft-2020-12 objects with `"type": "object"`.
/// Returns `Ok(())` on success; otherwise returns the first violation found.
pub fn validate_narrowing(
    parent_schema: &Value,
    child_schema: &Value,
) -> Result<(), NarrowingError> {
    let parent_props = schema_properties(parent_schema);
    let child_props = schema_properties(child_schema);
    let parent_required = schema_required(parent_schema);
    let child_required = schema_required(child_schema);

    // 1. Child must not add new properties
    for (key, _) in &child_props {
        if !parent_props.contains_key(key.as_str()) {
            return Err(NarrowingError::NewProperty(key.clone()));
        }
    }

    // 2. Child must not remove parent-required fields
    for req in &parent_required {
        if !child_required.contains(req) && child_props.contains_key(req.as_str()) {
            // field is still present but no longer required — allowed
        }
        if !child_required.contains(req) && !child_props.contains_key(req.as_str()) {
            return Err(NarrowingError::RemovedRequired(req.clone()));
        }
    }

    // 3. Per-property constraint checks
    for (key, child_prop) in &child_props {
        if let Some(parent_prop) = parent_props.get(key.as_str()) {
            validate_property_narrowing(key, parent_prop, child_prop)?;
        }
    }

    Ok(())
}

/// Validate that a single property's constraints in the child are equal or stricter
/// than in the parent.
fn validate_property_narrowing(
    field: &str,
    parent: &Value,
    child: &Value,
) -> Result<(), NarrowingError> {
    // maxLength: child <= parent
    check_numeric_tightened(field, parent, child, "maxLength", |pc, cc| cc <= pc)?;

    // minLength: child >= parent
    check_numeric_tightened(field, parent, child, "minLength", |pc, cc| cc >= pc)?;

    // maximum: child <= parent
    check_numeric_tightened(field, parent, child, "maximum", |pc, cc| cc <= pc)?;

    // minimum: child >= parent
    check_numeric_tightened(field, parent, child, "minimum", |pc, cc| cc >= pc)?;

    // exclusiveMaximum: child <= parent
    check_numeric_tightened(field, parent, child, "exclusiveMaximum", |pc, cc| cc <= pc)?;

    // exclusiveMinimum: child >= parent
    check_numeric_tightened(field, parent, child, "exclusiveMinimum", |pc, cc| cc >= pc)?;

    // enum: child set must be subset of parent set
    if let Some(parent_enum) = parent.get("enum") {
        if let Some(child_enum) = child.get("enum") {
            let parent_vals: Vec<&Value> = parent_enum
                .as_array()
                .map(|a| a.iter().collect())
                .unwrap_or_default();
            let child_vals: Vec<&Value> = child_enum
                .as_array()
                .map(|a| a.iter().collect())
                .unwrap_or_default();
            for cv in &child_vals {
                if !parent_vals.contains(cv) {
                    return Err(NarrowingError::WidenedConstraint {
                        field: field.to_string(),
                        detail: format!("enum value {cv} not in parent enum"),
                    });
                }
            }
        }
        // If child does not have enum but parent does, child must have const
        // that is in parent enum — or no constraint (which is widening).
        // We allow omitting enum only if child has a const in the parent enum.
        if child.get("enum").is_none() {
            if let Some(child_const) = child.get("const") {
                let parent_vals: Vec<&Value> = parent_enum
                    .as_array()
                    .map(|a| a.iter().collect())
                    .unwrap_or_default();
                if !parent_vals.contains(&child_const) {
                    return Err(NarrowingError::WidenedConstraint {
                        field: field.to_string(),
                        detail: format!("const value {child_const} not in parent enum"),
                    });
                }
            } else {
                // No enum and no const in child — widening
                return Err(NarrowingError::WidenedConstraint {
                    field: field.to_string(),
                    detail: "child removes parent enum constraint without adding const".to_string(),
                });
            }
        }
    }

    // const: if parent has const, child must have same const
    if let Some(parent_const) = parent.get("const") {
        match child.get("const") {
            Some(child_const) if child_const == parent_const => {}
            Some(child_const) => {
                return Err(NarrowingError::WidenedConstraint {
                    field: field.to_string(),
                    detail: format!(
                        "child const {child_const} differs from parent const {parent_const}"
                    ),
                });
            }
            None => {
                return Err(NarrowingError::WidenedConstraint {
                    field: field.to_string(),
                    detail: "child removes parent const constraint".to_string(),
                });
            }
        }
    }

    // pattern: child may add a pattern; may not remove a parent pattern
    if parent.get("pattern").is_some() && child.get("pattern").is_none() {
        // Only invalid if child also doesn't have const (const is stricter)
        if child.get("const").is_none() {
            return Err(NarrowingError::WidenedConstraint {
                field: field.to_string(),
                detail: "child removes parent pattern constraint".to_string(),
            });
        }
    }

    Ok(())
}

/// Check a numeric keyword where the child value must satisfy `predicate(parent_val, child_val)`.
/// Returns an error if the predicate fails (i.e., the child widens the constraint).
/// If only the child has the keyword, that is a valid tightening.
/// If only the parent has the keyword, the child widens (missing constraint).
fn check_numeric_tightened<F>(
    field: &str,
    parent: &Value,
    child: &Value,
    keyword: &str,
    tighter: F,
) -> Result<(), NarrowingError>
where
    F: Fn(f64, f64) -> bool,
{
    match (parent.get(keyword), child.get(keyword)) {
        (Some(pv), Some(cv)) => {
            let pf = pv.as_f64().ok_or_else(|| {
                NarrowingError::InvalidStructure(format!(
                    "parent field '{field}' keyword '{keyword}' is not a number"
                ))
            })?;
            let cf = cv.as_f64().ok_or_else(|| {
                NarrowingError::InvalidStructure(format!(
                    "child field '{field}' keyword '{keyword}' is not a number"
                ))
            })?;
            if !tighter(pf, cf) {
                return Err(NarrowingError::WidenedConstraint {
                    field: field.to_string(),
                    detail: format!("{keyword}: child value {cf} widens parent value {pf}"),
                });
            }
        }
        (Some(_), None) => {
            // Child removes a constraint — only acceptable if child has `const`
            if child.get("const").is_none() {
                return Err(NarrowingError::WidenedConstraint {
                    field: field.to_string(),
                    detail: format!("child removes parent '{keyword}' constraint"),
                });
            }
        }
        (None, Some(_)) => {
            // Child adds a constraint — always valid (tightening)
        }
        (None, None) => {}
    }
    Ok(())
}

/// Extract `properties` map from a schema object.
fn schema_properties(schema: &Value) -> std::collections::HashMap<String, &Value> {
    schema
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v)).collect())
        .unwrap_or_default()
}

/// Extract `required` array from a schema object.
fn schema_required(schema: &Value) -> Vec<String> {
    schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn platform_identity_schema() -> Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "signer_did": { "type": "string", "pattern": "^did:pkh:", "maxLength": 256 },
                "provider": { "type": "string", "minLength": 1, "maxLength": 64 },
                "provider_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 },
                "email": { "type": "string", "format": "idn-email" },
                "proof_url": { "type": "string", "maxLength": 2048 },
                "valid_from": { "type": "integer", "minimum": 0 },
                "valid_until": { "type": "integer", "minimum": 0 },
                "metadata": { "type": "object" }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name"],
            "additionalProperties": false
        })
    }

    // ── Valid narrowing operations ──────────────────────────────────────────

    #[test]
    fn valid_add_required() {
        // Make optional `email` required — valid narrowing
        let child = json!({
            "type": "object",
            "properties": {
                "signer_did": { "type": "string", "pattern": "^did:pkh:", "maxLength": 256 },
                "provider": { "type": "string", "minLength": 1, "maxLength": 64 },
                "provider_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 },
                "email": { "type": "string", "format": "idn-email" }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name", "email"],
            "additionalProperties": false
        });
        assert!(validate_narrowing(&platform_identity_schema(), &child).is_ok());
    }

    #[test]
    fn valid_add_const() {
        // Narrow `provider` to const "email" — valid
        let child = json!({
            "type": "object",
            "properties": {
                "signer_did": { "type": "string", "pattern": "^did:pkh:", "maxLength": 256 },
                "provider": { "type": "string", "const": "email" },
                "provider_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name"],
            "additionalProperties": false
        });
        assert!(validate_narrowing(&platform_identity_schema(), &child).is_ok());
    }

    #[test]
    fn valid_tighten_max_length() {
        let child = json!({
            "type": "object",
            "properties": {
                "signer_did": { "type": "string", "pattern": "^did:pkh:", "maxLength": 256 },
                "provider": { "type": "string", "minLength": 1, "maxLength": 32 }, // 32 < 64
                "provider_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name"],
            "additionalProperties": false
        });
        assert!(validate_narrowing(&platform_identity_schema(), &child).is_ok());
    }

    #[test]
    fn valid_remove_optional_field() {
        // Remove optional `metadata` field entirely — valid narrowing
        let child = json!({
            "type": "object",
            "properties": {
                "signer_did": { "type": "string", "pattern": "^did:pkh:", "maxLength": 256 },
                "provider": { "type": "string", "minLength": 1, "maxLength": 64 },
                "provider_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name"],
            "additionalProperties": false
        });
        assert!(validate_narrowing(&platform_identity_schema(), &child).is_ok());
    }

    #[test]
    fn valid_add_enum() {
        let parent = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string" }
            },
            "required": ["status"]
        });
        let child = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["active", "inactive"] }
            },
            "required": ["status"]
        });
        assert!(validate_narrowing(&parent, &child).is_ok());
    }

    // ── Invalid narrowing operations ────────────────────────────────────────

    #[test]
    fn invalid_add_new_property() {
        let child = json!({
            "type": "object",
            "properties": {
                "signer_did": { "type": "string" },
                "provider": { "type": "string" },
                "provider_id": { "type": "string" },
                "display_name": { "type": "string" },
                "new_field": { "type": "string" }  // not in parent
            },
            "required": ["signer_did", "provider", "provider_id", "display_name"],
            "additionalProperties": false
        });
        let err = validate_narrowing(&platform_identity_schema(), &child).unwrap_err();
        assert!(matches!(err, NarrowingError::NewProperty(_)));
    }

    #[test]
    fn invalid_remove_required_field() {
        // Remove required `display_name` entirely
        let child = json!({
            "type": "object",
            "properties": {
                "signer_did": { "type": "string" },
                "provider": { "type": "string" },
                "provider_id": { "type": "string" }
                // display_name is absent from both properties and required
            },
            "required": ["signer_did", "provider", "provider_id"],
            "additionalProperties": false
        });
        let err = validate_narrowing(&platform_identity_schema(), &child).unwrap_err();
        assert!(matches!(err, NarrowingError::RemovedRequired(_)));
    }

    #[test]
    fn invalid_widen_max_length() {
        // Increase maxLength — widening
        let child = json!({
            "type": "object",
            "properties": {
                "signer_did": { "type": "string", "maxLength": 256 },
                "provider": { "type": "string", "maxLength": 128 }, // 128 > 64
                "provider_id": { "type": "string", "maxLength": 256 },
                "display_name": { "type": "string", "maxLength": 256 }
            },
            "required": ["signer_did", "provider", "provider_id", "display_name"]
        });
        let err = validate_narrowing(&platform_identity_schema(), &child).unwrap_err();
        assert!(matches!(err, NarrowingError::WidenedConstraint { .. }));
    }

    #[test]
    fn invalid_widen_enum() {
        let parent = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["active", "inactive"] }
            },
            "required": ["status"]
        });
        let child = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["active", "inactive", "pending"] } // added
            },
            "required": ["status"]
        });
        let err = validate_narrowing(&parent, &child).unwrap_err();
        assert!(matches!(err, NarrowingError::WidenedConstraint { .. }));
    }

    #[test]
    fn invalid_remove_enum_without_const() {
        let parent = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["active", "inactive"] }
            },
            "required": ["status"]
        });
        // Child removes enum entirely without const — widening
        let child = json!({
            "type": "object",
            "properties": {
                "status": { "type": "string" }
            },
            "required": ["status"]
        });
        let err = validate_narrowing(&parent, &child).unwrap_err();
        assert!(matches!(err, NarrowingError::WidenedConstraint { .. }));
    }

    #[test]
    fn valid_replace_enum_with_const_in_enum() {
        let parent = json!({
            "type": "object",
            "properties": {
                "provider": { "type": "string", "enum": ["email", "github", "twitter"] }
            },
            "required": ["provider"]
        });
        let child = json!({
            "type": "object",
            "properties": {
                "provider": { "type": "string", "const": "email" }
            },
            "required": ["provider"]
        });
        assert!(validate_narrowing(&parent, &child).is_ok());
    }
}
