use std::collections::BTreeMap;

use crate::primitives::{HashType, Method, MethodError, RevisionLink};
use crate::schema::template::BuiltInTemplate;
use crate::schema::templates::File;
use crate::schema::{
    file_data::FileData, file_data::FileMetadata, tree::Tree, AnyRevision, Object,
};
use crate::verification::canonicalize::Linkable;

use super::object::create_object_util_with_name;

/// Create a genesis file tree: Template + Anchor(genesis) → Object(File payload).
///
/// Delegates to `create_object_util_with_name` so all genesis trees share the
/// same construction logic (template insertion, anchor creation, schema validation).
pub fn create_genesis_revision(
    file_data: FileData,
    canonicalization_method: Method,
) -> Result<Tree, MethodError> {
    let hash_type = HashType::Sha3_256;

    let payload = File {
        descriptor: "".to_string(),
        hash: hash_type.hash(&file_data.file_content),
        hash_type,
        file_type: "file".to_string(),
        size: file_data.file_size(),
        content_type: guess_content_type(&file_data.file_name),
    };

    let template_link = crate::primitives::RevisionLink::from_bytes(File::TEMPLATE_LINK);
    let payload_json = serde_json::to_value(&payload)?;

    create_object_util_with_name(
        template_link,
        None,
        payload_json,
        canonicalization_method,
        file_data.file_name,
        hash_type,
    )
}

/// Create a minimal genesis tree: a single Object revision with no previous_revision.
///
/// Unlike `create_genesis_revision` (which produces anchor + template + object),
/// this returns a self-contained tree with exactly one revision and one file_index
/// entry, suitable for standalone single-revision files.
pub fn create_minimal_genesis_revision(
    file_data: FileData,
    canonicalization_method: Method,
) -> Result<Tree, MethodError> {
    let hash_type = HashType::Sha3_256;

    let payload = File {
        descriptor: "".to_string(),
        hash: hash_type.hash(&file_data.file_content),
        hash_type,
        file_type: "file".to_string(),
        size: file_data.file_size(),
        content_type: guess_content_type(&file_data.file_name),
    };

    let template_link = RevisionLink::from_bytes(File::TEMPLATE_LINK);

    let mut object =
        Object::genesis(template_link, canonicalization_method, payload).genericize()?;

    let hash = object.calculate_link(hash_type)?;
    object.populate_leaves(hash_type)?;

    let mut revisions = BTreeMap::new();
    revisions.insert(hash.clone(), AnyRevision::Typed(object));

    let mut file_index = BTreeMap::new();
    file_index.insert(hash, file_data.file_name);

    Ok(Tree {
        revisions,
        file_index,
    })
}

/// Create a genesis file tree from pre-computed content hash and file size.
///
/// Identical to `create_genesis_revision` but skips the SHA3-256 pass over the
/// file content, accepting a caller-provided hash instead. Use this when the
/// caller has already hashed the bytes (e.g. content-addressed storage) to avoid
/// redundant work and the need to hold the full file in memory.
pub fn create_genesis_revision_from_metadata(
    metadata: FileMetadata,
    canonicalization_method: Method,
) -> Result<Tree, MethodError> {
    let hash_type = HashType::Sha3_256;

    let payload = File {
        descriptor: "".to_string(),
        hash: metadata.content_hash,
        hash_type,
        file_type: "file".to_string(),
        size: metadata.file_size,
        content_type: guess_content_type(&metadata.file_name),
    };

    let template_link = crate::primitives::RevisionLink::from_bytes(File::TEMPLATE_LINK);
    let payload_json = serde_json::to_value(&payload)?;

    create_object_util_with_name(
        template_link,
        None,
        payload_json,
        canonicalization_method,
        metadata.file_name,
        hash_type,
    )
}

fn guess_content_type(file_name: &str) -> String {
    let ext = file_name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "json" => "application/json",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "xml" => "application/xml",
        "csv" => "text/csv",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
    .to_string()
}
