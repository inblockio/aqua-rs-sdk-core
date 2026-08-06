use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileData {
    pub file_name: String,
    pub file_content: Vec<u8>,
    pub path: PathBuf,
}

impl FileData {
    pub fn new(file_name: String, file_content: Vec<u8>, path: PathBuf) -> Self {
        Self {
            file_name,
            file_content,
            path,
        }
    }

    pub fn file_size(&self) -> u64 {
        self.file_content.len() as u64
    }
}

/// Lightweight alternative to `FileData` for callers that already computed the
/// content hash (e.g. content-addressed storage). Avoids a second SHA3-256 pass
/// over the file bytes and eliminates the need to hold the full file in memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub file_name: String,
    pub content_hash: Vec<u8>,
    pub file_size: u64,
    pub path: PathBuf,
}

impl FileMetadata {
    pub fn new(file_name: String, content_hash: Vec<u8>, file_size: u64, path: PathBuf) -> Self {
        Self {
            file_name,
            content_hash,
            file_size,
            path,
        }
    }
}
