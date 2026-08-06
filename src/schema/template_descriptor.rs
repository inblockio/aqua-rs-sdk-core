use crate::primitives::RevisionLink;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
pub struct TemplateDescriptor {
    hash: RevisionLink,
    key: String,
    name: String,
    version: String,
}

impl TemplateDescriptor {
    /// Creates a new TemplateDescriptor instance
    pub fn new(hash: RevisionLink, key: String, name: String, version: String) -> Self {
        Self {
            hash,
            key,
            name,
            version,
        }
    }

    /// Creates a new TemplateDescriptor from string slices (convenience method for &str)
    pub fn from_str_parts(hash: RevisionLink, key: &str, name: &str, version: &str) -> Self {
        Self {
            hash,
            key: key.to_string(),
            name: name.to_string(),
            version: version.to_string(),
        }
    }

    /// Creates a default TemplateDescriptor with empty values
    pub fn default_with_hash(hash: RevisionLink) -> Self {
        Self {
            hash,
            key: String::new(),
            name: String::new(),
            version: String::new(),
        }
    }

    // Getters for the private fields
    pub fn hash(&self) -> &RevisionLink {
        &self.hash
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    // Setters (if you want mutable access)
    pub fn set_key(&mut self, key: String) {
        self.key = key;
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn set_version(&mut self, version: String) {
        self.version = version;
    }
}
