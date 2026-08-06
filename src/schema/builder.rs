use crate::primitives::*;
use crate::schema::template::BuiltInTemplate;

use super::{Anchor, Object, Signature, SignatureValue, Template};

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Builder {
    object_method: Method,
    other_method: Method,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            object_method: Method::Tree,
            other_method: Method::Scalar,
        }
    }

    /// Set the method for all revision types (overrides both object and other defaults).
    pub fn method(mut self, method: Method) -> Self {
        self.object_method = method;
        self.other_method = method;
        self
    }

    /// Set the default method for object revisions (default: Tree).
    pub fn object_method(mut self, method: Method) -> Self {
        self.object_method = method;
        self
    }

    /// Set the default method for non-object revisions (default: Scalar).
    pub fn other_method(mut self, method: Method) -> Self {
        self.other_method = method;
        self
    }

    pub fn template(self, schema: serde_json::Value) -> Template {
        Template::new(
            self.other_method,
            schema,
            RevisionLink::from_bytes(crate::schema::templates::TemplateMeta::TEMPLATE_LINK),
        )
    }

    pub fn anchor(self, previous_revision: RevisionLink, links: Vec<RevisionLink>) -> Anchor {
        Anchor::new(previous_revision, self.other_method, links)
    }

    pub fn signature(
        self,
        previous_revision: RevisionLink,
        signer: String,
        signature: SignatureValue,
    ) -> Signature {
        Signature::new(previous_revision, self.other_method, signer, signature)
    }

    pub fn genesis_object<P>(self, revision_type: RevisionLink, payload: P) -> Object<P> {
        Object::genesis(revision_type, self.object_method, payload)
    }

    pub fn object<P>(
        self,
        previous_revision: RevisionLink,
        revision_type: RevisionLink,
        payload: P,
    ) -> Object<P> {
        Object::new(
            previous_revision,
            revision_type,
            self.object_method,
            payload,
        )
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}
