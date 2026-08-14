//! Template definitions shipped with aqua-rs-sdk-core.
//!
//! The built-in **catalog** is the 8 contract templates: machinery
//! (`template_meta`, `anchor_template`, `file`) and the signature family
//! (`signature_base` plus the four concrete suites). Those are
//! byte-identical with the full SDK.
//!
//! The 11 audit identities (t1–t8 plus `audit_artifact`,
//! `audit_round_anchor`, `audit_session_close`) stay on disk as fixtures
//! and typed payload structs. They are registry-distributed, byte-identical
//! with the full SDK, and **not** part of the built-in catalog. Retrieve
//! them from `aqua-template-registry` (`audit-set-v1`) and pass them as
//! explicit template sources.
//!
//! The template hash is the type identity and must never drift.

mod anchor_template;
mod audit_agent_response;
mod audit_agent_thinking;
mod audit_agent_tool_call;
mod audit_api_response;
mod audit_artifact;
mod audit_hitl_approval;
mod audit_round_anchor;
mod audit_session_close;
mod audit_tool_result;
mod audit_user_prompt;
mod audit_user_turn_marker;
mod file;
mod signature_base;
mod signature_ed25519;
mod signature_eip191;
mod signature_p256;
mod signature_webauthn;
mod template_meta;

pub use anchor_template::AnchorTemplate;
pub use audit_agent_response::{AuditAgentResponse, AuditAgentResponseError};
pub use audit_agent_thinking::{AuditAgentThinking, AuditAgentThinkingError};
pub use audit_agent_tool_call::{AuditAgentToolCall, AuditAgentToolCallError};
pub use audit_api_response::{AuditApiResponse, AuditApiResponseError};
pub use audit_artifact::{AuditArtifact, AuditArtifactError};
pub use audit_hitl_approval::{AuditHitlApproval, AuditHitlApprovalError, HitlDecision};
pub use audit_round_anchor::{AuditRoundAnchor, AuditRoundAnchorError};
pub use audit_session_close::{AuditSessionClose, AuditSessionCloseError};
pub use audit_tool_result::{AuditToolResult, AuditToolResultError};
pub use audit_user_prompt::{AttachedFile, AuditUserPrompt, AuditUserPromptError};
pub use audit_user_turn_marker::{AuditUserTurnMarker, AuditUserTurnMarkerError};
pub use file::File;
pub use signature_base::SignatureBase;
pub use signature_ed25519::SignatureEd25519;
pub use signature_eip191::SignatureEip191;
pub use signature_p256::SignatureP256;
pub use signature_webauthn::SignatureWebauthn;
pub use template_meta::TemplateMeta;
