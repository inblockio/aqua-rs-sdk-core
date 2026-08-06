//! Built-in template definitions shipped with aqua-rs-sdk-core.
//!
//! This is the compatible subset of the full aqua-rs-sdk template
//! catalog: template machinery (template_meta, anchor_template,
//! identity_base, file), the base signature templates, the t1-t8
//! agentic audit family, and the timestamp templates retained for
//! revision classification only (core ships no timestamping).
//! Every .json file is byte-identical to the full SDK's copy; the
//! template hash is the type identity and must never drift.

mod anchor_template;
mod audit_agent_response;
mod audit_agent_thinking;
mod audit_agent_tool_call;
mod audit_artifact;
mod audit_gusto_api_response;
mod audit_hitl_approval;
mod audit_round_anchor;
mod audit_session_close;
mod audit_tool_result;
mod audit_user_prompt;
mod audit_user_turn_marker;
mod file;
mod identity_base;
mod signature_base;
mod signature_ed25519;
mod signature_eip191;
mod signature_p256;
mod signature_webauthn;
mod template_meta;
mod timestamp_base;
mod timestamp_evm;
mod timestamp_tsa;

pub use anchor_template::AnchorTemplate;
pub use audit_agent_response::{AuditAgentResponse, AuditAgentResponseError};
pub use audit_agent_thinking::{AuditAgentThinking, AuditAgentThinkingError};
pub use audit_agent_tool_call::{AuditAgentToolCall, AuditAgentToolCallError};
pub use audit_artifact::{AuditArtifact, AuditArtifactError};
pub use audit_gusto_api_response::{AuditGustoApiResponse, AuditGustoApiResponseError};
pub use audit_hitl_approval::{AuditHitlApproval, AuditHitlApprovalError, HitlDecision};
pub use audit_round_anchor::{AuditRoundAnchor, AuditRoundAnchorError};
pub use audit_session_close::{AuditSessionClose, AuditSessionCloseError};
pub use audit_tool_result::{AuditToolResult, AuditToolResultError};
pub use audit_user_prompt::{AttachedFile, AuditUserPrompt, AuditUserPromptError};
pub use audit_user_turn_marker::{AuditUserTurnMarker, AuditUserTurnMarkerError};
pub use file::File;
pub use identity_base::IdentityBase;
pub use signature_base::SignatureBase;
pub use signature_ed25519::SignatureEd25519;
pub use signature_eip191::SignatureEip191;
pub use signature_p256::SignatureP256;
pub use signature_webauthn::SignatureWebauthn;
pub use template_meta::TemplateMeta;
pub use timestamp_base::TimestampBase;
pub use timestamp_evm::EvmTimestampPayload;
pub use timestamp_tsa::TsaTimestampPayload;
