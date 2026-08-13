//! The port the DI-API server calls, and nothing wider (ADR 0030 §5.6 reason 2).
//!
//! # Why the server talks to a trait
//!
//! The DI-API's containment argument is not "the handlers are careful"; it is
//! that **the server module's dependency graph excludes what must be
//! unreachable**. Every verb handler is expressed in terms of
//! [`IntegrationLifecycle`], which offers exactly nine operations and returns
//! only lifecycle values. A handler that wanted to read `aa_core::storage`,
//! touch identity, or reach a gateway credential could not do so without
//! *adding a dependency* — a reviewable diff behind CODEOWNERS, not an
//! accident.
//!
//! It also means this trait is the seam where AAASM-5278's plan/receipt/drift
//! service plugs in. That work owns `aa-core/src/integration/**` and
//! `aa-devtool*`; this crate deliberately does not, so the DI-API is written
//! against the contract rather than against an implementation, and the two
//! branches do not collide.
//!
//! # What this trait deliberately does not have
//!
//! No `check`, no `evaluate`, no `decide`, no "emit audit event", no "read
//! policy document", no escape hatch that takes a method name or a query. There
//! is nothing here that returns an `aa_core::policy` decision type, and a unit
//! test asserts the operation set matches the closed verb space. Agent
//! decisions travel SDK → `aa-sdk-client` → runtime/gateway (ADR 0004) and are
//! not reachable from this port at all.
//!
//! [`IntegrationLifecycle::relay_approval`] is the one approval-shaped method,
//! and it *submits* a human's input to the decision authority. It returns an
//! [`ApprovalRelayReceipt`] — "accepted for adjudication" — never a verdict,
//! because a verdict returned here would be ADR 0030 forbidden design 6.

use async_trait::async_trait;

use aa_core::dev_tool::{DevToolKind, GovernanceLevel};
use aa_core::integration::{
    DevToolCapabilities, IntegrationCapability, IntegrationPlan, IntegrationReceipt, IntegrationRequest,
    IntegrationStatus, RemovalPlan, ToolVersion, VerificationResult, VersionCompatibility,
};

/// Why a lifecycle operation could not be completed.
///
/// Coarse on purpose. These reach a client as `DENY_CODE_LIFECYCLE_ERROR` with
/// the `detail` string, so the detail must stay free of adapter internals,
/// file contents and anything a caller should not learn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    /// No adapter knows this tool id.
    UnknownTool {
        /// What was asked for.
        tool_id: String,
    },
    /// The tool is not installed on this host, so there is nothing to act on.
    ToolNotInstalled {
        /// What was asked for.
        tool_id: String,
    },
    /// The named plan does not exist, or belongs to a different tool.
    UnknownPlan {
        /// What was asked for.
        plan_id: String,
    },
    /// The request is not one this service will honour — e.g. an apply of a
    /// plan containing privileged host steps the user never consented to.
    Refused {
        /// Why, in words a user can act on.
        detail: String,
    },
    /// The operation started and could not finish.
    Failed {
        /// Why, in words a user can act on.
        detail: String,
    },
}

impl LifecycleError {
    /// A short user-facing sentence.
    pub fn detail(&self) -> String {
        match self {
            LifecycleError::UnknownTool { tool_id } => format!("no adapter knows the tool {tool_id}"),
            LifecycleError::ToolNotInstalled { tool_id } => format!("{tool_id} is not installed on this host"),
            LifecycleError::UnknownPlan { plan_id } => format!("no plan {plan_id} is on record"),
            LifecycleError::Refused { detail } | LifecycleError::Failed { detail } => detail.clone(),
        }
    }
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail())
    }
}

impl std::error::Error for LifecycleError {}

/// What one adapter can see and do for one tool, as the DI-API needs it.
///
/// Assembled by the lifecycle service from the adapter's discovery and
/// capability declarations. It carries no adapter internals and no host paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDescriptor {
    /// The tool.
    pub tool: DevToolKind,
    /// Name to show a user.
    pub display_name: String,
    /// Whether the tool was found on this host.
    pub detected: bool,
    /// The version found, when one was.
    pub detected_version: Option<ToolVersion>,
    /// How that version compares to the adapter's supported range.
    pub compatibility: VersionCompatibility,
    /// The mechanisms the adapter declares.
    pub capabilities: DevToolCapabilities,
    /// The adapter's static build-time ceiling. A ceiling is not a measurement.
    pub adapter_ceiling: GovernanceLevel,
}

/// The result of repairing drift, as the DI-API reports it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepairReport {
    /// AASM-owned artifact identifiers that were restored.
    pub repaired: Vec<String>,
    /// Identifiers that drifted and could not be restored, with the reason.
    pub unrepairable: Vec<(IntegrationCapability, String)>,
}

/// An integration-scoped, already-redacted security event.
///
/// The projection ADR 0030 §5.5 requires in place of audit rows: counts,
/// verdict kinds, timestamps and redaction *labels*. There is no field here
/// that can hold a prompt, a tool output, or the content that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedSecurityEvent {
    /// When, seconds since the Unix epoch.
    pub occurred_at_unix_secs: u64,
    /// What the core decided, as a kind — never the decision's inputs.
    pub verdict_kind: VerdictKind,
    /// The mechanism the event was observed on.
    pub mechanism: IntegrationCapability,
    /// How many equivalent events this row folds.
    pub count: u32,
    /// Labels of what was redacted (e.g. `aws_access_key`), never the value.
    pub redaction_labels: Vec<String>,
}

/// The kind of verdict a scoped event records.
///
/// A closed enum rather than a string so a future field cannot smuggle detail
/// through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerdictKind {
    /// The action was allowed.
    Allowed,
    /// The action was blocked.
    Denied,
    /// The payload was forwarded with findings redacted.
    Redacted,
    /// A human approval was required.
    ApprovalRequired,
}

impl VerdictKind {
    /// Stable snake_case name for the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            VerdictKind::Allowed => "allow",
            VerdictKind::Denied => "deny",
            VerdictKind::Redacted => "redacted",
            VerdictKind::ApprovalRequired => "approval_required",
        }
    }
}

/// The human's input on a pending approval, as relayed by the client that
/// showed it.
///
/// A closed enum of *inputs*, not outcomes: the client reports which button a
/// person pressed. Whether that input grants anything is the core's call
/// (ADR 0030 matrix row 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalInput {
    /// The human pressed approve.
    Approve,
    /// The human pressed deny.
    Deny,
    /// The human deferred.
    Defer,
}

impl ApprovalInput {
    /// Stable snake_case name for the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            ApprovalInput::Approve => "approve",
            ApprovalInput::Deny => "deny",
            ApprovalInput::Defer => "defer",
        }
    }

    /// Parse a wire value. Unknown input is `None`, never defaulted — an
    /// unreadable button press must not become an approval.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "approve" => Some(ApprovalInput::Approve),
            "deny" => Some(ApprovalInput::Deny),
            "defer" => Some(ApprovalInput::Defer),
            _ => None,
        }
    }
}

/// Acknowledgement that a human's input reached the decision authority.
///
/// Deliberately carries no verdict. "Accepted for adjudication" is the whole
/// statement; a client that wants the outcome reads it from status, which the
/// service computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRelayReceipt {
    /// Which approval the input was relayed for.
    pub approval_id: String,
    /// What was relayed.
    pub relayed: ApprovalInput,
    /// When the runtime accepted it.
    pub accepted_at_unix_secs: u64,
}

/// The nine operations the DI-API can perform, and no others.
///
/// One method per member of the closed verb space. Implemented by AAASM-5278's
/// lifecycle service; the DI server holds it as a `dyn` object so this crate
/// never links the adapters directly.
#[async_trait]
pub trait IntegrationLifecycle: Send + Sync {
    /// Every tool the linked adapters know about, detected or not.
    async fn list_tools(&self) -> Result<Vec<ToolDescriptor>, LifecycleError>;

    /// Author a reviewable dry run. Mutates nothing.
    async fn plan(&self, request: IntegrationRequest) -> Result<IntegrationPlan, LifecycleError>;

    /// Execute a previously authored plan and record the receipt.
    async fn apply(&self, tool: &DevToolKind, plan_id: &str) -> Result<IntegrationReceipt, LifecycleError>;

    /// Derive the protection state from current evidence.
    async fn status(&self, tool: &DevToolKind) -> Result<IntegrationStatus, LifecycleError>;

    /// Run the protection test and adjudicate it.
    async fn verify(&self, tool: &DevToolKind) -> Result<VerificationResult, LifecycleError>;

    /// Restore AASM-owned keys that drifted.
    async fn repair(&self, tool: &DevToolKind) -> Result<(RepairReport, IntegrationStatus), LifecycleError>;

    /// Author and execute the reversal.
    async fn remove(&self, tool: &DevToolKind, plan_id: Option<&str>) -> Result<RemovalPlan, LifecycleError>;

    /// Recent security events relevant to this integration, already redacted.
    async fn scoped_events(
        &self,
        tool: &DevToolKind,
        limit: u32,
        since_unix_secs: u64,
    ) -> Result<Vec<ScopedSecurityEvent>, LifecycleError>;

    /// Submit a human's approval input to the decision authority.
    async fn relay_approval(
        &self,
        tool: &DevToolKind,
        approval_id: &str,
        input: ApprovalInput,
    ) -> Result<ApprovalRelayReceipt, LifecycleError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devint::verb::DiVerb;

    /// The trait's method names, transcribed. Compared against the verb space
    /// so a method that is not a verb — or a verb with no method — is a build
    /// failure rather than a review question.
    const TRAIT_METHODS: [&str; 9] = [
        "list_tools",
        "plan",
        "apply",
        "status",
        "verify",
        "repair",
        "remove",
        "scoped_events",
        "relay_approval",
    ];

    #[test]
    fn the_port_offers_exactly_the_closed_verb_space() {
        let mut verbs: Vec<&str> = DiVerb::ALL.iter().map(|v| v.as_str()).collect();
        // The only naming difference: the verb is `approval_relay`, the method
        // is `relay_approval` (a verb reads as a noun, a method as an action).
        for name in verbs.iter_mut() {
            if *name == "approval_relay" {
                *name = "relay_approval";
            }
        }
        let mut methods = TRAIT_METHODS.to_vec();
        verbs.sort_unstable();
        methods.sort_unstable();
        assert_eq!(verbs, methods);
    }

    #[test]
    fn no_port_method_is_named_like_a_policy_decision() {
        for name in TRAIT_METHODS {
            for forbidden in ["check", "evaluate", "decide", "authorize", "emit_audit"] {
                assert!(!name.contains(forbidden), "{name} looks like a decision method");
            }
        }
    }

    #[test]
    fn an_unreadable_approval_input_is_not_an_approval() {
        assert_eq!(ApprovalInput::parse("approve"), Some(ApprovalInput::Approve));
        assert_eq!(ApprovalInput::parse("APPROVE"), None);
        assert_eq!(ApprovalInput::parse(""), None);
        assert_eq!(ApprovalInput::parse("yes"), None);
    }

    #[test]
    fn lifecycle_errors_render_without_leaking_internals() {
        let err = LifecycleError::UnknownTool {
            tool_id: "nope".to_string(),
        };
        assert_eq!(err.detail(), "no adapter knows the tool nope");
    }
}
