//! Validated, strongly-typed policy document types for aa-gateway.

use crate::policy::scope::PolicyScope;

/// Validated network egress policy.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkPolicy {
    /// Domain glob patterns the agent may connect to.
    pub allowlist: Vec<String>,
}

/// Validated active-hours window.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveHours {
    /// Window start in `HH:MM` 24-hour format.
    pub start: String,
    /// Window end in `HH:MM` 24-hour format.
    pub end: String,
    /// IANA timezone name.
    pub timezone: String,
}

/// Validated schedule policy.
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulePolicy {
    /// Optional time window during which the agent is permitted to run.
    pub active_hours: Option<ActiveHours>,
}

/// Action to take when budget limit is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActionOnExceed {
    /// Deny individual requests but keep the agent active (default).
    #[default]
    Deny,
    /// Suspend the agent entirely until budget resets.
    Suspend,
}

/// Validated spend budget policy.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetPolicy {
    /// Maximum USD spend per calendar day; `None` means no limit.
    pub daily_limit_usd: Option<f64>,
    /// Maximum USD spend per calendar month; `None` means no limit.
    pub monthly_limit_usd: Option<f64>,
    /// IANA timezone for daily/monthly reset boundary. `None` means UTC.
    pub timezone: Option<String>,
    /// Action when budget is exceeded: deny individual requests or suspend agent.
    pub action_on_exceed: ActionOnExceed,
}

/// Validated data / PII policy.
#[derive(Debug, Clone, PartialEq)]
pub struct DataPolicy {
    /// Compiled regex patterns for PII / credential detection.
    pub sensitive_patterns: Vec<String>,
}

/// Per-policy approval escalation overrides.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalPolicy {
    /// Override escalation timeout in seconds for this policy.
    pub timeout_seconds: Option<u32>,
    /// Override the escalation role / approver group for this policy.
    pub escalation_role: Option<String>,
}

/// Validated per-tool policy entry.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolPolicy {
    /// Whether this tool is permitted.
    pub allow: bool,
    /// Max calls per hour; `None` means unlimited.
    pub limit_per_hour: Option<u32>,
    /// CEL expression that triggers human-in-the-loop approval.
    pub requires_approval_if: Option<String>,
}

/// Fully validated policy document produced by [`super::validator::PolicyValidator`].
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDocument {
    /// Human-readable policy name from the YAML envelope `metadata.name`.
    /// `None` when parsed from the flat (non-envelope) format.
    pub name: Option<String>,
    /// Policy revision version from the YAML envelope `metadata.version`.
    /// `None` when parsed from the flat (non-envelope) format.
    pub policy_version: Option<String>,
    /// Schema version string.
    pub version: Option<String>,
    /// Hierarchical scope this policy applies to. Defaults to
    /// [`PolicyScope::Global`] when the `scope` YAML field is absent so
    /// pre-F92 policies keep their existing semantics.
    pub scope: PolicyScope,
    /// Network egress policy.
    pub network: Option<NetworkPolicy>,
    /// Schedule / active-hours policy.
    pub schedule: Option<SchedulePolicy>,
    /// Spend budget policy.
    pub budget: Option<BudgetPolicy>,
    /// Data / PII policy.
    pub data: Option<DataPolicy>,
    /// Seconds before an approval request times out. Default: 300.
    pub approval_timeout_secs: u32,
    /// Per-policy approval escalation overrides. `None` means use team routing defaults.
    pub approval_policy: Option<ApprovalPolicy>,
    /// Per-tool policies keyed by tool name.
    pub tools: std::collections::HashMap<String, ToolPolicy>,
    /// Capability allow/deny restrictions for this policy scope.
    pub capabilities: Option<aa_core::CapabilitySet>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_document_default_tools_is_empty_map() {
        let doc = PolicyDocument {
            name: None,
            policy_version: None,
            version: None,
            scope: PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: std::collections::HashMap::new(),
            capabilities: None,
        };
        assert!(doc.tools.is_empty());
    }

    #[test]
    fn network_policy_stores_allowlist() {
        let np = NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        };
        assert_eq!(np.allowlist.len(), 1);
    }

    #[test]
    fn tool_policy_allow_defaults() {
        let tp = ToolPolicy {
            allow: true,
            limit_per_hour: None,
            requires_approval_if: None,
        };
        assert!(tp.allow);
        assert!(tp.limit_per_hour.is_none());
    }
}
