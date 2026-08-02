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
    /// AAASM-5087 — Maximum USD spend per calendar day, per team.
    /// Enforced independently of `daily_limit_usd` (which is the global cap).
    /// `None` means no per-team daily limit.
    pub team_daily_limit_usd: Option<f64>,
    /// AAASM-5087 — Maximum USD spend per calendar month, per team.
    /// `None` means no per-team monthly limit.
    pub team_monthly_limit_usd: Option<f64>,
    /// AAASM-2022 — Maximum USD spend per calendar day, per organisation.
    /// Enforced independently of `daily_limit_usd` (which is the global cap).
    /// `None` means no per-org daily limit.
    pub org_daily_limit_usd: Option<f64>,
    /// AAASM-2022 — Maximum USD spend per calendar month, per organisation.
    /// `None` means no per-org monthly limit.
    pub org_monthly_limit_usd: Option<f64>,
    /// IANA timezone for daily/monthly reset boundary. `None` means UTC.
    pub timezone: Option<String>,
    /// Action when budget is exceeded: deny individual requests or suspend agent.
    pub action_on_exceed: ActionOnExceed,
    /// Optional sub-day rollover window parsed from the YAML `window:` field.
    /// `None` preserves the historical calendar-day rollover behaviour.
    /// AAASM-1600.
    pub window: Option<std::time::Duration>,
}

/// Action to take when the credential / sensitive-data scanner produces
/// a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredentialAction {
    /// Refuse the action: engine returns `Deny` with reason
    /// `"credential detected"`; upstream never receives the payload.
    Block,
    /// Forward a redacted form of the payload upstream (default; preserves
    /// the historical behaviour from before this enum existed).
    #[default]
    RedactOnly,
    /// Forward the unmodified payload and raise an alert side-effect.
    /// Documented as a deliberate downgrade for low-risk audit-only modes.
    ///
    /// SECURITY (AAASM-3137): this forwards the *raw* secret upstream. Prefer
    /// [`CredentialAction::AlertAndRedact`] when an alert is wanted but the
    /// secret must still not leave the boundary.
    AlertOnly,
    /// Raise an alert side-effect **and** forward a redacted payload. This is
    /// the safe alerting mode: the operator gets notified of the finding, but
    /// the raw secret is redacted before it leaves the boundary regardless of
    /// the alert (AAASM-3137).
    AlertAndRedact,
}

/// Validated data / PII policy.
#[derive(Debug, Clone, PartialEq)]
pub struct DataPolicy {
    /// Compiled regex patterns for PII / credential detection.
    pub sensitive_patterns: Vec<String>,
    /// Action to take when the scanner produces a finding. Defaults to
    /// [`CredentialAction::RedactOnly`] so policies that omit the field
    /// keep the historical behaviour.
    pub credential_action: CredentialAction,
    /// AAASM-5354 — BCP-47 tags of the deterministic locale recognizer packs
    /// this policy asks the gateway to run, resolved by
    /// [`resolve_locale_packs`](crate::engine::detection::resolve_locale_packs).
    ///
    /// **Empty by default, and that default is load-bearing.** Stage 6 runs on
    /// the synchronous pre-action path, where `credential_action: block` denies
    /// an agent's action before any byte leaves. AAASM-5353 measured the
    /// 統一編號 (business-registration) checksum in the `zh-TW` pack at a
    /// **22.0000%** residual: roughly one random eight-digit string in five
    /// satisfies it. Enabling that by default would put a one-in-five-wrong
    /// detector on the block path — which is this Epic's founding defect, a
    /// detector firing on ordinary content and denying a Chinese-speaking
    /// agent, aimed at a new population.
    ///
    /// So a pack is production-wired and genuinely reachable, but only when an
    /// operator names it here, having accepted that residual for their
    /// deployment. With the list empty the merged findings are byte-identical
    /// to the pre-AAASM-5354 two-pass scan.
    pub locale_packs: Vec<String>,
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

    #[test]
    fn credential_action_default_is_redact_only() {
        assert_eq!(CredentialAction::default(), CredentialAction::RedactOnly);
    }
}
