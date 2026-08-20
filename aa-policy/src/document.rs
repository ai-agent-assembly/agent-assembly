//! Validated, strongly-typed policy document types for aa-gateway.

use crate::scope::PolicyScope;

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
    /// this policy asks the gateway to run.
    ///
    /// Carried verbatim. This crate is a leaf and does not know which packs a
    /// build contains; `aa_gateway::engine::detection::resolve_locale_packs`
    /// owns the catalogue and fails closed on a tag it does not recognise,
    /// rather than treating it as "no pack configured".
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
    /// AAASM-5751 — filesystem path scope for this policy scope.
    ///
    /// `None` means the operator stated nothing about paths — **not** that
    /// paths are unrestricted. See
    /// [`aa_security::policy::FilesystemPolicy`] for the three authored states
    /// and why an empty scope is deny-all rather than the absence of one.
    ///
    /// # Why this reuses the canonical type verbatim
    ///
    /// Most other cross-layer dimensions on this document have a gateway-side
    /// twin that [`PolicyDocument::to_canonical`] converts into. That pattern
    /// is what let the syscall node fall out of the projection unnoticed
    /// (AAASM-5753): a second type makes "carried across the bridge" a thing
    /// someone has to remember to do. Holding the canonical type itself makes
    /// the projection a move rather than a translation, so this node cannot
    /// acquire a second, divergent definition.
    pub filesystem: Option<aa_security::policy::FilesystemPolicy>,
    /// AAASM-5753 — kernel syscall allowlist for this policy scope.
    ///
    /// Holds [`aa_security::policy::SyscallAllowlist`] verbatim, for the reason
    /// spelled out on [`filesystem`](Self::filesystem) above: this field exists
    /// because the syscall node had no gateway-side representation, so
    /// [`PolicyDocument::to_canonical`] hard-coded the canonical node to `None`
    /// and discarded whatever an operator wrote. Reintroducing the omission as
    /// a gateway-side twin would recreate the translation step that went
    /// missing. The projection is a move.
    ///
    /// # Two authored states, and they are not the same fact
    ///
    /// | Authored form | Meaning |
    /// | --- | --- |
    /// | `None` — no `syscalls:` section | The operator stated nothing. **Not a grant** |
    /// | `Some` with a non-empty set | Only these calls are permitted |
    /// | `Some` with an empty set | A restriction is in force and permits nothing |
    ///
    /// The third row is the one that reads wrong if it collapses onto the
    /// first: `syscalls:` written with no `allow:` under it is the most
    /// restrictive posture available here, not the absence of a posture. This
    /// is the same reading [`aa_security::policy::FilesystemPolicy`] documents
    /// for an empty [`PathScope`](aa_security::policy::PathScope), and the same
    /// one `aa_security::policy::PolicyDocument::from_yaml` already gives the
    /// `syscalls:` section — so the two ingest paths for one on-disk contract
    /// answer this question identically rather than each inventing an answer.
    pub syscall_allowlist: Option<aa_security::policy::SyscallAllowlist>,
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
            filesystem: None,
            syscall_allowlist: None,
        };
        assert!(doc.tools.is_empty());
        // AAASM-5751 — an unstated path node. Read this as "nobody said",
        // never as "nothing is restricted".
        assert!(doc.filesystem.is_none());
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
