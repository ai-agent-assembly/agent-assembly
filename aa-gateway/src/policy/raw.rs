//! Unvalidated serde deserialization targets for policy YAML.

use std::collections::HashMap;

use serde::Deserialize;

/// Raw (unvalidated) deserialization target for the `network` policy section.
#[derive(Debug, Deserialize)]
pub struct RawNetworkPolicy {
    /// Domain glob patterns the agent may connect to.
    pub allowlist: Option<Vec<String>>,
    /// Unknown keys captured for warning emission.
    #[serde(flatten)]
    pub unknown: HashMap<String, serde_yaml::Value>,
}

/// Raw (unvalidated) deserialization target for `schedule.active_hours`.
#[derive(Debug, Deserialize)]
pub struct RawActiveHours {
    /// Window start in `HH:MM` 24-hour format.
    pub start: Option<String>,
    /// Window end in `HH:MM` 24-hour format.
    pub end: Option<String>,
    /// IANA timezone name (e.g. `"Asia/Taipei"`).
    pub timezone: Option<String>,
    /// Unknown keys captured for warning emission.
    #[serde(flatten)]
    pub unknown: HashMap<String, serde_yaml::Value>,
}

/// Raw (unvalidated) deserialization target for the `schedule` policy section.
#[derive(Debug, Deserialize)]
pub struct RawSchedulePolicy {
    /// Time window during which the agent is permitted to run.
    pub active_hours: Option<RawActiveHours>,
    /// Unknown keys captured for warning emission.
    #[serde(flatten)]
    pub unknown: HashMap<String, serde_yaml::Value>,
}

/// Raw (unvalidated) deserialization target for the `budget` policy section.
#[derive(Debug, Deserialize)]
pub struct RawBudgetPolicy {
    /// Maximum USD spend per calendar day; `None` means no limit.
    pub daily_limit_usd: Option<f64>,
    /// Maximum USD spend per calendar month; `None` means no limit.
    pub monthly_limit_usd: Option<f64>,
    /// Optional IANA timezone for daily/monthly reset boundary. Defaults to UTC if absent.
    pub timezone: Option<String>,
    /// Action when budget is exceeded: `"deny"` (default) or `"suspend"`.
    pub action_on_exceed: Option<String>,
    /// Unknown keys captured for warning emission.
    #[serde(flatten)]
    pub unknown: HashMap<String, serde_yaml::Value>,
}

/// Raw (unvalidated) deserialization target for the `data` policy section.
#[derive(Debug, Deserialize)]
pub struct RawDataPolicy {
    /// Regex patterns for PII / credential detection.
    pub sensitive_patterns: Option<Vec<String>>,
    /// Unknown keys captured for warning emission.
    #[serde(flatten)]
    pub unknown: HashMap<String, serde_yaml::Value>,
}

/// Raw (unvalidated) deserialization target for the `capabilities` policy section.
#[derive(Debug, Deserialize)]
pub struct RawCapabilitySet {
    /// Capability strings that are explicitly permitted.
    pub allow: Option<Vec<String>>,
    /// Capability strings that are explicitly denied.
    pub deny: Option<Vec<String>>,
    /// Unknown keys captured for warning emission.
    #[serde(flatten)]
    pub unknown: HashMap<String, serde_yaml::Value>,
}

/// Raw (unvalidated) deserialization target for the `metadata` section
/// of the governance policy YAML envelope.
#[derive(Debug, Deserialize)]
pub struct RawMetadata {
    /// Human-readable policy name.
    pub name: Option<String>,
    /// Semver version string for this policy revision.
    pub version: Option<String>,
    /// Optional description text.
    pub description: Option<String>,
}

/// Raw deserialization target for the governance policy YAML envelope.
///
/// Detects the `apiVersion`/`kind`/`metadata`/`spec` wrapper format used by
/// `policy-examples/*.yaml`. When `spec` is present the inner value is
/// re-parsed as [`RawPolicyDocument`].
#[derive(Debug, Deserialize)]
pub struct GovernancePolicyEnvelope {
    /// Schema version URI (e.g. `"agent-assembly/v1"`).
    #[serde(rename = "apiVersion")]
    pub api_version: Option<String>,
    /// Resource kind (e.g. `"Policy"`).
    pub kind: Option<String>,
    /// Policy metadata (name, version, description).
    pub metadata: Option<RawMetadata>,
    /// The inner spec section, kept as an opaque YAML value so it can be
    /// re-parsed as [`RawPolicyDocument`] by the validator.
    pub spec: Option<serde_yaml::Value>,
}

/// Raw (unvalidated) top-level deserialization target for a policy document.
#[derive(Debug, Deserialize)]
pub struct RawPolicyDocument {
    /// Version tag from the YAML front-matter.
    pub version: Option<String>,
    /// Optional hierarchical scope this policy applies to. When absent the
    /// validator defaults to [`crate::policy::scope::PolicyScope::Global`] so
    /// pre-F92 policy files keep their existing semantics.
    pub scope: Option<crate::policy::scope::PolicyScope>,
    /// Network egress policy.
    pub network: Option<RawNetworkPolicy>,
    /// Schedule / active-hours policy.
    pub schedule: Option<RawSchedulePolicy>,
    /// Spend budget policy.
    pub budget: Option<RawBudgetPolicy>,
    /// Data / PII policy.
    pub data: Option<RawDataPolicy>,
    /// Per-tool policies keyed by tool name.
    pub tools: Option<HashMap<String, RawToolPolicy>>,
    /// Per-level capability restrictions.
    pub capabilities: Option<RawCapabilitySet>,
    /// Seconds before an approval request times out.
    /// Defaults to 300 when absent.
    pub approval_timeout_secs: Option<u32>,
    /// Unknown top-level keys captured for warning emission.
    #[serde(flatten)]
    pub unknown: HashMap<String, serde_yaml::Value>,
}

/// Raw (unvalidated) deserialization target for a single entry in `tools`.
#[derive(Debug, Deserialize)]
pub struct RawToolPolicy {
    /// Whether this tool is permitted.
    pub allow: Option<bool>,
    /// Max calls per hour; `None` means unlimited.
    pub limit_per_hour: Option<u32>,
    /// CEL expression that triggers human-in-the-loop approval.
    pub requires_approval_if: Option<String>,
    /// Unknown keys captured for warning emission.
    #[serde(flatten)]
    pub unknown: HashMap<String, serde_yaml::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RawNetworkPolicy ────────────────────────────────────────────────────

    #[test]
    fn raw_network_deserializes_allowlist() {
        let yaml = "allowlist:\n  - api.openai.com\n  - slack.com\n";
        let raw: RawNetworkPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            raw.allowlist,
            Some(vec!["api.openai.com".to_string(), "slack.com".to_string()])
        );
        assert!(raw.unknown.is_empty());
    }

    #[test]
    fn raw_network_captures_unknown_keys() {
        let yaml = "allowlist:\n  - api.openai.com\nblocklist:\n  - \"*\"\n";
        let raw: RawNetworkPolicy = serde_yaml::from_str(yaml).unwrap();
        assert!(raw.unknown.contains_key("blocklist"));
    }

    #[test]
    fn raw_network_absent_allowlist_is_none() {
        let yaml = "{}\n";
        let raw: RawNetworkPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.allowlist, None);
    }

    // ── RawPolicyDocument ───────────────────────────────────────────────────

    #[test]
    fn raw_policy_document_deserializes_version_and_sections() {
        let yaml = "version: \"1.0\"\nnetwork:\n  allowlist:\n    - api.openai.com\nbudget:\n  daily_limit_usd: 10.0\n";
        let raw: RawPolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.version, Some("1.0".to_string()));
        assert!(raw.network.is_some());
        assert!(raw.budget.is_some());
        assert!(raw.unknown.is_empty());
    }

    #[test]
    fn raw_policy_document_all_sections_absent_is_none() {
        let yaml = "{}\n";
        let raw: RawPolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert!(raw.version.is_none());
        assert!(raw.network.is_none());
        assert!(raw.schedule.is_none());
        assert!(raw.budget.is_none());
        assert!(raw.data.is_none());
        assert!(raw.tools.is_none());
    }

    #[test]
    fn raw_policy_document_deserializes_approval_timeout() {
        let yaml = "approval_timeout_secs: 600\n";
        let raw: RawPolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.approval_timeout_secs, Some(600));
    }

    #[test]
    fn raw_policy_document_absent_approval_timeout_is_none() {
        let yaml = "{}\n";
        let raw: RawPolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.approval_timeout_secs, None);
    }

    #[test]
    fn raw_policy_document_captures_unknown_top_level_key() {
        let yaml = "risk_tier: high\n";
        let raw: RawPolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert!(raw.unknown.contains_key("risk_tier"));
    }

    // ── RawSchedulePolicy / RawActiveHours ─────────────────────────────────

    #[test]
    fn raw_active_hours_deserializes_all_fields() {
        let yaml = "start: \"09:00\"\nend: \"18:00\"\ntimezone: \"Asia/Taipei\"\n";
        let raw: RawActiveHours = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.start, Some("09:00".to_string()));
        assert_eq!(raw.end, Some("18:00".to_string()));
        assert_eq!(raw.timezone, Some("Asia/Taipei".to_string()));
        assert!(raw.unknown.is_empty());
    }

    #[test]
    fn raw_schedule_active_hours_absent_is_none() {
        let yaml = "{}\n";
        let raw: RawSchedulePolicy = serde_yaml::from_str(yaml).unwrap();
        assert!(raw.active_hours.is_none());
    }

    // ── RawBudgetPolicy ─────────────────────────────────────────────────────

    #[test]
    fn raw_budget_deserializes_daily_limit() {
        let yaml = "daily_limit_usd: 50.0\n";
        let raw: RawBudgetPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.daily_limit_usd, Some(50.0));
    }

    #[test]
    fn raw_budget_absent_limit_is_none() {
        let yaml = "{}\n";
        let raw: RawBudgetPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.daily_limit_usd, None);
    }

    #[test]
    fn raw_budget_deserializes_action_on_exceed() {
        let yaml = "daily_limit_usd: 50.0\naction_on_exceed: suspend\n";
        let raw: RawBudgetPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.action_on_exceed, Some("suspend".to_string()));
    }

    #[test]
    fn raw_budget_absent_action_on_exceed_is_none() {
        let yaml = "daily_limit_usd: 50.0\n";
        let raw: RawBudgetPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.action_on_exceed, None);
    }

    // ── RawDataPolicy ───────────────────────────────────────────────────────

    #[test]
    fn raw_data_deserializes_sensitive_patterns() {
        let yaml = "sensitive_patterns:\n  - \"sk-[a-zA-Z0-9]{48}\"\n  - \"\\\\b\\\\d{4}\\\\b\"\n";
        let raw: RawDataPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.sensitive_patterns.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn raw_data_absent_patterns_is_none() {
        let yaml = "{}\n";
        let raw: RawDataPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.sensitive_patterns, None);
    }

    // ── RawToolPolicy ───────────────────────────────────────────────────────

    #[test]
    fn raw_tool_deserializes_all_fields() {
        let yaml = "allow: true\nlimit_per_hour: 10\nrequires_approval_if: \"amount > 100\"\n";
        let raw: RawToolPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.allow, Some(true));
        assert_eq!(raw.limit_per_hour, Some(10));
        assert_eq!(raw.requires_approval_if, Some("amount > 100".to_string()));
        assert!(raw.unknown.is_empty());
    }

    #[test]
    fn raw_tool_allow_false_captured() {
        let yaml = "allow: false\n";
        let raw: RawToolPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(raw.allow, Some(false));
        assert_eq!(raw.limit_per_hour, None);
    }

    #[test]
    fn raw_tool_captures_unknown_key() {
        let yaml = "allow: true\nconstraint: \"read-only\"\n";
        let raw: RawToolPolicy = serde_yaml::from_str(yaml).unwrap();
        assert!(raw.unknown.contains_key("constraint"));
    }

    // ── RawCapabilitySet ────────────────────────────────────────────────────

    #[test]
    fn raw_capabilities_deserializes_allow_and_deny() {
        let yaml = "capabilities:\n  allow:\n    - file_read\n  deny:\n    - terminal_exec\n";
        let raw: RawPolicyDocument = serde_yaml::from_str(yaml).unwrap();
        let caps = raw.capabilities.as_ref().unwrap();
        assert_eq!(caps.allow, Some(vec!["file_read".to_string()]));
        assert_eq!(caps.deny, Some(vec!["terminal_exec".to_string()]));
    }

    #[test]
    fn raw_capabilities_absent_is_none() {
        let yaml = "{}\n";
        let raw: RawPolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert!(raw.capabilities.is_none());
    }

    #[test]
    fn raw_capabilities_captures_unknown_key() {
        let yaml = "capabilities:\n  allow: []\n  extra_field: true\n";
        let raw: RawPolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert!(raw.capabilities.as_ref().unwrap().unknown.contains_key("extra_field"));
    }
}
