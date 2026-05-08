use aa_core::{PolicyDecision, PolicyDocument};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ClaudePermissions {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClaudeSettings {
    pub permissions: ClaudePermissions,
    pub permission_mode: String,
    pub enabled_mcpjson_servers: Vec<String>,
    pub disabled_mcpjson_servers: Vec<String>,
}

pub(crate) fn map_policy_to_settings(policy: &PolicyDocument) -> ClaudeSettings {
    let mut allow = Vec::new();
    let mut deny = Vec::new();
    let mut enabled_mcp = Vec::new();
    let mut disabled_mcp = Vec::new();
    let mut has_deny = false;
    let mut has_require_approval = false;

    for rule in &policy.rules {
        let pattern = &rule.action_pattern;
        if let Some(server) = pattern.strip_prefix("mcp:") {
            match rule.decision {
                PolicyDecision::Allow => enabled_mcp.push(server.to_string()),
                PolicyDecision::Deny | PolicyDecision::RequireApproval => {
                    disabled_mcp.push(server.to_string());
                }
            }
        } else {
            match rule.decision {
                PolicyDecision::Allow => allow.push(pattern.clone()),
                PolicyDecision::Deny => {
                    deny.push(pattern.clone());
                    has_deny = true;
                }
                PolicyDecision::RequireApproval => {
                    deny.push(pattern.clone());
                    has_require_approval = true;
                }
            }
        }
    }

    let permission_mode = if has_require_approval {
        "plan"
    } else if has_deny {
        "default"
    } else {
        "acceptEdits"
    }
    .to_string();

    ClaudeSettings {
        permissions: ClaudePermissions { allow, deny },
        permission_mode,
        enabled_mcpjson_servers: enabled_mcp,
        disabled_mcpjson_servers: disabled_mcp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::{PolicyDecision, PolicyDocument, PolicyRule};

    fn rule(pattern: &str, decision: PolicyDecision) -> PolicyRule {
        PolicyRule {
            action_pattern: pattern.to_string(),
            decision,
        }
    }

    fn doc(rules: Vec<PolicyRule>) -> PolicyDocument {
        PolicyDocument {
            version: 1,
            name: "test".to_string(),
            rules,
        }
    }

    #[test]
    fn policy_with_bash_allow_emits_allow_bash() {
        let policy = doc(vec![rule("Bash", PolicyDecision::Allow)]);
        let s = map_policy_to_settings(&policy);
        assert_eq!(s.permissions.allow, vec!["Bash"]);
        assert!(s.permissions.deny.is_empty());
    }

    #[test]
    fn enforce_policy_maps_to_default_mode() {
        let policy = doc(vec![
            rule("Bash", PolicyDecision::Allow),
            rule("Edit", PolicyDecision::Deny),
        ]);
        let s = map_policy_to_settings(&policy);
        assert_eq!(s.permission_mode, "default");
        assert_eq!(s.permissions.deny, vec!["Edit"]);
    }

    #[test]
    fn permissive_policy_maps_to_accept_edits() {
        let policy = doc(vec![
            rule("Bash", PolicyDecision::Allow),
            rule("Read", PolicyDecision::Allow),
        ]);
        let s = map_policy_to_settings(&policy);
        assert_eq!(s.permission_mode, "acceptEdits");
    }

    #[test]
    fn mcp_allow_list_emits_enabled_servers() {
        let policy = doc(vec![
            rule("mcp:filesystem", PolicyDecision::Allow),
            rule("mcp:search", PolicyDecision::Deny),
        ]);
        let s = map_policy_to_settings(&policy);
        assert_eq!(s.enabled_mcpjson_servers, vec!["filesystem"]);
        assert_eq!(s.disabled_mcpjson_servers, vec!["search"]);
    }

    #[test]
    fn require_approval_maps_to_plan_mode() {
        let policy = doc(vec![
            rule("Bash", PolicyDecision::Allow),
            rule("Edit", PolicyDecision::RequireApproval),
        ]);
        let s = map_policy_to_settings(&policy);
        assert_eq!(s.permission_mode, "plan");
        assert_eq!(s.permissions.deny, vec!["Edit"]);
    }

    #[test]
    fn snapshot_full_policy_fixture() {
        let policy = doc(vec![
            rule("Bash", PolicyDecision::Allow),
            rule("Read", PolicyDecision::Allow),
            rule("Edit", PolicyDecision::Deny),
            rule("WebFetch", PolicyDecision::RequireApproval),
            rule("mcp:filesystem", PolicyDecision::Allow),
            rule("mcp:search", PolicyDecision::Deny),
        ]);
        let s = map_policy_to_settings(&policy);
        let json = serde_json::to_string_pretty(&s).unwrap();
        insta::assert_snapshot!(json);
    }
}
