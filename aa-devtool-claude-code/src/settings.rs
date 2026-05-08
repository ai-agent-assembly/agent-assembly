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
