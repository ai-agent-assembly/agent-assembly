//! Per-level capability types for fine-grained agent permission control.
//!
//! A [`Capability`] represents a discrete action category that policy can allow
//! or deny. A [`CapabilitySet`] aggregates allow and deny sets for a given scope.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use core::str::FromStr;

/// A discrete action category that policy can allow or deny for an agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Capability {
    /// Read access to the filesystem.
    FileRead,
    /// Write access to the filesystem.
    FileWrite,
    /// Outbound network connections.
    NetworkOutbound,
    /// Inbound network connections.
    NetworkInbound,
    /// Execute commands in a terminal/shell.
    TerminalExec,
    /// Use a named MCP tool.
    McpTool(String),
    /// Use a named AI model.
    Model(String),
    /// Spawn child agents.
    AgentSpawn,
}

/// Aggregates allow and deny capability sets for a given policy scope.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CapabilitySet {
    /// Capabilities explicitly allowed.
    pub allow: BTreeSet<Capability>,
    /// Capabilities explicitly denied.
    pub deny: BTreeSet<Capability>,
}

impl FromStr for Capability {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "file_read" => Ok(Capability::FileRead),
            "file_write" => Ok(Capability::FileWrite),
            "network_outbound" => Ok(Capability::NetworkOutbound),
            "network_inbound" => Ok(Capability::NetworkInbound),
            "terminal_exec" => Ok(Capability::TerminalExec),
            "agent_spawn" => Ok(Capability::AgentSpawn),
            _ => {
                if let Some(name) = s.strip_prefix("mcp_tool:") {
                    if name.is_empty() {
                        return Err("mcp_tool: name must not be empty".to_string());
                    }
                    Ok(Capability::McpTool(name.to_string()))
                } else if let Some(name) = s.strip_prefix("model:") {
                    if name.is_empty() {
                        return Err("model: name must not be empty".to_string());
                    }
                    Ok(Capability::Model(name.to_string()))
                } else {
                    Err(alloc::format!("unknown capability: '{s}'"))
                }
            }
        }
    }
}

impl core::fmt::Display for Capability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Capability::FileRead => f.write_str("file_read"),
            Capability::FileWrite => f.write_str("file_write"),
            Capability::NetworkOutbound => f.write_str("network_outbound"),
            Capability::NetworkInbound => f.write_str("network_inbound"),
            Capability::TerminalExec => f.write_str("terminal_exec"),
            Capability::AgentSpawn => f.write_str("agent_spawn"),
            Capability::McpTool(name) => write!(f, "mcp_tool:{name}"),
            Capability::Model(name) => write!(f, "model:{name}"),
        }
    }
}

/// Merge a parent [`CapabilitySet`] with a child [`CapabilitySet`] using
/// parent-deny-wins semantics.
///
/// Rules:
/// - `deny` = union of both deny sets; parent deny always wins over child allow.
/// - `allow`:
///   - Both empty → empty (no allow-list restriction).
///   - Parent empty, child non-empty → `child.allow` minus merged deny.
///   - Parent non-empty, child empty → `parent.allow` minus merged deny.
///   - Both non-empty → intersection of `parent.allow` and `child.allow`, minus merged deny.
///
/// Requires the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn merge_capabilities(parent: &CapabilitySet, child: &CapabilitySet) -> CapabilitySet {
    // deny = union of both deny sets
    let deny: BTreeSet<Capability> = parent.deny.union(&child.deny).cloned().collect();

    let allow: BTreeSet<Capability> = match (parent.allow.is_empty(), child.allow.is_empty()) {
        // Both empty → no allow-list restriction
        (true, true) => BTreeSet::new(),
        // Parent empty, child non-empty → use child.allow
        (true, false) => child.allow.difference(&deny).cloned().collect(),
        // Parent non-empty, child empty → use parent.allow
        (false, true) => parent.allow.difference(&deny).cloned().collect(),
        // Both non-empty → intersection, then subtract deny
        (false, false) => parent
            .allow
            .intersection(&child.allow)
            .filter(|c| !deny.contains(c))
            .cloned()
            .collect(),
    };

    CapabilitySet { allow, deny }
}

/// Map a [`crate::GovernanceAction`] to the [`Capability`] it exercises,
/// or `None` if the action does not map to a known capability.
///
/// Requires the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn action_to_capability(action: &crate::GovernanceAction) -> Option<Capability> {
    use crate::policy::FileMode;
    use crate::GovernanceAction;

    // NOTE: Capability::AgentSpawn, NetworkInbound, and Model variants have no
    // corresponding GovernanceAction yet. When new action variants land, add
    // mappings here to avoid silent policy bypasses.
    match action {
        GovernanceAction::ToolCall { name, .. } => Some(Capability::McpTool(name.clone())),
        GovernanceAction::FileAccess {
            mode: FileMode::Read, ..
        } => Some(Capability::FileRead),
        GovernanceAction::FileAccess {
            mode: FileMode::Write | FileMode::Append | FileMode::Delete,
            ..
        } => Some(Capability::FileWrite),
        GovernanceAction::NetworkRequest { .. } => Some(Capability::NetworkOutbound),
        GovernanceAction::ProcessExec { .. } => Some(Capability::TerminalExec),
        GovernanceAction::SendMessage { .. } => None,
    }
}

/// Per-scope contribution to an effective permission set.
///
/// Carries the `allow` and `deny` capabilities a single policy document declares
/// at one scope along the cascade chain. The `scope` field is a wire-format
/// label such as `"global"`, `"org:acme"`, `"team:platform"`, or
/// `"agent:<uuid>"`; the gateway populates it from the policy's own
/// `PolicyScope` so the renderer can show provenance without depending on the
/// gateway's enum.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PermissionSource {
    /// Wire-format scope label (e.g. `"global"`, `"team:platform"`).
    pub scope: String,
    /// Capabilities this scope explicitly allows.
    pub allow: BTreeSet<Capability>,
    /// Capabilities this scope explicitly denies.
    pub deny: BTreeSet<Capability>,
}

/// Effective capability set for a single agent, with cascade provenance.
///
/// `merged` is the result of folding `merge_capabilities` left-to-right over
/// every policy document that applies to the agent (Global → Org → Team →
/// Agent → Tool). `sources` records each contributing scope's individual
/// `allow`/`deny`, in cascade order, so consumers (CLI, dashboard) can show
/// *where* each capability decision originates.
///
/// `sources` may be empty if no policy in the cascade declares a
/// `capabilities` block, in which case `merged` is also empty (no allow-list
/// restriction).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EffectivePermissions {
    /// Merged result after most-restrictive-wins cascade.
    pub merged: CapabilitySet,
    /// Per-scope contribution, in cascade order (broadest → narrowest).
    pub sources: alloc::vec::Vec<PermissionSource>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn capability_variants_are_distinct() {
        assert_ne!(Capability::FileRead, Capability::FileWrite);
        assert_ne!(
            Capability::McpTool("a".to_string()),
            Capability::McpTool("b".to_string())
        );
    }

    #[test]
    fn mcp_tool_same_name_eq() {
        assert_eq!(
            Capability::McpTool("bash".to_string()),
            Capability::McpTool("bash".to_string())
        );
    }

    #[test]
    fn capability_hashable_in_set() {
        let mut set: BTreeSet<Capability> = BTreeSet::new();
        set.insert(Capability::FileRead);
        set.insert(Capability::FileWrite);
        set.insert(Capability::McpTool("bash".to_string()));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn capability_set_default_is_empty() {
        let cs = CapabilitySet::default();
        assert!(cs.allow.is_empty());
        assert!(cs.deny.is_empty());
    }

    #[test]
    fn capability_from_str_file_read() {
        assert_eq!("file_read".parse::<Capability>().unwrap(), Capability::FileRead);
    }

    #[test]
    fn capability_from_str_file_write() {
        assert_eq!("file_write".parse::<Capability>().unwrap(), Capability::FileWrite);
    }

    #[test]
    fn capability_from_str_network_outbound() {
        assert_eq!(
            "network_outbound".parse::<Capability>().unwrap(),
            Capability::NetworkOutbound
        );
    }

    #[test]
    fn capability_from_str_network_inbound() {
        assert_eq!(
            "network_inbound".parse::<Capability>().unwrap(),
            Capability::NetworkInbound
        );
    }

    #[test]
    fn capability_from_str_terminal_exec() {
        assert_eq!("terminal_exec".parse::<Capability>().unwrap(), Capability::TerminalExec);
    }

    #[test]
    fn capability_from_str_mcp_tool() {
        assert_eq!(
            "mcp_tool:bash".parse::<Capability>().unwrap(),
            Capability::McpTool("bash".to_string())
        );
    }

    #[test]
    fn capability_from_str_model() {
        assert_eq!(
            "model:gpt-4o".parse::<Capability>().unwrap(),
            Capability::Model("gpt-4o".to_string())
        );
    }

    #[test]
    fn capability_from_str_agent_spawn() {
        assert_eq!("agent_spawn".parse::<Capability>().unwrap(), Capability::AgentSpawn);
    }

    #[test]
    fn capability_from_str_unknown_returns_err() {
        assert!("unknown_cap".parse::<Capability>().is_err());
    }

    #[test]
    fn capability_from_str_mcp_tool_empty_name_returns_err() {
        assert!("mcp_tool:".parse::<Capability>().is_err());
    }

    #[test]
    fn capability_from_str_model_empty_name_returns_err() {
        assert!("model:".parse::<Capability>().is_err());
    }

    #[test]
    fn capability_display_round_trips_simple_variant() {
        let cap = Capability::FileRead;
        assert_eq!(cap.to_string().parse::<Capability>().unwrap(), cap);
    }

    #[test]
    fn capability_display_round_trips_mcp_tool() {
        let cap = Capability::McpTool("bash".to_string());
        assert_eq!(cap.to_string().parse::<Capability>().unwrap(), cap);
    }

    // ------------------------------------------------------------------
    // merge_capabilities tests
    // ------------------------------------------------------------------

    fn cap_set(allow: &[Capability], deny: &[Capability]) -> CapabilitySet {
        CapabilitySet {
            allow: allow.iter().cloned().collect(),
            deny: deny.iter().cloned().collect(),
        }
    }

    #[test]
    fn merge_empty_parent_with_child_deny() {
        let parent = CapabilitySet::default();
        let child = cap_set(&[], &[Capability::FileWrite]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(result.deny.contains(&Capability::FileWrite));
        assert!(result.allow.is_empty());
    }

    #[test]
    fn merge_parent_deny_wins_over_child_allow() {
        let parent = cap_set(&[], &[Capability::NetworkOutbound]);
        let child = cap_set(&[Capability::FileRead, Capability::NetworkOutbound], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(result.allow.contains(&Capability::FileRead));
        assert!(!result.allow.contains(&Capability::NetworkOutbound));
    }

    #[test]
    fn merge_deny_is_union() {
        let parent = cap_set(&[], &[Capability::FileWrite]);
        let child = cap_set(&[], &[Capability::TerminalExec]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(result.deny.contains(&Capability::FileWrite));
        assert!(result.deny.contains(&Capability::TerminalExec));
    }

    #[test]
    fn merge_both_allow_nonempty_takes_intersection() {
        let parent = cap_set(&[Capability::FileRead, Capability::FileWrite], &[]);
        let child = cap_set(&[Capability::FileRead, Capability::NetworkOutbound], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert_eq!(
            result.allow,
            [Capability::FileRead].iter().cloned().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn merge_parent_allow_nonempty_child_allow_empty_uses_parent() {
        let parent = cap_set(&[Capability::FileRead], &[]);
        let child = cap_set(&[], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert_eq!(
            result.allow,
            [Capability::FileRead].iter().cloned().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn merge_parent_allow_empty_child_allow_nonempty_uses_child() {
        let parent = cap_set(&[], &[]);
        let child = cap_set(&[Capability::FileRead], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert_eq!(
            result.allow,
            [Capability::FileRead].iter().cloned().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn merge_parent_deny_overrides_intersection_allow() {
        let parent = cap_set(&[Capability::FileRead, Capability::FileWrite], &[Capability::FileRead]);
        let child = cap_set(&[Capability::FileRead], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(
            result.allow.is_empty(),
            "FileRead was denied by parent, should be absent from allow"
        );
        assert!(result.deny.contains(&Capability::FileRead));
    }

    #[test]
    fn merge_both_empty_returns_empty() {
        let parent = CapabilitySet::default();
        let child = CapabilitySet::default();
        let result = super::merge_capabilities(&parent, &child);
        assert_eq!(result, CapabilitySet::default());
    }

    // ------------------------------------------------------------------
    // action_to_capability tests
    // ------------------------------------------------------------------

    #[test]
    fn action_to_capability_tool_call() {
        let action = crate::GovernanceAction::ToolCall {
            name: "bash".to_string(),
            args: "{}".to_string(),
        };
        assert_eq!(
            super::action_to_capability(&action),
            Some(Capability::McpTool("bash".to_string()))
        );
    }

    #[test]
    fn action_to_capability_file_read() {
        let action = crate::GovernanceAction::FileAccess {
            path: "/tmp/f".to_string(),
            mode: crate::policy::FileMode::Read,
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::FileRead));
    }

    #[test]
    fn action_to_capability_file_write() {
        let action = crate::GovernanceAction::FileAccess {
            path: "/tmp/f".to_string(),
            mode: crate::policy::FileMode::Write,
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::FileWrite));
    }

    #[test]
    fn action_to_capability_file_append_is_file_write() {
        let action = crate::GovernanceAction::FileAccess {
            path: "/tmp/f".to_string(),
            mode: crate::policy::FileMode::Append,
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::FileWrite));
    }

    #[test]
    fn action_to_capability_file_delete_is_file_write() {
        let action = crate::GovernanceAction::FileAccess {
            path: "/tmp/f".to_string(),
            mode: crate::policy::FileMode::Delete,
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::FileWrite));
    }

    #[test]
    fn action_to_capability_network_request() {
        let action = crate::GovernanceAction::NetworkRequest {
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::NetworkOutbound));
    }

    #[test]
    fn action_to_capability_process_exec() {
        let action = crate::GovernanceAction::ProcessExec {
            command: "ls".to_string(),
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::TerminalExec));
    }
}
