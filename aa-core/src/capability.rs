//! Per-level capability types for fine-grained agent permission control.
//!
//! A [`Capability`] represents a discrete action category that policy can allow
//! or deny. A [`CapabilitySet`] aggregates allow and deny sets for a given scope.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use core::str::FromStr;

/// A discrete action category that policy can allow or deny for an agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
}
