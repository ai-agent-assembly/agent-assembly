//! Capability vocabulary for the canonical policy AST.
//!
//! This is the leaf-crate-owned capability model. It deliberately mirrors the
//! `file_read` / `file_write` / `network_outbound` / `terminal_exec` / … wire
//! vocabulary used by `policy-examples/*.yaml` so the canonical
//! [`PolicyDocument`](super::PolicyDocument) parses the same on-disk contract
//! the gateway already honours.
//!
//! It lives in `aa-security` (a leaf crate with no `aa-core` dependency)
//! because `aa-core` itself depends on `aa-security`; defining the shared
//! policy AST here is what lets BOTH the gateway rule engine and the
//! (privilege-separated) eBPF loader depend on the exact same types without a
//! dependency cycle. See AAASM-3606.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// A discrete action category a policy can allow or deny for an agent.
///
/// The string forms match the `capabilities.allow` / `capabilities.deny`
/// entries in the policy YAML contract (`file_read`, `network_outbound`,
/// `mcp_tool:<name>`, `model:<name>`, …).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Capability {
    /// Read access to the filesystem.
    FileRead,
    /// Write access to the filesystem.
    FileWrite,
    /// Delete/unlink access to the filesystem.
    ///
    /// A distinct verb from [`Capability::FileWrite`] so a policy can allow
    /// writes while denying deletes. Mirrors `aa_core::Capability::FileDelete`
    /// so the gateway→canonical projection stays lossless. See AAASM-4103.
    FileDelete,
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
            "file_delete" => Ok(Capability::FileDelete),
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
                    Err(format!("unknown capability: '{s}'"))
                }
            }
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::FileRead => f.write_str("file_read"),
            Capability::FileWrite => f.write_str("file_write"),
            Capability::FileDelete => f.write_str("file_delete"),
            Capability::NetworkOutbound => f.write_str("network_outbound"),
            Capability::NetworkInbound => f.write_str("network_inbound"),
            Capability::TerminalExec => f.write_str("terminal_exec"),
            Capability::AgentSpawn => f.write_str("agent_spawn"),
            Capability::McpTool(name) => write!(f, "mcp_tool:{name}"),
            Capability::Model(name) => write!(f, "model:{name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_simple_variant() {
        assert_eq!("file_read".parse::<Capability>().unwrap(), Capability::FileRead);
        assert_eq!("file_write".parse::<Capability>().unwrap(), Capability::FileWrite);
        assert_eq!(
            "network_outbound".parse::<Capability>().unwrap(),
            Capability::NetworkOutbound
        );
        assert_eq!("terminal_exec".parse::<Capability>().unwrap(), Capability::TerminalExec);
    }

    #[test]
    fn parses_parameterised_variants() {
        assert_eq!(
            "mcp_tool:git".parse::<Capability>().unwrap(),
            Capability::McpTool("git".to_string())
        );
        assert_eq!(
            "model:gpt-4".parse::<Capability>().unwrap(),
            Capability::Model("gpt-4".to_string())
        );
    }

    #[test]
    fn rejects_empty_parameterised_name() {
        assert!("mcp_tool:".parse::<Capability>().is_err());
        assert!("model:".parse::<Capability>().is_err());
    }

    #[test]
    fn rejects_unknown_capability() {
        assert!("teleport".parse::<Capability>().is_err());
    }

    #[test]
    fn display_round_trips() {
        for cap in [
            Capability::FileRead,
            Capability::FileWrite,
            Capability::NetworkOutbound,
            Capability::NetworkInbound,
            Capability::TerminalExec,
            Capability::AgentSpawn,
            Capability::McpTool("bash".to_string()),
            Capability::Model("claude".to_string()),
        ] {
            let rendered = cap.to_string();
            assert_eq!(rendered.parse::<Capability>().unwrap(), cap);
        }
    }
}
