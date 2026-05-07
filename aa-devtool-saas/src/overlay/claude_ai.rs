//! Claude.ai governance overlay — MCP allowlist enforcement.
//!
//! Claude.ai exposes MCP server configuration via its Workspaces API.
//! [`ClaudeAiOverlay`] holds an operator-defined allowlist of permitted MCP
//! server names and rejects any server not on that list.
//!
//! This is an advisory L1 control: the allowlist check is enforced when the
//! operator applies the overlay to a Workspace configuration. It does not
//! provide in-process or network-level enforcement (see governance-limits.md).

/// Governance overlay for Claude.ai workspaces.
///
/// The `mcp_allowlist` field contains the set of MCP server names that are
/// permitted to be configured in this workspace. The operator is responsible
/// for applying this overlay to the Claude.ai Workspaces API.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClaudeAiOverlay {
    /// Names of MCP servers permitted in this workspace.
    ///
    /// An empty list means no MCP servers are permitted.
    pub mcp_allowlist: Vec<String>,
}

/// Error returned when an MCP server is not on the allowlist.
#[derive(Debug, thiserror::Error)]
#[error("MCP server '{name}' is not on the Claude.ai allowlist")]
pub struct McpDeniedError {
    /// Name of the MCP server that was rejected.
    pub name: String,
}

impl ClaudeAiOverlay {
    /// Check whether `server_name` is permitted by this overlay.
    ///
    /// # Errors
    ///
    /// Returns [`McpDeniedError`] when `server_name` is not in `mcp_allowlist`.
    pub fn check_mcp_server(&self, server_name: &str) -> Result<(), McpDeniedError> {
        if self.mcp_allowlist.iter().any(|s| s == server_name) {
            Ok(())
        } else {
            Err(McpDeniedError {
                name: server_name.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlisted_server_passes() {
        let overlay = ClaudeAiOverlay {
            mcp_allowlist: vec!["filesystem".into(), "github".into()],
        };
        assert!(overlay.check_mcp_server("filesystem").is_ok());
        assert!(overlay.check_mcp_server("github").is_ok());
    }

    #[test]
    fn unlisted_server_is_rejected() {
        let overlay = ClaudeAiOverlay {
            mcp_allowlist: vec!["filesystem".into()],
        };
        let err = overlay.check_mcp_server("slack").unwrap_err();
        assert!(err.to_string().contains("slack"));
        assert!(err.to_string().contains("not on the Claude.ai allowlist"));
    }

    #[test]
    fn empty_allowlist_rejects_all() {
        let overlay = ClaudeAiOverlay {
            mcp_allowlist: vec![],
        };
        assert!(overlay.check_mcp_server("filesystem").is_err());
        assert!(overlay.check_mcp_server("github").is_err());
    }
}
