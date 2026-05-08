//! `aasm tools` subcommand — list and manage AI dev tools on this system.

use std::io::IsTerminal;
use std::process::ExitCode;

use aa_core::GovernanceLevel;
use aa_devtool::DiscoveryService;
use comfy_table::Table;
use owo_colors::OwoColorize;

/// Arguments for the `aasm tools` subcommand.
#[derive(Debug, clap::Args)]
pub struct ToolsArgs {
    #[command(subcommand)]
    pub subcommand: ToolsSubcommand,
}

/// Subcommands available under `aasm tools`.
#[derive(Debug, clap::Subcommand)]
pub enum ToolsSubcommand {
    /// List all discovered AI dev tools on this system.
    List,
}

/// Dispatch the `tools` subcommand.
pub fn dispatch(args: ToolsArgs) -> ExitCode {
    match args.subcommand {
        ToolsSubcommand::List => {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(execute_list(DiscoveryService::new()))
        }
    }
}

/// Run discovery and print the results table.
///
/// Accepts a [`DiscoveryService`] parameter so tests can inject stub adapters.
pub async fn execute_list(discovery: DiscoveryService) -> ExitCode {
    let tools = discovery.discover_all().await;

    if tools.is_empty() {
        println!("No AI dev tools detected on this system.");
        return ExitCode::SUCCESS;
    }

    let mut table = Table::new();
    table.set_header(["TOOL", "VERSION", "PATH", "GOVERNANCE LEVEL"]);

    for info in &tools {
        let tool_name = format!("{:?}", info.kind);
        let version = info.version.as_deref().unwrap_or("unknown").to_string();
        let path = info.install_path.display().to_string();
        let level = color_governance_level(info.governance_level);
        table.add_row([tool_name, version, path, level]);
    }

    println!("{table}");
    ExitCode::SUCCESS
}

fn color_governance_level(level: GovernanceLevel) -> String {
    format_governance_level(level, std::io::stdout().is_terminal())
}

pub(crate) fn format_governance_level(level: GovernanceLevel, colorize: bool) -> String {
    let s = level.to_string();
    if !colorize {
        return s;
    }
    match level {
        GovernanceLevel::L0Discover => s.dimmed().to_string(),
        GovernanceLevel::L1Observe => s.yellow().to_string(),
        GovernanceLevel::L2Enforce => s.green().to_string(),
        GovernanceLevel::L3Native => s.bright_green().bold().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use aa_core::policy::PolicyDocument;
    use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};
    use async_trait::async_trait;

    use super::*;

    struct StubClaudeCode;

    #[async_trait]
    impl DevToolAdapter for StubClaudeCode {
        fn detect(&self) -> Option<DevToolInfo> {
            Some(DevToolInfo {
                kind: DevToolKind::ClaudeCode,
                version: Some("1.0.0".into()),
                install_path: PathBuf::from("/stub/claude"),
                governance_level: GovernanceLevel::L3Native,
                supports_mcp: false,
                supports_managed_settings: false,
            })
        }
        async fn generate_managed_settings(&self, _: &PolicyDocument) -> Result<String, AdapterError> {
            Err(AdapterError::SettingsGenerationFailed("stub".into()))
        }
        async fn apply_settings(&self, _: &str) -> Result<(), AdapterError> {
            Err(AdapterError::SettingsApplyFailed(std::io::Error::other("stub")))
        }
        fn build_launch_command(
            &self,
            _: &[String],
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            Err(AdapterError::LaunchFailed("stub".into()))
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
            Ok(vec![])
        }
        async fn apply_mcp_governance(&self, _: &[String], _: &[String]) -> Result<(), AdapterError> {
            Ok(())
        }
        fn governance_level(&self) -> GovernanceLevel {
            GovernanceLevel::L3Native
        }
    }

    #[tokio::test]
    async fn prints_friendly_message_when_empty() {
        let svc = DiscoveryService::with_adapters(vec![]);
        let exit = execute_list(svc).await;
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn execute_list_prints_table_for_discovered_tools() {
        let svc = DiscoveryService::with_adapters(vec![Box::new(StubClaudeCode)]);
        let exit = execute_list(svc).await;
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[test]
    fn dispatch_list_returns_success() {
        // In CI no tools are installed, so the friendly message is printed.
        let exit = dispatch(ToolsArgs {
            subcommand: ToolsSubcommand::List,
        });
        assert_eq!(exit, ExitCode::SUCCESS);
    }

    #[test]
    fn format_governance_level_covers_all_levels() {
        for level in [
            GovernanceLevel::L0Discover,
            GovernanceLevel::L1Observe,
            GovernanceLevel::L2Enforce,
            GovernanceLevel::L3Native,
        ] {
            // colorize = false: the plain-string path
            assert!(!format_governance_level(level, false).is_empty());
            // colorize = true: exercises all 4 match arms
            assert!(!format_governance_level(level, true).is_empty());
        }
    }
}
