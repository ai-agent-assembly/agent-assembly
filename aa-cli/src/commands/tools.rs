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
    // Only colorize when stdout is a TTY.
    let is_tty = std::io::stdout().is_terminal();
    let s = level.to_string();
    if !is_tty {
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
    use super::*;

    #[tokio::test]
    async fn prints_friendly_message_when_empty() {
        let svc = DiscoveryService::with_adapters(vec![]);
        let exit = execute_list(svc).await;
        assert_eq!(exit, ExitCode::SUCCESS);
    }
}
