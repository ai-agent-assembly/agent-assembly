//! Policy version history subcommands — apply, history, rollback, diff.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use aa_gateway::policy::history::{FsHistoryStore, HistoryConfig, PolicyHistoryStore};
use clap::Args;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};

use crate::config::ResolvedContext;
use crate::sanitize::sanitize_terminal;

/// Request body for `POST /api/v1/policies`.
#[derive(Debug, Serialize)]
pub struct CreatePolicyRequest {
    /// Raw YAML content of the governance policy.
    pub policy_yaml: String,
}

/// Response from `POST /api/v1/policies`.
#[derive(Debug, Deserialize)]
pub struct PolicyApplyResponse {
    /// Policy name (SHA-256 prefix).
    pub name: String,
    /// Policy version string (timestamp).
    pub version: String,
    /// Whether this is the currently active policy.
    pub active: bool,
    /// Number of rules in this policy version.
    pub rule_count: usize,
}

/// Arguments for `aasm policy apply`.
#[derive(Args)]
pub struct ApplyArgs {
    /// Path to the policy YAML file.
    pub file: PathBuf,
    /// Identity of the person or system applying the policy.
    #[arg(long)]
    pub applied_by: Option<String>,
}

/// Arguments for `aasm policy history`.
#[derive(Args)]
pub struct HistoryArgs {
    /// Maximum number of versions to show.
    #[arg(short = 'n', long, default_value_t = 10)]
    pub limit: usize,
}

/// Arguments for `aasm policy rollback`.
#[derive(Args)]
pub struct RollbackArgs {
    /// Version identifier (SHA-256 prefix) to roll back to.
    pub version: String,
}

/// Arguments for `aasm policy diff`.
#[derive(Args)]
pub struct DiffArgs {
    /// First version identifier (SHA-256 prefix).
    pub version_a: String,
    /// Second version identifier (SHA-256 prefix).
    pub version_b: String,
}

/// Execute the `aasm policy apply` command.
pub fn run_apply(args: ApplyArgs, ctx: &ResolvedContext) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        let yaml = match std::fs::read_to_string(&args.file) {
            Ok(y) => y,
            Err(e) => {
                eprintln!("error: failed to read {}: {}", args.file.display(), e);
                return ExitCode::FAILURE;
            }
        };
        if let Err(errs) = aa_gateway::policy::PolicyValidator::from_yaml(&yaml) {
            eprintln!("error: policy validation failed: {:?}", errs);
            return ExitCode::FAILURE;
        }
        let body = CreatePolicyRequest { policy_yaml: yaml };
        match crate::client::post_json::<_, PolicyApplyResponse>(ctx, "/api/v1/policies", &body).await {
            Ok(resp) => {
                println!("Policy applied successfully.");
                // resp.name/version are echoed from the server; sanitize.
                println!("  Version:    {}", sanitize_terminal(&resp.name));
                println!("  Timestamp:  {}", sanitize_terminal(&resp.version));
                println!("  Active:     {}", resp.active);
                println!("  Rules:      {}", resp.rule_count);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {}", e);
                ExitCode::FAILURE
            }
        }
    })
}

/// Execute the `aasm policy history` command.
pub fn run_history(args: HistoryArgs) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        let store = FsHistoryStore::new(HistoryConfig::default_config());
        match store.list(args.limit).await {
            Ok(versions) => {
                if versions.is_empty() {
                    println!("No policy versions found.");
                    return ExitCode::SUCCESS;
                }
                println!(
                    "{:<14} {:<26} {:<12} {:<10} {:<16}",
                    "VERSION", "TIMESTAMP", "APPLIED BY", "ROLLBACK", "FIRST EVENT"
                );
                println!("{}", "-".repeat(80));
                for meta in versions {
                    let version_short = &meta.sha256[..meta.sha256.len().min(12)];
                    let applied_by = meta.applied_by.as_deref().unwrap_or("-");
                    let rollback = if meta.is_rollback { "yes" } else { "-" };
                    let first_event = meta.first_event_covered.as_deref().unwrap_or("-");
                    println!(
                        "{:<14} {:<26} {:<12} {:<10} {:<16}",
                        version_short, meta.timestamp, applied_by, rollback, first_event
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {}", e);
                ExitCode::FAILURE
            }
        }
    })
}

/// Execute the `aasm policy rollback` command.
pub fn run_rollback(args: RollbackArgs) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        let store = FsHistoryStore::new(HistoryConfig::default_config());
        match store.rollback(&args.version).await {
            Ok(meta) => {
                println!("Rolled back successfully.");
                println!("  New version:    {}", &meta.sha256[..12]);
                println!("  Timestamp:      {}", meta.timestamp);
                println!(
                    "  Rolled back to: {}",
                    meta.rollback_target.as_deref().unwrap_or("unknown")
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {}", e);
                ExitCode::FAILURE
            }
        }
    })
}

/// Execute the `aasm policy diff` command.
pub fn run_diff(args: DiffArgs) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        let store = FsHistoryStore::new(HistoryConfig::default_config());
        match store.diff(&args.version_a, &args.version_b).await {
            Ok(diff) => {
                if diff.lines().count() <= 2 {
                    println!("No differences between the two versions.");
                } else {
                    print_colored_diff(&diff);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {}", e);
                ExitCode::FAILURE
            }
        }
    })
}

/// Print a unified diff with ANSI colors.
///
/// Colors are suppressed when stdout is not a TTY so piped output
/// remains machine-readable.
fn print_colored_diff(diff: &str) {
    let use_color = std::io::stdout().is_terminal();
    for line in diff.lines() {
        if use_color {
            println!("{}", colorize_diff_line(line));
        } else {
            println!("{line}");
        }
    }
}

/// Apply color to a single diff line based on its prefix.
fn colorize_diff_line(line: &str) -> String {
    if line.starts_with("---") {
        line.red().to_string()
    } else if line.starts_with("+++") {
        line.green().to_string()
    } else if line.starts_with("@@") {
        line.cyan().to_string()
    } else if line.starts_with('-') {
        line.red().to_string()
    } else if line.starts_with('+') {
        line.green().to_string()
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colorize_removal_header() {
        let out = colorize_diff_line("--- abc123def456");
        // Must contain ANSI red escape and the original text.
        assert!(out.contains("--- abc123def456"));
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn colorize_addition_header() {
        let out = colorize_diff_line("+++ 789abc012def");
        assert!(out.contains("+++ 789abc012def"));
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn colorize_hunk_marker() {
        let out = colorize_diff_line("@@ -1,3 +1,3 @@");
        assert!(out.contains("@@ -1,3 +1,3 @@"));
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn colorize_removed_line() {
        let out = colorize_diff_line("-max_actions_per_minute: 100");
        assert!(out.contains("-max_actions_per_minute: 100"));
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn colorize_added_line() {
        let out = colorize_diff_line("+max_actions_per_minute: 200");
        assert!(out.contains("+max_actions_per_minute: 200"));
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn colorize_context_line_unchanged() {
        let out = colorize_diff_line(" tier: low");
        // Context lines get no ANSI escapes.
        assert_eq!(out, " tier: low");
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn colorize_empty_line() {
        let out = colorize_diff_line("");
        assert_eq!(out, "");
    }

    #[test]
    fn print_colored_diff_does_not_panic_on_empty() {
        print_colored_diff("");
    }
}
