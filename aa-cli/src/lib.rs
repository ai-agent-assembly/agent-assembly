//! `aa-cli` library — shared types for the `aasm` binary and integration tests.

use clap::Parser;

pub mod client;
pub mod commands;
pub mod config;
pub mod error;
pub mod output;

#[cfg(test)]
mod test_support;

/// Agent Assembly CLI — governance gateway management tool.
#[derive(Parser)]
#[command(name = "aasm", version, about)]
pub struct Cli {
    /// Named context from ~/.aa/config.yaml to use.
    #[arg(long, global = true)]
    pub context: Option<String>,

    /// Output format for list/get commands.
    #[arg(long, global = true, value_enum, default_value_t = output::OutputFormat::Table)]
    pub output: output::OutputFormat,

    /// Override the API URL (takes precedence over context config).
    #[arg(long, global = true)]
    pub api_url: Option<String>,

    /// Override the API key (takes precedence over context config).
    ///
    /// Reads from the `AASM_API_KEY` environment variable when the flag is
    /// absent. Prefer the env var: passing `--api-key` on the command line
    /// leaks the operator bearer token into argv, which is world-readable via
    /// `ps`, `/proc/<pid>/cmdline`, and shell history. The flag still wins when
    /// both are set, so existing scripts keep working.
    #[arg(long, global = true, env = "AASM_API_KEY")]
    pub api_key: Option<String>,

    #[command(subcommand)]
    pub command: commands::Commands,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The global `--api-key` flag must fall back to `AASM_API_KEY` so the
    /// operator bearer token need never appear in argv (ps/proc/shell history).
    #[test]
    fn api_key_resolves_from_env_when_flag_absent() {
        let _guard = test_support::env_guard();
        std::env::set_var("AASM_API_KEY", "env-secret");
        let parsed = Cli::try_parse_from(["aasm", "version"]);
        std::env::remove_var("AASM_API_KEY");
        let cli = parsed.expect("parse must succeed");
        assert_eq!(cli.api_key.as_deref(), Some("env-secret"));
    }

    /// An explicit `--api-key` flag still wins over the env var (back-compat).
    #[test]
    fn api_key_flag_takes_precedence_over_env() {
        let _guard = test_support::env_guard();
        std::env::set_var("AASM_API_KEY", "env-secret");
        let parsed = Cli::try_parse_from(["aasm", "--api-key", "flag-secret", "version"]);
        std::env::remove_var("AASM_API_KEY");
        let cli = parsed.expect("parse must succeed");
        assert_eq!(cli.api_key.as_deref(), Some("flag-secret"));
    }

    /// With neither flag nor env set, `--api-key` resolves to `None` (no panic).
    #[test]
    fn api_key_none_when_neither_flag_nor_env_set() {
        let _guard = test_support::env_guard();
        std::env::remove_var("AASM_API_KEY");
        let cli = Cli::try_parse_from(["aasm", "version"]).expect("parse must succeed");
        assert!(cli.api_key.is_none());
    }
}
