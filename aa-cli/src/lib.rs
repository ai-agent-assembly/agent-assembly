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
