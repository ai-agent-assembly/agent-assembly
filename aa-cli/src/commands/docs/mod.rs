//! `aasm docs` — generate documentation from the live CLI definition.

use std::process::ExitCode;

use clap::{Args, Subcommand};

pub mod export;

/// Arguments for the `aasm docs` subcommand group.
#[derive(Args)]
pub struct DocsArgs {
    #[command(subcommand)]
    pub command: DocsCommands,
}

/// Available `aasm docs` subcommands.
#[derive(Subcommand)]
pub enum DocsCommands {
    /// Export the CLI reference, one Markdown file per command.
    Export(export::ExportArgs),
}

/// Dispatch a `docs` subcommand.
pub fn dispatch(args: DocsArgs) -> ExitCode {
    match args.command {
        DocsCommands::Export(export_args) => export::run(export_args),
    }
}
