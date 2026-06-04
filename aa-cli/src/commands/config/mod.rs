//! Runtime configuration subcommands (`aasm config ...`).

use std::process::ExitCode;

use clap::{Args, Subcommand};

pub mod validate;

/// Arguments for the `aasm config` subcommand group.
#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

/// Available config subcommands.
#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Validate an `agent-assembly.toml` file (currently the `[storage]` section).
    Validate(validate::ValidateArgs),
}

/// Dispatch a config subcommand.
pub fn dispatch(args: ConfigArgs) -> ExitCode {
    match args.command {
        ConfigCommands::Validate(val_args) => validate::run(val_args),
    }
}
