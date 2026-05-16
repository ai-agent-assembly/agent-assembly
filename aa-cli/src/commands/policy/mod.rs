//! Policy management subcommands (`aasm policy ...`).

use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

pub mod get;
pub mod history;
pub mod list;
pub mod show;
pub mod simulate;
pub mod validate;

/// Arguments for the `aasm policy` subcommand group.
#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommands,
}

/// Available policy subcommands.
#[derive(Subcommand)]
pub enum PolicyCommands {
    /// Apply a policy YAML file and save it to version history.
    Apply(history::ApplyArgs),
    /// List recent policy versions.
    History(history::HistoryArgs),
    /// Roll back to a previous policy version.
    Rollback(history::RollbackArgs),
    /// Show the diff between two policy versions.
    Diff(history::DiffArgs),
    /// Simulate a policy against historical events or live traffic (dry-run).
    Simulate(simulate::SimulateArgs),
    /// Validate a policy YAML file locally (no apply).
    Validate(validate::ValidateArgs),
    /// Show the currently active policy YAML (or a specific version).
    Get(get::GetArgs),
    /// List all policies deployed to the governance runtime.
    List(list::ListArgs),
    /// Show an agent's effective policy view (use `--show-permissions`).
    Show(show::ShowArgs),
}

/// Dispatch a policy subcommand.
pub fn dispatch(args: PolicyArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    match args.command {
        PolicyCommands::Apply(apply_args) => history::run_apply(apply_args, ctx),
        PolicyCommands::History(history_args) => history::run_history(history_args),
        PolicyCommands::Rollback(rollback_args) => history::run_rollback(rollback_args),
        PolicyCommands::Diff(diff_args) => history::run_diff(diff_args),
        PolicyCommands::Simulate(sim_args) => simulate::run(sim_args),
        PolicyCommands::Validate(val_args) => validate::run(val_args),
        PolicyCommands::Get(get_args) => get::run(get_args),
        PolicyCommands::List(list_args) => list::run(list_args, ctx, output),
        PolicyCommands::Show(show_args) => show::run(show_args, ctx, output),
    }
}
