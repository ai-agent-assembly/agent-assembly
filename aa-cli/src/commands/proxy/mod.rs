//! `aasm proxy` — manage the aa-proxy sidecar: lifecycle, CA, and log tailing.

pub mod ca;
pub mod logs;
pub mod pid;
pub mod start;
pub mod status;
pub mod stop;

use std::process::ExitCode;

use clap::{Args, Subcommand};

/// Subcommands for `aasm proxy`.
#[derive(Debug, Subcommand)]
pub enum ProxyCommands {
    /// Spawn the aa-proxy sidecar in the background (or foreground with --no-detach).
    Start(start::StartArgs),
    /// Stop the running aa-proxy sidecar.
    Stop,
    /// Show whether the aa-proxy sidecar is running.
    Status(status::StatusArgs),
    /// Install the proxy CA certificate into the OS trust store.
    InstallCa(ca::CaArgs),
    /// Remove the proxy CA certificate from the OS trust store.
    UninstallCa(ca::CaArgs),
    /// Tail the proxy log file.
    Logs(logs::LogsArgs),
}

/// Arguments for `aasm proxy`.
#[derive(Debug, Args)]
pub struct ProxyArgs {
    #[command(subcommand)]
    pub command: ProxyCommands,
}

pub fn dispatch(args: ProxyArgs) -> ExitCode {
    match args.command {
        ProxyCommands::Start(a) => start::dispatch(a),
        ProxyCommands::Stop => stop::dispatch(),
        ProxyCommands::Status(a) => status::dispatch(a),
        ProxyCommands::InstallCa(a) => ca::install(a),
        ProxyCommands::UninstallCa(a) => ca::uninstall(a),
        ProxyCommands::Logs(a) => logs::dispatch(a),
    }
}
