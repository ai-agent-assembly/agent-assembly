//! Top-level CLI subcommand definitions and dispatch.

use std::process::ExitCode;

use clap::Subcommand;

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

pub mod agent;
pub mod alerts;
pub mod approvals;
pub mod audit;
pub mod budget;
pub mod completion;
pub mod context;
pub mod cost;
pub mod dashboard;
pub mod gateway;
pub mod logs;
pub mod permissions;
pub mod policy;
pub mod proxy;
pub mod run;
pub mod status;
pub mod tools;
pub mod topology;
pub mod trace;
pub mod version;

/// Top-level subcommands for the `aasm` CLI.
#[derive(Subcommand)]
pub enum Commands {
    /// Manage monitored agent processes.
    Agent(agent::AgentArgs),
    /// Manage governance alerts.
    Alerts(alerts::AlertsArgs),
    /// Query audit log entries and export compliance reports.
    Audit(audit::AuditArgs),
    /// Query and stream audit log events.
    Logs(logs::LogsArgs),
    /// Manage governance policies.
    Policy(policy::PolicyArgs),
    /// Manage named API contexts (connection profiles).
    Context(context::ContextArgs),
    /// Generate shell completion scripts.
    Completion(completion::CompletionArgs),
    /// Show fleet health, agents, approvals, and budget at a glance.
    Status(status::StatusArgs),
    /// Show CLI and gateway version information.
    Version,
    /// Visualize a session trace (tree or timeline).
    Trace(trace::TraceArgs),
    /// Manage human-in-the-loop approval requests.
    Approvals(approvals::ApprovalsArgs),
    /// Query cost summary and forecast spending.
    Cost(cost::CostArgs),
    /// Open an interactive TUI dashboard for real-time governance monitoring.
    Dashboard(dashboard::DashboardArgs),
    /// Manage the aa-gateway governance daemon — agent registry, policy engine, audit log.
    Gateway(gateway::GatewayArgs),
    /// Launch an AI dev tool (claude, codex, copilot, windsurf) with governance wiring.
    Run(run::RunArgs),
    /// List and manage AI dev tools on this system.
    Tools(tools::ToolsArgs),
    /// Visualize agent topology, trees, lineage, and statistics.
    Topology(topology::TopologyArgs),
    /// Manage the aa-proxy sidecar — lifecycle, CA trust, and log tailing.
    Proxy(proxy::ProxyArgs),
}

/// Dispatch the parsed CLI command to the appropriate handler.
pub fn dispatch(cmd: Commands, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    match cmd {
        Commands::Agent(args) => agent::dispatch(args, ctx, output),
        Commands::Alerts(args) => alerts::dispatch(args, ctx, output),
        Commands::Audit(args) => audit::dispatch(args, ctx, output),
        Commands::Logs(args) => logs::dispatch(args, ctx),
        Commands::Policy(args) => policy::dispatch(args, ctx, output),
        Commands::Context(args) => context::dispatch(args),
        Commands::Completion(args) => completion::run(args),
        Commands::Status(args) => status::dispatch(args, ctx, output),
        Commands::Version => version::run(ctx, output),
        Commands::Trace(args) => trace::dispatch(args, ctx, output),
        Commands::Approvals(args) => approvals::dispatch(args, ctx, output),
        Commands::Cost(args) => cost::dispatch(args, ctx, output),
        Commands::Dashboard(args) => dashboard::dispatch(args, ctx),
        Commands::Gateway(args) => gateway::dispatch(args),
        Commands::Run(args) => run::dispatch(args, ctx, output),
        Commands::Tools(args) => tools::dispatch(args),
        Commands::Topology(args) => topology::dispatch(args, ctx, output),
        Commands::Proxy(args) => proxy::dispatch(args),
    }
}
