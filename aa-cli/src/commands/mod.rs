//! Top-level CLI subcommand definitions and dispatch.

use std::process::ExitCode;

use clap::Subcommand;

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

pub mod admin;
pub mod agent;
pub mod alerts;
pub mod approvals;
pub mod audit;
pub mod budget;
pub mod completion;
pub mod config;
pub mod context;
pub mod cost;
pub mod dashboard;
pub mod gateway;
pub mod gw_probe;
pub mod logs;
pub mod permissions;
pub mod pidfile;
pub mod policy;
pub mod proxy;
// strip-for-publish:begin devtool
pub mod run;
// strip-for-publish:end devtool
pub mod sandbox;
pub mod start;
pub mod status;
pub mod stop;
// strip-for-publish:begin devtool
pub mod tools;
// strip-for-publish:end devtool
pub mod topology;
pub mod trace;
pub mod uninstall;
pub mod version;

/// Top-level subcommands for the `aasm` CLI.
#[derive(Subcommand)]
pub enum Commands {
    /// Gateway administrative operations.
    Admin(admin::AdminArgs),
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
    /// Validate an `agent-assembly.toml` runtime configuration file.
    Config(config::ConfigArgs),
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
    // strip-for-publish:begin devtool
    /// Launch an AI dev tool (claude, codex, copilot, windsurf) with governance wiring.
    Run(run::RunArgs),
    // strip-for-publish:end devtool
    /// Run a WebAssembly tool inside the Agent Assembly sandbox (filesystem + CPU + memory + wall-clock isolation).
    Sandbox(sandbox::SandboxArgs),
    // strip-for-publish:begin devtool
    /// List and manage AI dev tools on this system.
    Tools(tools::ToolsArgs),
    // strip-for-publish:end devtool
    /// Visualize agent topology, trees, lineage, and statistics.
    Topology(topology::TopologyArgs),
    /// Manage the aa-proxy sidecar — lifecycle, CA trust, and log tailing.
    Proxy(proxy::ProxyArgs),
    /// Start the locally-managed Agent Assembly gateway process.
    Start(start::StartArgs),
    /// Stop the locally-managed Agent Assembly gateway process.
    Stop(stop::StopArgs),
    /// Uninstall Agent Assembly tools installed via the curl installer (safe by
    /// default; `--purge` also removes local data; Homebrew installs redirected).
    Uninstall(uninstall::UninstallArgs),
}

/// Dispatch the parsed CLI command to the appropriate handler.
pub fn dispatch(cmd: Commands, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    match cmd {
        Commands::Admin(args) => admin::dispatch(args, ctx, output),
        Commands::Agent(args) => agent::dispatch(args, ctx, output),
        Commands::Alerts(args) => alerts::dispatch(args, ctx, output),
        Commands::Audit(args) => audit::dispatch(args, ctx, output),
        Commands::Logs(args) => logs::dispatch(args, ctx),
        Commands::Policy(args) => policy::dispatch(args, ctx, output),
        Commands::Context(args) => context::dispatch(args),
        Commands::Config(args) => config::dispatch(args),
        Commands::Completion(args) => completion::run(args),
        Commands::Status(args) => status::dispatch(args, ctx, output),
        Commands::Version => version::run(ctx, output),
        Commands::Trace(args) => trace::dispatch(args, ctx, output),
        Commands::Approvals(args) => approvals::dispatch(args, ctx, output),
        Commands::Cost(args) => cost::dispatch(args, ctx, output),
        Commands::Dashboard(args) => dashboard::dispatch(args, ctx),
        Commands::Gateway(args) => gateway::dispatch(args),
        // strip-for-publish:begin devtool
        Commands::Run(args) => run::dispatch(args, ctx, output),
        // strip-for-publish:end devtool
        Commands::Sandbox(args) => sandbox::dispatch(args),
        // strip-for-publish:begin devtool
        Commands::Tools(args) => tools::dispatch(args),
        // strip-for-publish:end devtool
        Commands::Topology(args) => topology::dispatch(args, ctx, output),
        Commands::Proxy(args) => proxy::dispatch(args),
        Commands::Start(args) => start::run(args),
        Commands::Stop(args) => stop::run(args),
        Commands::Uninstall(args) => uninstall::dispatch(args),
    }
}
