//! `aa-gateway` — Agent Assembly governance gateway gRPC server.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use tracing_subscriber::EnvFilter;

/// Deployment topology selected at boot.
///
/// `LegacyGrpc` preserves the gRPC + policy YAML flow the binary has
/// always exposed and is the default until `--mode` or `AA_MODE` says
/// otherwise. `Local` and `Remote` map onto the Epic 17 deployment
/// modes from `aa_core::config::DeploymentMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum Mode {
    /// Existing gRPC + policy server entry — default for backwards
    /// compatibility while AAASM-1577 and AAASM-1576 land.
    LegacyGrpc,
    /// Local Dev Mode (AAASM-1576 / E17 S-B). Bootstrap is not yet
    /// wired — selecting this mode exits with a clear error pointing
    /// at the tracking Sub-task.
    Local,
    /// Remote Control-Plane Mode (AAASM-1577 / E17 S-C). Drives the
    /// `aa_gateway::remote_mode::start_remote` entrypoint.
    Remote,
}

/// Agent Assembly governance gateway — gRPC policy evaluation server.
#[derive(Parser)]
#[command(name = "aa-gateway", version, about)]
struct Cli {
    /// Deployment mode. Overrides the `AA_MODE` environment variable.
    /// Default — when neither flag nor env are set — is `legacy-grpc`.
    #[arg(long, value_enum)]
    mode: Option<Mode>,

    /// Path to the policy YAML file. Required by `legacy-grpc`; ignored by
    /// `remote` and `local` modes.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// TCP listen address (e.g. "127.0.0.1:50051").
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,

    /// Unix domain socket path. When set, takes precedence over --listen.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();

    let policy = cli
        .policy
        .as_ref()
        .ok_or("--policy is required in legacy-grpc mode")?
        .clone();

    tracing::info!(policy = %policy.display(), "loading policy");

    let registry = Arc::new(aa_gateway::AgentRegistry::new());

    // Create the approval queue — gateway-owned, shared with the runtime via gRPC.
    let approval_queue = aa_runtime::approval::ApprovalQueue::new();

    // Create a budget alert broadcast channel shared between the PolicyEngine
    // (sender, via BudgetTracker) and the webhook delivery loop (receiver).
    let (budget_alert_tx, budget_alert_rx) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);

    // Optionally spawn the webhook delivery loop (reads AA_WEBHOOK_URL).
    let _webhook_handle = aa_gateway::events::startup::maybe_spawn_webhook(&approval_queue, budget_alert_rx);

    if let Some(socket_path) = &cli.socket {
        aa_gateway::server::serve_uds(&policy, socket_path, registry, approval_queue, budget_alert_tx).await
    } else {
        aa_gateway::server::serve_tcp(&policy, &cli.listen, registry, approval_queue, budget_alert_tx).await
    }
}
