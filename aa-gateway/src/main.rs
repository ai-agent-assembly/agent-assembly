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

/// Resolve the active deployment mode using the documented precedence:
/// explicit `--mode` flag > `AA_MODE` environment variable > default
/// (`Mode::LegacyGrpc`).
///
/// `env_lookup` is parameterised so unit tests can inject a stub
/// without poisoning the real process environment.
fn resolve_mode(cli_mode: Option<Mode>, env_lookup: impl Fn(&str) -> Option<String>) -> Result<Mode, String> {
    if let Some(m) = cli_mode {
        return Ok(m);
    }
    if let Some(raw) = env_lookup("AA_MODE") {
        return match raw.to_ascii_lowercase().as_str() {
            "legacy-grpc" => Ok(Mode::LegacyGrpc),
            "local" => Ok(Mode::Local),
            "remote" => Ok(Mode::Remote),
            other => Err(format!(
                "invalid AA_MODE={other:?} — expected one of: legacy-grpc, local, remote"
            )),
        };
    }
    Ok(Mode::LegacyGrpc)
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

    let mode = resolve_mode(cli.mode, |k| std::env::var(k).ok())?;

    match mode {
        Mode::LegacyGrpc => run_legacy_grpc(cli).await,
        Mode::Local => Err("Local Dev Mode bootstrap (E17 S-B / AAASM-1576) is not yet implemented".into()),
        Mode::Remote => run_remote().await,
    }
}

/// Existing gRPC + policy serving path. Preserves the pre-Epic-17
/// invocation contract `aasm-gateway --policy /path [--listen ...]`.
async fn run_legacy_grpc(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
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

/// Remote Control-Plane Mode entry: load the persisted `GatewayConfig`
/// (YAML + env overrides) and hand its `remote` section to
/// `aa_gateway::remote_mode::start_remote`. Blocks until SIGTERM /
/// SIGINT triggers graceful drain.
async fn run_remote() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = aa_core::config::GatewayConfig::load()?;
    aa_gateway::remote_mode::start_remote(&cfg.remote).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a closure that pretends `AA_MODE` is set to `value`.
    fn env_with(value: &'static str) -> impl Fn(&str) -> Option<String> {
        move |k| (k == "AA_MODE").then(|| value.to_string())
    }

    #[test]
    fn cli_flag_overrides_env() {
        let resolved = resolve_mode(Some(Mode::Remote), env_with("local")).expect("resolve");
        assert_eq!(resolved, Mode::Remote);
    }

    #[test]
    fn falls_back_to_aa_mode_env() {
        let resolved = resolve_mode(None, env_with("remote")).expect("resolve");
        assert_eq!(resolved, Mode::Remote);
    }

    #[test]
    fn defaults_to_legacy_grpc() {
        let resolved = resolve_mode(None, |_| None).expect("resolve");
        assert_eq!(resolved, Mode::LegacyGrpc);
    }
}
