//! gRPC server startup — loads policy, builds service, serves over TCP or UDS.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tonic::transport::Server;

use crate::audit::AuditWriter;
use crate::engine::PolicyEngine;
use crate::registry::AgentRegistry;
use crate::service::{AgentLifecycleServiceImpl, ApprovalServiceImpl, AuditServiceImpl, PolicyServiceImpl};
use aa_core::AuditEntry;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleServiceServer;
use aa_proto::assembly::approval::v1::approval_service_server::ApprovalServiceServer;
use aa_proto::assembly::audit::v1::audit_service_server::AuditServiceServer;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use tokio::sync::broadcast;

use aa_runtime::approval::ApprovalQueue;

use crate::budget::persistence::{default_budget_path, load_from_disk, save_to_disk_atomic, start_background_writer};
use crate::budget::{BudgetAlert, BudgetTracker};

/// Default audit directory relative to the system data directory (`~/.aa/audit`).
fn default_audit_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("aa")
        .join("audit")
}

/// Resolve the JSONL path for the given agent/session pair.
fn audit_file_path(audit_dir: &Path, agent_id: &str, session_id: &str) -> PathBuf {
    audit_dir.join(format!("{agent_id}-{session_id}.jsonl"))
}

/// Create the audit channel, spawn the background `AuditWriter`, and return
/// the sender, drop counter, and the last persisted hash (for chain continuity).
async fn setup_audit(
    agent_id: &str,
    session_id: &str,
) -> Result<(tokio::sync::mpsc::Sender<AuditEntry>, Arc<AtomicU64>, [u8; 32]), Box<dyn std::error::Error>> {
    let audit_dir = default_audit_dir();

    // Read the last hash from the existing JSONL file (if any) so the hash
    // chain is maintained across process restarts.
    let audit_path = audit_file_path(&audit_dir, agent_id, session_id);
    let initial_hash = AuditWriter::read_last_hash(&audit_path).await?.unwrap_or([0u8; 32]);

    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    let writer = AuditWriter::new(audit_dir, agent_id, session_id, audit_rx).await?;
    tokio::spawn(writer.run());

    Ok((audit_tx, audit_drops, initial_hash))
}

/// Load persisted budget state from `~/.aa/budget.json`, construct a
/// [`BudgetTracker`] pre-populated with the restored spend totals, and
/// return it wrapped in `Arc` alongside the budget file path.
///
/// Falls back to an empty tracker if the file is missing or corrupt.
fn setup_budget(policy_path: &Path, budget_alert_tx: broadcast::Sender<BudgetAlert>) -> (Arc<BudgetTracker>, PathBuf) {
    let budget_path = default_budget_path();

    let persisted = load_from_disk(&budget_path).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to load budget state, starting fresh");
        crate::budget::persistence::PersistedBudget {
            per_agent: vec![],
            team_budgets: Default::default(),
            global: crate::budget::types::BudgetState::new_today(),
            timezone: chrono_tz::UTC,
        }
    });

    // Extract limits from the policy YAML so the tracker enforces them.
    let yaml = std::fs::read_to_string(policy_path).unwrap_or_default();
    let (daily_limit, monthly_limit) = if let Ok(output) = crate::policy::PolicyValidator::from_yaml(&yaml) {
        let daily = output
            .document
            .budget
            .as_ref()
            .and_then(|bp| bp.daily_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        let monthly = output
            .document
            .budget
            .as_ref()
            .and_then(|bp| bp.monthly_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        (daily, monthly)
    } else {
        (None, None)
    };

    let tracker = Arc::new(BudgetTracker::with_state_and_alert_sender(
        crate::budget::PricingTable::default_table(),
        daily_limit,
        monthly_limit,
        persisted,
        budget_alert_tx,
    ));

    tracing::info!(path = %budget_path.display(), "budget state loaded");

    (tracker, budget_path)
}

/// Wait for SIGINT or SIGTERM, then return so the server can shut down gracefully.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => tracing::info!("received SIGINT, shutting down"),
            _ = sigterm.recv() => tracing::info!("received SIGTERM, shutting down"),
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        tracing::info!("received SIGINT, shutting down");
    }
}

/// Persist the current budget snapshot to disk. Best-effort — logs on failure.
fn final_budget_save(tracker: &BudgetTracker, budget_path: &Path) {
    let snapshot = tracker.snapshot();
    match save_to_disk_atomic(budget_path, &snapshot) {
        Ok(()) => tracing::info!(path = %budget_path.display(), "budget state saved on shutdown"),
        Err(e) => tracing::error!(error = %e, "failed to save budget state on shutdown"),
    }
}

/// Start the gRPC server on a TCP address.
///
/// Loads the policy from `policy_path`, wraps it in a `PolicyServiceImpl`, and
/// serves on `listen_addr` (e.g. `"127.0.0.1:50051"`). The `registry` is shared
/// with the `AgentLifecycleService` for agent registration and heartbeat tracking.
pub async fn serve_tcp(
    policy_path: &Path,
    listen_addr: &str,
    registry: Arc<AgentRegistry>,
    approval_queue: Arc<ApprovalQueue>,
    budget_alert_tx: broadcast::Sender<BudgetAlert>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tracker, budget_path) = setup_budget(policy_path, budget_alert_tx);
    let _budget_writer = start_background_writer(Arc::clone(&tracker), budget_path.clone());
    let engine = PolicyEngine::load_from_file_with_budget(policy_path, Arc::clone(&tracker))
        .map_err(|e| format!("failed to load policy: {e:?}"))?;
    let (audit_tx, audit_drops, initial_hash) = setup_audit("gateway", "default").await?;
    let policy_svc = PolicyServiceImpl::with_registry_and_approval(
        Arc::new(engine),
        Arc::clone(&registry),
        Arc::clone(&approval_queue),
        audit_tx.clone(),
        Arc::clone(&audit_drops),
        initial_hash,
    );
    let audit_svc = AuditServiceImpl::new_with_registry(audit_tx, audit_drops, initial_hash, Arc::clone(&registry));
    let lifecycle_svc = AgentLifecycleServiceImpl::new(registry);
    let approval_svc = ApprovalServiceImpl::new(approval_queue);

    let addr = listen_addr.parse()?;
    tracing::info!(%addr, "starting gRPC server on TCP");

    Server::builder()
        .add_service(PolicyServiceServer::new(policy_svc))
        .add_service(AuditServiceServer::new(audit_svc))
        .add_service(AgentLifecycleServiceServer::new(lifecycle_svc))
        .add_service(ApprovalServiceServer::new(approval_svc))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    // Final flush so the last ≤60 s of spend is not lost.
    final_budget_save(&tracker, &budget_path);

    Ok(())
}

/// Start the gRPC server on a Unix domain socket.
///
/// Loads the policy from `policy_path`, wraps it in a `PolicyServiceImpl`, and
/// serves on the given `socket_path`. Removes any stale socket file first.
/// The `registry` is shared with the `AgentLifecycleService`.
pub async fn serve_uds(
    policy_path: &Path,
    socket_path: &Path,
    registry: Arc<AgentRegistry>,
    approval_queue: Arc<ApprovalQueue>,
    budget_alert_tx: broadcast::Sender<BudgetAlert>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tracker, budget_path) = setup_budget(policy_path, budget_alert_tx);
    let _budget_writer = start_background_writer(Arc::clone(&tracker), budget_path.clone());
    let engine = PolicyEngine::load_from_file_with_budget(policy_path, Arc::clone(&tracker))
        .map_err(|e| format!("failed to load policy: {e:?}"))?;
    let (audit_tx, audit_drops, initial_hash) = setup_audit("gateway", "default").await?;
    let policy_svc = PolicyServiceImpl::with_registry_and_approval(
        Arc::new(engine),
        Arc::clone(&registry),
        Arc::clone(&approval_queue),
        audit_tx.clone(),
        Arc::clone(&audit_drops),
        initial_hash,
    );
    let audit_svc = AuditServiceImpl::new_with_registry(audit_tx, audit_drops, initial_hash, Arc::clone(&registry));
    let lifecycle_svc = AgentLifecycleServiceImpl::new(registry);
    let approval_svc = ApprovalServiceImpl::new(approval_queue);

    tracing::info!(socket = %socket_path.display(), "starting gRPC server on UDS");

    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let uds = tokio::net::UnixListener::bind(socket_path)?;
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);

    Server::builder()
        .add_service(PolicyServiceServer::new(policy_svc))
        .add_service(AuditServiceServer::new(audit_svc))
        .add_service(AgentLifecycleServiceServer::new(lifecycle_svc))
        .add_service(ApprovalServiceServer::new(approval_svc))
        .serve_with_incoming_shutdown(incoming, shutdown_signal())
        .await?;

    // Final flush so the last ≤60 s of spend is not lost.
    final_budget_save(&tracker, &budget_path);

    Ok(())
}
