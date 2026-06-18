//! gRPC server startup — loads policy, builds service, serves over TCP or UDS.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tonic::transport::Server;

use crate::audit::AuditWriter;
use crate::edges::InMemoryEdgeRepo;
use crate::engine::PolicyEngine;
use crate::invalidation::{InvalidationHub, InvalidationServiceImpl};
use crate::registry::AgentRegistry;
use crate::secrets::InMemorySecretsStore;
use crate::service::{
    AgentLifecycleServiceImpl, ApprovalServiceImpl, AuditServiceImpl, PolicyServiceImpl, SecretsServiceImpl,
    TopologyServiceImpl,
};
use aa_core::{AuditEntry, AuditEventType};
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleServiceServer;
use aa_proto::assembly::approval::v1::approval_service_server::ApprovalServiceServer;
use aa_proto::assembly::audit::v1::audit_service_server::AuditServiceServer;
use aa_proto::assembly::gateway::v1::invalidation_service_server::InvalidationServiceServer;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::secrets::v1::secrets_service_server::SecretsServiceServer;
use aa_proto::assembly::topology::v1::topology_service_server::TopologyServiceServer;
use tokio::sync::broadcast;

use aa_runtime::approval::{ApprovalQueue, ApprovalResolvedNotifier};

use crate::approval::clock::SystemClock;
use crate::approval::db_escalation_scheduler::DbEscalationScheduler;
use crate::approval::escalation::EscalationScheduler;
use crate::approval::NoopAuditSink;
use crate::budget::persistence::{
    default_budget_path, load_from_disk, save_to_disk_atomic, start_background_writer, start_window_flush_task,
};
use crate::budget::{BudgetAlert, BudgetTracker, BudgetWindow};
use tokio_util::sync::CancellationToken;

/// Default audit directory.
///
/// Resolves in this order:
/// 1. `AA_AUDIT_DIR` environment variable, when set (used by integration
///    tests that need per-test audit isolation — AAASM-1601).
/// 2. `dirs::data_dir()/aa/audit` (e.g. `~/.local/share/aa/audit` on
///    Linux, `~/Library/Application Support/aa/audit` on macOS).
/// 3. `./aa/audit` if neither the env var nor a system data dir is
///    available.
fn default_audit_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AA_AUDIT_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
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
///
/// Epic 18 Story S-I.3 (AAASM-1867): when `storage` is `Some`, the spawned
/// `AuditWriter` runs in dual-sink mode — every entry is both appended to
/// the JSONL chain and persisted through `storage.append_audit_event(...)`,
/// so audit events written during the session are queryable after a
/// gateway restart.
async fn setup_audit(
    agent_id: &str,
    session_id: &str,
    storage: Option<Arc<dyn crate::storage::StorageBackend>>,
) -> Result<(tokio::sync::mpsc::Sender<AuditEntry>, Arc<AtomicU64>, [u8; 32], u64), Box<dyn std::error::Error>> {
    let audit_dir = default_audit_dir();

    // Read the last hash AND seq from the existing JSONL file (if any) so both
    // the hash chain and the monotonic sequence counter are maintained across
    // process restarts. AAASM-3356: recovering only the hash (not the seq) made
    // the seq counter restart at 0 and emit duplicate sequence numbers.
    let audit_path = audit_file_path(&audit_dir, agent_id, session_id);
    let initial_hash = AuditWriter::read_last_hash(&audit_path).await?.unwrap_or([0u8; 32]);
    // `initial_seq` is the *next* seq to emit: last persisted seq + 1, or 0 for
    // a fresh chain.
    let initial_seq = AuditWriter::read_last_seq(&audit_path)
        .await?
        .map_or(0, |last| last + 1);

    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    let mut writer = AuditWriter::new(audit_dir, agent_id, session_id, audit_rx).await?;
    if let Some(storage) = storage {
        writer = writer.with_storage(storage);
    }
    tokio::spawn(writer.run());

    Ok((audit_tx, audit_drops, initial_hash, initial_seq))
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

    // Extract limits and rollover window from the policy YAML so the tracker
    // enforces them.
    let yaml = std::fs::read_to_string(policy_path).unwrap_or_default();
    let (daily_limit, monthly_limit, window) = if let Ok(output) = crate::policy::PolicyValidator::from_yaml(&yaml) {
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
        let window = output.document.budget.as_ref().and_then(|bp| bp.window);
        (daily, monthly, window)
    } else {
        (None, None, None)
    };

    let mut tracker = BudgetTracker::with_state_and_alert_sender(
        crate::budget::PricingTable::default_table(),
        daily_limit,
        monthly_limit,
        persisted,
        budget_alert_tx,
    );
    if let Some(d) = window {
        tracker = tracker.with_window(crate::budget::BudgetWindow::Duration(d));
        tracing::info!(
            window_ms = d.as_millis() as u64,
            "budget sub-day rollover window configured"
        );
    }
    let tracker = Arc::new(tracker);

    tracing::info!(path = %budget_path.display(), "budget state loaded");

    (tracker, budget_path)
}

/// Spawn a periodic flush task when the tracker is configured with a
/// sub-day rollover window; return `None` for the default `Daily` window
/// (lazy reset in `record_cost` is sufficient there). The returned handle
/// is kept alive by the caller so the task is dropped on gateway shutdown.
fn maybe_spawn_window_flush(tracker: Arc<BudgetTracker>) -> Option<tokio::task::JoinHandle<()>> {
    match tracker.window() {
        BudgetWindow::Daily => None,
        BudgetWindow::Duration(interval) => {
            // Tick at roughly one-quarter of the configured window so the
            // background flush is reactive without busy-spinning. Floor at
            // 50 ms — anything shorter is the test-fixture domain and the
            // lazy reset in `record_cost` covers it.
            let flush_interval = std::cmp::max(interval / 4, std::time::Duration::from_millis(50));
            Some(start_window_flush_task(tracker, flush_interval))
        }
    }
}

/// Spawn the [`EscalationScheduler`] background task and return the `Arc<EscalationScheduler>`.
///
/// The `run()` task is spawned internally. The returned `Arc` can be shared
/// with `PolicyServiceImpl` (to register escalations) and `ApprovalServiceImpl`
/// (to cancel them on decision).
///
/// Falls back gracefully — if the scheduler cannot be initialised (e.g. the
/// persistence path is not writable), a warning is logged and `None` is returned
/// so the rest of the server can still start.
/// Start the [`DbEscalationScheduler`] and its background polling task.
///
/// The scheduler connects to `~/.aa/aa_gateway.db`, runs pending migrations,
/// and polls `pending_escalations` every 30 s. The returned `CancellationToken`
/// must be cancelled at shutdown so the task flushes any due rows before exit.
///
/// Falls back gracefully — if the DB cannot be opened a warning is logged and
/// `None` is returned; the rest of the server continues without DB escalation.
async fn start_db_escalation_scheduler(
    approval_queue: Arc<ApprovalQueue>,
    token: CancellationToken,
) -> Option<Arc<DbEscalationScheduler>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let db_path = std::path::PathBuf::from(home).join(".aa").join("aa_gateway.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    let pool = match sqlx::SqlitePool::connect(&db_url).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "failed to open gateway SQLite DB — DB escalation scheduler disabled");
            return None;
        }
    };

    let (tx, _rx) = tokio::sync::broadcast::channel(256);
    match DbEscalationScheduler::new(
        pool,
        Arc::new(SystemClock),
        approval_queue,
        Arc::new(NoopAuditSink),
        tx,
        std::time::Duration::from_secs(30),
    )
    .await
    {
        Ok(scheduler) => {
            let scheduler = Arc::new(scheduler);
            tokio::spawn(Arc::clone(&scheduler).run(token));
            tracing::info!("DB escalation scheduler started");
            Some(scheduler)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to start DB escalation scheduler — DB escalation disabled");
            None
        }
    }
}

fn start_escalation_scheduler() -> Option<Arc<EscalationScheduler>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let path = std::path::PathBuf::from(home)
        .join(".aa")
        .join("pending_escalations.json");

    let (tx, _rx) = tokio::sync::broadcast::channel(256);
    match EscalationScheduler::new(path, tx, std::time::Duration::from_secs(30)) {
        Ok(scheduler) => {
            let scheduler = Arc::new(scheduler);
            tokio::spawn(Arc::clone(&scheduler).run());
            tracing::info!("escalation scheduler started");
            Some(scheduler)
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to start escalation scheduler — approval escalation disabled");
            None
        }
    }
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

/// Spawn a background task that converts escalation events into `ApprovalEscalated` audit entries
/// and updates the routing status on the pending approval queue entry.
fn spawn_escalation_audit_task(
    scheduler: &Option<Arc<EscalationScheduler>>,
    audit_tx: tokio::sync::mpsc::Sender<AuditEntry>,
    approval_queue: Arc<ApprovalQueue>,
) {
    let Some(sched) = scheduler else { return };
    let mut rx = sched.subscribe();
    tokio::spawn(async move {
        let seq_base = std::sync::atomic::AtomicU64::new(u64::MAX / 2);
        let mut prev_hash = [0u8; 32];
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let seq = seq_base.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;
                    let to_role = event.escalation_approvers.join(",");
                    let payload = serde_json::json!({
                        "approval_id": event.request_id.to_string(),
                        "team_id": event.team_id,
                        "from_role": event.team_id,
                        "to_role": to_role,
                        "escalation_approvers": event.escalation_approvers,
                    })
                    .to_string();
                    let agent_id = aa_core::identity::AgentId::from_bytes([0u8; 16]);
                    let session_id = aa_core::identity::SessionId::from_bytes([0u8; 16]);
                    let entry = AuditEntry::new(
                        seq,
                        now,
                        AuditEventType::ApprovalEscalated,
                        agent_id,
                        session_id,
                        payload,
                        prev_hash,
                    );
                    prev_hash = *entry.entry_hash();
                    let _ = audit_tx.try_send(entry);
                    // Update the pending approval's routing status so dashboard/CLI
                    // consumers see the escalation reflected immediately.
                    let escalation_ts = now / 1_000_000_000; // ns → s
                    let escalation_status = format!("escalated:{to_role}");
                    let history_entry = aa_runtime::approval::RoutingHistoryEntry {
                        at: escalation_ts,
                        action: "escalated".to_string(),
                        from_role: None,
                        to_role: to_role.clone(),
                    };
                    approval_queue.record_routing(
                        event.request_id,
                        escalation_status,
                        Some(to_role),
                        None,
                        None,
                        Some(history_entry),
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "escalation audit subscriber lagged");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
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
    storage: Option<Arc<dyn crate::storage::StorageBackend>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tracker, budget_path) = setup_budget(policy_path, budget_alert_tx);
    let _budget_writer = start_background_writer(Arc::clone(&tracker), budget_path.clone());
    let _budget_flush = maybe_spawn_window_flush(Arc::clone(&tracker));
    let invalidation_hub = InvalidationHub::new();
    let engine = Arc::new(
        PolicyEngine::load_from_file_with_budget(policy_path, Arc::clone(&tracker))
            .map_err(|e| format!("failed to load policy: {e:?}"))?
            .with_invalidation_hub(Arc::clone(&invalidation_hub)),
    );
    // Reuse the push channel for approval notifications: a dashboard verdict
    // (POST /approvals/{id}/approve|reject → ApprovalQueue::decide) fans out as
    // an `ApprovalResolved` event so blocked agents need not poll. AAASM-2378.
    let approval_notifier: Arc<dyn ApprovalResolvedNotifier> = invalidation_hub.clone();
    approval_queue.set_resolved_notifier(approval_notifier);
    let (audit_tx, audit_drops, initial_hash, initial_seq) = setup_audit("gateway", "default", storage).await?;
    let escalation_scheduler = start_escalation_scheduler();
    let db_token = CancellationToken::new();
    let db_scheduler = start_db_escalation_scheduler(Arc::clone(&approval_queue), db_token.clone()).await;

    spawn_escalation_audit_task(&escalation_scheduler, audit_tx.clone(), Arc::clone(&approval_queue));

    let policy_svc = PolicyServiceImpl::with_registry_approval_and_escalation(
        Arc::clone(&engine),
        Arc::clone(&registry),
        Arc::clone(&approval_queue),
        escalation_scheduler.clone(),
        audit_tx.clone(),
        Arc::clone(&audit_drops),
        initial_hash,
    )
    .with_initial_seq(initial_seq)
    .with_db_scheduler(db_scheduler.clone());
    let audit_svc = AuditServiceImpl::new_with_registry(audit_tx, audit_drops, initial_hash, Arc::clone(&registry));
    let (edge_repo, _cross_team_rx) = InMemoryEdgeRepo::with_events(Arc::clone(&registry));
    let topology_svc = TopologyServiceImpl::new(Arc::clone(&registry), edge_repo);
    let lifecycle_svc = AgentLifecycleServiceImpl::new(registry);
    let approval_svc =
        ApprovalServiceImpl::new_with_escalation(approval_queue, escalation_scheduler).with_db_scheduler(db_scheduler);
    let secrets_svc = SecretsServiceImpl::new(Arc::new(InMemorySecretsStore::new()));

    let addr = listen_addr.parse()?;
    tracing::info!(%addr, "starting gRPC server on TCP");

    Server::builder()
        .add_service(PolicyServiceServer::new(policy_svc))
        .add_service(AuditServiceServer::new(audit_svc))
        .add_service(AgentLifecycleServiceServer::new(lifecycle_svc))
        .add_service(ApprovalServiceServer::new(approval_svc))
        .add_service(TopologyServiceServer::new(topology_svc))
        .add_service(SecretsServiceServer::new(secrets_svc))
        .add_service(InvalidationServiceServer::new(InvalidationServiceImpl::new(
            Arc::clone(&invalidation_hub),
        )))
        .serve_with_shutdown(addr, async move {
            shutdown_signal().await;
            db_token.cancel();
        })
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
    storage: Option<Arc<dyn crate::storage::StorageBackend>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tracker, budget_path) = setup_budget(policy_path, budget_alert_tx);
    let _budget_writer = start_background_writer(Arc::clone(&tracker), budget_path.clone());
    let _budget_flush = maybe_spawn_window_flush(Arc::clone(&tracker));
    let invalidation_hub = InvalidationHub::new();
    let engine = Arc::new(
        PolicyEngine::load_from_file_with_budget(policy_path, Arc::clone(&tracker))
            .map_err(|e| format!("failed to load policy: {e:?}"))?
            .with_invalidation_hub(Arc::clone(&invalidation_hub)),
    );
    // Reuse the push channel for approval notifications: a dashboard verdict
    // (POST /approvals/{id}/approve|reject → ApprovalQueue::decide) fans out as
    // an `ApprovalResolved` event so blocked agents need not poll. AAASM-2378.
    let approval_notifier: Arc<dyn ApprovalResolvedNotifier> = invalidation_hub.clone();
    approval_queue.set_resolved_notifier(approval_notifier);
    let (audit_tx, audit_drops, initial_hash, initial_seq) = setup_audit("gateway", "default", storage).await?;
    let escalation_scheduler = start_escalation_scheduler();
    let db_token = CancellationToken::new();
    let db_scheduler = start_db_escalation_scheduler(Arc::clone(&approval_queue), db_token.clone()).await;

    spawn_escalation_audit_task(&escalation_scheduler, audit_tx.clone(), Arc::clone(&approval_queue));

    let policy_svc = PolicyServiceImpl::with_registry_approval_and_escalation(
        Arc::clone(&engine),
        Arc::clone(&registry),
        Arc::clone(&approval_queue),
        escalation_scheduler.clone(),
        audit_tx.clone(),
        Arc::clone(&audit_drops),
        initial_hash,
    )
    .with_initial_seq(initial_seq)
    .with_db_scheduler(db_scheduler.clone());
    let audit_svc = AuditServiceImpl::new_with_registry(audit_tx, audit_drops, initial_hash, Arc::clone(&registry));
    let (edge_repo, _cross_team_rx) = InMemoryEdgeRepo::with_events(Arc::clone(&registry));
    let topology_svc = TopologyServiceImpl::new(Arc::clone(&registry), edge_repo);
    let lifecycle_svc = AgentLifecycleServiceImpl::new(registry);
    let approval_svc =
        ApprovalServiceImpl::new_with_escalation(approval_queue, escalation_scheduler).with_db_scheduler(db_scheduler);
    let secrets_svc = SecretsServiceImpl::new(Arc::new(InMemorySecretsStore::new()));

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
        .add_service(TopologyServiceServer::new(topology_svc))
        .add_service(SecretsServiceServer::new(secrets_svc))
        .add_service(InvalidationServiceServer::new(InvalidationServiceImpl::new(
            Arc::clone(&invalidation_hub),
        )))
        .serve_with_incoming_shutdown(incoming, async move {
            shutdown_signal().await;
            db_token.cancel();
        })
        .await?;

    // Final flush so the last ≤60 s of spend is not lost.
    final_budget_save(&tracker, &budget_path);

    Ok(())
}
