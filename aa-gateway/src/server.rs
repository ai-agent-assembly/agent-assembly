//! gRPC server startup — loads policy, builds service, serves over TCP or UDS.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tonic::service::interceptor::InterceptedService;
use tonic::transport::Server;

use crate::anomaly::{AnomalyConfig, AnomalyDetector, AnomalyEvent};
use crate::audit::AuditWriter;
use crate::edges::InMemoryEdgeRepo;
use crate::engine::PolicyEngine;
use crate::invalidation::{InvalidationHub, InvalidationServiceImpl};
use crate::registry::AgentRegistry;
use crate::secrets::InMemorySecretsStore;
use crate::service::{
    AgentLifecycleServiceImpl, ApprovalServiceImpl, AuditServiceImpl, PolicyServiceImpl, SecretsServiceImpl,
    TenancyMode, TopologyServiceImpl,
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

/// Explicit inbound gRPC message-size cap for every gateway service (AAASM-4133).
///
/// tonic defaults `max_decoding_message_size` to 4 MiB; pin it explicitly on
/// each service so the ceiling is intentional and centrally tunable rather than
/// an implicit library default an agent-supplied payload could quietly rely on.
/// The value matches the current default, so existing traffic is unaffected —
/// only the bound is now owned in-tree.
const MAX_DECODING_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

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

/// Return the YAML of the first Global-scoped `*.yaml` document in a cascade
/// directory (alphabetical order), or empty string if none parses as Global.
///
/// AAASM-3499 — the budget tracker the gateway's persistence loop owns must
/// reflect the same limits `load_cascade_from_dir` derives, which come from
/// the Global-scoped document. Returning empty on absence makes the limits
/// default to `None`, identical to the cascade loader's own behaviour.
fn read_global_doc_yaml(dir: &Path) -> String {
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
            .collect(),
        Err(_) => return String::new(),
    };
    entries.sort();
    for path in &entries {
        let Ok(yaml) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Ok(output) = crate::policy::PolicyValidator::from_yaml(&yaml) {
            if matches!(output.document.scope, crate::policy::scope::PolicyScope::Global) {
                return yaml;
            }
        }
    }
    String::new()
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
    // enforces them. For a cascade directory (AAASM-3499) the limits live in
    // the first Global-scoped document, mirroring `load_cascade_from_dir`;
    // for a single file we read it directly.
    let yaml = if policy_path.is_dir() {
        read_global_doc_yaml(policy_path)
    } else {
        std::fs::read_to_string(policy_path).unwrap_or_default()
    };
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
        // AAASM-4793: honours AA_PRICING_FILE when the operator has set it,
        // falling back to default_table() unchanged when unset.
        crate::budget::PricingTable::from_env(),
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

/// Build the [`PolicyEngine`] from `policy_path`, routing on whether the path
/// is a directory.
///
/// AAASM-3499 — a directory activates the multi-document Global/Org/Team/Agent
/// cascade via `PolicyEngine::load_cascade_from_dir_with_budget`; a single
/// file preserves the long-standing `PolicyEngine::load_from_file_with_budget`
/// behaviour unchanged (back-compat). Both adopt the pre-built `tracker` so the
/// gateway's persistence loop owns the same budget state either way.
fn load_policy_engine(
    policy_path: &Path,
    tracker: Arc<BudgetTracker>,
) -> Result<PolicyEngine, crate::engine::PolicyLoadError> {
    if policy_path.is_dir() {
        tracing::info!(dir = %policy_path.display(), "loading policy cascade from directory");
        PolicyEngine::load_cascade_from_dir_with_budget(policy_path, tracker)
    } else {
        PolicyEngine::load_from_file_with_budget(policy_path, tracker)
    }
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

/// Construct the live anomaly-detection hook for the gateway serve path
/// (AAASM-3378).
///
/// The `aa-gateway::anomaly` engine was fully implemented and unit-tested but
/// had **zero production callers** — the serve path never attached it, so the
/// shipped gateway ran with anomaly detection OFF and no `AnomalyEvent` could
/// ever fire on live traffic. This builds an [`AnomalyDetector`] with the
/// default config plus the broadcast channel it publishes detections on, so
/// `serve_tcp` / `serve_uds` can opt the live service in via
/// [`PolicyServiceImpl::with_anomaly_detection`].
///
/// The returned [`broadcast::Receiver`] is retained by the caller so the
/// channel is not immediately closed (the detector's `send` would otherwise
/// always error with no subscribers); future work can route it to alert sinks.
fn setup_anomaly() -> (
    Arc<AnomalyDetector>,
    broadcast::Sender<AnomalyEvent>,
    broadcast::Receiver<AnomalyEvent>,
) {
    let detector = Arc::new(AnomalyDetector::new(AnomalyConfig::default()));
    let (event_tx, event_rx) = broadcast::channel::<AnomalyEvent>(256);
    tracing::info!("anomaly detection enabled on the gateway serve path");
    (detector, event_tx, event_rx)
}

/// Build the in-process op-control broadcast for the gRPC `op_control_stream`,
/// and — when cross-process delivery is configured — spawn the NATS bridge that
/// feeds it (AAASM-3883).
///
/// The returned [`SharedOpControlPublisher`] is attached to
/// [`PolicyServiceImpl::with_ops_publisher`] so `op_control_stream` is live (no
/// longer `Unavailable`) for in-process / co-located halts. When
/// `AA_OPCONTROL_NATS_URL` is set, a bridge task subscribes to
/// `assembly.opcontrol.>` and forwards every halt published by the aa-api process
/// into this broadcast, so an operator halt issued on the HTTP endpoints reaches
/// the runtimes streamed from this gateway. See ADR 0011.
fn setup_op_control() -> crate::ops::SharedOpControlPublisher {
    let publisher = Arc::new(crate::ops::OpControlPublisher::new());
    match crate::ops::OpControlNatsConfig::from_env() {
        Some(config) => {
            tracing::info!(
                url = %config.url,
                "op-control NATS bridge enabled — cross-process halts will be delivered to op_control_stream"
            );
            crate::ops::nats::spawn_bridge(config, Arc::clone(&publisher));
        }
        None => {
            tracing::info!(
                "op-control NATS bridge disabled (AA_OPCONTROL_NATS_URL unset) — \
                 op_control_stream serves in-process halts only"
            );
        }
    }
    publisher
}

/// Select the registration-challenge store backend from the gateway's Redis
/// config (AAASM-3884).
///
/// Mirrors [`PolicyCache::from_config_async`](crate::storage::PolicyCache::from_config_async):
/// when the shared Redis cache backend is enabled **and** the `redis-cache`
/// feature is compiled in, connect a replica-shared
/// `RedisChallengeStore` so a
/// multi-replica gateway can issue a registration nonce on one replica and
/// consume it on another. Returns `None` when Redis is disabled, the feature is
/// not built in, or the connection fails — the caller then keeps the in-memory
/// default. Connection failure is fail-soft (logged, `None`) so a transient
/// Redis outage never blocks gateway startup, matching the policy cache's
/// fallback-to-disabled behaviour. The `redis-cache` feature gate and the same
/// `storage.redis` config are reused — no new config surface is added.
async fn select_challenge_store(
    redis: &aa_core::config::RedisConfig,
) -> Option<Arc<dyn crate::service::lifecycle_service::ChallengeStoreLike>> {
    if !redis.enabled {
        return None;
    }
    #[cfg(feature = "redis-cache")]
    {
        let cfg = crate::storage::RedisConfig {
            enabled: redis.enabled,
            url: redis.url.clone(),
            policy_cache_ttl_secs: redis.policy_cache_ttl_secs,
            max_connections: redis.max_connections,
        };
        match crate::storage::RedisChallengeStore::connect(&cfg).await {
            Ok(store) => {
                tracing::info!("redis-backed registration challenge store selected (replica-shared)");
                Some(Arc::new(store))
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "redis challenge store connect failed — falling back to in-memory challenge store"
                );
                None
            }
        }
    }
    #[cfg(not(feature = "redis-cache"))]
    {
        tracing::warn!(
            "storage.redis.enabled = true but the `redis-cache` feature is not compiled in; \
             using the in-memory registration challenge store"
        );
        None
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

/// Build the standard gRPC Health Checking Protocol service
/// (`grpc.health.v1.Health`) with every gateway service — and the overall
/// server (`""`) — reported as `SERVING`.
///
/// AAASM-4759: the published `aa-gateway` container previously exposed no
/// health endpoint, so `Health/Check` answered `Unimplemented` and
/// orchestrators/liveness probes had nothing to call. This is registered
/// **without** the credential interceptor (unlike every agent-plane service)
/// so an unauthenticated probe can confirm liveness — the health protocol
/// carries no sensitive data.
///
/// `health_reporter()` seeds the overall server (`""`) as `Serving`; we also
/// advertise each registered service by name so a per-service `Check` returns
/// `SERVING` rather than `NotFound`. The trait bound is spelled via
/// `tonic_health::pb::health_server::Health` because `tonic_health::server`
/// only re-exports the trait privately.
async fn serving_health_service(
) -> tonic_health::pb::health_server::HealthServer<impl tonic_health::pb::health_server::Health + use<>> {
    let (reporter, health_service) = tonic_health::server::health_reporter();
    reporter.set_serving::<PolicyServiceServer<PolicyServiceImpl>>().await;
    reporter.set_serving::<AuditServiceServer<AuditServiceImpl>>().await;
    reporter
        .set_serving::<AgentLifecycleServiceServer<AgentLifecycleServiceImpl>>()
        .await;
    reporter
        .set_serving::<ApprovalServiceServer<ApprovalServiceImpl>>()
        .await;
    reporter
        .set_serving::<TopologyServiceServer<TopologyServiceImpl>>()
        .await;
    reporter.set_serving::<SecretsServiceServer<SecretsServiceImpl>>().await;
    reporter
        .set_serving::<InvalidationServiceServer<InvalidationServiceImpl>>()
        .await;
    health_service
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
        load_policy_engine(policy_path, Arc::clone(&tracker))
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

    // AAASM-3378: enable the live anomaly detector on the shipped serve path.
    let (anomaly_detector, anomaly_tx, _anomaly_rx) = setup_anomaly();

    // AAASM-3883: attach the op-control broadcast so `op_control_stream` is live,
    // and (when AA_OPCONTROL_NATS_URL is set) bridge cross-process halts into it.
    let op_control_publisher = setup_op_control();

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
    .with_db_scheduler(db_scheduler.clone())
    .with_anomaly_detection(anomaly_detector, anomaly_tx)
    .with_ops_publisher(op_control_publisher);
    let audit_svc = AuditServiceImpl::new_with_registry(audit_tx, audit_drops, initial_hash, Arc::clone(&registry))
        .with_initial_seq(initial_seq);
    let (edge_repo, _cross_team_rx) = InMemoryEdgeRepo::with_events(Arc::clone(&registry));
    // AAASM-4032: resolve the deployment tenancy posture once at boot. It now
    // gates only team-less agent *registration* (see `AgentLifecycleServiceImpl`);
    // cross-tenant access is fail-safe unconditionally (AAASM-4140). Default is
    // Untenanted so OSS/single-tenant registration (and existing tests) are
    // unchanged.
    let tenancy_mode = TenancyMode::from_env();
    let topology_svc = TopologyServiceImpl::new(Arc::clone(&registry), edge_repo);
    // AAASM-3788 — build the agent-plane auth interceptors from the shared
    // registry before it is moved into the lifecycle service. `auth` is
    // fail-closed (applied to the previously-unauthenticated services); `enrich`
    // never rejects (applied to lifecycle/policy, which self-validate the body
    // token authoritatively, so a verified identity is available without
    // breaking bootstrap Register / policy optional-enrichment).
    let auth = crate::iam::auth_interceptor(Arc::clone(&registry));
    let enrich = crate::iam::enrich_interceptor(Arc::clone(&registry));
    // AAASM-3884: activate the AAASM-3882 seam — select the registration-
    // challenge store from config. When the shared Redis backend is enabled
    // (and the `redis-cache` feature is built in) a replica-shared
    // `RedisChallengeStore` is injected so a horizontally-scaled gateway can
    // issue a nonce on one replica and consume it on another; otherwise the
    // in-memory default is kept. Mirrors how `PolicyCache` selects Redis.
    let challenge_store = match aa_core::config::GatewayConfig::load() {
        Ok(cfg) => select_challenge_store(&cfg.storage.redis).await,
        Err(e) => {
            tracing::warn!(error = %e, "gateway config load failed — using in-memory challenge store");
            None
        }
    };
    let lifecycle_svc = match challenge_store {
        Some(store) => AgentLifecycleServiceImpl::new(registry)
            .with_challenge_store(store)
            .with_tenancy_mode(tenancy_mode),
        None => AgentLifecycleServiceImpl::new(registry).with_tenancy_mode(tenancy_mode),
    };
    let approval_svc =
        ApprovalServiceImpl::new_with_escalation(approval_queue, escalation_scheduler).with_db_scheduler(db_scheduler);
    let secrets_svc = SecretsServiceImpl::new(Arc::new(InMemorySecretsStore::new()));

    let addr = listen_addr.parse()?;

    // AAASM-3788 — mTLS wire point. The credential-token interceptor above is
    // the always-on authentication layer; mTLS is optional transport hardening.
    // The live handshake is a follow-up under AAASM-3418, so when TLS is
    // *requested* via the environment we fail closed rather than serve plaintext
    // on a socket the operator believes is encrypted.
    if let Some(tls) = crate::iam::GrpcTlsConfig::from_env() {
        return Err(format!(
            "gRPC TLS requested (mutual={}) via {}/{} but TLS support is not yet \
             compiled into aa-gateway (tracked under AAASM-3418). Refusing to start \
             plaintext; unset the TLS env vars to run the default loopback posture.",
            tls.is_mutual(),
            crate::iam::grpc_tls::GrpcTlsConfig::ENV_CERT,
            crate::iam::grpc_tls::GrpcTlsConfig::ENV_KEY,
        )
        .into());
    }

    tracing::info!(%addr, "starting gRPC server on TCP (per-RPC credential auth enforced)");

    Server::builder()
        // AAASM-4759: unauthenticated liveness endpoint — see `serving_health_service`.
        .add_service(serving_health_service().await)
        .add_service(InterceptedService::new(
            PolicyServiceServer::new(policy_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            enrich.clone(),
        ))
        .add_service(InterceptedService::new(
            AuditServiceServer::new(audit_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
        .add_service(InterceptedService::new(
            AgentLifecycleServiceServer::new(lifecycle_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            enrich.clone(),
        ))
        .add_service(InterceptedService::new(
            ApprovalServiceServer::new(approval_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
        .add_service(InterceptedService::new(
            TopologyServiceServer::new(topology_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
        .add_service(InterceptedService::new(
            SecretsServiceServer::new(secrets_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
        .add_service(InterceptedService::new(
            InvalidationServiceServer::new(InvalidationServiceImpl::new(Arc::clone(&invalidation_hub)))
                .max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
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
        load_policy_engine(policy_path, Arc::clone(&tracker))
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

    // AAASM-3378: enable the live anomaly detector on the shipped serve path.
    let (anomaly_detector, anomaly_tx, _anomaly_rx) = setup_anomaly();

    // AAASM-3883: attach the op-control broadcast so `op_control_stream` is live,
    // and (when AA_OPCONTROL_NATS_URL is set) bridge cross-process halts into it.
    let op_control_publisher = setup_op_control();

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
    .with_db_scheduler(db_scheduler.clone())
    .with_anomaly_detection(anomaly_detector, anomaly_tx)
    .with_ops_publisher(op_control_publisher);
    let audit_svc = AuditServiceImpl::new_with_registry(audit_tx, audit_drops, initial_hash, Arc::clone(&registry))
        .with_initial_seq(initial_seq);
    let (edge_repo, _cross_team_rx) = InMemoryEdgeRepo::with_events(Arc::clone(&registry));
    // AAASM-4032: resolve the deployment tenancy posture once at boot. It now
    // gates only team-less agent *registration* (see `AgentLifecycleServiceImpl`);
    // cross-tenant access is fail-safe unconditionally (AAASM-4140). Default is
    // Untenanted so OSS/single-tenant registration (and existing tests) are
    // unchanged.
    let tenancy_mode = TenancyMode::from_env();
    let topology_svc = TopologyServiceImpl::new(Arc::clone(&registry), edge_repo);
    // AAASM-3788 — agent-plane auth interceptors (see serve_tcp for the
    // fail-closed vs enrich rationale). UDS is additionally protected by
    // filesystem permissions; the credential interceptor is enforced regardless.
    let auth = crate::iam::auth_interceptor(Arc::clone(&registry));
    let enrich = crate::iam::enrich_interceptor(Arc::clone(&registry));
    // AAASM-3884: activate the AAASM-3882 seam — select the registration-
    // challenge store from config. When the shared Redis backend is enabled
    // (and the `redis-cache` feature is built in) a replica-shared
    // `RedisChallengeStore` is injected so a horizontally-scaled gateway can
    // issue a nonce on one replica and consume it on another; otherwise the
    // in-memory default is kept. Mirrors how `PolicyCache` selects Redis.
    let challenge_store = match aa_core::config::GatewayConfig::load() {
        Ok(cfg) => select_challenge_store(&cfg.storage.redis).await,
        Err(e) => {
            tracing::warn!(error = %e, "gateway config load failed — using in-memory challenge store");
            None
        }
    };
    let lifecycle_svc = match challenge_store {
        Some(store) => AgentLifecycleServiceImpl::new(registry)
            .with_challenge_store(store)
            .with_tenancy_mode(tenancy_mode),
        None => AgentLifecycleServiceImpl::new(registry).with_tenancy_mode(tenancy_mode),
    };
    let approval_svc =
        ApprovalServiceImpl::new_with_escalation(approval_queue, escalation_scheduler).with_db_scheduler(db_scheduler);
    let secrets_svc = SecretsServiceImpl::new(Arc::new(InMemorySecretsStore::new()));

    tracing::info!(socket = %socket_path.display(), "starting gRPC server on UDS (per-RPC credential auth enforced)");

    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let uds = tokio::net::UnixListener::bind(socket_path)?;
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);

    Server::builder()
        // AAASM-4759: unauthenticated liveness endpoint — see `serving_health_service`.
        .add_service(serving_health_service().await)
        .add_service(InterceptedService::new(
            PolicyServiceServer::new(policy_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            enrich.clone(),
        ))
        .add_service(InterceptedService::new(
            AuditServiceServer::new(audit_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
        .add_service(InterceptedService::new(
            AgentLifecycleServiceServer::new(lifecycle_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            enrich.clone(),
        ))
        .add_service(InterceptedService::new(
            ApprovalServiceServer::new(approval_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
        .add_service(InterceptedService::new(
            TopologyServiceServer::new(topology_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
        .add_service(InterceptedService::new(
            SecretsServiceServer::new(secrets_svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
        .add_service(InterceptedService::new(
            InvalidationServiceServer::new(InvalidationServiceImpl::new(Arc::clone(&invalidation_hub)))
                .max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            auth.clone(),
        ))
        .serve_with_incoming_shutdown(incoming, async move {
            shutdown_signal().await;
            db_token.cancel();
        })
        .await?;

    // Final flush so the last ≤60 s of spend is not lost.
    final_budget_save(&tracker, &budget_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::identity::{AgentId, SessionId};
    use aa_core::time::Timestamp;
    use aa_core::{AgentContext, GovernanceAction, PolicyResult};
    use std::collections::BTreeMap;

    /// AAASM-4759 — the gRPC Health Checking service must answer `Health/Check`
    /// with `SERVING` (not `Unimplemented`) once the gateway is up, so
    /// orchestrators/liveness probes can health-check the published container.
    /// Exercises the real wire path: serve the same `serving_health_service()`
    /// that `serve_tcp`/`serve_uds` register, then Check it with a gRPC client.
    #[tokio::test]
    async fn health_check_reports_serving() {
        use tonic::server::NamedService;
        use tonic_health::pb::health_check_response::ServingStatus;
        use tonic_health::pb::health_client::HealthClient;
        use tonic_health::pb::HealthCheckRequest;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(serving_health_service().await)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        // Build the channel via aa-gateway's own tonic transport: tonic-health
        // itself is compiled without the transport feature, so `HealthClient::
        // connect` does not exist — construct the channel here and hand it in.
        let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = HealthClient::new(channel);

        // Overall server health ("") — what a k8s gRPC liveness probe checks.
        let overall = client
            .check(HealthCheckRequest { service: String::new() })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(overall.status, ServingStatus::Serving as i32);

        // A specific registered service resolves too (not NotFound).
        let policy_name = <PolicyServiceServer<PolicyServiceImpl> as NamedService>::NAME;
        let per_service = client
            .check(HealthCheckRequest {
                service: policy_name.to_string(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(per_service.status, ServingStatus::Serving as i32);

        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }

    fn new_tracker() -> Arc<BudgetTracker> {
        Arc::new(BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ))
    }

    fn ctx_in_org(agent_byte: u8, org: &str) -> AgentContext {
        let mut metadata = BTreeMap::new();
        metadata.insert("org_id".to_string(), org.to_string());
        AgentContext {
            agent_id: AgentId::from_bytes([agent_byte; 16]),
            session_id: SessionId::from_bytes([2u8; 16]),
            pid: 1,
            started_at: Timestamp::from_nanos(0),
            metadata,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
        }
    }

    fn bash_call() -> GovernanceAction {
        GovernanceAction::ToolCall {
            name: "bash".to_string(),
            args: String::new(),
        }
    }

    fn write_cascade_dir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("000-global.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: srv-global\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("100-org.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: srv-org\n  version: \"0.1.0\"\n\
             spec:\n  scope: org:acme\n  tools:\n    bash:\n      allow: false\n",
        )
        .unwrap();
        tmp
    }

    /// AAASM-3499 — `load_policy_engine` must route a *directory* to the
    /// multi-document cascade loader, making the documented Org/Team/Agent
    /// cascade reachable from the shipped `aa-gateway` binary. Asserted
    /// behaviourally: the org-acme `bash` deny overrides the Global allow for
    /// an org-acme agent, while a different org falls through to allow.
    #[test]
    fn load_policy_engine_routes_directory_to_cascade() {
        let tmp = write_cascade_dir();
        let engine = load_policy_engine(tmp.path(), new_tracker()).expect("directory loads");

        assert_eq!(
            engine.evaluate(&ctx_in_org(0xac, "acme"), &bash_call()).decision,
            PolicyResult::Deny {
                reason: "tool denied by policy".into()
            },
            "org-acme bash must be denied by the cascade loaded from the directory"
        );
        assert_eq!(
            engine.evaluate(&ctx_in_org(0x07, "other"), &bash_call()).decision,
            PolicyResult::Allow,
            "a non-matching org must fall through to the Global allow-all"
        );
    }

    /// A single file preserves the long-standing single-policy behaviour: with
    /// no cascade loaded, the same org-acme agent is not subject to any
    /// org-scoped deny (the directory document is never consulted).
    #[test]
    fn load_policy_engine_routes_file_to_single_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("policy.yaml");
        std::fs::write(
            &file,
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: srv-single\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();

        let engine = load_policy_engine(&file, new_tracker()).expect("file loads");
        assert_eq!(
            engine.evaluate(&ctx_in_org(0xac, "acme"), &bash_call()).decision,
            PolicyResult::Allow,
            "single-file load must not apply any org-scoped cascade deny"
        );
    }

    /// AAASM-3884: with Redis disabled (the default posture), boot keeps the
    /// in-memory registration-challenge store — `select_challenge_store`
    /// returns `None`, so `AgentLifecycleServiceImpl` keeps its default.
    #[tokio::test]
    async fn select_challenge_store_keeps_in_memory_default_when_redis_disabled() {
        let redis = aa_core::config::RedisConfig::default();
        assert!(!redis.enabled, "default posture must be Redis-disabled");
        assert!(
            select_challenge_store(&redis).await.is_none(),
            "disabled Redis must keep the in-memory challenge store default",
        );
    }

    /// AAASM-3884: a Redis connect failure falls back to the in-memory default
    /// (fail-soft) rather than blocking gateway startup — mirrors
    /// `PolicyCache::from_config_async`'s fallback-to-disabled behaviour.
    #[cfg(feature = "redis-cache")]
    #[tokio::test]
    async fn select_challenge_store_falls_back_to_default_on_connect_failure() {
        // 127.0.0.1:1 is reserved and refuses connections, exercising the
        // runtime connect-failure branch (not the URL-parse branch).
        let redis = aa_core::config::RedisConfig {
            enabled: true,
            url: Some("redis://127.0.0.1:1".into()),
            ..aa_core::config::RedisConfig::default()
        };
        assert!(
            select_challenge_store(&redis).await.is_none(),
            "connect failure must fall back to the in-memory default, not panic",
        );
    }

    /// AAASM-3884: when the `redis-cache` feature is not compiled in, an enabled
    /// Redis config still resolves to the in-memory default — the feature gate
    /// (mirrored from the policy cache) decides availability.
    #[cfg(not(feature = "redis-cache"))]
    #[tokio::test]
    async fn select_challenge_store_in_memory_without_redis_feature() {
        let redis = aa_core::config::RedisConfig {
            enabled: true,
            url: Some("redis://example:6379".into()),
            ..aa_core::config::RedisConfig::default()
        };
        assert!(
            select_challenge_store(&redis).await.is_none(),
            "without the redis-cache feature the in-memory default is kept",
        );
    }
}
