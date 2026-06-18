//! Shared application state for the Axum server.

use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

use aa_devtool::DiscoveryService;
use tokio::sync::mpsc;

use aa_core::topology::EdgeRepo;
use aa_core::AuditEntry;
use aa_gateway::budget::tracker::BudgetTracker;
use aa_gateway::engine::PolicyEngine;
use aa_gateway::iam::IamApiKeyStore;
use aa_gateway::policy::history::PolicyHistoryStore;
use aa_gateway::registry::AgentRegistry;
use aa_gateway::secrets::SecretsStore;
use aa_gateway::storage::RetentionEngine;
use aa_gateway::AuditReader;
use aa_runtime::approval::ApprovalQueue;
use aa_sandbox::registry::ToolRegistry;

use crate::alerts::rules::destinations::DestinationRegistry;
use crate::alerts::rules::store::AlertRuleStore;
use crate::alerts::silence_store::SilenceStore;
use crate::alerts::AlertStore;
use crate::auth::api_key::ApiKeyStore;
use crate::auth::config::{AuthConfig, AuthMode};
use crate::auth::jwt::{JwtSigner, JwtVerifier};
use crate::auth::rate_limit::RateLimiter;
use crate::destinations::store::DestinationStore;
use crate::events::EventBroadcast;
use crate::models::topology::{AgentLineage, AgentTree, TeamTopology, TopologyOverview, TopologyStats};
use crate::ops::OpsRegistry;
use crate::replay::ReplayBuffer;
use crate::routes::capability::CapabilityStore;
use crate::trace_store::TraceStore;

/// Shared state available to all Axum handlers via `Extension<AppState>`.
#[derive(Clone)]
pub struct AppState {
    /// Agent registry for tracking active agents.
    pub agent_registry: Arc<AgentRegistry>,
    /// Policy engine for governance decisions.
    pub policy_engine: Arc<PolicyEngine>,
    /// Cost tracking and budget enforcement.
    pub budget_tracker: Arc<BudgetTracker>,
    /// Human-in-the-loop approval request queue.
    pub approval_queue: Arc<ApprovalQueue>,
    /// Policy version history store.
    pub policy_history: Arc<dyn PolicyHistoryStore>,
    /// Persistent alert store for budget alerts.
    pub alert_store: Arc<dyn AlertStore>,
    /// In-memory store for active alert silences. Populated by
    /// `POST /api/v1/alerts/silence` and drained by the silence-expiry
    /// watcher spawned in `run_server` (AAASM-1646 / AAASM-1647).
    pub silence_store: Arc<dyn SilenceStore>,
    /// Unified event broadcast bus for streaming to clients.
    pub events: Arc<EventBroadcast>,
    /// Circular replay buffer for reconnecting WebSocket clients.
    pub replay_buffer: ReplayBuffer,
    /// Monotonic counter for assigning GovernanceEvent ids.
    pub next_event_id: Arc<AtomicU64>,
    /// Authentication configuration.
    pub auth_config: Arc<AuthConfig>,
    /// Loaded API key entries for validation.
    pub key_store: Arc<ApiKeyStore>,
    /// Per-key rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
    /// JWT token signer.
    pub jwt_signer: Arc<JwtSigner>,
    /// JWT token verifier.
    pub jwt_verifier: Arc<JwtVerifier>,
    /// Session trace storage for the trace query endpoint.
    pub trace_store: Arc<dyn TraceStore>,
    /// Audit log reader for querying JSONL entries.
    pub audit_reader: Arc<AuditReader>,
    /// Timestamp when the server started, used to compute uptime.
    pub startup_time: Instant,
    /// Number of currently active WebSocket/SSE connections.
    pub active_connections: Arc<AtomicI64>,
    /// Dev tool auto-discovery service.
    pub discovery: Arc<DiscoveryService>,
    /// Topology edge store for mesh edge queries.
    pub edge_repo: Arc<dyn EdgeRepo>,
    /// Short-lived cache for GET /topology/overview responses (1 s TTL).
    pub topology_overview_cache: moka::future::Cache<String, Arc<TopologyOverview>>,
    /// Short-lived cache for GET /topology/tree/{root_id} responses (5 s TTL).
    pub topology_tree_cache: moka::future::Cache<String, Arc<AgentTree>>,
    /// Short-lived cache for GET /topology/team/{team_id} responses (5 s TTL).
    pub topology_team_cache: moka::future::Cache<String, Arc<TeamTopology>>,
    /// Short-lived cache for GET /topology/lineage/{agent_id} responses (5 s TTL).
    pub topology_lineage_cache: moka::future::Cache<String, Arc<AgentLineage>>,
    /// Short-lived cache for GET /topology/stats responses (10 s TTL).
    pub topology_stats_cache: moka::future::Cache<&'static str, Arc<TopologyStats>>,
    /// Dashboard Capability Matrix store (AAASM-1366).
    pub capability_store: Arc<CapabilityStore>,
    /// Dashboard Identity & Access — IAM API key management (AAASM-1397).
    pub iam_api_key_store: Arc<IamApiKeyStore>,
    /// In-flight operation lifecycle registry (AAASM-1525).
    pub ops_registry: Arc<OpsRegistry>,
    /// Notification-destination store backing `/alerts/destinations` (AAASM-1388).
    pub destination_store: Arc<dyn DestinationStore>,
    /// Optional sender into the shared audit-ingest channel (see
    /// `aa-gateway::audit::AuditWriter`). When `None`, audit-emitting
    /// handlers respond with HTTP 503 to signal that the audit pipeline
    /// is not connected — they do not buffer events. The webhook handler
    /// in `routes::devtools::saas_webhook` is the first consumer of this
    /// seam (AAASM-924); future routes wire in the same way.
    pub audit_sender: Option<mpsc::Sender<AuditEntry>>,
    /// Per-provider HMAC secret cache used by the SaaS webhook handler
    /// (AAASM-924). 5-minute TTL by default. Shared across requests so
    /// the resolver backend is hit at most once per TTL window per key.
    pub saas_secret_cache: Arc<crate::routes::devtools::secret_cache::SecretCache>,
    /// Alert-rule CRUD store (AAASM-1386).
    pub alert_rule_store: Arc<dyn AlertRuleStore>,
    /// Allow-set of destinations alert rules may target (AAASM-1386).
    pub destination_registry: Arc<DestinationRegistry>,
    /// Retention engine backing the admin REST `/api/v1/admin/retention-policy`
    /// handlers (AAASM-1592 S-K). `None` when the gateway is started without
    /// a `storage` section — the handlers respond with 503 in that case.
    pub retention_engine: Option<Arc<RetentionEngine>>,
    /// Placeholder → credential registry consumed by `POST /v1/dispatch_tool`
    /// (AAASM-1920 Secret Injection). `Arc<dyn SecretsStore>` so the handler
    /// can resolve `${NAME}` tokens via
    /// `aa-gateway::secrets::resolver::resolve_placeholders`.
    pub secrets_store: Arc<dyn SecretsStore>,
    /// In-memory `tools/call` registry consumed by `POST /v1/dispatch_tool`
    /// when the named tool is a WASM-marked entry. The handler invokes
    /// [`aa_sandbox::wasm_dispatch::dispatch_wasm_tool`] for those; native
    /// (or absent) entries fall through to the existing
    /// secret-injection / forward-upstream path. (AAASM-2033 /
    /// F116 ST-W data-path follow-up.)
    pub tool_registry: ToolRegistry,
}

/// Error returned by [`AppState::local_in_memory`] when the in-memory wiring
/// cannot be constructed — currently only when the bundled minimal policy
/// fails to materialise on disk or the policy engine refuses to load it.
#[derive(Debug, thiserror::Error)]
pub enum LocalStateError {
    /// Writing the bundled minimal policy to a temp file failed.
    #[error("failed to write bootstrap policy at {path}: {source}", path = path.display())]
    PolicyWrite {
        /// The temp policy path we tried to write.
        path: std::path::PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Loading the bundled minimal policy into a [`PolicyEngine`] failed.
    #[error("failed to load bootstrap policy: {0}")]
    PolicyLoad(String),
}

impl AppState {
    /// Build a fully-wired `AppState` backed entirely by in-memory / default
    /// implementations (AAASM-3360).
    ///
    /// This is the production seam that lets a single shipped entrypoint serve
    /// the full `/api/v1/*` REST surface in local / single-process mode without
    /// the operator wiring ~30 subsystems by hand. Every store is the same
    /// in-memory implementation the gateway already uses for ephemeral state;
    /// nothing here touches a remote database, NATS, or the network.
    ///
    /// Authentication is disabled ([`AuthMode::Off`]) so the protected
    /// `/api/v1/*` routes are reachable without a bearer credential — this is a
    /// local single-process developer surface, not a hardened deployment.
    ///
    /// Documented limitations of the in-memory wiring (callers / the PR body
    /// should surface these):
    /// * `audit_sender` is `None` — audit-emitting handlers (e.g. the SaaS
    ///   webhook) respond 503; audit *reads* return an empty list.
    /// * `retention_engine` is `None` — `/api/v1/admin/retention-policy`
    ///   handlers respond 503 (no `storage` section in this mode).
    /// * The alert-rule evaluator runs against a `NullMetricSource`, so rules
    ///   never fire (same as the existing `run_server` wiring).
    ///
    /// The bootstrap policy is an empty section-based envelope (allow-by-default
    /// with a daily budget limit) written to a per-process temp file because
    /// [`PolicyEngine::load_from_file`] is the only public loader.
    pub fn local_in_memory() -> Result<Self, LocalStateError> {
        use std::sync::atomic::AtomicUsize;

        // Unique temp paths per call so concurrent processes / tests do not
        // collide on the bootstrap policy / history / audit directories.
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let uniq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();

        let policy_dir = std::env::temp_dir().join(format!("aa-api-local-policy-{pid}-{uniq}"));
        std::fs::create_dir_all(&policy_dir).map_err(|source| LocalStateError::PolicyWrite {
            path: policy_dir.clone(),
            source,
        })?;
        let policy_path = policy_dir.join("local-policy.yaml");
        std::fs::write(
            &policy_path,
            // Minimal valid section-based envelope. AAASM-3351 made the
            // validator fail closed on the legacy rule-list schema, so this
            // must use the `spec:` section form.
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n  \
             name: local-policy\n  \
             version: \"0.1.0\"\n\
             spec:\n  \
             budget:\n    \
             daily_limit_usd: 100.0\n",
        )
        .map_err(|source| LocalStateError::PolicyWrite {
            path: policy_path.clone(),
            source,
        })?;

        let events = Arc::new(EventBroadcast::default());
        let budget_alert_tx = events.budget_sender();
        let policy_engine = Arc::new(
            aa_gateway::engine::PolicyEngine::load_from_file(&policy_path, budget_alert_tx)
                .map_err(|e| LocalStateError::PolicyLoad(format!("{e:?}")))?
                .with_invalidation_hub(aa_gateway::invalidation::InvalidationHub::new()),
        );

        let budget_tracker = Arc::new(BudgetTracker::new(
            aa_gateway::budget::pricing::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));

        let history_dir = std::env::temp_dir().join(format!("aa-api-local-history-{pid}-{uniq}"));
        let policy_history = Arc::new(aa_gateway::policy::history::FsHistoryStore::new(
            aa_gateway::policy::history::HistoryConfig {
                history_dir,
                max_versions: 50,
            },
        ));

        let auth_config = Arc::new(AuthConfig {
            mode: AuthMode::Off,
            jwt_secret: None,
            api_keys_path: std::path::PathBuf::from("/dev/null"),
            rate_limit_rpm: 1000,
        });
        // AuthMode::Off bypasses the gate, so any JWT secret works for the
        // signer/verifier (the token-issue route still needs them to exist).
        const LOCAL_JWT_SECRET: &[u8] = b"aa-local-mode-jwt-secret-not-for-production-use!!";
        let jwt_signer = Arc::new(JwtSigner::new(LOCAL_JWT_SECRET));
        let jwt_verifier = Arc::new(JwtVerifier::new(LOCAL_JWT_SECRET));
        // `load` on a non-existent path returns an empty store (infallible).
        let key_store = Arc::new(
            ApiKeyStore::load(std::path::Path::new("/nonexistent-aa-local-keys"))
                .expect("loading a non-existent key file yields an empty store"),
        );
        let rate_limiter = Arc::new(RateLimiter::new(1000));

        let audit_dir = std::env::temp_dir().join(format!("aa-api-local-audit-{pid}-{uniq}"));
        std::fs::create_dir_all(&audit_dir).map_err(|source| LocalStateError::PolicyWrite {
            path: audit_dir.clone(),
            source,
        })?;
        let audit_reader = Arc::new(AuditReader::new(audit_dir));

        Ok(AppState {
            agent_registry: Arc::new(AgentRegistry::new()),
            policy_engine,
            budget_tracker,
            approval_queue: ApprovalQueue::new(),
            policy_history,
            alert_store: Arc::new(crate::alerts::store::InMemoryAlertStore::new()),
            silence_store: Arc::new(crate::alerts::silence_store::InMemorySilenceStore::new()),
            events,
            replay_buffer: ReplayBuffer::new(),
            next_event_id: Arc::new(AtomicU64::new(0)),
            auth_config,
            key_store,
            rate_limiter,
            jwt_signer,
            jwt_verifier,
            trace_store: Arc::new(crate::trace_store::InMemoryTraceStore::new()),
            audit_reader,
            startup_time: Instant::now(),
            active_connections: Arc::new(AtomicI64::new(0)),
            discovery: Arc::new(DiscoveryService::with_adapters(vec![])),
            edge_repo: Arc::new(aa_gateway::edges::InMemoryEdgeRepo::new()),
            topology_overview_cache: moka::future::Cache::builder()
                .time_to_live(std::time::Duration::from_secs(1))
                .build(),
            topology_tree_cache: moka::future::Cache::builder()
                .time_to_live(std::time::Duration::from_secs(5))
                .build(),
            topology_team_cache: moka::future::Cache::builder()
                .time_to_live(std::time::Duration::from_secs(5))
                .build(),
            topology_lineage_cache: moka::future::Cache::builder()
                .time_to_live(std::time::Duration::from_secs(5))
                .build(),
            topology_stats_cache: moka::future::Cache::builder()
                .time_to_live(std::time::Duration::from_secs(10))
                .build(),
            capability_store: crate::routes::capability::CapabilityStore::new_seeded(),
            iam_api_key_store: crate::routes::iam::seeded_iam_store(),
            ops_registry: Arc::new(OpsRegistry::new()),
            destination_store: Arc::new(crate::destinations::store::InMemoryDestinationStore::new(Arc::new(
                crate::destinations::store::NoopRuleReferenceChecker,
            ))),
            audit_sender: None,
            saas_secret_cache: Arc::new(crate::routes::devtools::secret_cache::SecretCache::new()),
            alert_rule_store: Arc::new(crate::alerts::rules::store::InMemoryAlertRuleStore::new()),
            destination_registry: Arc::new(DestinationRegistry::seeded()),
            retention_engine: None,
            secrets_store: Arc::new(aa_gateway::secrets::InMemorySecretsStore::new()),
            tool_registry: ToolRegistry::new(),
        })
    }
}
