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
    pub topology_stats_cache: moka::future::Cache<String, Arc<TopologyStats>>,
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
    /// Replay-dedup cache for the SaaS webhook handler (AAASM-4897). The
    /// per-provider HMAC signs the body only — with no timestamp/nonce a
    /// validly-signed webhook can be re-sent verbatim. Keyed by the
    /// authenticated `(provider, event_id)`, this admits each event once
    /// within a TTL window and rejects the replay with 409. Shared across
    /// requests so every request observes the same seen-set.
    pub saas_replay_cache: Arc<crate::routes::devtools::replay_cache::ReplayCache>,
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
    /// Per-tenant trust-score weight config backing `GET /api/v1/analytics/trust`
    /// and the `/api/v1/analytics/trust/config` read/write surface (AAASM-5083,
    /// ADR 0019 Option D). Keyed by tenant `org_id`; a tenant with no override
    /// reads the Option A defaults. In-memory, following the same pattern as the
    /// other per-tenant aa-api stores (`alert_rule_store`, `destination_store`).
    pub trust_config: Arc<crate::trust::TrustConfigStore>,
    /// Postgres-backed native-account store (AAASM-5305, ADR 0031). `None` in the
    /// in-memory wiring: native email/password auth is Postgres-gated (D2), so the
    /// login/register/invite/refresh/logout endpoints report "unavailable" and
    /// `GET /auth/methods` advertises only `api_key` when this is absent. Only a
    /// Postgres-backed deployment populates it, unlocking the password auth path.
    pub auth_store: Option<Arc<aa_storage_postgres::PgUserStore>>,
    /// Static configuration for the native-auth endpoints (default workspace,
    /// open-registration flag, lockout policy, token lifetimes). Read at request
    /// time so behaviour is deterministic regardless of `auth_store` presence.
    pub native_auth: crate::native_auth::NativeAuthConfig,
    /// Outbound email transport for the password-reset flow (AAASM-5306, ADR 0031
    /// §Q4). A real `SmtpMailer` when `AA_SMTP_HOST` is configured, otherwise the
    /// no-op `LoggingMailer` so an SMTP-less deployment degrades gracefully. The
    /// reset endpoint dispatches through this and never panics on a mail outage.
    pub mailer: Arc<dyn crate::mailer::Mailer>,
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
    /// Opening / migrating the local SQLite storage backend failed.
    #[error("failed to open local storage backend: {0}")]
    Storage(String),
    /// Constructing the audit writer over the local audit directory failed.
    #[error("failed to start local audit writer: {0}")]
    Audit(String),
    /// `AA_RATE_LIMIT_RPM` was set to an invalid (non-`u32`) value.
    #[error("invalid AA_RATE_LIMIT_RPM: {0}")]
    RateLimit(String),
}

/// Resolved authentication posture for the local single-process entrypoint
/// (AAASM-3369).
///
/// The shipped `aa-api-server` binary serves the *protected* `/api/v1/*` surface
/// over the loopback interface. Defaulting to [`AuthMode::Off`] there shipped an
/// unauthenticated admin surface; [`LocalAuth`] lets the binary require a real
/// API key by default while keeping an explicit opt-out for throwaway local dev.
#[derive(Debug, Clone)]
pub enum LocalAuth {
    /// Authentication is bypassed — every request is treated as admin. Only for
    /// throwaway local dev; selected via `AASM_API_AUTH=off`.
    Off,
    /// Require an `Authorization: Bearer aa_…` API key. The single seeded key has
    /// admin scope. The plaintext is surfaced to the operator on startup.
    ApiKey {
        /// The plaintext admin API key callers must present.
        key: String,
    },
}

impl LocalAuth {
    /// Resolve the local auth posture from the environment.
    ///
    /// * `AASM_API_AUTH=off` → [`LocalAuth::Off`] (explicit opt-out).
    /// * `AASM_API_KEY=aa_…` → [`LocalAuth::ApiKey`] using the supplied key.
    /// * otherwise → [`LocalAuth::ApiKey`] with a freshly generated admin key.
    ///
    /// Returns the resolved posture and whether the key was generated (so the
    /// caller can print it prominently on first boot).
    pub fn from_env() -> (Self, bool) {
        if matches!(std::env::var("AASM_API_AUTH").as_deref(), Ok("off") | Ok("OFF")) {
            return (LocalAuth::Off, false);
        }
        match std::env::var("AASM_API_KEY") {
            Ok(key) if !key.is_empty() => (LocalAuth::ApiKey { key }, false),
            _ => {
                let key = crate::auth::api_key::ApiKey::generate().as_str().to_string();
                (LocalAuth::ApiKey { key }, true)
            }
        }
    }
}

impl AppState {
    /// Build a fully-wired `AppState` backed entirely by in-memory / default
    /// implementations (AAASM-3360).
    ///
    /// This is the unauthenticated base wiring. The shipped `aa-api-server`
    /// entrypoint builds on it via [`local_hardened`](Self::local_hardened),
    /// which adds API-key auth and SQLite-backed audit / retention. It lets a
    /// single process serve the full `/api/v1/*` REST surface in local /
    /// single-process mode without the operator wiring ~30 subsystems by hand.
    /// Every store is the same
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
        Self::local_in_memory_with_registry(Arc::new(AgentRegistry::new()))
    }

    /// [`local_in_memory`](Self::local_in_memory) over a caller-supplied agent
    /// registry.
    ///
    /// AAASM-5102 — the engine has to adopt the *same* `Arc<AgentRegistry>` the
    /// `AppState` exposes, and [`local_hardened_at`](Self::local_hardened_at)
    /// needs a durable SQLite-backed registry rather than the throwaway
    /// in-memory one. Threading it in here is what lets both entrypoints share
    /// one registry instance; replacing `state.agent_registry` after the fact
    /// would leave the engine holding the discarded registry.
    fn local_in_memory_with_registry(agent_registry: Arc<AgentRegistry>) -> Result<Self, LocalStateError> {
        use std::sync::atomic::AtomicUsize;

        // Unique temp paths per call so concurrent processes / tests do not
        // collide on the bootstrap policy / history / audit directories.
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let uniq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();

        let events = Arc::new(EventBroadcast::default());
        let budget_alert_tx = events.budget_sender();

        // AAASM-5299 (ADR-0023 Option a): route on the operator-configured
        // `$AA_POLICY` source, mirroring what `aa-gateway` does with its
        // `--policy` / `$AA_POLICY` input. A directory populates the scope-index
        // cascade so the dashboard projections reflect the enforced policy
        // source; a file keeps today's primary-slot behaviour; unset synthesises
        // the budget-only bootstrap policy as before, leaving the cascade empty
        // (`cascade_loaded() == false`) so a generated bootstrap is never
        // presented as an operator-authored cascade (ADR-0024).
        //
        // AAASM-5102: whichever loader runs, the engine adopts the *same*
        // registry the AppState exposes. Without `with_registry`,
        // `PolicyEngine::registry` stays `None`, and every lineage-less cascade
        // read (`collect_cascade` → `effective_permissions`, behind
        // `GET /agents/{id}/capabilities`) resolves `Lineage::default()` and
        // walks only Global and Agent — silently dropping every Org- and
        // Team-scoped allow *and* deny. Enforcement was never affected: it
        // resolves tenancy itself via `authoritative_lineage` (AAASM-3729).
        let engine = match resolve_policy_source(|k| std::env::var(k).ok()) {
            PolicySource::Directory(dir) => {
                aa_gateway::engine::PolicyEngine::load_cascade_from_dir(&dir, budget_alert_tx)
                    .map_err(|e| LocalStateError::PolicyLoad(format!("{e:?}")))?
            }
            PolicySource::File(file) => aa_gateway::engine::PolicyEngine::load_from_file(&file, budget_alert_tx)
                .map_err(|e| LocalStateError::PolicyLoad(format!("{e:?}")))?,
            PolicySource::Unset => {
                // No operator policy configured: synthesise the budget-only
                // bootstrap envelope into a per-process temp file and load it
                // via the single-file loader. This leaves the scope-index
                // cascade empty (`cascade_loaded() == false`).
                let policy_dir = std::env::temp_dir().join(format!("aa-api-local-policy-{pid}-{uniq}"));
                std::fs::create_dir_all(&policy_dir).map_err(|source| LocalStateError::PolicyWrite {
                    path: policy_dir.clone(),
                    source,
                })?;
                let policy_path = policy_dir.join("local-policy.yaml");
                std::fs::write(
                    &policy_path,
                    // Minimal valid section-based envelope. AAASM-3351 made the
                    // validator fail closed on the legacy rule-list schema, so
                    // this must use the `spec:` section form.
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
                aa_gateway::engine::PolicyEngine::load_from_file(&policy_path, budget_alert_tx)
                    .map_err(|e| LocalStateError::PolicyLoad(format!("{e:?}")))?
            }
        };
        let policy_engine = Arc::new(
            engine
                .with_registry(Arc::clone(&agent_registry))
                .with_invalidation_hub(aa_gateway::invalidation::InvalidationHub::new()),
        );

        let budget_tracker = Arc::new(BudgetTracker::new(
            // AAASM-4793: honours AA_PRICING_FILE when the operator has set it,
            // falling back to default_table() unchanged when unset.
            aa_gateway::budget::pricing::PricingTable::from_env(),
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
            agent_registry,
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
            // AAASM-5296: `DiscoveryService::new()` resolves the built-in
            // adapters from `aa_devtool::registry::built_in_adapters()` — the
            // same authoritative table `aasm tools list` / `aasm run` use
            // (AAASM-5274) — so every deployment mode reports the tools that
            // are actually installed instead of an empty stub set.
            discovery: Arc::new(DiscoveryService::new()),
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
            capability_store: crate::routes::capability::CapabilityStore::new(),
            iam_api_key_store: crate::routes::iam::seeded_iam_store(),
            ops_registry: Arc::new(OpsRegistry::new()),
            destination_store: Arc::new(crate::destinations::store::InMemoryDestinationStore::new(Arc::new(
                crate::destinations::store::NoopRuleReferenceChecker,
            ))),
            audit_sender: None,
            saas_secret_cache: Arc::new(crate::routes::devtools::secret_cache::SecretCache::new()),
            saas_replay_cache: Arc::new(crate::routes::devtools::replay_cache::ReplayCache::new()),
            alert_rule_store: Arc::new(crate::alerts::rules::store::InMemoryAlertRuleStore::new()),
            destination_registry: Arc::new(DestinationRegistry::seeded()),
            retention_engine: None,
            secrets_store: Arc::new(aa_gateway::secrets::InMemorySecretsStore::new()),
            tool_registry: ToolRegistry::new(),
            trust_config: Arc::new(crate::trust::TrustConfigStore::new()),
            // Native email/password auth is Postgres-gated (ADR 0031 D2); the
            // in-memory wiring stays API-key-only, so the store is absent and the
            // native-auth endpoints degrade honestly. Config is resolved from the
            // environment even here so `/auth/methods` and the closed-registration
            // default behave identically once a Postgres store is wired in.
            auth_store: None,
            native_auth: crate::native_auth::NativeAuthConfig::from_env(),
            // AAASM-5306: resolve the mailer from AA_SMTP_* (SmtpMailer when
            // configured, else the LoggingMailer fallback). Present in every
            // wiring so the reset endpoint always has a transport; delivery only
            // actually happens on a Postgres-backed deployment with SMTP set.
            mailer: crate::mailer::build_mailer(),
        })
    }

    /// Build a hardened local `AppState` for the shipped `aa-api-server`
    /// entrypoint (AAASM-3369).
    ///
    /// This is [`local_in_memory`](Self::local_in_memory) plus the wiring that
    /// turns the documented 503 / no-op seams into real behaviour for a local
    /// single-process deployment:
    ///
    /// * **Auth** — when `auth` is [`LocalAuth::ApiKey`], the protected
    ///   `/api/v1/*` surface requires an `Authorization: Bearer aa_…` key
    ///   ([`AuthMode::On`]); the single seeded key carries admin scope. With
    ///   [`LocalAuth::Off`] it stays bypassed exactly like `local_in_memory`.
    /// * **Audit + retention** — a SQLite [`StorageBackend`] is opened under a
    ///   per-process temp directory. An [`AuditWriter`] is spawned in dual-sink
    ///   mode (JSONL + SQLite) and its sender is threaded into `audit_sender`, so
    ///   audit-emitting handlers persist instead of returning 503. A
    ///   [`RetentionEngine`] over the same backend backs the
    ///   `/api/v1/admin/retention-policy` handlers (get / put / run-once) instead
    ///   of 503. The audit *reader* points at the same JSONL directory.
    ///
    /// The alert-rule evaluator metric source is still wired by `run_server`; see
    /// [`crate::alerts::rules::evaluator::BudgetMetricSource`] for the real
    /// budget-spent source this entrypoint installs.
    ///
    /// AAASM-4447 — the agent registry is backed by a durable SQLite store and
    /// rehydrated on boot (see [`local_hardened_at`](Self::local_hardened_at)).
    /// This constructor uses a hermetic per-process temp database so tests stay
    /// isolated; the shipped [`serve_local`](crate::serve_local) entrypoint
    /// instead binds the durable `~/.aasm/local.db` shared with `aa-gateway` via
    /// [`resolve_local_registry_db_path`].
    pub async fn local_hardened(auth: LocalAuth) -> Result<Self, LocalStateError> {
        use std::sync::atomic::AtomicUsize;

        // Hermetic default: a unique per-process temp registry DB so concurrent
        // tests / processes do not collide or read a developer's real
        // `~/.aasm/local.db`.
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let uniq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let registry_db_path = std::env::temp_dir()
            .join(format!("aa-api-local-registry-{pid}-{uniq}"))
            .join("local.db");
        Self::local_hardened_at(auth, registry_db_path).await
    }

    /// Same as [`local_hardened`](Self::local_hardened) but backs the agent
    /// registry with the durable SQLite database at `registry_db_path`
    /// (AAASM-4447 / AAASM-4459).
    ///
    /// Split out so the shipped entrypoint can bind the production
    /// `~/.aasm/local.db` while tests supply a hermetic per-test path.
    pub async fn local_hardened_at(
        auth: LocalAuth,
        registry_db_path: std::path::PathBuf,
    ) -> Result<Self, LocalStateError> {
        use std::sync::atomic::AtomicUsize;

        // --- Durable agent registry (AAASM-4447 / AAASM-4459). ---
        // Built *before* the base wiring (AAASM-5102): `local_in_memory` attaches
        // whatever registry it is given to the policy engine, so the durable one
        // has to exist first. Assigning `state.agent_registry` afterwards would
        // leave the engine resolving lineage against the discarded throwaway
        // registry — i.e. against an always-empty registry, which is exactly the
        // `Lineage::default()` fallback this ticket removes.
        //
        // The embedded gRPC `AgentLifecycleService` (AAASM-4460) and the
        // REST/dashboard surface share this SAME `Arc<AgentRegistry>`, so an
        // SDK-registered agent is immediately visible to the dashboard and
        // persists across restarts (mirrors aa-gateway/src/main.rs).
        if let Some(parent) = registry_db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|source| LocalStateError::PolicyWrite {
                    path: registry_db_path.clone(),
                    source,
                })?;
            }
        }
        let registry_storage = aa_gateway::storage::open_sqlite_backend(&registry_db_path)
            .await
            .map_err(|e| LocalStateError::Storage(format!("{e}")))?;
        let registry = Arc::new(AgentRegistry::new().with_storage(registry_storage));
        let restored = registry
            .rehydrate_from_storage()
            .await
            .map_err(|e| LocalStateError::Storage(format!("registry rehydrate failed: {e}")))?;
        if restored > 0 {
            tracing::info!(
                restored,
                path = %registry_db_path.display(),
                "rehydrated agents from durable registry store"
            );
        }

        let mut state = Self::local_in_memory_with_registry(registry)?;

        // --- Rate limiting: honour AA_RATE_LIMIT_RPM in the live limiter. ---
        // `local_in_memory` hard-codes 1000; the shipped binary resolves the
        // operator-configured limit here so the live `rate_limiter` (and the
        // advertised `auth_config.rate_limit_rpm`) reflect the env (AAASM-3441).
        let rate_limit_rpm =
            crate::auth::config::resolve_rate_limit_rpm().map_err(|e| LocalStateError::RateLimit(format!("{e}")))?;
        state.rate_limiter = Arc::new(RateLimiter::new(rate_limit_rpm));
        state.auth_config = Arc::new(AuthConfig {
            mode: state.auth_config.mode,
            jwt_secret: state.auth_config.jwt_secret.clone(),
            api_keys_path: state.auth_config.api_keys_path.clone(),
            rate_limit_rpm,
        });

        // --- Auth: require an API key unless explicitly opted out. ---
        match &auth {
            LocalAuth::Off => { /* keep the AuthMode::Off wiring from local_in_memory */ }
            LocalAuth::ApiKey { key } => {
                let parsed = crate::auth::api_key::ApiKey::parse(key)
                    .map_err(|e| LocalStateError::PolicyLoad(format!("invalid AASM_API_KEY: {e}")))?;
                let key_hash = parsed
                    .hash()
                    .map_err(|e| LocalStateError::PolicyLoad(format!("failed to hash AASM_API_KEY: {e}")))?;
                let entry = crate::auth::api_key::ApiKeyEntry {
                    id: "local-admin".to_string(),
                    key_hash,
                    scopes: vec![
                        crate::auth::scope::Scope::Read,
                        crate::auth::scope::Scope::Write,
                        crate::auth::scope::Scope::Admin,
                    ],
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    label: Some("local single-process admin key".to_string()),
                    // The local single-process admin key does not expire.
                    expires_at: None,
                    team_id: None,
                    org_id: None,
                    // AAASM-4075 — index this key so credential validation runs
                    // argon2 only on the matching candidate, not per-key.
                    key_lookup: Some(parsed.lookup()),
                };
                state.auth_config = Arc::new(AuthConfig {
                    mode: AuthMode::On,
                    jwt_secret: state.auth_config.jwt_secret.clone(),
                    api_keys_path: state.auth_config.api_keys_path.clone(),
                    rate_limit_rpm: state.auth_config.rate_limit_rpm,
                });
                state.key_store = Arc::new(ApiKeyStore::from_entries(vec![entry]));
            }
        }

        // --- Audit + retention: open a local SQLite backend and wire the
        // dual-sink writer + retention engine over it. ---
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let uniq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let storage_dir = std::env::temp_dir().join(format!("aa-api-local-storage-{pid}-{uniq}"));
        std::fs::create_dir_all(&storage_dir).map_err(|source| LocalStateError::PolicyWrite {
            path: storage_dir.clone(),
            source,
        })?;
        let db_path = storage_dir.join("local.db");
        let storage = aa_gateway::storage::open_sqlite_backend(&db_path)
            .await
            .map_err(|e| LocalStateError::Storage(format!("{e}")))?;

        // Audit writer (dual-sink) over a dedicated JSONL directory; the reader
        // points at the same directory so reads see what the writer persists.
        let audit_jsonl_dir = storage_dir.join("audit");
        let (audit_tx, audit_rx) = mpsc::channel::<AuditEntry>(4096);
        let writer = aa_gateway::audit::AuditWriter::new(audit_jsonl_dir.clone(), "local", "local", audit_rx)
            .await
            .map_err(|e| LocalStateError::Audit(format!("{e}")))?
            .with_storage(storage.clone());
        tokio::spawn(writer.run());
        state.audit_sender = Some(audit_tx);
        state.audit_reader = Arc::new(AuditReader::new(audit_jsonl_dir));

        // Retention engine over the same backend, using aa-core's validated
        // default policy (daily 03:00 UTC). Constructed directly — the admin
        // REST handlers drive run_once / hot_reload on demand, so the cron
        // background loop is not required for the local entrypoint.
        let retention_cfg = aa_gateway::storage::RetentionConfig::default();
        state.retention_engine = Some(Arc::new(RetentionEngine::new(storage, retention_cfg)));

        // --- Cross-process op-control kill switch (AAASM-3883). ---
        // When AA_OPCONTROL_NATS_URL is set, attach a NATS op-control publisher to
        // the ops registry so the operator halt endpoints publish onto the shared
        // subject the gateway process bridges into op_control_stream (ADR 0011).
        // Without it the registry keeps its in-process-only behavior. A connect
        // failure is logged and left disconnected (the halt endpoints then return
        // an honest 503) rather than blocking startup.
        if let Some(cfg) = crate::ops::OpControlNatsConfig::from_env() {
            match crate::ops::OpControlNatsPublisher::connect(&cfg).await {
                Ok(publisher) => {
                    state.ops_registry = Arc::new(OpsRegistry::new().with_nats_publisher(Arc::new(publisher)));
                    tracing::info!(
                        url = %cfg.url,
                        "op-control NATS publisher connected — operator halts will be delivered cross-process"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        url = %cfg.url,
                        "op-control NATS publisher disabled — halt endpoints will return 503 until NATS is reachable"
                    );
                }
            }
        }

        Ok(state)
    }
}

/// The operator-configured policy source for `aa-api`, resolved from
/// `$AA_POLICY` (AAASM-5299 / ADR-0023 Option a).
///
/// This mirrors the resolution semantics `aa-gateway` already uses for its
/// `--policy` / `$AA_POLICY` input (`aa-cli::commands::gateway::start::resolve_policy`
/// → `aa-gateway::server::load_policy_engine`): the value is routed on the
/// *shape* of the path it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PolicySource {
    /// `$AA_POLICY` is unset (or empty, or points at a non-existent path).
    /// `aa-api` synthesises its budget-only bootstrap policy and loads it via
    /// the single-file loader, exactly as it did before AAASM-5299. The
    /// scope-index cascade stays empty, so `PolicyEngine::cascade_loaded()`
    /// reports `false` — the "unconfigured / Unknown" signal the dashboard
    /// projections rely on (ADR-0024). A generated bootstrap policy must never
    /// be presented as an operator-authored cascade.
    Unset,
    /// `$AA_POLICY` points at a single YAML file. Loaded via
    /// `PolicyEngine::load_from_file` — the primary slot only, matching today's
    /// behaviour. The cascade stays empty (`cascade_loaded() == false`).
    File(std::path::PathBuf),
    /// `$AA_POLICY` points at a directory of scoped `*.yaml` documents. Loaded
    /// via `PolicyEngine::load_cascade_from_dir`, which populates the scope
    /// index so the cascade-derived projections reflect the enforced source
    /// (`cascade_loaded() == true`).
    Directory(std::path::PathBuf),
}

/// Resolve the operator policy source from `$AA_POLICY` (AAASM-5299).
///
/// Matches `aa-gateway`'s `$AA_POLICY` semantics: an existing file resolves to
/// [`PolicySource::File`], an existing directory to [`PolicySource::Directory`],
/// and an unset / empty / non-existent value to [`PolicySource::Unset`]. The
/// caller supplies the env lookup so tests can inject a value without poisoning
/// the real process environment.
pub(crate) fn resolve_policy_source(env_lookup: impl Fn(&str) -> Option<String>) -> PolicySource {
    match env_lookup("AA_POLICY") {
        Some(raw) if !raw.is_empty() => {
            let path = std::path::PathBuf::from(raw);
            if path.is_dir() {
                PolicySource::Directory(path)
            } else if path.is_file() {
                PolicySource::File(path)
            } else {
                PolicySource::Unset
            }
        }
        _ => PolicySource::Unset,
    }
}

/// Resolve the durable local-mode registry database path (AAASM-4447).
///
/// Matches the `aa-gateway` legacy-grpc path exactly: reads
/// `GatewayConfig.local.storage_path` (default `~/.aasm/local.db`, with `~`
/// expanded by `GatewayConfig::load`). This is why an agent registered over the
/// embedded gRPC listener lands in the *same* durable store a gateway process
/// would use. Falls back to the expanded default when the config cannot be
/// loaded so an unconfigured host still resolves the shared location.
pub fn resolve_local_registry_db_path() -> std::path::PathBuf {
    match aa_core::config::GatewayConfig::load() {
        Ok(cfg) => cfg.local.storage_path,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "gateway config load failed — using default local registry path"
            );
            let mut cfg = aa_core::config::GatewayConfig::default();
            cfg.expand_paths();
            cfg.local.storage_path
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_in_memory_has_documented_disconnected_seams() {
        let state = AppState::local_in_memory().expect("in-memory state builds");
        // The in-memory wiring deliberately leaves these seams disconnected.
        assert!(state.audit_sender.is_none(), "audit pipeline is disconnected");
        assert!(state.retention_engine.is_none(), "no storage section in this mode");
        assert!(matches!(state.auth_config.mode, AuthMode::Off), "auth is bypassed");
        assert!(state.secrets_store.list().is_empty(), "no secrets pre-registered");
    }

    #[tokio::test]
    async fn local_hardened_off_keeps_auth_bypassed_but_wires_audit() {
        let state = AppState::local_hardened(LocalAuth::Off)
            .await
            .expect("hardened state builds");
        // LocalAuth::Off keeps the bypass, but hardening still connects the
        // audit + retention seams that local_in_memory leaves None.
        assert!(matches!(state.auth_config.mode, AuthMode::Off));
        assert!(
            state.audit_sender.is_some(),
            "hardened mode connects the audit pipeline"
        );
        assert!(state.retention_engine.is_some(), "hardened mode wires retention");
    }

    #[tokio::test]
    async fn local_hardened_api_key_requires_auth() {
        let key = crate::auth::api_key::ApiKey::generate().as_str().to_string();
        let state = AppState::local_hardened(LocalAuth::ApiKey { key })
            .await
            .expect("hardened state builds");
        // Supplying a key flips the gate on and seeds exactly one admin key.
        assert!(matches!(state.auth_config.mode, AuthMode::On));
        assert_eq!(state.key_store.len(), 1, "exactly the seeded admin key is present");
    }

    /// AAASM-5102 — the shipped `serve_local` entrypoint goes through
    /// `local_hardened_at`, which swaps in a durable SQLite-backed registry.
    /// The engine has to end up holding *that* registry: if it keeps the
    /// throwaway one `local_in_memory` would otherwise have created, every
    /// lineage lookup misses and the cascade silently degrades to Global+Agent
    /// again — the wiring fix would then never reach production.
    #[tokio::test]
    async fn local_hardened_engine_resolves_lineage_from_the_durable_registry() {
        let mut state = AppState::local_hardened(LocalAuth::Off)
            .await
            .expect("hardened state builds");

        let mut caps = aa_core::CapabilitySet::default();
        caps.deny.insert(aa_core::Capability::TerminalExec);
        let engine = Arc::get_mut(&mut state.policy_engine).expect("engine is unshared right after construction");
        engine.load_policy(aa_gateway::policy::PolicyDocument {
            name: Some("team-rules".to_string()),
            policy_version: Some("1".to_string()),
            version: None,
            scope: aa_gateway::policy::PolicyScope::Team("team-alpha".to_string()),
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: Default::default(),
            capabilities: Some(caps),
        });

        state
            .agent_registry
            .register(test_record([0x01; 16], "team-alpha"))
            .expect("register");

        let merged = state
            .policy_engine
            .effective_permissions(&aa_core::identity::AgentId::from_bytes([0x01; 16]))
            .merged;
        assert!(
            merged.deny.contains(&aa_core::Capability::TerminalExec),
            "the engine must resolve the durable registry's lineage: {:?}",
            merged.deny
        );
    }

    /// Minimal registered agent owned by `team_id`.
    fn test_record(agent_id: [u8; 16], team_id: &str) -> aa_gateway::registry::AgentRecord {
        aa_gateway::registry::AgentRecord {
            agent_id,
            name: "a".to_string(),
            framework: "langgraph".to_string(),
            version: "0.1.0".to_string(),
            risk_tier: 1,
            tool_names: Vec::new(),
            public_key: "pk".to_string(),
            credential_token: "tok".to_string(),
            metadata: std::collections::BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: aa_gateway::registry::AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            active_sessions: Vec::new(),
            recent_events: std::collections::VecDeque::new(),
            recent_traces: Vec::new(),
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: Some(team_id.to_string()),
            org_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some(agent_id),
            children: Vec::new(),
            parent_key: None,
            enforcement_mode: None,
        }
    }

    #[test]
    fn local_state_error_messages_are_descriptive() {
        let load = LocalStateError::PolicyLoad("bad policy".to_string());
        assert_eq!(load.to_string(), "failed to load bootstrap policy: bad policy");

        let storage = LocalStateError::Storage("disk full".to_string());
        assert_eq!(storage.to_string(), "failed to open local storage backend: disk full");

        let rate = LocalStateError::RateLimit("abc".to_string());
        assert_eq!(rate.to_string(), "invalid AA_RATE_LIMIT_RPM: abc");
    }

    /// AAASM-5299 — `resolve_policy_source` routes on the *shape* of the
    /// `$AA_POLICY` value exactly like `aa-gateway`: an existing directory is a
    /// cascade source, an existing file is a single-policy source, and an
    /// unset / empty / non-existent value is `Unset` (bootstrap-synthesis).
    /// The env lookup is injected so this test never touches the real
    /// process environment.
    #[test]
    fn resolve_policy_source_routes_on_path_shape() {
        let dir = std::env::temp_dir().join(format!("aa-api-resolve-src-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("policy.yaml");
        std::fs::write(&file, "x").expect("temp file");

        let dir_str = dir.to_string_lossy().into_owned();
        let file_str = file.to_string_lossy().into_owned();

        // Directory → Directory.
        assert_eq!(
            resolve_policy_source(|_| Some(dir_str.clone())),
            PolicySource::Directory(dir.clone()),
        );
        // File → File.
        assert_eq!(
            resolve_policy_source(|_| Some(file_str.clone())),
            PolicySource::File(file.clone()),
        );
        // Unset → Unset.
        assert_eq!(resolve_policy_source(|_| None), PolicySource::Unset);
        // Empty string → Unset.
        assert_eq!(resolve_policy_source(|_| Some(String::new())), PolicySource::Unset);
        // Non-existent path → Unset (never presented as an operator source).
        assert_eq!(
            resolve_policy_source(|_| Some("/nonexistent-aa-policy-path-xyz".to_string())),
            PolicySource::Unset,
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
