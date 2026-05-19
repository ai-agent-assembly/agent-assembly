// Shared across multiple test binaries (smoke, sdk_driver_selftest, …); not
// every binary uses every helper, so dead-code warnings here are noise.
#![allow(dead_code)]

//! Test harness for the topology integration test suite (AAASM-1066 / ST-1).
//!
//! Provides `TopologyTestEnv` — a self-contained fixture that builds a minimal
//! [`AppState`], binds the aa-api Axum router to a free TCP port, and spawns
//! it on a background Tokio task. The Drop impl signals shutdown so the
//! server task is reaped between tests.
//!
//! See the parent Story's AC and the divergence note in the ST-1 PR
//! description for why this harness uses an in-process axum server rather
//! than spawning the `aa-gateway` binary as the ticket text suggests
//! (`aa-gateway` is gRPC-only and there is currently no `aa-api` HTTP
//! binary in the workspace).
//!
//! Also re-exports [`MockLlmServer`] (see [`mock_llm`]) — the hermetic mock
//! LLM upstream that the deferred secret-detection E2E tests
//! (AAASM-1521 / AAASM-1549) use to assert what the SUT forwarded after
//! policy enforcement. Module-level docs in [`mock_llm`] cover usage.

#[allow(dead_code)]
pub mod cli;
#[allow(dead_code)]
pub mod format;
#[allow(dead_code)]
pub mod mock_llm;
#[allow(dead_code)]
pub mod scenario;
#[allow(dead_code)]
pub mod sdk_driver;

// Ergonomic re-exports — keep the public surface flat at `common::*`,
// matching how `TopologyTestEnv` is reached today. AAASM-1547 AC explicitly
// requires `common::MockLlmServer` (not `common::mock_llm::MockLlmServer`)
// be available to all integration tests.
#[allow(unused_imports)]
pub use mock_llm::{MockLlmServer, RecordedRequest};

use rust_decimal::Decimal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aa_api::alerts::store::InMemoryAlertStore;
use aa_api::auth::api_key::{ApiKey, ApiKeyEntry, ApiKeyStore};
use aa_api::auth::config::{AuthConfig, AuthMode};
use aa_api::auth::jwt::{JwtSigner, JwtVerifier};
use aa_api::auth::rate_limit::RateLimiter;
use aa_api::events::EventBroadcast;
use aa_api::ops::OpsRegistry;
use aa_api::replay::ReplayBuffer;
use aa_api::server::build_app;
use aa_api::state::AppState;
use aa_api::trace_store::{InMemoryTraceStore, TraceStore};
use aa_core::DevToolAdapter;
use aa_devtool::DiscoveryService;
use aa_gateway::budget::pricing::PricingTable;
use aa_gateway::budget::tracker::BudgetTracker;
use aa_gateway::edges::InMemoryEdgeRepo;
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::history::{FsHistoryStore, HistoryConfig};
use aa_gateway::registry::{AgentRegistry, OrphanMode};
use aa_gateway::AuditReader;
use aa_runtime::approval::ApprovalQueue;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Per-process counter for unique temp-file names.
static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// In-process integration-test environment for the topology pipeline.
pub struct TopologyTestEnv {
    /// Address the server is listening on (loopback + free port).
    pub addr: SocketAddr,
    /// Shared registry — mutate via gRPC in real tests; in ST-1 the smoke
    /// test just checks the HTTP plane.
    #[allow(dead_code)]
    pub agent_registry: Arc<AgentRegistry>,
    /// Shared trace store. Exposed so the `aasm trace` CLI integration
    /// tests (AAASM-1468 / ST-12) can seed session spans directly into
    /// the same store the HTTP route reads from — the gateway exposes
    /// no HTTP route for span ingestion, so direct insertion is the
    /// test-only equivalent (same pattern as `agent_registry`).
    #[allow(dead_code)]
    pub trace_store: Arc<dyn TraceStore>,
    /// Shared approval queue — used by `CliFixture::seed_approval` (ST-10)
    /// to submit pending requests that `aasm status` / `aasm approvals` then
    /// observe via the HTTP plane.
    #[allow(dead_code)]
    pub approval_queue: Arc<ApprovalQueue>,
    /// On-disk JSONL audit directory the harness's `AuditReader` scans.
    /// Exposed so per-leaf seed helpers (e.g. `CliFixture::seed_audit_events`)
    /// can write entries that the `aasm logs` snapshot path observes.
    pub audit_dir: PathBuf,
    /// Shared budget tracker. Exposed so the `aasm cost` CLI integration
    /// tests (AAASM-1470 / ST-14) can seed per-agent / per-team spend
    /// directly via `BudgetTracker::record_raw_spend` — the gateway exposes
    /// no HTTP route for recording cost samples, so direct insertion is
    /// the test-only equivalent (same pattern as `agent_registry` and
    /// `trace_store`). Matches the ST-0 design note that downstream cost
    /// ST adds its own seed plumbing against the resource it touches.
    #[allow(dead_code)]
    pub budget_tracker: Arc<BudgetTracker>,
    /// Concrete handle on the in-memory alert store backing the API. Held
    /// here (rather than reached through the `Arc<dyn AlertStore>` on
    /// `AppState`) so per-leaf seed helpers can call `record()` directly
    /// without trait downcasting. Populated by `cli_alerts.rs` (AAASM-1460).
    #[allow(dead_code)]
    pub alert_store: Arc<InMemoryAlertStore>,
    /// Shared API key store — same Arc the running server holds.
    /// Auth integration tests (AAASM-1485) call `key_store.revoke()` here
    /// to exercise the revocation path without restarting the server.
    #[allow(dead_code)]
    pub key_store: Arc<ApiKeyStore>,
    /// Shared event broadcast channels — same Arc the running server holds.
    /// WS integration tests (AAASM-1497 / F122 ST-P) publish events via
    /// `pipeline_sender()`, `approval_sender()`, and `budget_sender()` to
    /// drive the streaming endpoint without going through a gRPC path.
    #[allow(dead_code)]
    pub events: Arc<EventBroadcast>,
    /// Replay buffer — same instance the server holds (clone shares the
    /// internal `Arc<Mutex<VecDeque>>`). WS tests seed it directly via
    /// `push()` to test the `?since=` replay path.
    #[allow(dead_code)]
    pub replay_buffer: ReplayBuffer,
    /// Monotonically-increasing event ID counter — same Arc the server holds.
    /// Tests can read the current value or advance it to control replay ranges.
    #[allow(dead_code)]
    pub next_event_id: Arc<AtomicU64>,
    /// In-flight ops registry — same Arc the running server holds.
    /// Ops integration tests (AAASM-1525) seed ops directly via `register()`
    /// so lifecycle endpoints can be exercised without a gRPC registration path.
    #[allow(dead_code)]
    pub ops_registry: Arc<OpsRegistry>,
    /// Trigger to stop the background axum task.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Handle for the spawned axum task; awaited during teardown.
    server_handle: Option<JoinHandle<()>>,
    /// Idempotency guard for the cleanup helper — set once `cleanup()` runs
    /// successfully so an explicit cleanup + Drop don't double-tap the
    /// registry.
    cleaned: bool,
}

impl TopologyTestEnv {
    /// Spin up the harness: build the AppState, bind axum to a free port,
    /// spawn the server task, and poll `/api/v1/health` until ready.
    pub async fn start() -> anyhow::Result<Self> {
        let (state, audit_dir, alert_store, key_store) = build_test_state()?;
        let agent_registry = Arc::clone(&state.agent_registry);
        let trace_store = Arc::clone(&state.trace_store);
        let approval_queue = Arc::clone(&state.approval_queue);
        let budget_tracker = Arc::clone(&state.budget_tracker);
        let events = Arc::clone(&state.events);
        let replay_buffer = state.replay_buffer.clone();
        let next_event_id = Arc::clone(&state.next_event_id);
        let ops_registry = Arc::clone(&state.ops_registry);

        let port = portpicker::pick_unused_port().ok_or_else(|| anyhow::anyhow!("no free TCP port"))?;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;

        let app = build_app(state);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let env = Self {
            addr: bound_addr,
            agent_registry,
            trace_store,
            approval_queue,
            audit_dir,
            budget_tracker,
            alert_store,
            key_store,
            events,
            replay_buffer,
            next_event_id,
            ops_registry,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
            cleaned: false,
        };
        env.await_ready().await?;
        Ok(env)
    }

    /// Spin up the harness with authentication enabled.
    ///
    /// `entries` are pre-seeded into the `ApiKeyStore`; `rate_limit_rpm` caps
    /// per-key request rate for this environment (use a small value for the
    /// rate-limit smoke test only).
    ///
    /// **Coordination point (AAASM-1485)**: ST-R will reuse this builder.
    /// Whichever ST opens first adds it here; the other rebases.
    #[allow(dead_code)]
    pub async fn start_with_auth(entries: &[ApiKeyEntry], rate_limit_rpm: u32) -> anyhow::Result<Self> {
        let (state, audit_dir, alert_store, key_store) = build_test_state_with_auth(entries, rate_limit_rpm)?;
        let agent_registry = Arc::clone(&state.agent_registry);
        let trace_store = Arc::clone(&state.trace_store);
        let approval_queue = Arc::clone(&state.approval_queue);
        let budget_tracker = Arc::clone(&state.budget_tracker);
        let events = Arc::clone(&state.events);
        let replay_buffer = state.replay_buffer.clone();
        let next_event_id = Arc::clone(&state.next_event_id);
        let ops_registry = Arc::clone(&state.ops_registry);

        let port = portpicker::pick_unused_port().ok_or_else(|| anyhow::anyhow!("no free TCP port"))?;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;

        let app = build_app(state);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let env = Self {
            addr: bound_addr,
            agent_registry,
            trace_store,
            approval_queue,
            audit_dir,
            budget_tracker,
            alert_store,
            key_store,
            events,
            replay_buffer,
            next_event_id,
            ops_registry,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
            cleaned: false,
        };
        env.await_ready().await?;
        Ok(env)
    }

    /// Spin up the harness with auth enabled and an explicit rate-limit window.
    ///
    /// Like [`start_with_auth`] but the token-bucket window is `rate_limit_window_secs`
    /// instead of the production default of 60 s.  Pass `1` to make the refill
    /// cycle 1 second so `auth_rate_limit_resets_after_window` completes in CI
    /// without the `#[ignore]` annotation (AAASM-1527).
    #[allow(dead_code)]
    pub async fn start_with_auth_and_window(
        entries: &[ApiKeyEntry],
        rate_limit_rpm: u32,
        rate_limit_window_secs: u64,
    ) -> anyhow::Result<Self> {
        let (state, audit_dir, alert_store, key_store) =
            build_test_state_with_auth_and_window(entries, rate_limit_rpm, rate_limit_window_secs)?;
        let agent_registry = Arc::clone(&state.agent_registry);
        let trace_store = Arc::clone(&state.trace_store);
        let approval_queue = Arc::clone(&state.approval_queue);
        let budget_tracker = Arc::clone(&state.budget_tracker);
        let ops_registry = Arc::clone(&state.ops_registry);
        let events = Arc::clone(&state.events);
        let replay_buffer = state.replay_buffer.clone();
        let next_event_id = Arc::clone(&state.next_event_id);

        let port = portpicker::pick_unused_port().ok_or_else(|| anyhow::anyhow!("no free TCP port"))?;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;

        let app = build_app(state);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let env = Self {
            addr: bound_addr,
            agent_registry,
            trace_store,
            approval_queue,
            audit_dir,
            budget_tracker,
            ops_registry,
            alert_store,
            key_store,
            events,
            replay_buffer,
            next_event_id,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
            cleaned: false,
        };
        env.await_ready().await?;
        Ok(env)
    }

    /// Spin up the harness with a custom set of [`DevToolAdapter`]s injected
    /// into the [`DiscoveryService`].
    ///
    /// Used by `api_tools.rs` (AAASM-1495 / F122 ST-N) to seed stub adapters
    /// so that `GET /api/v1/tools` returns a deterministic non-empty list.
    /// The default harness wires `DiscoveryService::with_adapters(vec![])`,
    /// which returns `[]` on every CI machine; this variant overrides that.
    #[allow(dead_code)]
    pub async fn start_with_discovery(adapters: Vec<Box<dyn DevToolAdapter>>) -> anyhow::Result<Self> {
        let (mut state, audit_dir, alert_store, key_store) = build_test_state()?;
        state.discovery = Arc::new(DiscoveryService::with_adapters(adapters));
        let agent_registry = Arc::clone(&state.agent_registry);
        let trace_store = Arc::clone(&state.trace_store);
        let approval_queue = Arc::clone(&state.approval_queue);
        let budget_tracker = Arc::clone(&state.budget_tracker);
        let events = Arc::clone(&state.events);
        let replay_buffer = state.replay_buffer.clone();
        let next_event_id = Arc::clone(&state.next_event_id);
        let ops_registry = Arc::clone(&state.ops_registry);

        let port = portpicker::pick_unused_port().ok_or_else(|| anyhow::anyhow!("no free TCP port"))?;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;

        let app = build_app(state);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let env = Self {
            addr: bound_addr,
            agent_registry,
            trace_store,
            approval_queue,
            audit_dir,
            budget_tracker,
            alert_store,
            key_store,
            events,
            replay_buffer,
            next_event_id,
            ops_registry,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
            cleaned: false,
        };
        env.await_ready().await?;
        Ok(env)
    }

    /// Spin up a harness with an empty, un-named policy engine.
    ///
    /// The engine's `active_policy_info().name` is `None`, so
    /// `GET /api/v1/policies/active` returns 404. Used by the integration
    /// test that verifies the documented 404 path (AAASM-1484 test 3).
    #[allow(dead_code)]
    pub async fn start_empty_policy() -> anyhow::Result<Self> {
        let (state, audit_dir, alert_store) = build_test_state_empty_policy()?;
        let agent_registry = Arc::clone(&state.agent_registry);
        let trace_store = Arc::clone(&state.trace_store);
        let approval_queue = Arc::clone(&state.approval_queue);
        let budget_tracker = Arc::clone(&state.budget_tracker);
        let key_store = Arc::clone(&state.key_store);
        let events = Arc::clone(&state.events);
        let replay_buffer = state.replay_buffer.clone();
        let next_event_id = Arc::clone(&state.next_event_id);
        let ops_registry = Arc::clone(&state.ops_registry);

        let port = portpicker::pick_unused_port().ok_or_else(|| anyhow::anyhow!("no free TCP port"))?;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;

        let app = build_app(state);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let env = Self {
            addr: bound_addr,
            agent_registry,
            trace_store,
            approval_queue,
            audit_dir,
            budget_tracker,
            alert_store,
            key_store,
            events,
            replay_buffer,
            next_event_id,
            ops_registry,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
            cleaned: false,
        };
        env.await_ready().await?;
        Ok(env)
    }

    /// Spin up the harness with a per-team daily spend cap.
    ///
    /// `team_limit_usd` is passed to `BudgetTracker::with_team_daily_limit`;
    /// the cap applies equally to every team that records spend. Used by the
    /// budget E2E suite (AAASM-1518 / F116 ST-F).
    #[allow(dead_code)]
    pub async fn start_with_team_budget(team_limit_usd: Decimal) -> anyhow::Result<Self> {
        let (state, audit_dir, alert_store, key_store) = build_test_state_with_team_budget(team_limit_usd)?;
        let agent_registry = Arc::clone(&state.agent_registry);
        let trace_store = Arc::clone(&state.trace_store);
        let approval_queue = Arc::clone(&state.approval_queue);
        let budget_tracker = Arc::clone(&state.budget_tracker);
        let events = Arc::clone(&state.events);
        let replay_buffer = state.replay_buffer.clone();
        let next_event_id = Arc::clone(&state.next_event_id);
        let ops_registry = Arc::clone(&state.ops_registry);

        let port = portpicker::pick_unused_port().ok_or_else(|| anyhow::anyhow!("no free TCP port"))?;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;

        let app = build_app(state);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let env = Self {
            addr: bound_addr,
            agent_registry,
            trace_store,
            approval_queue,
            audit_dir,
            budget_tracker,
            alert_store,
            key_store,
            events,
            replay_buffer,
            next_event_id,
            ops_registry,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
            cleaned: false,
        };
        env.await_ready().await?;
        Ok(env)
    }

    /// Base URL for HTTP requests in tests (e.g. `http://127.0.0.1:PORT`).
    #[allow(dead_code)]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Tear down per-test state: cascade-deregister every agent under the
    /// `topology-it` team from the shared `Arc<AgentRegistry>`. Adapted
    /// from the ticket AC text (DELETE + TRUNCATE against Postgres) — see
    /// the ST-1 / ST-3 divergence notes for why registry deregistration is
    /// the in-process equivalent. Idempotent via `self.cleaned`; errors
    /// are logged but never panic so `Drop` stays safe.
    pub fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        let team_id = "topology-it";
        for agent_key in self.agent_registry.team_members(team_id) {
            if let Err(err) = self
                .agent_registry
                .deregister(&agent_key, OrphanMode::CascadeDeregister)
            {
                eprintln!(
                    "topology-it cleanup: failed to deregister agent {}: {err:?}",
                    uuid_string(&agent_key),
                );
            }
        }
        self.cleaned = true;
    }

    /// Poll `/api/v1/health` until it returns 200 or a 5 s budget is exhausted.
    async fn await_ready(&self) -> anyhow::Result<()> {
        let client = reqwest::Client::builder().timeout(Duration::from_millis(500)).build()?;
        let url = format!("http://{}/api/v1/health", self.addr);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match client.get(&url).send().await {
                Ok(resp) if resp.status() == reqwest::StatusCode::OK => return Ok(()),
                _ if Instant::now() >= deadline => {
                    return Err(anyhow::anyhow!("health endpoint never returned 200 within 5s"));
                }
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }
}

impl Drop for TopologyTestEnv {
    fn drop(&mut self) {
        // Cleanup runs unconditionally but is idempotent (guarded by
        // `self.cleaned`), so an explicit `env.cleanup()` in test code
        // doesn't double-deregister.
        self.cleanup();
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // We don't .await the JoinHandle here (Drop is sync); aborting is
        // sufficient since the graceful-shutdown signal was already sent.
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

/// Render a 16-byte agent key as the 32-char lowercase hex string used
/// across the test surface (matches `aa_api::models::topology::format_id`).
fn uuid_string(key: &[u8; 16]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a minimal `AppState` for the harness. Adapted from
/// `aa-api/tests/common/mod.rs::test_state_with_auth` to avoid pulling that
/// crate's `dev-dependencies` test helpers across crate boundaries.
///
/// Returns the populated state, the on-disk audit dir, a concrete handle on
/// the in-memory alert store, and the key store Arc so callers can mutate it
/// (e.g. call `revoke()`) after construction.
fn build_test_state() -> anyhow::Result<(AppState, PathBuf, Arc<InMemoryAlertStore>, Arc<ApiKeyStore>)> {
    let policy_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let policy_dir = std::env::temp_dir().join(format!("aa-topology-it-policy-{}-{policy_id}", std::process::id()));
    std::fs::create_dir_all(&policy_dir)?;
    let policy_path = policy_dir.join("test-policy.yaml");
    std::fs::write(
        &policy_path,
        r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: topology-it-policy
  version: "0.1.0"
spec:
  rules: []
"#,
    )?;

    let events = Arc::new(EventBroadcast::default());
    let budget_alert_tx = events.budget_sender();
    let policy_engine = Arc::new(
        PolicyEngine::load_from_file(&policy_path, budget_alert_tx)
            .map_err(|e| anyhow::anyhow!("load policy: {e:?}"))?,
    );
    let budget_tracker = Arc::new(BudgetTracker::new(
        PricingTable::default_table(),
        None,
        None,
        chrono_tz::UTC,
    ));
    let approval_queue = ApprovalQueue::new();
    let agent_registry = Arc::new(AgentRegistry::new());

    let history_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let history_dir = std::env::temp_dir().join(format!("aa-topology-it-history-{}-{history_id}", std::process::id()));
    let policy_history = Arc::new(FsHistoryStore::new(HistoryConfig {
        history_dir,
        max_versions: 50,
    }));

    let auth_config = Arc::new(AuthConfig {
        mode: AuthMode::Off,
        jwt_secret: None,
        api_keys_path: std::path::PathBuf::from("/dev/null"),
        rate_limit_rpm: 1000,
    });
    let key_store = Arc::new(
        ApiKeyStore::load(Path::new("/dev/null"))
            .unwrap_or_else(|_| ApiKeyStore::load(Path::new("/nonexistent")).expect("empty key store")),
    );
    let key_store_handle = Arc::clone(&key_store);
    const TEST_SECRET: &[u8] = b"topology-it-test-secret-32-bytes-long-padding";
    let jwt_signer = Arc::new(JwtSigner::new(TEST_SECRET));
    let jwt_verifier = Arc::new(JwtVerifier::new(TEST_SECRET));
    let rate_limiter = Arc::new(RateLimiter::new(1000));
    let alert_store: Arc<InMemoryAlertStore> = Arc::new(InMemoryAlertStore::new());
    let alert_store_handle = Arc::clone(&alert_store);

    let audit_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let audit_dir = std::env::temp_dir().join(format!("aa-topology-it-audit-{}-{audit_id}", std::process::id()));
    std::fs::create_dir_all(&audit_dir)?;
    let audit_reader = Arc::new(AuditReader::new(audit_dir.clone()));

    Ok((
        AppState {
            agent_registry,
            policy_engine,
            budget_tracker,
            approval_queue,
            policy_history,
            alert_store,
            events,
            replay_buffer: ReplayBuffer::new(),
            next_event_id: Arc::new(AtomicU64::new(0)),
            auth_config,
            key_store,
            rate_limiter,
            jwt_signer,
            jwt_verifier,
            trace_store: Arc::new(InMemoryTraceStore::new()),
            audit_reader,
            startup_time: Instant::now(),
            active_connections: Arc::new(AtomicI64::new(0)),
            discovery: Arc::new(DiscoveryService::with_adapters(vec![])),
            edge_repo: Arc::new(InMemoryEdgeRepo::new()),
            topology_overview_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(1))
                .build(),
            topology_tree_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_team_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_lineage_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_stats_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(10))
                .build(),
            capability_store: aa_api::routes::capability::CapabilityStore::new_seeded(),
            iam_api_key_store: aa_api::routes::iam::seeded_iam_store(),
            ops_registry: Arc::new(OpsRegistry::new()),
        },
        audit_dir,
        alert_store_handle,
        key_store_handle,
    ))
}

/// JWT secret used by `start_with_auth` — exposed so tests can decode tokens.
pub const AUTH_IT_JWT_SECRET: &[u8] = b"auth-it-test-secret-32-bytes-long!!";

/// Build a minimal `AppState` with authentication enabled and pre-seeded API keys.
///
/// Used by `TopologyTestEnv::start_with_auth` (AAASM-1485 / F122 ST-D).
fn build_test_state_with_auth(
    entries: &[ApiKeyEntry],
    rate_limit_rpm: u32,
) -> anyhow::Result<(AppState, PathBuf, Arc<InMemoryAlertStore>, Arc<ApiKeyStore>)> {
    let policy_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let policy_dir = std::env::temp_dir().join(format!("aa-auth-it-policy-{}-{policy_id}", std::process::id()));
    std::fs::create_dir_all(&policy_dir)?;
    let policy_path = policy_dir.join("test-policy.yaml");
    std::fs::write(
        &policy_path,
        r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: auth-it-policy
  version: "0.1.0"
spec:
  rules: []
"#,
    )?;

    let events = Arc::new(EventBroadcast::default());
    let budget_alert_tx = events.budget_sender();
    let policy_engine = Arc::new(
        PolicyEngine::load_from_file(&policy_path, budget_alert_tx)
            .map_err(|e| anyhow::anyhow!("load policy: {e:?}"))?,
    );
    let budget_tracker = Arc::new(BudgetTracker::new(
        PricingTable::default_table(),
        None,
        None,
        chrono_tz::UTC,
    ));
    let approval_queue = ApprovalQueue::new();
    let agent_registry = Arc::new(AgentRegistry::new());

    let history_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let history_dir = std::env::temp_dir().join(format!("aa-auth-it-history-{}-{history_id}", std::process::id()));
    let policy_history = Arc::new(FsHistoryStore::new(HistoryConfig {
        history_dir,
        max_versions: 50,
    }));

    let auth_config = Arc::new(AuthConfig {
        mode: AuthMode::On,
        jwt_secret: Some(AUTH_IT_JWT_SECRET.to_vec()),
        api_keys_path: std::path::PathBuf::from("/dev/null"),
        rate_limit_rpm,
    });

    let key_store = if entries.is_empty() {
        Arc::new(
            ApiKeyStore::load(Path::new("/dev/null"))
                .unwrap_or_else(|_| ApiKeyStore::load(Path::new("/nonexistent")).expect("empty key store")),
        )
    } else {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!("aa-auth-it-keys-{}-{id}.json", std::process::id()));
        let json = serde_json::to_string(entries).unwrap();
        std::fs::write(&tmp, &json).unwrap();
        Arc::new(ApiKeyStore::load(&tmp).unwrap())
    };
    let key_store_handle = Arc::clone(&key_store);

    let jwt_signer = Arc::new(JwtSigner::new(AUTH_IT_JWT_SECRET));
    let jwt_verifier = Arc::new(JwtVerifier::new(AUTH_IT_JWT_SECRET));
    let rate_limiter = Arc::new(RateLimiter::new(rate_limit_rpm));
    let alert_store: Arc<InMemoryAlertStore> = Arc::new(InMemoryAlertStore::new());
    let alert_store_handle = Arc::clone(&alert_store);

    let audit_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let audit_dir = std::env::temp_dir().join(format!("aa-auth-it-audit-{}-{audit_id}", std::process::id()));
    std::fs::create_dir_all(&audit_dir)?;
    let audit_reader = Arc::new(AuditReader::new(audit_dir.clone()));

    Ok((
        AppState {
            agent_registry,
            policy_engine,
            budget_tracker,
            approval_queue,
            policy_history,
            alert_store,
            events,
            replay_buffer: ReplayBuffer::new(),
            next_event_id: Arc::new(AtomicU64::new(0)),
            auth_config,
            key_store,
            rate_limiter,
            jwt_signer,
            jwt_verifier,
            trace_store: Arc::new(InMemoryTraceStore::new()),
            audit_reader,
            startup_time: Instant::now(),
            active_connections: Arc::new(AtomicI64::new(0)),
            discovery: Arc::new(DiscoveryService::with_adapters(vec![])),
            edge_repo: Arc::new(InMemoryEdgeRepo::new()),
            topology_overview_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(1))
                .build(),
            topology_tree_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_team_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_lineage_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_stats_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(10))
                .build(),
            capability_store: aa_api::routes::capability::CapabilityStore::new_seeded(),
            iam_api_key_store: aa_api::routes::iam::seeded_iam_store(),
            ops_registry: Arc::new(OpsRegistry::new()),
        },
        audit_dir,
        alert_store_handle,
        key_store_handle,
    ))
}

/// Build a minimal `AppState` with auth enabled and a short rate-limit window.
///
/// Identical to [`build_test_state_with_auth`] except the `RateLimiter` is
/// created with an explicit `rate_limit_window_secs` instead of the
/// production default of 60 s.  Used by
/// [`TopologyTestEnv::start_with_auth_and_window`] (AAASM-1527).
fn build_test_state_with_auth_and_window(
    entries: &[ApiKeyEntry],
    rate_limit_rpm: u32,
    rate_limit_window_secs: u64,
) -> anyhow::Result<(AppState, PathBuf, Arc<InMemoryAlertStore>, Arc<ApiKeyStore>)> {
    let policy_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let policy_dir = std::env::temp_dir().join(format!("aa-auth-it-policy-{}-{policy_id}", std::process::id()));
    std::fs::create_dir_all(&policy_dir)?;
    let policy_path = policy_dir.join("test-policy.yaml");
    std::fs::write(
        &policy_path,
        r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: auth-it-policy
  version: "0.1.0"
spec:
  rules: []
"#,
    )?;

    let events = Arc::new(EventBroadcast::default());
    let budget_alert_tx = events.budget_sender();
    let policy_engine = Arc::new(
        PolicyEngine::load_from_file(&policy_path, budget_alert_tx)
            .map_err(|e| anyhow::anyhow!("load policy: {e:?}"))?,
    );
    let budget_tracker = Arc::new(BudgetTracker::new(
        PricingTable::default_table(),
        None,
        None,
        chrono_tz::UTC,
    ));
    let approval_queue = ApprovalQueue::new();
    let agent_registry = Arc::new(AgentRegistry::new());

    let history_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let history_dir = std::env::temp_dir().join(format!("aa-auth-it-history-{}-{history_id}", std::process::id()));
    let policy_history = Arc::new(FsHistoryStore::new(HistoryConfig {
        history_dir,
        max_versions: 50,
    }));

    let auth_config = Arc::new(AuthConfig {
        mode: AuthMode::On,
        jwt_secret: Some(AUTH_IT_JWT_SECRET.to_vec()),
        api_keys_path: std::path::PathBuf::from("/dev/null"),
        rate_limit_rpm,
    });

    let key_store = if entries.is_empty() {
        Arc::new(
            ApiKeyStore::load(Path::new("/dev/null"))
                .unwrap_or_else(|_| ApiKeyStore::load(Path::new("/nonexistent")).expect("empty key store")),
        )
    } else {
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!("aa-auth-it-keys-{}-{id}.json", std::process::id()));
        let json = serde_json::to_string(entries).unwrap();
        std::fs::write(&tmp, &json).unwrap();
        Arc::new(ApiKeyStore::load(&tmp).unwrap())
    };
    let key_store_handle = Arc::clone(&key_store);

    let jwt_signer = Arc::new(JwtSigner::new(AUTH_IT_JWT_SECRET));
    let jwt_verifier = Arc::new(JwtVerifier::new(AUTH_IT_JWT_SECRET));
    let rate_limiter = Arc::new(RateLimiter::new_with_window(rate_limit_rpm, rate_limit_window_secs));
    let alert_store: Arc<InMemoryAlertStore> = Arc::new(InMemoryAlertStore::new());
    let alert_store_handle = Arc::clone(&alert_store);

    let audit_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let audit_dir = std::env::temp_dir().join(format!("aa-auth-it-audit-{}-{audit_id}", std::process::id()));
    std::fs::create_dir_all(&audit_dir)?;
    let audit_reader = Arc::new(AuditReader::new(audit_dir.clone()));

    Ok((
        AppState {
            agent_registry,
            policy_engine,
            budget_tracker,
            approval_queue,
            policy_history,
            alert_store,
            events,
            replay_buffer: ReplayBuffer::new(),
            next_event_id: Arc::new(AtomicU64::new(0)),
            auth_config,
            key_store,
            rate_limiter,
            jwt_signer,
            jwt_verifier,
            trace_store: Arc::new(InMemoryTraceStore::new()),
            audit_reader,
            startup_time: Instant::now(),
            active_connections: Arc::new(AtomicI64::new(0)),
            discovery: Arc::new(DiscoveryService::with_adapters(vec![])),
            edge_repo: Arc::new(InMemoryEdgeRepo::new()),
            topology_overview_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(1))
                .build(),
            topology_tree_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_team_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_lineage_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_stats_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(10))
                .build(),
            capability_store: aa_api::routes::capability::CapabilityStore::new_seeded(),
            iam_api_key_store: aa_api::routes::iam::seeded_iam_store(),
            ops_registry: Arc::new(OpsRegistry::new()),
        },
        audit_dir,
        alert_store_handle,
        key_store_handle,
    ))
}

/// Build a minimal `AppState` with a per-team daily spend limit applied to the
/// `BudgetTracker`. Identical to [`build_test_state`] except the tracker is
/// constructed with `.with_team_daily_limit(team_limit_usd)`.
///
/// Used by [`TopologyTestEnv::start_with_team_budget`] (AAASM-1518 / F116 ST-F).
fn build_test_state_with_team_budget(
    team_limit_usd: Decimal,
) -> anyhow::Result<(AppState, PathBuf, Arc<InMemoryAlertStore>, Arc<ApiKeyStore>)> {
    let policy_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let policy_dir = std::env::temp_dir().join(format!("aa-budget-it-policy-{}-{policy_id}", std::process::id()));
    std::fs::create_dir_all(&policy_dir)?;
    let policy_path = policy_dir.join("test-policy.yaml");
    std::fs::write(
        &policy_path,
        r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: budget-it-policy
  version: "0.1.0"
spec:
  rules: []
"#,
    )?;

    let events = Arc::new(EventBroadcast::default());
    let budget_alert_tx = events.budget_sender();
    let policy_engine = Arc::new(
        PolicyEngine::load_from_file(&policy_path, budget_alert_tx)
            .map_err(|e| anyhow::anyhow!("load policy: {e:?}"))?,
    );
    let budget_tracker = Arc::new(
        BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC)
            .with_team_daily_limit(team_limit_usd),
    );
    let approval_queue = ApprovalQueue::new();
    let agent_registry = Arc::new(AgentRegistry::new());

    let history_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let history_dir = std::env::temp_dir().join(format!("aa-budget-it-history-{}-{history_id}", std::process::id()));
    let policy_history = Arc::new(FsHistoryStore::new(HistoryConfig {
        history_dir,
        max_versions: 50,
    }));

    let auth_config = Arc::new(AuthConfig {
        mode: AuthMode::Off,
        jwt_secret: None,
        api_keys_path: std::path::PathBuf::from("/dev/null"),
        rate_limit_rpm: 1000,
    });
    let key_store = Arc::new(
        ApiKeyStore::load(Path::new("/dev/null"))
            .unwrap_or_else(|_| ApiKeyStore::load(Path::new("/nonexistent")).expect("empty key store")),
    );
    let key_store_handle = Arc::clone(&key_store);
    const TEST_SECRET: &[u8] = b"budget-it-test-secret-32-bytes-long!!!!";
    let jwt_signer = Arc::new(JwtSigner::new(TEST_SECRET));
    let jwt_verifier = Arc::new(JwtVerifier::new(TEST_SECRET));
    let rate_limiter = Arc::new(RateLimiter::new(1000));
    let alert_store: Arc<InMemoryAlertStore> = Arc::new(InMemoryAlertStore::new());
    let alert_store_handle = Arc::clone(&alert_store);

    let audit_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let audit_dir = std::env::temp_dir().join(format!("aa-budget-it-audit-{}-{audit_id}", std::process::id()));
    std::fs::create_dir_all(&audit_dir)?;
    let audit_reader = Arc::new(AuditReader::new(audit_dir.clone()));

    Ok((
        AppState {
            agent_registry,
            policy_engine,
            budget_tracker,
            approval_queue,
            policy_history,
            alert_store,
            events,
            replay_buffer: ReplayBuffer::new(),
            next_event_id: Arc::new(AtomicU64::new(0)),
            auth_config,
            key_store,
            rate_limiter,
            jwt_signer,
            jwt_verifier,
            trace_store: Arc::new(InMemoryTraceStore::new()),
            audit_reader,
            startup_time: Instant::now(),
            active_connections: Arc::new(AtomicI64::new(0)),
            discovery: Arc::new(DiscoveryService::with_adapters(vec![])),
            edge_repo: Arc::new(InMemoryEdgeRepo::new()),
            topology_overview_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(1))
                .build(),
            topology_tree_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_team_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_lineage_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_stats_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(10))
                .build(),
            capability_store: aa_api::routes::capability::CapabilityStore::new_seeded(),
            iam_api_key_store: aa_api::routes::iam::seeded_iam_store(),
            ops_registry: Arc::new(OpsRegistry::new()),
        },
        audit_dir,
        alert_store_handle,
        key_store_handle,
    ))
}

/// Generate a test API key, returning (plaintext, `ApiKeyEntry`).
///
/// The entry can be passed to `TopologyTestEnv::start_with_auth`.
pub fn make_api_key(id: &str, scopes: Vec<aa_api::auth::scope::Scope>) -> (String, ApiKeyEntry) {
    let key = ApiKey::generate();
    let hash = key.hash().expect("hashing should succeed");
    let entry = ApiKeyEntry {
        id: id.to_string(),
        key_hash: hash,
        scopes,
        created_at: 1_700_000_000,
        label: Some(format!("test key {id}")),
    };
    (key.as_str().to_string(), entry)
}

/// Build an `AppState` where the `PolicyEngine` carries no named policy.
///
/// `active_policy_info().name` is `None`, so `GET /api/v1/policies/active`
/// returns 404. Used by `TopologyTestEnv::start_empty_policy()`.
fn build_test_state_empty_policy() -> anyhow::Result<(AppState, PathBuf, Arc<InMemoryAlertStore>)> {
    let events = Arc::new(EventBroadcast::default());
    let policy_engine = Arc::new(aa_gateway::engine::PolicyEngine::for_testing());
    let budget_tracker = Arc::new(BudgetTracker::new(
        PricingTable::default_table(),
        None,
        None,
        chrono_tz::UTC,
    ));
    let approval_queue = ApprovalQueue::new();
    let agent_registry = Arc::new(AgentRegistry::new());

    let history_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let history_dir = std::env::temp_dir().join(format!(
        "aa-topology-it-empty-history-{}-{history_id}",
        std::process::id()
    ));
    let policy_history = Arc::new(FsHistoryStore::new(HistoryConfig {
        history_dir,
        max_versions: 50,
    }));

    let auth_config = Arc::new(AuthConfig {
        mode: AuthMode::Off,
        jwt_secret: None,
        api_keys_path: std::path::PathBuf::from("/dev/null"),
        rate_limit_rpm: 1000,
    });
    let key_store = Arc::new(
        ApiKeyStore::load(std::path::Path::new("/dev/null"))
            .unwrap_or_else(|_| ApiKeyStore::load(std::path::Path::new("/nonexistent")).expect("empty key store")),
    );
    const TEST_SECRET: &[u8] = b"topology-it-test-secret-32-bytes-long-padding";
    let jwt_signer = Arc::new(JwtSigner::new(TEST_SECRET));
    let jwt_verifier = Arc::new(JwtVerifier::new(TEST_SECRET));
    let rate_limiter = Arc::new(RateLimiter::new(1000));
    let alert_store: Arc<InMemoryAlertStore> = Arc::new(InMemoryAlertStore::new());
    let alert_store_handle = Arc::clone(&alert_store);

    let audit_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let audit_dir = std::env::temp_dir().join(format!("aa-topology-it-empty-audit-{}-{audit_id}", std::process::id()));
    std::fs::create_dir_all(&audit_dir)?;
    let audit_reader = Arc::new(AuditReader::new(audit_dir.clone()));

    Ok((
        AppState {
            agent_registry,
            policy_engine,
            budget_tracker,
            approval_queue,
            policy_history,
            alert_store,
            events,
            replay_buffer: ReplayBuffer::new(),
            next_event_id: Arc::new(AtomicU64::new(0)),
            auth_config,
            key_store,
            rate_limiter,
            jwt_signer,
            jwt_verifier,
            trace_store: Arc::new(InMemoryTraceStore::new()),
            audit_reader,
            startup_time: Instant::now(),
            active_connections: Arc::new(AtomicI64::new(0)),
            discovery: Arc::new(DiscoveryService::with_adapters(vec![])),
            edge_repo: Arc::new(InMemoryEdgeRepo::new()),
            topology_overview_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(1))
                .build(),
            topology_tree_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_team_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_lineage_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(5))
                .build(),
            topology_stats_cache: moka::future::Cache::builder()
                .time_to_live(Duration::from_secs(10))
                .build(),
            capability_store: aa_api::routes::capability::CapabilityStore::new_seeded(),
            iam_api_key_store: aa_api::routes::iam::seeded_iam_store(),
            ops_registry: Arc::new(OpsRegistry::new()),
        },
        audit_dir,
        alert_store_handle,
    ))
}
