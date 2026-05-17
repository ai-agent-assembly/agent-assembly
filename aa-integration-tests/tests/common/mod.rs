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

#[allow(dead_code)]
pub mod cli;
#[allow(dead_code)]
pub mod format;
#[allow(dead_code)]
pub mod scenario;
#[allow(dead_code)]
pub mod sdk_driver;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aa_api::alerts::store::InMemoryAlertStore;
use aa_api::auth::api_key::ApiKeyStore;
use aa_api::auth::config::{AuthConfig, AuthMode};
use aa_api::auth::jwt::{JwtSigner, JwtVerifier};
use aa_api::auth::rate_limit::RateLimiter;
use aa_api::events::EventBroadcast;
use aa_api::replay::ReplayBuffer;
use aa_api::server::build_app;
use aa_api::state::AppState;
use aa_api::trace_store::{InMemoryTraceStore, TraceStore};
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
        let state = build_test_state()?;
        let agent_registry = Arc::clone(&state.agent_registry);
        let trace_store = Arc::clone(&state.trace_store);

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
fn build_test_state() -> anyhow::Result<AppState> {
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
    const TEST_SECRET: &[u8] = b"topology-it-test-secret-32-bytes-long-padding";
    let jwt_signer = Arc::new(JwtSigner::new(TEST_SECRET));
    let jwt_verifier = Arc::new(JwtVerifier::new(TEST_SECRET));
    let rate_limiter = Arc::new(RateLimiter::new(1000));
    let alert_store: Arc<InMemoryAlertStore> = Arc::new(InMemoryAlertStore::new());

    let audit_id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let audit_dir = std::env::temp_dir().join(format!("aa-topology-it-audit-{}-{audit_id}", std::process::id()));
    std::fs::create_dir_all(&audit_dir)?;
    let audit_reader = Arc::new(AuditReader::new(audit_dir));

    Ok(AppState {
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
    })
}
