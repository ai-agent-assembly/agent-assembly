//! Shared test utilities for aa-api integration tests.

use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize};
use std::sync::Arc;
use std::time::Instant;

use aa_api::alerts::store::InMemoryAlertStore;
use aa_api::auth::api_key::{ApiKey, ApiKeyEntry, ApiKeyStore};
use aa_api::auth::config::{AuthConfig, AuthMode};
use aa_api::auth::jwt::{JwtSigner, JwtVerifier};
use aa_api::auth::rate_limit::RateLimiter;
use aa_api::auth::scope::Scope;
use aa_api::events::EventBroadcast;
use aa_api::replay::ReplayBuffer;
use aa_api::server::build_app;
use aa_api::state::AppState;
use aa_api::trace_store::InMemoryTraceStore;
use aa_devtool::DiscoveryService;
use aa_gateway::budget::pricing::PricingTable;
use aa_gateway::budget::tracker::BudgetTracker;
use aa_gateway::edges::InMemoryEdgeRepo;
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::history::{FsHistoryStore, HistoryConfig};
use aa_gateway::registry::AgentRegistry;
use aa_gateway::AuditReader;
use aa_runtime::approval::ApprovalQueue;
use axum::Router;

/// Default JWT test secret (>= 32 bytes).
const TEST_SECRET: &[u8] = b"test-secret-key-that-is-at-least-32-bytes-long!!";

/// Counter for generating unique temp file names across concurrent tests.
static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Build a minimal `AppState` for gateway/non-auth tests (auth disabled).
#[allow(dead_code)]
pub fn test_state() -> AppState {
    test_state_with_auth(AuthMode::Off, &[], 1000)
}

/// Build an `AppState` with auth enabled and the given API key entries.
#[allow(dead_code)]
pub fn test_state_with_auth(mode: AuthMode, entries: &[ApiKeyEntry], rpm: u32) -> AppState {
    // PolicyEngine requires a policy file; use a minimal valid policy.
    let policy_id = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let policy_dir = std::env::temp_dir().join(format!("aa-api-test-policy-{}-{policy_id}", std::process::id()));
    std::fs::create_dir_all(&policy_dir).unwrap();
    let policy_path = policy_dir.join("test-policy.yaml");
    std::fs::write(
        &policy_path,
        r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: test-policy
  version: "0.1.0"
spec:
  rules: []
"#,
    )
    .unwrap();

    let events = Arc::new(EventBroadcast::default());
    let budget_alert_tx = events.budget_sender();
    let policy_engine = Arc::new(PolicyEngine::load_from_file(&policy_path, budget_alert_tx).unwrap());
    let budget_tracker = Arc::new(BudgetTracker::new(
        PricingTable::default_table(),
        None,
        None,
        chrono_tz::UTC,
    ));
    let approval_queue = ApprovalQueue::new();

    let agent_registry = Arc::new(AgentRegistry::new());

    let history_id = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let history_dir = std::env::temp_dir().join(format!("aa-api-test-history-{}-{history_id}", std::process::id()));
    let policy_history = Arc::new(FsHistoryStore::new(HistoryConfig {
        history_dir,
        max_versions: 50,
    }));

    let jwt_secret = match mode {
        AuthMode::On => Some(TEST_SECRET.to_vec()),
        AuthMode::Off => None,
    };

    let auth_config = Arc::new(AuthConfig {
        mode,
        jwt_secret: jwt_secret.clone(),
        api_keys_path: std::path::PathBuf::from("/dev/null"),
        rate_limit_rpm: rpm,
    });

    let key_store = Arc::new(ApiKeyStore::load(Path::new("/dev/null")).unwrap_or_else(|_| {
        // Fallback: construct empty store
        ApiKeyStore::load(Path::new("/nonexistent")).unwrap()
    }));

    // For tests with pre-loaded keys, we need to build the store differently.
    // We'll use a temp file approach.
    let key_store = if entries.is_empty() {
        key_store
    } else {
        let id = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!("aa-api-test-keys-{}-{id}.json", std::process::id()));
        let json = serde_json::to_string(entries).unwrap();
        std::fs::write(&tmp, &json).unwrap();
        Arc::new(ApiKeyStore::load(&tmp).unwrap())
    };

    let secret = jwt_secret.as_deref().unwrap_or(TEST_SECRET);
    let jwt_signer = Arc::new(JwtSigner::new(secret));
    let jwt_verifier = Arc::new(JwtVerifier::new(secret));
    let rate_limiter = Arc::new(RateLimiter::new(rpm));
    let alert_store: Arc<InMemoryAlertStore> = Arc::new(InMemoryAlertStore::new());

    let audit_id = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let audit_dir = std::env::temp_dir().join(format!("aa-api-test-audit-{}-{audit_id}", std::process::id()));
    std::fs::create_dir_all(&audit_dir).unwrap();
    let audit_reader = Arc::new(AuditReader::new(audit_dir));

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
    }
}

/// Build the full app for testing (router + middleware + state, auth disabled).
#[allow(dead_code)]
pub fn test_app() -> Router {
    build_app(test_state())
}

/// Build the full app with auth enabled and the given API key entries.
#[allow(dead_code)]
pub fn test_app_with_auth(entries: &[ApiKeyEntry], rpm: u32) -> Router {
    build_app(test_state_with_auth(AuthMode::On, entries, rpm))
}

/// Build the full app with auth disabled (bypass mode).
#[allow(dead_code)]
pub fn test_app_no_auth() -> Router {
    build_app(test_state_with_auth(AuthMode::Off, &[], 1000))
}

/// Generate a test API key and return (plaintext, ApiKeyEntry).
#[allow(dead_code)]
pub fn generate_test_api_key(id: &str, scopes: Vec<Scope>) -> (String, ApiKeyEntry) {
    let key = ApiKey::generate();
    let hash = key.hash().expect("hashing should succeed");
    let entry = ApiKeyEntry {
        id: id.to_string(),
        key_hash: hash,
        scopes,
        created_at: 1700000000,
        label: Some(format!("test key {id}")),
    };
    (key.as_str().to_string(), entry)
}

/// Generate a test JWT token for the given key ID and scopes.
#[allow(dead_code)]
pub fn generate_test_jwt(key_id: &str, scopes: &[Scope]) -> String {
    let signer = JwtSigner::new(TEST_SECRET);
    signer.sign(key_id, scopes).expect("signing should succeed")
}
