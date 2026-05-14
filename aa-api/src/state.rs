//! Shared application state for the Axum server.

use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

use aa_devtool::DiscoveryService;

use aa_core::topology::EdgeRepo;
use aa_gateway::budget::tracker::BudgetTracker;
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::history::PolicyHistoryStore;
use aa_gateway::registry::AgentRegistry;
use aa_gateway::AuditReader;
use aa_runtime::approval::ApprovalQueue;

use crate::alerts::AlertStore;
use crate::auth::api_key::ApiKeyStore;
use crate::auth::config::AuthConfig;
use crate::auth::jwt::{JwtSigner, JwtVerifier};
use crate::auth::rate_limit::RateLimiter;
use crate::events::EventBroadcast;
use crate::models::topology::{AgentLineage, AgentTree, TeamTopology, TopologyOverview, TopologyStats};
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
}
