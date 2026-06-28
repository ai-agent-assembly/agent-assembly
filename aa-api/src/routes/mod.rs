//! Route definitions for the REST API.
//!
//! All endpoints are nested under `/api/v1/`.

pub mod admin;
pub mod agents;
pub mod alert_rules;
pub mod alerts;
pub mod approvals;
pub mod audit;
pub mod auth;
pub mod capability;
pub mod costs;
pub mod destinations;
pub mod devtools;
pub mod dispatch;
pub mod edges;
pub mod health;
pub mod iam;
pub mod logs;
pub mod ops;
pub mod policies;
pub mod tools;
pub mod topology;
pub mod traces;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::error::ProblemDetail;

/// Build the v1 API router with all registered routes.
///
/// The router is split into two layers (AAASM-3125):
///
/// * [`public_router`] — endpoints that are reachable without a bearer
///   credential: liveness, the token-issue endpoint (it authenticates the
///   caller itself), the WebSocket upgrade handlers, and the SaaS webhook
///   (HMAC-authenticated in-handler).
/// * [`protected_router`] — everything else, gated by the deny-by-default
///   [`require_authentication`] middleware. A newly-added route is
///   authenticated unless it is deliberately mounted on the public router.
///
/// [`require_authentication`]: crate::auth::gate::require_authentication
pub fn v1_router() -> Router {
    public_router().merge(protected_router())
}

/// Build the router of endpoints reachable without a bearer credential.
///
/// These either need to be reachable to obtain a credential (`/auth/token`),
/// are unauthenticated liveness probes (`/health`), authenticate themselves
/// out of band (`/devtools/saas/{provider}/events` via HMAC), or perform
/// their auth handshake during the WebSocket upgrade.
fn public_router() -> Router {
    Router::new()
        // Health
        .route("/health", get(health::health))
        // WebSocket
        .route("/ws/events", get(crate::ws::handler::ws_events_handler))
        // Auth
        .route("/auth/token", post(auth::issue_token))
        // AAASM-1389: real-time alert event stream.
        .route("/alerts/ws", get(crate::ws::alerts_handler::ws_alerts_handler))
        // Dev tool webhooks — HMAC-authenticated in-handler.
        .route("/devtools/saas/{provider}/events", post(devtools::saas_webhook))
}

/// Build the router of endpoints that require an authenticated caller.
///
/// The whole router is wrapped in the [`require_authentication`] gate via
/// `route_layer`, so every handler runs only after a valid API key / JWT has
/// been verified (or `AuthMode::Off` bypasses it). Per-handler scope and
/// tenant checks remain the handler's responsibility.
///
/// [`require_authentication`]: crate::auth::gate::require_authentication
fn protected_router() -> Router {
    Router::new()
        // Secret Injection — tool dispatch (AAASM-1920)
        .route("/dispatch_tool", post(dispatch::dispatch_tool))
        // Agents
        .route("/agents", get(agents::list_agents))
        .route("/agents/{id}", get(agents::get_agent).delete(agents::delete_agent))
        .route("/agents/{id}/suspend", post(agents::suspend_agent))
        .route("/agents/{id}/resume", post(agents::resume_agent))
        .route("/agents/{id}/capabilities", get(agents::get_agent_capabilities))
        .route("/agents/{id}/budget", get(agents::get_agent_budget))
        .route("/agents/{id}/subtree-burn", get(agents::get_agent_subtree_burn))
        // Logs
        .route("/logs", get(logs::list_logs))
        // Traces
        .route("/traces/{session_id}", get(traces::get_trace))
        // Policies
        .route("/policies", get(policies::list_policies).post(policies::create_policy))
        .route("/policies/active", get(policies::get_active_policy))
        // Approvals
        .route("/approvals", get(approvals::list_approvals))
        .route("/approvals/{id}", get(approvals::get_approval))
        .route("/approvals/{id}/approve", post(approvals::approve_action))
        .route("/approvals/{id}/reject", post(approvals::reject_action))
        // Costs
        .route("/costs", get(costs::get_cost_summary))
        // Capability matrix (dashboard) — AAASM-1366
        .route("/capability/matrix", get(capability::get_matrix))
        .route("/capability/override", get(capability::list_overrides).post(capability::apply_override))
        .route("/capability/override/{id}", delete(capability::revoke_override))
        // Identity & Access — API key management (dashboard) — AAASM-1397
        .route("/iam/api-keys", get(iam::list_api_keys).post(iam::generate_api_key))
        .route("/iam/api-keys/{id}/revoke", post(iam::revoke_api_key))
        .route("/iam/api-keys/{id}/rotate", post(iam::rotate_api_key))
        // Alerts
        .route("/alerts", get(alerts::list_alerts))
        // AAASM-1648: silence-an-alert endpoint. Literal "silence" path
        // segment must come BEFORE /alerts/{id} so it isn't captured
        // as an id.
        .route("/alerts/silence", post(alerts::silence_alert))
        // Alert-rule CRUD (AAASM-1386). Literal "rules" segment must
        // also come BEFORE /alerts/{id} so it isn't captured as an id.
        .route(
            "/alerts/rules",
            get(alert_rules::list_rules).post(alert_rules::create_rule),
        )
        .route(
            "/alerts/rules/{id}",
            get(alert_rules::get_rule)
                .put(alert_rules::update_rule)
                .delete(alert_rules::delete_rule),
        )
        .route("/alerts/{id}", get(alerts::get_alert))
        .route("/alerts/{id}/resolve", post(alerts::resolve_alert))
        // Alert destinations — AAASM-1388
        .route(
            "/alerts/destinations",
            get(destinations::list_destinations).post(destinations::create_destination),
        )
        .route(
            "/alerts/destinations/{id}",
            get(destinations::get_destination)
                .put(destinations::update_destination)
                .delete(destinations::delete_destination),
        )
        .route("/alerts/destinations/{id}/test", post(destinations::test_destination))
        // Tools
        .route("/tools", get(tools::list_tools))
        // Topology
        .route("/topology/overview", get(topology::get_overview))
        .route("/topology/tree/{root_id}", get(topology::get_tree))
        .route("/topology/team/{team_id}", get(topology::get_team))
        .route("/topology/lineage/{agent_id}", get(topology::get_lineage))
        .route("/topology/stats", get(topology::get_stats))
        // Edges (mesh topology edge store)
        .route("/topology/edges", post(edges::report_edge).get(edges::list_topology_edges))
        .route("/agents/{id}/edges", get(edges::list_agent_edges))
        .route("/agents/{id}/graph", get(edges::get_agent_graph))
        // Per-op lifecycle registry (AAASM-1525)
        .route("/ops", get(ops::list_ops).post(ops::register_op))
        .route("/ops/{id}/pause", post(ops::pause_op))
        .route("/ops/{id}/resume", post(ops::resume_op))
        .route("/ops/{id}/terminate", post(ops::terminate_op))
        // Operator kill-switch under reserved op-ids (AAASM-3881 / AAASM-3873)
        .route("/ops/{id}/halt-agent", post(ops::halt_agent_for_op))
        .route("/ops/global/halt", post(ops::halt_global))
        // Audit aggregations
        .route("/audit/violations-by-lineage", get(audit::get_violations_by_lineage))
        // Sandbox / observe-mode aggregate for SandboxSummaryCard — AAASM-1911
        .route("/audit/sandbox-summary", get(audit::get_sandbox_summary))
        // Admin — retention policy (AAASM-1592 S-K)
        .route(
            "/admin/retention-policy",
            get(admin::get_retention_policy).put(admin::update_retention_policy),
        )
        .route("/admin/retention-policy/run", post(admin::run_retention_policy))
        // Deny-by-default auth gate over every protected route (AAASM-3125).
        .route_layer(axum::middleware::from_fn(crate::auth::gate::require_authentication))
}

/// Fallback handler returning a 404 RFC 7807 response.
pub async fn fallback_404(uri: axum::http::Uri) -> ProblemDetail {
    ProblemDetail::from_status(axum::http::StatusCode::NOT_FOUND)
        .with_detail(format!("No route matched: {uri}"))
        .with_instance(uri.to_string())
}
