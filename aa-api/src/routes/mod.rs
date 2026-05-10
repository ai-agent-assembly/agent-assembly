//! Route definitions for the REST API.
//!
//! All endpoints are nested under `/api/v1/`.

pub mod agents;
pub mod alerts;
pub mod approvals;
pub mod auth;
pub mod costs;
pub mod devtools;
pub mod edges;
pub mod health;
pub mod logs;
pub mod policies;
pub mod tools;
pub mod topology;
pub mod traces;

use axum::routing::{get, post};
use axum::Router;

use crate::error::ProblemDetail;

/// Build the v1 API router with all registered routes.
pub fn v1_router() -> Router {
    Router::new()
        // Health
        .route("/health", get(health::health))
        // WebSocket
        .route("/ws/events", get(crate::ws::handler::ws_events_handler))
        // Auth
        .route("/auth/token", post(auth::issue_token))
        // Agents
        .route("/agents", get(agents::list_agents))
        .route("/agents/{id}", get(agents::get_agent).delete(agents::delete_agent))
        .route("/agents/{id}/suspend", post(agents::suspend_agent))
        .route("/agents/{id}/resume", post(agents::resume_agent))
        // Logs
        .route("/logs", get(logs::list_logs))
        // Traces
        .route("/traces/{session_id}", get(traces::get_trace))
        // Policies
        .route("/policies", get(policies::list_policies).post(policies::create_policy))
        .route("/policies/active", get(policies::get_active_policy))
        // Approvals
        .route("/approvals", get(approvals::list_approvals))
        .route("/approvals/{id}/approve", post(approvals::approve_action))
        .route("/approvals/{id}/reject", post(approvals::reject_action))
        // Costs
        .route("/costs", get(costs::get_cost_summary))
        // Alerts
        .route("/alerts", get(alerts::list_alerts))
        // Dev tool webhooks
        .route(
            "/devtools/saas/{provider}/events",
            post(devtools::saas_webhook),
        )
        // Tools
        .route("/tools", get(tools::list_tools))
        // Topology
        .route("/topology/overview", get(topology::get_overview))
        .route("/topology/tree/{root_id}", get(topology::get_tree))
        .route("/topology/team/{team_id}", get(topology::get_team))
        .route("/topology/lineage/{agent_id}", get(topology::get_lineage))
        .route("/topology/stats", get(topology::get_stats))
        // Edges (mesh topology edge store)
        .route("/topology/edges", post(edges::report_edge))
        .route("/agents/{id}/edges", get(edges::list_agent_edges))
        .route("/agents/{id}/graph", get(edges::get_agent_graph))
}

/// Fallback handler returning a 404 RFC 7807 response.
pub async fn fallback_404(uri: axum::http::Uri) -> ProblemDetail {
    ProblemDetail::from_status(axum::http::StatusCode::NOT_FOUND)
        .with_detail(format!("No route matched: {uri}"))
        .with_instance(uri.to_string())
}
