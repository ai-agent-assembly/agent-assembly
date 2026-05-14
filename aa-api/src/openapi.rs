//! OpenAPI spec aggregation via utoipa.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::ComponentsBuilder;
use utoipa::{Modify, OpenApi};

use crate::models::capability::{
    AgentMode, AgentStatus, CapCell, CapabilityAgent, CapabilityMatrix, CapabilityOverrideRequest,
    CapabilityOverrideResponse, ChangeType, Decision, Policy, PolicyRule, PolicyStatus, Resource, ResourceGroup,
    SampleCall, Verb,
};
use crate::models::event::GovernanceEvent;
use crate::models::event_type::EventType;
use crate::models::trace::{TraceResponse, TraceSpan};
use crate::models::ws_payloads::{ApprovalPayload, BudgetAlertPayload, EventPayload, ViolationPayload};
use crate::routes::{agents, alerts, approvals, auth, capability, costs, edges, logs, ops, policies, topology, traces};

/// Root OpenAPI document collecting all annotated paths and schemas.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Agent Assembly API",
        version = "0.0.1",
        description = "REST API for the Agent Assembly governance gateway.\n\nThis spec is auto-generated from `aa-api` route annotations via `utoipa`. CI fails if the generated spec drifts from the committed `openapi/v1.yaml`.",
        license(name = "Apache 2.0", url = "https://www.apache.org/licenses/LICENSE-2.0.html"),
        contact(name = "Agent Assembly Contributors", url = "https://github.com/AI-agent-assembly/agent-assembly")
    ),
    servers(
        (url = "http://localhost:7700", description = "Local development gateway")
    ),
    tags(
        (name = "health", description = "Liveness and readiness probes"),
        (name = "agents", description = "Agent management"),
        (name = "logs", description = "Audit log queries"),
        (name = "traces", description = "Agent session traces"),
        (name = "policies", description = "Policy management"),
        (name = "approvals", description = "Human-in-the-loop approvals"),
        (name = "costs", description = "Cost and budget tracking"),
        (name = "alerts", description = "Governance alerts"),
        (name = "auth", description = "Authentication and token issuance"),
        (name = "events", description = "Real-time event streaming via WebSocket"),
        (name = "topology", description = "Agent topology — tree, team, lineage, statistics, and mesh edge queries"),
        (name = "ops", description = "Per-operation lifecycle actions (pause / resume / terminate)"),
        (name = "capability", description = "Dashboard Capability Matrix — agent × resource × verb × decision view"),
    ),
    paths(
        crate::routes::health::health,
        agents::list_agents,
        agents::get_agent,
        agents::delete_agent,
        agents::suspend_agent,
        agents::resume_agent,
        logs::list_logs,
        traces::get_trace,
        policies::list_policies,
        policies::create_policy,
        policies::get_active_policy,
        approvals::list_approvals,
        approvals::approve_action,
        approvals::reject_action,
        costs::get_cost_summary,
        alerts::list_alerts,
        auth::issue_token,
        crate::ws::handler::ws_events_handler,
        topology::get_overview,
        topology::get_tree,
        topology::get_team,
        topology::get_lineage,
        topology::get_stats,
        edges::report_edge,
        edges::list_agent_edges,
        edges::get_agent_graph,
        ops::pause_op,
        ops::resume_op,
        ops::terminate_op,
        capability::get_matrix,
        capability::apply_override,
    ),
    components(schemas(
        crate::routes::health::HealthResponse,
        crate::error::ProblemDetail,
        agents::AgentResponse,
        agents::ActiveSessionResponse,
        agents::RecentEventResponse,
        agents::RecentTraceResponse,
        agents::SuspendRequest,
        agents::SuspendResponse,
        agents::ResumeResponse,
        logs::LogEntry,
        TraceResponse,
        TraceSpan,
        policies::PolicyResponse,
        policies::CreatePolicyRequest,
        approvals::ApprovalResponse,
        approvals::DecideRequest,
        costs::CostSummary,
        costs::AgentCostEntry,
        costs::TeamCostEntry,
        alerts::AlertResponse,
        auth::TokenRequest,
        auth::TokenResponse,
        crate::auth::scope::Scope,
        topology::TopologyOverview,
        topology::TeamSummary,
        topology::AgentNode,
        topology::AgentTree,
        topology::TeamTopology,
        topology::AgentLineage,
        topology::LineageStep,
        topology::TopologyStats,
        edges::ReportEdgeRequest,
        edges::ReportEdgeResponse,
        edges::EdgeResponse,
        edges::EdgeListResponse,
        edges::GraphNode,
        edges::GraphResponse,
        ops::OpActionAck,
        GovernanceEvent,
        EventType,
        ViolationPayload,
        ApprovalPayload,
        BudgetAlertPayload,
        EventPayload,
        Verb,
        Decision,
        ResourceGroup,
        Resource,
        CapCell,
        AgentMode,
        AgentStatus,
        CapabilityAgent,
        PolicyStatus,
        PolicyRule,
        Policy,
        ChangeType,
        SampleCall,
        CapabilityMatrix,
        CapabilityOverrideRequest,
        CapabilityOverrideResponse,
    )),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

/// Adds the `bearer_auth` security scheme to the generated OpenAPI spec.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(|| ComponentsBuilder::new().build());
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .description(Some("API key (`aa_…` prefix) or JWT bearer token".to_string()))
                    .build(),
            ),
        );
    }
}
