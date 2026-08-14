//! OpenAPI spec aggregation via utoipa.

use utoipa::openapi::extensions::ExtensionsBuilder;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::ComponentsBuilder;
use utoipa::{Modify, OpenApi};

use crate::models::alert_ws_payloads::AlertWsFrame;
use crate::models::capability::{
    AgentMode, AgentStatus, CapCell, CapabilityAgent, CapabilityMatrix, CapabilityOverrideRequest,
    CapabilityOverrideResponse, ChangeType, Decision, Policy, PolicyRule, PolicyStatus, Resource, ResourceGroup,
    SampleCall, Verb,
};
use crate::models::event::GovernanceEvent;
use crate::models::event_type::EventType;
use crate::models::retention::{
    ColdActionDto, RetentionPolicyDocument, RetentionRunStatsDto, RunRetentionRequest, UpdateRetentionPolicyRequest,
};
use crate::models::trace::{TraceResponse, TraceSpan};
use crate::models::ws_payloads::{ApprovalPayload, BudgetAlertPayload, EventPayload, ViolationPayload};
use crate::routes::{
    admin, agents, alert_rules, alerts, analytics, approvals, audit, auth, capability, costs, destinations, dispatch,
    edges, iam, logs, native_auth, ops, policies, scrub, sensitive_data, tools, topology, traces,
};

/// Root OpenAPI document collecting all annotated paths and schemas.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Agent Assembly API",
        version = "0.0.1",
        description = "REST API for the Agent Assembly governance gateway.\n\nThis spec is auto-generated from `aa-api` route annotations via `utoipa`. CI fails if the generated spec drifts from the committed `openapi/v1.yaml`.",
        license(name = "Apache 2.0", url = "https://www.apache.org/licenses/LICENSE-2.0.html"),
        contact(name = "Agent Assembly Contributors", url = "https://github.com/ai-agent-assembly/agent-assembly")
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
        (name = "alert-destinations", description = "Notification destinations — CRUD + test"),
        (name = "alert-rules", description = "Alert-rule CRUD (AAASM-1386)"),
        (name = "auth", description = "Authentication and token issuance"),
        (name = "events", description = "Real-time event streaming via WebSocket"),
        (name = "alerts-stream", description = "Real-time alert lifecycle WebSocket stream (subprotocol aaasm-alerts-v1) — AAASM-1389"),
        (name = "topology", description = "Agent topology — tree, team, lineage, statistics, and mesh edge queries"),
        (name = "ops", description = "Per-operation lifecycle actions (pause / resume / terminate)"),
        (name = "capability", description = "Dashboard Capability Matrix — agent × resource × verb × decision view"),
        (name = "iam", description = "Identity & Access — API key list / generate / revoke / rotate"),
        (name = "audit", description = "Audit log aggregations — violation heatmaps and lineage analytics"),
        (name = "analytics", description = "Dashboard analytics aggregations — KPIs, cost breakdown, action volume, tool usage, approvals, policy effectiveness, fleet health (AAASM-4141)"),
        (name = "admin", description = "Admin operations — retention policy hot-reload and on-demand run (AAASM-1592 S-K)"),
        (name = "dispatch", description = "Secret Injection — tool dispatch with placeholder resolution (AAASM-1920)"),
        (name = "tools", description = "Auto-discovered AI dev tools on the gateway host"),
        (name = "scrub", description = "DLP / secret-scrub — effective pattern catalogue, per-pattern detection counts, and leak posture (AAASM-5174)"),
        (name = "sensitive-data", description = "Sensitive-data analytics over the durable ADR 0032 §8 projection: counters that never collapse events into findings, bounded-cardinality breakdowns, privacy-safe drill-down, and an access-logged compliance export (AAASM-5359)"),
    ),
    paths(
        crate::routes::health::health,
        agents::list_agents,
        agents::get_agent,
        agents::delete_agent,
        agents::suspend_agent,
        agents::resume_agent,
        agents::set_enforcement_mode,
        agents::preview_enforcement_mode_cascade,
        agents::get_agent_capabilities,
        agents::get_agent_config,
        agents::get_agent_decisions,
        agents::get_agent_budget,
        agents::get_agent_subtree_burn,
        agents::list_active_sessions,
        logs::list_logs,
        traces::get_trace,
        policies::list_policies,
        policies::create_policy,
        policies::get_active_policy,
        policies::simulate_policy,
        policies::replay_policy,
        policies::list_team_policies,
        approvals::list_approvals,
        approvals::get_approval,
        approvals::approve_action,
        approvals::reject_action,
        approvals::forward_action,
        costs::get_cost_summary,
        alerts::list_alerts,
        alerts::get_alert,
        alerts::resolve_alert,
        alerts::silence_alert,
        destinations::list_destinations,
        destinations::create_destination,
        destinations::get_destination,
        destinations::update_destination,
        destinations::delete_destination,
        destinations::test_destination,
        alert_rules::list_rules,
        alert_rules::create_rule,
        alert_rules::get_rule,
        alert_rules::update_rule,
        alert_rules::delete_rule,
        crate::ws::alerts_handler::ws_alerts_handler,
        auth::issue_token,
        auth::issue_ws_ticket,
        native_auth::login,
        native_auth::register,
        native_auth::invite,
        native_auth::invite_accept,
        native_auth::refresh,
        native_auth::logout,
        native_auth::auth_methods,
        native_auth::password_reset,
        native_auth::password_reset_confirm,
        crate::ws::handler::ws_events_handler,
        topology::get_topology_graph,
        topology::get_overview,
        topology::get_tree,
        topology::get_team,
        topology::get_lineage,
        topology::get_stats,
        edges::report_edge,
        edges::list_topology_edges,
        edges::list_agent_edges,
        edges::get_agent_graph,
        tools::list_tools,
        ops::list_ops,
        ops::register_op,
        ops::pause_op,
        ops::resume_op,
        ops::terminate_op,
        ops::halt_agent_for_op,
        ops::halt_global,
        capability::get_matrix,
        capability::list_overrides,
        capability::apply_override,
        capability::revoke_override,
        iam::list_roles,
        iam::list_api_keys,
        iam::generate_api_key,
        iam::revoke_api_key,
        iam::rotate_api_key,
        audit::get_violations_by_lineage,
        audit::get_sandbox_summary,
        analytics::get_kpis,
        analytics::get_cost_breakdown,
        analytics::get_action_volume,
        analytics::get_tool_usage,
        analytics::get_approvals,
        analytics::get_policy_effectiveness,
        analytics::get_fleet_health,
        analytics::get_agent_enforcement,
        analytics::get_agent_decision_mix,
        analytics::get_trust,
        analytics::get_trust_config,
        analytics::put_trust_config,
        analytics::get_enforcement_timeline,
        analytics::get_cost_history,
        analytics::get_budget_tree,
        admin::get_retention_policy,
        admin::update_retention_policy,
        admin::run_retention_policy,
        dispatch::dispatch_tool,
        scrub::get_patterns,
        scrub::get_pattern_counts,
        scrub::get_posture,
        sensitive_data::get_summary,
        sensitive_data::get_timeseries,
        sensitive_data::get_breakdown,
        sensitive_data::list_events,
        sensitive_data::get_event,
        sensitive_data::get_top_offenders,
        sensitive_data::export_compliance_records,
    ),
    components(schemas(
        crate::routes::health::HealthResponse,
        crate::error::ProblemDetail,
        dispatch::DispatchToolRequest,
        dispatch::DispatchToolResponse,
        agents::AgentResponse,
        agents::PaginatedAgentResponse,
        alerts::PaginatedAlertResponse,
        policies::PaginatedPolicyResponse,
        logs::PaginatedLogResponse,
        agents::ActiveSessionResponse,
        agents::FleetActiveSessionResponse,
        agents::RecentEventResponse,
        agents::RecentTraceResponse,
        agents::SuspendRequest,
        agents::SuspendResponse,
        agents::ResumeResponse,
        agents::EnforcementModeTarget,
        agents::EnforcementModeRequest,
        agents::EnforcementModeResponse,
        agents::CascadeConfirmation,
        agents::EnforcementModeCascadePreviewResponse,
        agents::EnforcementModeCascadeResponse,
        agents::EnforcementModeApplyResponse,
        agents::PermissionSourceResponse,
        agents::EffectivePermissionsResponse,
        crate::models::verdict::RuntimeVerdict,
        crate::models::disposition::SensitiveDataDisposition,
        agents::DecisionLabel,
        agents::AgentDecisionResponse,
        agents::AgentDecisionsResponse,
        agents::BudgetRowResponse,
        agents::BudgetRollupResponse,
        agents::ChildSpendResponse,
        agents::DailyBurnPointResponse,
        agents::SubtreeBurnResponse,
        agents::EnforcementModeLabel,
        agents::AgentConfigPolicyRef,
        agents::DeniedResourceShare,
        agents::AgentConfigRecommendation,
        agents::AgentConfigResponse,
        logs::LogEventType,
        logs::LogEntry,
        TraceResponse,
        TraceSpan,
        policies::PolicyResponse,
        policies::CreatePolicyRequest,
        policies::SimulatePolicyRequest,
        policies::SimulateVerdict,
        policies::SimulatePolicyResponse,
        policies::ReplayPolicyRequest,
        policies::ReplayPolicyResponse,
        policies::ReplaySampleDiff,
        policies::TeamPolicyResponse,
        policies::TeamPoliciesResponse,
        approvals::ApprovalResponse,
        approvals::PaginatedApprovalResponse,
        approvals::DecideRequest,
        approvals::ForwardRequest,
        approvals::QuorumStatus,
        approvals::QuorumApproverStatus,
        costs::CostSummary,
        costs::AgentCostEntry,
        costs::TeamCostEntry,
        alerts::AlertResponse,
        alerts::AlertDetailResponse,
        alerts::ResolveAlertRequest,
        alerts::SilenceAlertRequest,
        alerts::SilenceResponse,
        destinations::DestinationResponse,
        destinations::CreateDestinationRequest,
        destinations::UpdateDestinationRequest,
        destinations::TestDestinationRequest,
        destinations::TestDestinationResponse,
        destinations::ConnectorFailedBody,
        crate::destinations::types::DestinationKind,
        crate::destinations::types::DestinationConfig,
        alert_rules::AlertRuleRequest,
        crate::alerts::rules::types::AlertRule,
        crate::alerts::rules::types::RuleMetric,
        crate::alerts::rules::types::RuleOperator,
        crate::alerts::rules::types::RuleSeverity,
        AlertWsFrame,
        crate::alerts::detail::RoutingLogEntry,
        crate::alerts::detail::Silence,
        auth::TokenRequest,
        auth::TokenResponse,
        auth::WsTicketRequest,
        auth::WsTicketResponse,
        native_auth::LoginRequest,
        native_auth::AccessTokenResponse,
        native_auth::RegisterRequest,
        native_auth::RegisterResponse,
        native_auth::InviteRequest,
        native_auth::InviteResponse,
        native_auth::InviteAcceptRequest,
        native_auth::AuthMethodsResponse,
        native_auth::PasswordResetRequest,
        native_auth::PasswordResetConfirmRequest,
        crate::auth::role::Role,
        crate::ws::ticket::WsTicketPurpose,
        crate::auth::scope::Scope,
        topology::TopologyOverview,
        topology::TopologyGraphResponse,
        topology::TopologyGraphEdge,
        topology::TeamSummary,
        topology::AgentNode,
        topology::AgentNodeStatus,
        topology::NodeBudget,
        topology::NodeEffectivePermissions,
        topology::PolicyChainTier,
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
        edges::TopologyEdgeListResponse,
        tools::ToolInfoSchema,
        ops::OpActionAck,
        ops::RegisterOpRequest,
        ops::OpHaltRequest,
        ops::OpHaltAck,
        crate::ops::OpRecord,
        crate::ops::OpState,
        audit::ViolationNode,
        audit::ViolationsByLineageResponse,
        audit::SandboxSummaryCounts,
        audit::SandboxSummaryTopRule,
        audit::SandboxSummaryResponse,
        analytics::KpiResponse,
        analytics::CostSegment,
        analytics::CostBucket,
        analytics::CostBreakdownResponse,
        analytics::SeriesPoint,
        analytics::ActionVolumeSeries,
        analytics::ActionVolumeResponse,
        analytics::ToolStat,
        analytics::ToolUsageResponse,
        analytics::ApprovalOutcome,
        analytics::ApprovalAnalyticsResponse,
        analytics::PolicyDay,
        analytics::PolicyRuleStat,
        analytics::PolicyEffectivenessResponse,
        analytics::HealthPoint,
        analytics::AgentHealth,
        analytics::FleetHealthResponse,
        analytics::AgentEnforcementCounts,
        analytics::AgentDecisionMixCounts,
        analytics::TrustSignalWeight,
        analytics::TrustWeightSet,
        analytics::AgentTrustScore,
        analytics::TrustResponse,
        analytics::EnforcementBucket,
        analytics::EnforcementTimelineResponse,
        analytics::CostHistoryPoint,
        analytics::CostHistoryResponse,
        analytics::BudgetTreeNode,
        analytics::BudgetTreeResponse,
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
        iam::RoleCapabilitiesResponse,
        iam::ApiKeyScopeResponse,
        iam::ApiKeyStatusResponse,
        iam::RecentActivityResponse,
        iam::ApiKeyResponse,
        iam::GeneratedApiKeyResponse,
        iam::GenerateApiKeyRequest,
        ColdActionDto,
        RetentionPolicyDocument,
        RetentionRunStatsDto,
        RunRetentionRequest,
        UpdateRetentionPolicyRequest,
        scrub::ScrubPattern,
        scrub::ScrubCatalogueResponse,
        scrub::PatternCount,
        scrub::PatternCountsResponse,
        scrub::PostureResponse,
        sensitive_data::SensitiveDataCounters,
        sensitive_data::SensitiveDataRates,
        sensitive_data::MetricDimension,
        sensitive_data::DimensionBucket,
        sensitive_data::QueryScope,
        sensitive_data::SensitiveDataSummaryResponse,
        sensitive_data::TimeseriesPoint,
        sensitive_data::SensitiveDataTimeseriesResponse,
        sensitive_data::SensitiveDataBreakdownResponse,
        sensitive_data::SensitiveDataEventSummary,
        sensitive_data::SensitiveDataFindingDetail,
        sensitive_data::SensitiveDataEventsResponse,
        sensitive_data::SensitiveDataEventDetailResponse,
        sensitive_data::TrendDirection,
        sensitive_data::TopOffenderEntry,
        sensitive_data::TopOffendersResponse,
        sensitive_data::ExportAccessRecord,
        sensitive_data::ExportedFindings,
        sensitive_data::ComplianceExportResponse,
    )),
    modifiers(&SecurityAddon, &AlertsWsSubprotocolAddon),
)]
pub struct ApiDoc;

/// Stamps `x-ws-subprotocol: aaasm-alerts-v1` onto the
/// `/api/v1/alerts/ws` path object so the generated YAML matches the
/// AAASM-1389 AC. `utoipa::path` doesn't expose path-level `x-*`
/// extensions, so we inject it after the spec is built.
struct AlertsWsSubprotocolAddon;

impl Modify for AlertsWsSubprotocolAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(path_item) = openapi.paths.paths.get_mut("/api/v1/alerts/ws") {
            let extensions = ExtensionsBuilder::new()
                .add("x-ws-subprotocol", serde_json::json!("aaasm-alerts-v1"))
                .build();
            path_item.extensions = Some(extensions);
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// AAASM-5104 — `trust` must have one representation and one null contract
    /// across every schema that carries it. Divergence here is invisible while
    /// the value is always `null`, and becomes two incompatible shapes for one
    /// concept in the generated TypeScript client the moment AAASM-5083 lands a
    /// real score.
    #[test]
    fn trust_has_one_type_and_one_null_contract_across_schemas() {
        let spec = serde_json::to_value(ApiDoc::openapi()).expect("spec serializes");
        for schema in ["AgentNode", "AgentTree", "CapabilityAgent"] {
            let node = spec
                .pointer(&format!("/components/schemas/{schema}"))
                .unwrap_or_else(|| panic!("{schema} missing from components/schemas"));
            let trust = node
                .pointer("/properties/trust")
                .unwrap_or_else(|| panic!("{schema}.trust missing"));
            assert_eq!(
                trust["type"],
                serde_json::json!(["integer", "null"]),
                "{schema}.trust must be a nullable integer — a float implies a \
                 precision no scoring formula has agreed to"
            );
            assert_eq!(trust["minimum"], 0, "{schema}.trust must declare the 0–100 floor");
            assert_eq!(trust["maximum"], 100, "{schema}.trust must declare the 0–100 ceiling");
            let required = node["required"]
                .as_array()
                .unwrap_or_else(|| panic!("{schema} declares no required fields"));
            assert!(
                required.iter().any(|f| f == "trust"),
                "{schema}.trust must be required-but-nullable: an absent key invites \
                 `?? 0`, which reads an unmeasured agent as a scored zero"
            );
        }
    }
}
