//! `TopologyServiceImpl` tonic trait implementation for agent graph queries.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use aa_core::identity::AgentId;
use aa_core::topology::{EdgeRepo, EdgeType, NewEdge};
use aa_proto::assembly::topology::v1::topology_service_server::TopologyService;
use aa_proto::assembly::topology::v1::{
    GetAgentTreeRequest, GetAgentTreeResponse, GetLineageRequest, GetLineageResponse, GetTeamMembersRequest,
    GetTeamMembersResponse, ReportEdgeRequest, ReportEdgeResponse, TopologyAgent, TreeNode,
};

use crate::edges::InMemoryEdgeRepo;
use crate::iam::VerifiedCaller;
use crate::registry::{AgentRecord, AgentRegistry, AgentStatus};

/// gRPC service implementation for topology queries.
pub struct TopologyServiceImpl {
    registry: Arc<AgentRegistry>,
    edge_repo: InMemoryEdgeRepo,
}

impl TopologyServiceImpl {
    pub fn new(registry: Arc<AgentRegistry>, edge_repo: InMemoryEdgeRepo) -> Self {
        Self { registry, edge_repo }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_agent_id(hex: &str) -> Result<[u8; 16], Status> {
    let bytes = hex::decode(hex).map_err(|_| Status::invalid_argument("agent_id is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| Status::invalid_argument("agent_id must be 32 hex characters (16 bytes)"))
}

fn format_id(id: &[u8; 16]) -> String {
    hex::encode(id)
}

/// Tenant-authorization rule for a topology resource (AAASM-3846 reads,
/// AAASM-3855 `report_edge` write).
///
/// The `auth_interceptor` authenticates the caller and injects a
/// [`VerifiedCaller`], but the handlers previously discarded it and operated on
/// any agent for any authenticated caller (a post-authN function-level/tenant
/// authz gap). This mirrors `approval_service::caller_may_act_on`, extended to
/// also bind the caller's `org_id`: a tenanted caller (a `Some` team/org) may
/// only act on a resource in the same team and org; when either side is
/// untenanted access is allowed (the untenanted/single-tenant deployment
/// fallback).
///
/// AAASM-4140: the fallback is fail-safe — a registered but team-less (resp.
/// org-less) caller can never read a *tenanted* resource, in any deployment
/// posture. The permissive path survives only where the resource itself is
/// untenanted; untenanted resources stay readable and same-tenant access is
/// unchanged (the AAASM-4133 item-5 residual).
fn caller_may_read(caller: &VerifiedCaller, resource_team: Option<&str>, resource_org: Option<&str>) -> bool {
    let team_ok = match (caller.team_id.as_deref(), resource_team) {
        (Some(caller_team), Some(resource_team)) => caller_team == resource_team,
        // Team-less caller vs a tenanted resource: fail safe — deny (AAASM-4140).
        (None, Some(_)) => false,
        _ => true,
    };
    let org_ok = match (caller.org_id.as_deref(), resource_org) {
        (Some(caller_org), Some(resource_org)) => caller_org == resource_org,
        // Org-less caller vs a tenanted resource: fail safe — deny (AAASM-4140).
        (None, Some(_)) => false,
        _ => true,
    };
    team_ok && org_ok
}

fn status_str(status: AgentStatus) -> &'static str {
    match status {
        AgentStatus::Active => "active",
        AgentStatus::Suspended(_) => "suspended",
        AgentStatus::Deregistered => "deregistered",
    }
}

fn record_to_topology_agent(record: &AgentRecord) -> TopologyAgent {
    TopologyAgent {
        id: format_id(&record.agent_id),
        name: record.name.clone(),
        depth: record.depth,
        status: status_str(record.status).to_owned(),
        team_id: record.team_id.clone().unwrap_or_default(),
        delegation_reason: record.delegation_reason.clone().unwrap_or_default(),
        spawned_by_tool: record.spawned_by_tool.clone().unwrap_or_default(),
    }
}

/// Recursively build a `TreeNode` starting at `agent_id`.
///
/// `remaining` is the number of additional levels to descend.
/// When `remaining == 0` and `unlimited == false`, children are omitted.
fn build_tree_node(registry: &AgentRegistry, agent_id: &[u8; 16], remaining: u32, unlimited: bool) -> Option<TreeNode> {
    let record = registry.get(agent_id)?;
    let children = if unlimited || remaining > 0 {
        let next = if unlimited { 0 } else { remaining - 1 };
        registry
            .children_of(agent_id)
            .iter()
            .filter_map(|child_id| build_tree_node(registry, child_id, next, unlimited))
            .collect()
    } else {
        vec![]
    };
    Some(TreeNode {
        agent: Some(record_to_topology_agent(&record)),
        children,
    })
}

// ── RPC handlers ──────────────────────────────────────────────────────────────

#[tonic::async_trait]
impl TopologyService for TopologyServiceImpl {
    async fn get_agent_tree(
        &self,
        request: Request<GetAgentTreeRequest>,
    ) -> Result<Response<GetAgentTreeResponse>, Status> {
        // AAASM-3846 — read the verified caller (injected by the auth
        // interceptor) before consuming the request, so the lookup can be bound
        // to the caller's tenant.
        let caller = request.extensions().get::<VerifiedCaller>().cloned();
        let req = request.into_inner();
        let agent_id = parse_agent_id(&req.agent_id)?;

        let record = self
            .registry
            .get(&agent_id)
            .ok_or_else(|| Status::not_found(format!("agent not found: {}", req.agent_id)))?;

        // AAASM-3846 — confine a tenanted caller to its own team/org so one team
        // cannot read another team's delegation tree.
        if let Some(caller) = &caller {
            if !caller_may_read(caller, record.team_id.as_deref(), record.org_id.as_deref()) {
                return Err(Status::permission_denied("agent belongs to a different tenant"));
            }
        }

        if record.parent_key.is_some() {
            return Err(Status::failed_precondition(format!(
                "agent {} is not a root agent",
                req.agent_id
            )));
        }

        let unlimited = req.max_depth == 0;
        let root_node = build_tree_node(&self.registry, &agent_id, req.max_depth, unlimited)
            .ok_or_else(|| Status::not_found(format!("agent not found: {}", req.agent_id)))?;

        Ok(Response::new(GetAgentTreeResponse { root: Some(root_node) }))
    }

    async fn get_lineage(&self, request: Request<GetLineageRequest>) -> Result<Response<GetLineageResponse>, Status> {
        // AAASM-3846 — read the verified caller before consuming the request.
        let caller = request.extensions().get::<VerifiedCaller>().cloned();
        let req = request.into_inner();
        let agent_id = parse_agent_id(&req.agent_id)?;

        let record = self
            .registry
            .get(&agent_id)
            .ok_or_else(|| Status::not_found(format!("agent not found: {}", req.agent_id)))?;

        // AAASM-3846 — a tenanted caller may only trace lineage for an agent in
        // its own team/org.
        if let Some(caller) = &caller {
            if !caller_may_read(caller, record.team_id.as_deref(), record.org_id.as_deref()) {
                return Err(Status::permission_denied("agent belongs to a different tenant"));
            }
        }

        // ancestors[0] is the agent itself; ancestors[last] is the root.
        let mut ancestors = vec![record_to_topology_agent(&record)];
        for ancestor_id in self.registry.ancestors_of(&agent_id) {
            if let Some(r) = self.registry.get(&ancestor_id) {
                ancestors.push(record_to_topology_agent(&r));
            }
        }

        Ok(Response::new(GetLineageResponse { ancestors }))
    }

    async fn get_team_members(
        &self,
        request: Request<GetTeamMembersRequest>,
    ) -> Result<Response<GetTeamMembersResponse>, Status> {
        // AAASM-3846 — read the verified caller before consuming the request.
        let caller = request.extensions().get::<VerifiedCaller>().cloned();
        let req = request.into_inner();

        if req.team_id.is_empty() {
            return Err(Status::invalid_argument("team_id must not be empty"));
        }

        // AAASM-3846 — a tenanted caller may only enumerate its own team's
        // members, never another team's roster.
        if let Some(caller) = &caller {
            match caller.team_id.as_deref() {
                Some(caller_team) if caller_team != req.team_id => {
                    return Err(Status::permission_denied("team belongs to a different tenant"));
                }
                // AAASM-4140: fail safe — a team-less caller may not enumerate a
                // team's roster (a tenanted resource); deny in every posture.
                None => {
                    return Err(Status::permission_denied("team belongs to a different tenant"));
                }
                _ => {}
            }
        }

        let member_ids = self.registry.team_members(&req.team_id);
        if member_ids.is_empty() {
            return Err(Status::not_found(format!(
                "team not found or has no agents: {}",
                req.team_id
            )));
        }

        let mut members: Vec<TopologyAgent> = member_ids
            .iter()
            .filter_map(|id| self.registry.get(id))
            .map(|r| record_to_topology_agent(&r))
            .collect();
        members.sort_by(|a, b| a.id.cmp(&b.id));

        Ok(Response::new(GetTeamMembersResponse { members }))
    }

    async fn report_edge(&self, request: Request<ReportEdgeRequest>) -> Result<Response<ReportEdgeResponse>, Status> {
        // AAASM-3855 — read the verified caller (injected by the fail-closed auth
        // interceptor) before consuming the request. AAASM-3846 gated the topology
        // read RPCs but explicitly scoped itself out of this write RPC; left
        // ungated, any authenticated tenant could forge an edge between arbitrary
        // (cross-tenant) agents. Absence means the request did not authenticate,
        // so fail closed rather than write a forgeable edge.
        let caller = request.extensions().get::<VerifiedCaller>().cloned().ok_or_else(|| {
            Status::unauthenticated("missing verified caller; reporting a topology edge requires authentication")
        })?;
        let req = request.into_inner();

        // Syntactic validation first (mirrors the read RPCs: parse before resolve),
        // so a malformed request from an authenticated caller is reported as
        // `invalid_argument` regardless of the registry state.
        let source_bytes = parse_agent_id(&req.source_agent_id)?;
        let target_bytes = parse_agent_id(&req.target_agent_id)?;

        let edge_type = EdgeType::try_from(req.edge_type.as_str())
            .map_err(|_| Status::invalid_argument(format!("unknown edge_type: {:?}", req.edge_type)))?;

        let metadata = if req.metadata_json.is_empty() {
            None
        } else {
            Some(
                serde_json::from_str::<serde_json::Value>(&req.metadata_json)
                    .map_err(|e| Status::invalid_argument(format!("metadata_json is not valid JSON: {e}")))?,
            )
        };

        // AAASM-3855 — confine a tenanted caller to its own tenant: both endpoints
        // must resolve to agents in the caller's team/org (the same predicate the
        // read RPCs apply), so one tenant cannot inject edges into another tenant's
        // topology graph. Mirror the read-RPC ordering: resolve then tenant-check.
        let source_record = self
            .registry
            .get(&source_bytes)
            .ok_or_else(|| Status::not_found(format!("agent not found: {}", req.source_agent_id)))?;
        if !caller_may_read(
            &caller,
            source_record.team_id.as_deref(),
            source_record.org_id.as_deref(),
        ) {
            return Err(Status::permission_denied("source agent belongs to a different tenant"));
        }
        let target_record = self
            .registry
            .get(&target_bytes)
            .ok_or_else(|| Status::not_found(format!("agent not found: {}", req.target_agent_id)))?;
        if !caller_may_read(
            &caller,
            target_record.team_id.as_deref(),
            target_record.org_id.as_deref(),
        ) {
            return Err(Status::permission_denied("target agent belongs to a different tenant"));
        }

        let source = AgentId::from_bytes(source_bytes);
        let target = AgentId::from_bytes(target_bytes);

        let id = self
            .edge_repo
            .insert(NewEdge {
                source,
                target,
                edge_type,
                metadata,
            })
            .await
            .map_err(|e| Status::internal(format!("edge store error: {e}")))?;

        Ok(Response::new(ReportEdgeResponse { id }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, VecDeque};

    use aa_proto::assembly::topology::v1::topology_service_server::TopologyService;

    /// Build a minimal active `AgentRecord` with an explicit tenant.
    fn make_record(
        id: [u8; 16],
        name: &str,
        parent_key: Option<[u8; 16]>,
        team_id: Option<&str>,
        org_id: Option<&str>,
    ) -> AgentRecord {
        AgentRecord {
            agent_id: id,
            name: name.into(),
            framework: "custom".into(),
            version: "1.0.0".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "pk_test".into(),
            credential_token: format!("tok_{}", hex::encode(id)),
            metadata: BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: VecDeque::new(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: team_id.map(str::to_owned),
            depth: if parent_key.is_some() { 1 } else { 0 },
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some(id),
            children: vec![],
            parent_key,
            enforcement_mode: None,
            org_id: org_id.map(str::to_owned),
        }
    }

    fn caller(team: Option<&str>, org: Option<&str>) -> VerifiedCaller {
        VerifiedCaller {
            agent_key: [1u8; 16],
            team_id: team.map(str::to_owned),
            org_id: org.map(str::to_owned),
        }
    }

    fn service_with(records: Vec<AgentRecord>) -> TopologyServiceImpl {
        let registry = Arc::new(AgentRegistry::new());
        for r in records {
            registry.register(r).unwrap();
        }
        TopologyServiceImpl::new(registry, InMemoryEdgeRepo::new())
    }

    #[tokio::test]
    async fn get_agent_tree_cross_tenant_is_permission_denied() {
        let root: [u8; 16] = [0xa0; 16];
        let svc = service_with(vec![make_record(root, "root", None, Some("team-b"), Some("org-b"))]);

        let mut req = Request::new(GetAgentTreeRequest {
            agent_id: format_id(&root),
            max_depth: 0,
        });
        req.extensions_mut().insert(caller(Some("team-a"), Some("org-a")));

        let err = svc.get_agent_tree(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn get_agent_tree_same_tenant_is_allowed() {
        let root: [u8; 16] = [0xa1; 16];
        let svc = service_with(vec![make_record(root, "root", None, Some("team-a"), Some("org-a"))]);

        let mut req = Request::new(GetAgentTreeRequest {
            agent_id: format_id(&root),
            max_depth: 0,
        });
        req.extensions_mut().insert(caller(Some("team-a"), Some("org-a")));

        let resp = svc.get_agent_tree(req).await.unwrap().into_inner();
        assert_eq!(resp.root.unwrap().agent.unwrap().id, format_id(&root));
    }

    #[tokio::test]
    async fn get_lineage_cross_tenant_is_permission_denied() {
        let root: [u8; 16] = [0xb0; 16];
        let svc = service_with(vec![make_record(root, "root", None, Some("team-b"), Some("org-b"))]);

        let mut req = Request::new(GetLineageRequest {
            agent_id: format_id(&root),
        });
        req.extensions_mut().insert(caller(Some("team-a"), Some("org-a")));

        let err = svc.get_lineage(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn get_team_members_cross_tenant_is_permission_denied() {
        let agent: [u8; 16] = [0xc0; 16];
        let svc = service_with(vec![make_record(agent, "a", None, Some("team-b"), None)]);

        let mut req = Request::new(GetTeamMembersRequest {
            team_id: "team-b".into(),
        });
        req.extensions_mut().insert(caller(Some("team-a"), None));

        let err = svc.get_team_members(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    // AAASM-4140 — zero-config preserved: a team-less caller may still read an
    // *untenanted* agent (single-tenant deployment fallback).
    #[tokio::test]
    async fn teamless_caller_allowed_reading_untenanted_agent() {
        let root: [u8; 16] = [0xd0; 16];
        let svc = service_with(vec![make_record(root, "root", None, None, None)]);

        let mut req = Request::new(GetAgentTreeRequest {
            agent_id: format_id(&root),
            max_depth: 0,
        });
        req.extensions_mut().insert(caller(None, None));

        let resp = svc.get_agent_tree(req).await.unwrap().into_inner();
        assert_eq!(resp.root.unwrap().agent.unwrap().id, format_id(&root));
    }

    // AAASM-4140 — fail-safe fallback: a registered but team-less caller may not
    // read a tenanted agent, in the default (Untenanted) posture too.
    #[tokio::test]
    async fn teamless_caller_denied_reading_tenanted_agent() {
        let root: [u8; 16] = [0xf0; 16];
        let svc = service_with(vec![make_record(root, "root", None, Some("team-b"), Some("org-b"))]);

        let mut req = Request::new(GetAgentTreeRequest {
            agent_id: format_id(&root),
            max_depth: 0,
        });
        req.extensions_mut().insert(caller(None, None));

        let err = svc.get_agent_tree(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    // AAASM-4140 — fail-safe fallback: a team-less caller may not enumerate a
    // team's roster, in the default (Untenanted) posture too.
    #[tokio::test]
    async fn teamless_caller_denied_enumerating_team() {
        let agent: [u8; 16] = [0xf1; 16];
        let svc = service_with(vec![make_record(agent, "a", None, Some("team-b"), None)]);

        let mut req = Request::new(GetTeamMembersRequest {
            team_id: "team-b".into(),
        });
        req.extensions_mut().insert(caller(None, None));

        let err = svc.get_team_members(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn caller_may_read_matrix() {
        // Team-less (resp. org-less) caller vs a tenanted resource: fail safe —
        // denied (AAASM-4140).
        assert!(!caller_may_read(&caller(None, None), Some("t"), None));
        assert!(!caller_may_read(&caller(None, None), None, Some("o")));
        // Untenanted resource stays readable for any caller.
        assert!(caller_may_read(&caller(Some("t"), None), None, None));
        assert!(caller_may_read(&caller(None, None), None, None));
        // Same-tenant match; cross-tenant mismatch.
        assert!(caller_may_read(&caller(Some("t"), Some("o")), Some("t"), Some("o")));
        assert!(!caller_may_read(&caller(Some("t"), Some("o")), Some("u"), Some("o")));
    }

    // ── report_edge tenant authz (AAASM-3855) ──────────────────────────────

    fn report_edge_req(source: &[u8; 16], target: &[u8; 16]) -> Request<ReportEdgeRequest> {
        Request::new(ReportEdgeRequest {
            source_agent_id: format_id(source),
            target_agent_id: format_id(target),
            edge_type: "delegates_to".into(),
            metadata_json: String::new(),
        })
    }

    #[tokio::test]
    async fn report_edge_cross_tenant_is_permission_denied() {
        // A tenant-A caller cannot forge an edge between tenant-B agents.
        let source: [u8; 16] = [0xe0; 16];
        let target: [u8; 16] = [0xe1; 16];
        let svc = service_with(vec![
            make_record(source, "src", None, Some("team-b"), Some("org-b")),
            make_record(target, "dst", None, Some("team-b"), Some("org-b")),
        ]);

        let mut req = report_edge_req(&source, &target);
        req.extensions_mut().insert(caller(Some("team-a"), Some("org-a")));

        let err = svc.report_edge(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn report_edge_same_tenant_is_allowed() {
        let source: [u8; 16] = [0xe2; 16];
        let target: [u8; 16] = [0xe3; 16];
        let svc = service_with(vec![
            make_record(source, "src", None, Some("team-a"), Some("org-a")),
            make_record(target, "dst", None, Some("team-a"), Some("org-a")),
        ]);

        let mut req = report_edge_req(&source, &target);
        req.extensions_mut().insert(caller(Some("team-a"), Some("org-a")));

        let resp = svc.report_edge(req).await.unwrap().into_inner();
        assert!(resp.id > 0);
    }

    #[tokio::test]
    async fn report_edge_missing_caller_is_unauthenticated() {
        // No VerifiedCaller in extensions ⇒ unauthenticated peer ⇒ fail closed.
        let source: [u8; 16] = [0xe4; 16];
        let target: [u8; 16] = [0xe5; 16];
        let svc = service_with(vec![
            make_record(source, "src", None, Some("team-a"), Some("org-a")),
            make_record(target, "dst", None, Some("team-a"), Some("org-a")),
        ]);

        let req = report_edge_req(&source, &target);

        let err = svc.report_edge(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
