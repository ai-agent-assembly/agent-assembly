//! `TopologyServiceImpl` tonic trait implementation for agent graph queries.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use aa_proto::assembly::topology::v1::topology_service_server::TopologyService;
use aa_proto::assembly::topology::v1::{
    GetAgentTreeRequest, GetAgentTreeResponse, GetLineageRequest, GetLineageResponse, GetTeamMembersRequest,
    GetTeamMembersResponse, TopologyAgent, TreeNode,
};

use crate::registry::{AgentRecord, AgentRegistry, AgentStatus};

/// gRPC service implementation for topology queries.
pub struct TopologyServiceImpl {
    registry: Arc<AgentRegistry>,
}

impl TopologyServiceImpl {
    pub fn new(registry: Arc<AgentRegistry>) -> Self {
        Self { registry }
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
        let req = request.into_inner();
        let agent_id = parse_agent_id(&req.agent_id)?;

        // Verify the root agent exists before building the tree.
        if self.registry.get(&agent_id).is_none() {
            return Err(Status::not_found(format!("agent not found: {}", req.agent_id)));
        }

        let unlimited = req.max_depth == 0;
        let root_node = build_tree_node(&self.registry, &agent_id, req.max_depth, unlimited)
            .ok_or_else(|| Status::not_found(format!("agent not found: {}", req.agent_id)))?;

        Ok(Response::new(GetAgentTreeResponse {
            root: Some(root_node),
        }))
    }

    async fn get_lineage(&self, request: Request<GetLineageRequest>) -> Result<Response<GetLineageResponse>, Status> {
        let req = request.into_inner();
        let agent_id = parse_agent_id(&req.agent_id)?;

        let record = self
            .registry
            .get(&agent_id)
            .ok_or_else(|| Status::not_found(format!("agent not found: {}", req.agent_id)))?;

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
        _request: Request<GetTeamMembersRequest>,
    ) -> Result<Response<GetTeamMembersResponse>, Status> {
        Err(Status::unimplemented("GetTeamMembers not yet implemented"))
    }
}
