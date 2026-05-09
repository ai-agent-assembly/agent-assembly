//! `TopologyServiceImpl` tonic trait implementation for agent graph queries.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use aa_proto::assembly::topology::v1::topology_service_server::TopologyService;
use aa_proto::assembly::topology::v1::{
    GetAgentTreeRequest, GetAgentTreeResponse, GetLineageRequest, GetLineageResponse,
    GetTeamMembersRequest, GetTeamMembersResponse,
};

use crate::registry::AgentRegistry;

/// gRPC service implementation for topology queries.
///
/// All RPCs are currently unimplemented stubs — handlers are wired in subsequent
/// subtasks (AAASM-1029, AAASM-1030).
pub struct TopologyServiceImpl {
    registry: Arc<AgentRegistry>,
}

impl TopologyServiceImpl {
    pub fn new(registry: Arc<AgentRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl TopologyService for TopologyServiceImpl {
    async fn get_agent_tree(
        &self,
        _request: Request<GetAgentTreeRequest>,
    ) -> Result<Response<GetAgentTreeResponse>, Status> {
        Err(Status::unimplemented("GetAgentTree not yet implemented"))
    }

    async fn get_lineage(
        &self,
        _request: Request<GetLineageRequest>,
    ) -> Result<Response<GetLineageResponse>, Status> {
        Err(Status::unimplemented("GetLineage not yet implemented"))
    }

    async fn get_team_members(
        &self,
        _request: Request<GetTeamMembersRequest>,
    ) -> Result<Response<GetTeamMembersResponse>, Status> {
        Err(Status::unimplemented("GetTeamMembers not yet implemented"))
    }
}
