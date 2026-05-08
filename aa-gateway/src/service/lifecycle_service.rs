//! `AgentLifecycleService` tonic trait implementation wiring gRPC RPCs to [`AgentRegistry`].

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;
use tonic::{Request, Response, Status};

use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleService;
use aa_proto::assembly::agent::v1::{
    ControlCommand, ControlStreamRequest, DeregisterRequest, DeregisterResponse, HeartbeatRequest, HeartbeatResponse,
    RegisterRequest, RegisterResponse,
};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;

use crate::engine::PolicyEngine;
use crate::registry::convert::{proto_agent_id_to_key, validate_proto_agent_id};
use crate::registry::store::AgentRecord;
use crate::registry::token::{generate_credential_token, validate_token};
use crate::events::publisher::agent_status_changed_to_envelope;
use crate::registry::{AgentRegistry, AgentStatus, LineageError, OrphanMode, RegistryError, SuspendReason};

/// Default heartbeat interval returned to agents at registration (seconds).
const DEFAULT_HEARTBEAT_INTERVAL_SEC: i64 = 30;

/// gRPC service implementation wiring `Register` / `Heartbeat` / `Deregister` /
/// `ControlStream` to the in-memory [`AgentRegistry`].
pub struct AgentLifecycleServiceImpl {
    registry: Arc<AgentRegistry>,
    policy_engine: Option<Arc<PolicyEngine>>,
}

impl AgentLifecycleServiceImpl {
    /// Create a new service backed by the given agent registry.
    pub fn new(registry: Arc<AgentRegistry>) -> Self {
        Self {
            registry,
            policy_engine: None,
        }
    }

    /// Create a new service with both an agent registry and a policy engine.
    ///
    /// When a policy engine is provided, the heartbeat handler can check budget
    /// state and auto-resume agents that were suspended due to budget limits.
    pub fn with_policy_engine(registry: Arc<AgentRegistry>, policy_engine: Arc<PolicyEngine>) -> Self {
        Self {
            registry,
            policy_engine: Some(policy_engine),
        }
    }
}

type ControlStreamOutput = Pin<Box<dyn tokio_stream::Stream<Item = Result<ControlCommand, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl AgentLifecycleService for AgentLifecycleServiceImpl {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();

        let proto_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        validate_proto_agent_id(proto_id).map_err(|e| Status::invalid_argument(e.to_string()))?;

        if req.public_key.is_empty() {
            return Err(Status::invalid_argument("missing public_key"));
        }

        // Validate that public_key is a valid Ed25519 public key (32 bytes, hex-encoded).
        let pk_bytes =
            hex::decode(&req.public_key).map_err(|_| Status::invalid_argument("public_key is not valid hex"))?;
        ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("public_key must be 32 bytes (64 hex chars)"))?,
        )
        .map_err(|_| Status::invalid_argument("invalid Ed25519 public key"))?;

        let agent_key = proto_agent_id_to_key(proto_id);
        let credential_token = generate_credential_token();
        let now = Utc::now();

        // Capture topology echo values before `req` is partially moved into `AgentRecord` below.
        let echo_parent_agent_id = req.parent_agent_id.clone();
        let echo_team_id = if proto_id.team_id.is_empty() {
            None
        } else {
            Some(proto_id.team_id.clone())
        };

        // Compute root_agent_id, parent_key, and depth server-side before building the record.
        // Root agents: root = self, depth = 0, parent_key = None.
        // Sub-agents: inherit parent's root (or parent itself), depth = parent.depth + 1.
        // Fail with INVALID_ARGUMENT if the declared parent is not registered.
        let (root_agent_id, resolved_parent_key, agent_depth) = if let Some(ref parent_str) = echo_parent_agent_id {
            let parent_proto_id = ProtoAgentId {
                org_id: proto_id.org_id.clone(),
                team_id: proto_id.team_id.clone(),
                agent_id: parent_str.clone(),
            };
            let pk = proto_agent_id_to_key(&parent_proto_id);
            let parent = self
                .registry
                .get(&pk)
                .ok_or_else(|| Status::invalid_argument("parent_agent_id not found in registry"))?;
            let root = Some(parent.root_agent_id.unwrap_or(parent.agent_id));
            let depth = parent.depth + 1;
            (root, Some(pk), depth)
        } else {
            (Some(agent_key), None, 0u32)
        };

        let record = AgentRecord {
            agent_id: agent_key,
            name: req.name,
            framework: req.framework,
            version: req.version,
            risk_tier: req.risk_tier,
            tool_names: req.tool_names,
            public_key: req.public_key,
            credential_token: credential_token.clone(),
            metadata: BTreeMap::from_iter(req.metadata),
            registered_at: now,
            last_heartbeat: now,
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: Vec::new(),
            recent_events: std::collections::VecDeque::new(),
            recent_traces: Vec::new(),
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: req.parent_agent_id,
            team_id: echo_team_id.clone(),
            depth: agent_depth,
            delegation_reason: req.delegation_reason,
            spawned_by_tool: req.spawned_by_tool,
            root_agent_id,
            children: Vec::new(),
            parent_key: resolved_parent_key,
        };

        self.registry.register(record).map_err(|e| match e {
            RegistryError::AlreadyRegistered(_) => Status::already_exists(e.to_string()),
            RegistryError::Lineage(LineageError::CircularDelegation { .. })
            | RegistryError::Lineage(LineageError::MaxDepthExceeded { .. }) => Status::invalid_argument(e.to_string()),
            _ => Status::internal(e.to_string()),
        })?;

        tracing::info!(agent_id = ?proto_id.agent_id, "agent registered");

        // root_agent_id is Copy ([u8;16]) so we can use it after moving into record above.
        let echo_root = root_agent_id.map(|b| b.to_vec());

        Ok(Response::new(RegisterResponse {
            credential_token,
            assigned_policy: String::new(),
            heartbeat_interval_sec: DEFAULT_HEARTBEAT_INTERVAL_SEC,
            parent_agent_id: echo_parent_agent_id,
            team_id: echo_team_id,
            root_agent_id: echo_root,
        }))
    }

    async fn heartbeat(&self, request: Request<HeartbeatRequest>) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();

        let proto_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        let agent_key = proto_agent_id_to_key(proto_id);

        validate_token(&self.registry, &agent_key, &req.credential_token)
            .map_err(|_| Status::unauthenticated("invalid credential token"))?;

        self.registry
            .update_heartbeat(&agent_key)
            .map_err(|e| Status::not_found(e.to_string()))?;

        let status = self.registry.agent_status(&agent_key).unwrap_or(AgentStatus::Active);

        // Lazy auto-resume: if agent was suspended due to budget and budget has
        // since reset (daily/monthly boundary crossed), resume the agent.
        let should_suspend = match status {
            AgentStatus::Suspended(SuspendReason::BudgetExceeded) => {
                let within_budget = self
                    .policy_engine
                    .as_ref()
                    .map(|pe| pe.is_within_budget(&agent_key))
                    .unwrap_or(false);
                if within_budget {
                    let _ = self.registry.resume_agent(&agent_key);
                    tracing::info!(agent_id = ?proto_id.agent_id, "auto-resumed: budget reset");
                    false
                } else {
                    true
                }
            }
            AgentStatus::Suspended(_) => true,
            _ => false,
        };

        tracing::debug!(agent_id = ?proto_id.agent_id, should_suspend, "heartbeat received");

        Ok(Response::new(HeartbeatResponse {
            policy_updated: false,
            should_suspend,
        }))
    }

    async fn deregister(&self, request: Request<DeregisterRequest>) -> Result<Response<DeregisterResponse>, Status> {
        let req = request.into_inner();

        let proto_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        let agent_key = proto_agent_id_to_key(proto_id);

        validate_token(&self.registry, &agent_key, &req.credential_token)
            .map_err(|_| Status::unauthenticated("invalid credential token"))?;

        let (_, effects) = self
            .registry
            .deregister(&agent_key, OrphanMode::Suspend)
            .map_err(|e| Status::not_found(e.to_string()))?;

        for effect in &effects {
            let envelope = agent_status_changed_to_envelope(effect, "parent agent deregistered");
            tracing::debug!(
                agent_id = %effect.agent_id_str,
                action = %effect.action,
                %envelope,
                "orphan effect applied"
            );
        }

        tracing::info!(agent_id = ?proto_id.agent_id, reason = %req.reason, "agent deregistered");

        Ok(Response::new(DeregisterResponse {
            success: true,
            agent_id: proto_id.agent_id.clone(),
        }))
    }

    type ControlStreamStream = ControlStreamOutput;

    async fn control_stream(
        &self,
        request: Request<ControlStreamRequest>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        let req = request.into_inner();

        let proto_id = req
            .agent_id
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing agent_id"))?;
        let agent_key = proto_agent_id_to_key(proto_id);

        validate_token(&self.registry, &agent_key, &req.credential_token)
            .map_err(|_| Status::unauthenticated("invalid credential token"))?;

        let rx = self
            .registry
            .open_control_stream(&agent_key)
            .map_err(|e| Status::not_found(e.to_string()))?;

        tracing::info!(agent_id = ?proto_id.agent_id, "control stream opened");

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::ControlStreamStream))
    }
}
