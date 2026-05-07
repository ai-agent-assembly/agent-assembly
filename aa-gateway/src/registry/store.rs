//! Agent registry store — `AgentRecord` and `AgentRegistry` backed by `DashMap`.

use std::collections::{BTreeMap, VecDeque};

use aa_core::GovernanceLevel;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::mpsc;
use tonic::Status;

use aa_proto::assembly::agent::v1::control_command::Command;
use aa_proto::assembly::agent::v1::{ControlCommand, SuspendCommand};

use super::{AgentStatus, RegistryError};

/// Maximum number of recent events retained per agent.
pub const MAX_RECENT_EVENTS: usize = 20;

/// Summary of an active session associated with an agent.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    /// Hex-encoded session UUID.
    pub session_id: String,
    /// Timestamp when the session started.
    pub started_at: DateTime<Utc>,
    /// Current status of the session (e.g. "running", "idle").
    pub status: String,
}

/// Summary of a recent event emitted by an agent.
#[derive(Debug, Clone)]
pub struct RecentEvent {
    /// Event type classification (e.g. "violation", "approval", "budget").
    pub event_type: String,
    /// Short human-readable summary of the event.
    pub summary: String,
    /// Timestamp when the event occurred.
    pub timestamp: DateTime<Utc>,
}

/// Summary of a recent trace session for an agent.
#[derive(Debug, Clone)]
pub struct RecentTrace {
    /// Hex-encoded session UUID, usable with `aasm trace <session-id>`.
    pub session_id: String,
    /// Timestamp when the trace session started.
    pub timestamp: DateTime<Utc>,
}

/// Identity and runtime state record for a single registered agent.
#[derive(Debug, Clone)]
pub struct AgentRecord {
    /// Raw 16-byte UUID identifying this agent.
    pub agent_id: [u8; 16],
    /// Human-readable agent name.
    pub name: String,
    /// Agent framework (e.g. "langgraph", "crewai", "custom").
    pub framework: String,
    /// Semver version of the agent process.
    pub version: String,
    /// Risk tier as the proto enum integer value.
    pub risk_tier: i32,
    /// Tools the agent declared at registration.
    pub tool_names: Vec<String>,
    /// Ed25519 public key (base64 or hex encoded).
    pub public_key: String,
    /// Short-lived credential token issued at registration.
    pub credential_token: String,
    /// Arbitrary key-value metadata (team, owner, environment, etc.).
    pub metadata: BTreeMap<String, String>,
    /// Timestamp when the agent was registered.
    pub registered_at: DateTime<Utc>,
    /// Timestamp of the most recent heartbeat.
    pub last_heartbeat: DateTime<Utc>,
    /// Current runtime status of the agent.
    pub status: AgentStatus,
    /// OS process ID of the agent, if known.
    pub pid: Option<u32>,
    /// Number of sessions this agent has handled.
    pub session_count: u32,
    /// Timestamp of the most recent event emitted by this agent.
    pub last_event: Option<DateTime<Utc>>,
    /// Number of policy violations recorded for this agent.
    pub policy_violations_count: u32,
    /// Currently active sessions for this agent.
    pub active_sessions: Vec<ActiveSession>,
    /// Most recent events emitted by this agent (bounded by [`MAX_RECENT_EVENTS`]).
    pub recent_events: VecDeque<RecentEvent>,
    /// Most recent trace session IDs for this agent.
    pub recent_traces: Vec<RecentTrace>,
    /// Governance layer this agent is assigned to (e.g. "advisory", "enforced").
    pub layer: Option<String>,
    /// Governance level (L0–L3) the registry tracks for this agent.
    ///
    /// Determined by the dev-tool adapter at registration time and consulted
    /// by `PolicyEngine::evaluate` for level-conditional rules. Defaults to
    /// [`GovernanceLevel::L0Discover`] when not declared by the registrant —
    /// existing agents registered before this field was introduced retain
    /// the discover-only default.
    pub governance_level: GovernanceLevel,
    /// Agent ID string of the parent that spawned this agent; `None` for root agents.
    pub parent_agent_id: Option<String>,
    /// Team this agent belongs to; `None` if not provided at registration.
    pub team_id: Option<String>,
    /// Delegation depth in the agent hierarchy — 0 for root agents.
    pub depth: u32,
    /// Human-readable reason the parent delegated to this agent.
    pub delegation_reason: Option<String>,
    /// Tool or framework that triggered the spawn (e.g. `"langgraph.subgraph"`).
    pub spawned_by_tool: Option<String>,
    /// Root of the delegation chain — computed server-side at registration.
    ///
    /// For root agents equals `Some(agent_id)`. For sub-agents set to
    /// `parent.root_agent_id.unwrap_or(parent.agent_id)` so any node can
    /// resolve its root in O(1) without walking the parent chain.
    pub root_agent_id: Option<[u8; 16]>,
    /// Registry keys of agents directly spawned by this agent.
    pub children: Vec<[u8; 16]>,
    /// Registry key of the parent that spawned this agent; `None` for root agents.
    pub parent_key: Option<[u8; 16]>,
}

/// Channel sender type for pushing [`ControlCommand`]s to an agent's control stream.
pub type ControlSender = mpsc::Sender<Result<ControlCommand, Status>>;

/// Channel receiver type returned to the gRPC `ControlStream` response.
pub type ControlReceiver = mpsc::Receiver<Result<ControlCommand, Status>>;

/// Thread-safe in-memory agent registry backed by [`DashMap`].
///
/// Keyed by the raw 16-byte `agent_id` UUID. Concurrent reads and writes
/// are safe without external locking.
pub struct AgentRegistry {
    agents: DashMap<[u8; 16], AgentRecord>,
    /// Per-agent control stream senders. Created when an agent opens a `ControlStream`.
    control_senders: DashMap<[u8; 16], ControlSender>,
}

impl AgentRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
            control_senders: DashMap::new(),
        }
    }

    /// Insert a new agent record. Returns an error if the ID is already registered.
    pub fn register(&self, record: AgentRecord) -> Result<(), RegistryError> {
        use dashmap::mapref::entry::Entry;
        match self.agents.entry(record.agent_id) {
            Entry::Occupied(_) => Err(RegistryError::AlreadyRegistered(record.agent_id)),
            Entry::Vacant(v) => {
                v.insert(record);
                Ok(())
            }
        }
    }

    /// Look up an agent by ID. Returns `None` if not found.
    pub fn get(&self, agent_id: &[u8; 16]) -> Option<AgentRecord> {
        self.agents.get(agent_id).map(|r| r.clone())
    }

    /// Remove an agent from the registry. Returns the removed record.
    ///
    /// Also removes any associated control stream sender.
    pub fn deregister(&self, agent_id: &[u8; 16]) -> Result<AgentRecord, RegistryError> {
        self.control_senders.remove(agent_id);
        self.agents
            .remove(agent_id)
            .map(|(_, record)| record)
            .ok_or(RegistryError::NotFound(*agent_id))
    }

    /// Update the `last_heartbeat` timestamp for an agent to now.
    pub fn update_heartbeat(&self, agent_id: &[u8; 16]) -> Result<(), RegistryError> {
        let mut entry = self
            .agents
            .get_mut(agent_id)
            .ok_or(RegistryError::NotFound(*agent_id))?;
        entry.last_heartbeat = Utc::now();
        Ok(())
    }

    /// Open a control stream for a registered agent.
    ///
    /// Creates an `mpsc` channel, stores the sender side in the registry,
    /// and returns the receiver to be used as the gRPC response stream.
    /// Returns an error if the agent is not registered.
    pub fn open_control_stream(&self, agent_id: &[u8; 16]) -> Result<ControlReceiver, RegistryError> {
        if !self.agents.contains_key(agent_id) {
            return Err(RegistryError::NotFound(*agent_id));
        }
        let (tx, rx) = mpsc::channel(32);
        self.control_senders.insert(*agent_id, tx);
        Ok(rx)
    }

    /// Send a [`ControlCommand`] to an agent's open control stream.
    ///
    /// Returns an error if the agent has no active control stream.
    pub async fn send_command(&self, agent_id: &[u8; 16], cmd: ControlCommand) -> Result<(), RegistryError> {
        let sender = self
            .control_senders
            .get(agent_id)
            .ok_or(RegistryError::NotFound(*agent_id))?;
        sender
            .send(Ok(cmd))
            .await
            .map_err(|_| RegistryError::NotFound(*agent_id))
    }

    /// Return a snapshot of all currently registered agents.
    pub fn list(&self) -> Vec<AgentRecord> {
        self.agents.iter().map(|r| r.value().clone()).collect()
    }

    /// Return the scope lineage (org, team) for `agent_id` by reading the
    /// `"org_id"` and `"team_id"` metadata keys written at registration.
    ///
    /// Returns `None` if the agent is not in the registry. Both inner fields
    /// may also be `None` if the agent was registered without org/team metadata.
    pub fn lineage(&self, agent_id: &[u8; 16]) -> Option<crate::registry::Lineage> {
        let record = self.agents.get(agent_id)?;
        Some(crate::registry::Lineage {
            org_id: record.metadata.get("org_id").cloned(),
            team_id: record.metadata.get("team_id").cloned(),
        })
    }

    /// Suspend an agent with the given reason.
    pub fn suspend_agent(&self, agent_id: &[u8; 16], reason: super::SuspendReason) -> Result<(), RegistryError> {
        let mut entry = self
            .agents
            .get_mut(agent_id)
            .ok_or(RegistryError::NotFound(*agent_id))?;
        entry.status = AgentStatus::Suspended(reason);
        Ok(())
    }

    /// Suspend an agent and send a [`SuspendCommand`] via the control stream.
    ///
    /// Sets the agent status to `Suspended(reason)` and, if a control stream
    /// is open, pushes a `SuspendCommand` with the given reason string.
    /// The control stream send is best-effort: if the stream is closed or full,
    /// the suspension still takes effect.
    pub async fn suspend_and_notify(
        &self,
        agent_id: &[u8; 16],
        reason: super::SuspendReason,
        reason_text: &str,
    ) -> Result<(), RegistryError> {
        self.suspend_agent(agent_id, reason)?;

        let cmd = ControlCommand {
            command: Some(Command::Suspend(SuspendCommand {
                reason: reason_text.to_string(),
            })),
        };
        // Best-effort: ignore errors if the stream is not open.
        let _ = self.send_command(agent_id, cmd).await;
        Ok(())
    }

    /// Resume a suspended agent back to Active status.
    pub fn resume_agent(&self, agent_id: &[u8; 16]) -> Result<(), RegistryError> {
        let mut entry = self
            .agents
            .get_mut(agent_id)
            .ok_or(RegistryError::NotFound(*agent_id))?;
        entry.status = AgentStatus::Active;
        Ok(())
    }

    /// Query the current status of an agent.
    pub fn agent_status(&self, agent_id: &[u8; 16]) -> Result<AgentStatus, RegistryError> {
        self.agents
            .get(agent_id)
            .map(|r| r.status)
            .ok_or(RegistryError::NotFound(*agent_id))
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}
