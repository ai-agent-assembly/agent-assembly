//! Agent registry store — `AgentRecord` and `AgentRegistry` backed by `DashMap`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use aa_core::GovernanceLevel;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::mpsc;
use tonic::Status;

use aa_proto::assembly::agent::v1::control_command::Command;
use aa_proto::assembly::agent::v1::{ControlCommand, SuspendCommand};

use super::{AgentStatus, LineageError, RegistryError};

/// Maximum number of recent events retained per agent.
pub const MAX_RECENT_EVENTS: usize = 20;

/// Maximum allowed delegation depth. Agents that would exceed this depth are rejected at registration.
pub const DEFAULT_MAX_AGENT_DEPTH: u32 = 10;

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
    /// Secondary index mapping team_id → set of agent registry keys.
    team_index: DashMap<String, dashmap::DashSet<[u8; 16]>>,
    /// Serialises the validate-then-insert step to prevent TOCTOU races.
    registration_lock: Mutex<()>,
    /// All active suspension reasons per agent. Supports multi-reason coexistence:
    /// an agent suspended for BudgetExceeded retains that reason when also
    /// suspended via ParentSuspended cascade.
    suspend_reasons: DashMap<[u8; 16], Vec<super::SuspendReason>>,
}

impl AgentRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
            control_senders: DashMap::new(),
            team_index: DashMap::new(),
            registration_lock: Mutex::new(()),
            suspend_reasons: DashMap::new(),
        }
    }

    /// Validate that registering `agent_id` with `parent_key` does not introduce a cycle
    /// or exceed `max_depth`. Must be called while holding `registration_lock`.
    pub(crate) fn validate_lineage(
        &self,
        agent_id: &[u8; 16],
        parent_key: &[u8; 16],
        max_depth: u32,
    ) -> Result<(), LineageError> {
        // Depth check.
        let parent_depth = self.agents.get(parent_key).map(|r| r.depth).unwrap_or(0);
        let new_depth = parent_depth + 1;
        if new_depth >= max_depth {
            return Err(LineageError::MaxDepthExceeded {
                depth: new_depth,
                max: max_depth,
            });
        }

        // Cycle check: check direct self-reference first, then walk ancestor chain.
        if parent_key == agent_id {
            return Err(LineageError::CircularDelegation {
                cycle: vec![*agent_id, *parent_key],
            });
        }
        let mut cycle = vec![*agent_id, *parent_key];
        let mut current = self.agents.get(parent_key).and_then(|r| r.parent_key);
        while let Some(pk) = current {
            if pk == *agent_id {
                cycle.push(pk);
                return Err(LineageError::CircularDelegation { cycle });
            }
            cycle.push(pk);
            current = self.agents.get(&pk).and_then(|r| r.parent_key);
        }
        Ok(())
    }

    /// Insert a new agent record. Returns an error if the ID is already registered.
    pub fn register(&self, record: AgentRecord) -> Result<(), RegistryError> {
        use dashmap::mapref::entry::Entry;
        let agent_id = record.agent_id;
        let parent_key = record.parent_key;
        let team_id = record.team_id.clone();

        {
            // Hold registration_lock across validate+insert to prevent TOCTOU races where
            // two concurrent registrations could each pass cycle detection independently
            // but together form a cycle once both are inserted.
            let _guard = self.registration_lock.lock().unwrap_or_else(|e| e.into_inner());

            if let Some(pk) = parent_key {
                self.validate_lineage(&agent_id, &pk, DEFAULT_MAX_AGENT_DEPTH)?;
            }

            match self.agents.entry(agent_id) {
                Entry::Occupied(_) => return Err(RegistryError::AlreadyRegistered(agent_id)),
                Entry::Vacant(v) => {
                    v.insert(record);
                }
            }
        } // registration_lock released here

        // Post-insert: update parent's children list and team index (safe outside lock).
        if let Some(pk) = parent_key {
            if let Some(mut parent) = self.agents.get_mut(&pk) {
                parent.children.push(agent_id);
            }
        }
        if let Some(tid) = team_id {
            self.team_index.entry(tid).or_default().insert(agent_id);
        }

        Ok(())
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
        let (_, record) = self.agents.remove(agent_id).ok_or(RegistryError::NotFound(*agent_id))?;

        // Remove from parent's children list.
        if let Some(pk) = record.parent_key {
            if let Some(mut parent) = self.agents.get_mut(&pk) {
                parent.children.retain(|&k| k != *agent_id);
            }
        }

        // Remove from team_index.
        if let Some(ref tid) = record.team_id {
            if let Some(set) = self.team_index.get(tid) {
                set.remove(agent_id);
            }
        }

        Ok(record)
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
    ///
    /// Adds `reason` to the agent's active suspend reasons and sets its status
    /// to `Suspended(reason)`. If the agent already has suspension reasons,
    /// the status is updated to reflect the new reason while prior reasons are
    /// retained in the multi-reason set.
    pub fn suspend_agent(&self, agent_id: &[u8; 16], reason: super::SuspendReason) -> Result<(), RegistryError> {
        {
            let mut reasons = self.suspend_reasons.entry(*agent_id).or_default();
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        let mut entry = self
            .agents
            .get_mut(agent_id)
            .ok_or(RegistryError::NotFound(*agent_id))?;
        entry.status = AgentStatus::Suspended(reason);
        Ok(())
    }

    /// Return all active suspension reasons for an agent.
    ///
    /// Returns an empty `Vec` if the agent has no suspension reasons or is not registered.
    pub fn get_suspend_reasons(&self, agent_id: &[u8; 16]) -> Vec<super::SuspendReason> {
        self.suspend_reasons
            .get(agent_id)
            .map(|r| r.value().clone())
            .unwrap_or_default()
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
    ///
    /// Clears all active suspension reasons and sets the agent's status to Active.
    /// Does not cascade to children — each child must be explicitly resumed.
    pub fn resume_agent(&self, agent_id: &[u8; 16]) -> Result<(), RegistryError> {
        self.suspend_reasons.remove(agent_id);
        let mut entry = self
            .agents
            .get_mut(agent_id)
            .ok_or(RegistryError::NotFound(*agent_id))?;
        entry.status = AgentStatus::Active;
        Ok(())
    }

    /// Suspend an agent and recursively suspend all its descendants.
    ///
    /// The root agent is suspended with `reason`. Each descendant receives
    /// `SuspendReason::ParentSuspended { parent_agent_id }` where `parent_agent_id`
    /// is the agent's direct parent — not necessarily the cascade root.
    ///
    /// Multi-reason semantics: if a descendant is already suspended for another
    /// reason (e.g. `BudgetExceeded`), that reason is retained and the
    /// `ParentSuspended` reason is added alongside it. The agent's primary status
    /// is NOT overwritten — it remains `Suspended(BudgetExceeded)`.
    ///
    /// Returns an [`AgentStatusChanged`](super::AgentStatusChanged) event for
    /// every agent whose status transitioned from Active to Suspended.
    pub fn suspend_with_cascade(
        &self,
        agent_id: &[u8; 16],
        reason: super::SuspendReason,
    ) -> Result<Vec<super::AgentStatusChanged>, RegistryError> {
        let mut events = Vec::new();

        // Suspend the root agent.
        if let Some(event) = self.apply_suspend_reason(agent_id, reason)? {
            events.push(event);
        }

        // BFS traversal — suspend all descendants.
        let mut queue: VecDeque<[u8; 16]> = VecDeque::new();
        for child in self.children_of(agent_id) {
            queue.push_back(child);
        }

        while let Some(descendant_id) = queue.pop_front() {
            // The direct parent of this descendant is its parent_key.
            let direct_parent = self
                .agents
                .get(&descendant_id)
                .and_then(|r| r.parent_key)
                .unwrap_or(*agent_id);

            let cascade_reason = super::SuspendReason::ParentSuspended {
                parent_agent_id: direct_parent,
            };

            if let Ok(Some(event)) = self.apply_suspend_reason(&descendant_id, cascade_reason) {
                events.push(event);
            }

            for grandchild in self.children_of(&descendant_id) {
                queue.push_back(grandchild);
            }
        }

        Ok(events)
    }

    /// Apply a single suspend reason to an agent without overwriting an existing suspension.
    ///
    /// Returns `Some(AgentStatusChanged)` if the agent transitioned from Active to
    /// Suspended (i.e. this was the first reason added). Returns `None` if the agent
    /// was already suspended or already held this reason.
    fn apply_suspend_reason(
        &self,
        agent_id: &[u8; 16],
        reason: super::SuspendReason,
    ) -> Result<Option<super::AgentStatusChanged>, RegistryError> {
        if !self.agents.contains_key(agent_id) {
            return Err(RegistryError::NotFound(*agent_id));
        }

        let was_empty = {
            let mut reasons = self.suspend_reasons.entry(*agent_id).or_default();
            if reasons.contains(&reason) {
                return Ok(None);
            }
            let empty = reasons.is_empty();
            reasons.push(reason);
            empty
        };

        if was_empty {
            if let Some(mut entry) = self.agents.get_mut(agent_id) {
                entry.status = AgentStatus::Suspended(reason);
            }
            Ok(Some(super::AgentStatusChanged {
                agent_id: *agent_id,
                new_status: AgentStatus::Suspended(reason),
                suspend_reason: reason,
            }))
        } else {
            Ok(None)
        }
    }

    /// Query the current status of an agent.
    pub fn agent_status(&self, agent_id: &[u8; 16]) -> Result<AgentStatus, RegistryError> {
        self.agents
            .get(agent_id)
            .map(|r| r.status)
            .ok_or(RegistryError::NotFound(*agent_id))
    }

    /// Return the direct child registry keys of the given agent.
    pub fn children_of(&self, agent_id: &[u8; 16]) -> Vec<[u8; 16]> {
        self.agents
            .get(agent_id)
            .map(|r| r.children.clone())
            .unwrap_or_default()
    }

    /// Return the ancestor chain from the given agent up to (but not including)
    /// the root. The first element is the direct parent; the last is the root.
    pub fn ancestors_of(&self, agent_id: &[u8; 16]) -> Vec<[u8; 16]> {
        let mut result = Vec::new();
        let mut current = match self.agents.get(agent_id) {
            Some(r) => r.parent_key,
            None => return result,
        };
        while let Some(pk) = current {
            result.push(pk);
            current = self.agents.get(&pk).and_then(|r| r.parent_key);
        }
        result
    }

    /// Return all agent keys belonging to the given team.
    pub fn team_members(&self, team_id: &str) -> Vec<[u8; 16]> {
        self.team_index
            .get(team_id)
            .map(|s| s.iter().map(|k| *k).collect())
            .unwrap_or_default()
    }

    /// Return the registry keys of all root agents (depth == 0).
    pub fn root_agents(&self) -> Vec<[u8; 16]> {
        self.agents
            .iter()
            .filter(|r| r.depth == 0)
            .map(|r| r.agent_id)
            .collect()
    }

    /// Return the delegation depth of the given agent, or `None` if not found.
    pub fn agent_depth(&self, agent_id: &[u8; 16]) -> Option<u32> {
        self.agents.get(agent_id).map(|r| r.depth)
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of registry-wide topology statistics.
#[derive(Debug, Clone)]
pub struct AgentGraph {
    /// Number of currently registered agents per team.
    pub team_stats: std::collections::HashMap<String, usize>,
}

impl AgentGraph {
    /// Build a snapshot from the current registry state.
    pub fn from_registry(registry: &AgentRegistry) -> Self {
        let mut team_stats = std::collections::HashMap::new();
        for entry in registry.team_index.iter() {
            team_stats.insert(entry.key().clone(), entry.value().len());
        }
        Self { team_stats }
    }
}

#[cfg(test)]
mod tree_tests {
    use super::*;
    use crate::registry::AgentStatus;

    fn make_record(id: [u8; 16], parent_key: Option<[u8; 16]>, team_id: Option<&str>, depth: u32) -> AgentRecord {
        AgentRecord {
            agent_id: id,
            name: "test".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "deadbeef".into(),
            credential_token: "tok".into(),
            metadata: Default::default(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: Default::default(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: team_id.map(|s| s.to_string()),
            depth,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key,
        }
    }

    #[test]
    fn children_of_root_then_deregister() {
        let reg = AgentRegistry::new();
        let root_id = [1u8; 16];
        let child_id = [2u8; 16];

        reg.register(make_record(root_id, None, Some("teamA"), 0)).unwrap();
        reg.register(make_record(child_id, Some(root_id), Some("teamA"), 1))
            .unwrap();

        // children_of root contains child
        let children = reg.children_of(&root_id);
        assert_eq!(children, vec![child_id]);

        // ancestors_of child is [root]
        let ancestors = reg.ancestors_of(&child_id);
        assert_eq!(ancestors, vec![root_id]);

        // team_members
        let members = reg.team_members("teamA");
        assert!(members.contains(&root_id));
        assert!(members.contains(&child_id));

        // root_agents
        let roots = reg.root_agents();
        assert!(roots.contains(&root_id));
        assert!(!roots.contains(&child_id));

        // agent_depth
        assert_eq!(reg.agent_depth(&root_id), Some(0));
        assert_eq!(reg.agent_depth(&child_id), Some(1));

        // deregister child — root's children cleared
        reg.deregister(&child_id).unwrap();
        assert!(reg.children_of(&root_id).is_empty());

        // team_index updated
        let members_after = reg.team_members("teamA");
        assert!(!members_after.contains(&child_id));
        assert!(members_after.contains(&root_id));
    }

    #[test]
    fn agent_graph_team_stats() {
        let reg = AgentRegistry::new();
        reg.register(make_record([10u8; 16], None, Some("eng"), 0)).unwrap();
        reg.register(make_record([11u8; 16], None, Some("eng"), 0)).unwrap();
        reg.register(make_record([12u8; 16], None, Some("ops"), 0)).unwrap();

        let graph = AgentGraph::from_registry(&reg);
        assert_eq!(graph.team_stats.get("eng"), Some(&2));
        assert_eq!(graph.team_stats.get("ops"), Some(&1));
    }

    #[test]
    fn ancestors_of_three_levels() {
        let reg = AgentRegistry::new();
        let r = [1u8; 16];
        let c = [2u8; 16];
        let g = [3u8; 16];

        reg.register(make_record(r, None, None, 0)).unwrap();
        reg.register(make_record(c, Some(r), None, 1)).unwrap();
        reg.register(make_record(g, Some(c), None, 2)).unwrap();

        // grandchild's ancestors: [child, root]
        let ancestors = reg.ancestors_of(&g);
        assert_eq!(ancestors, vec![c, r]);

        // children_of root = [child]
        assert_eq!(reg.children_of(&r), vec![c]);
        // children_of child = [grandchild]
        assert_eq!(reg.children_of(&c), vec![g]);
    }
}

#[cfg(test)]
mod lineage_tests {
    use super::*;
    use crate::registry::AgentStatus;

    fn make_record(id: [u8; 16], parent_key: Option<[u8; 16]>, depth: u32) -> AgentRecord {
        AgentRecord {
            agent_id: id,
            name: "test".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier: 1,
            tool_names: vec![],
            public_key: "test-pubkey".into(),
            credential_token: "test-token".into(),
            metadata: std::collections::BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: std::collections::VecDeque::new(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: None,
            depth,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key,
        }
    }

    #[test]
    fn valid_parent_child_registration_succeeds() {
        let reg = AgentRegistry::new();
        let a = [0x01u8; 16];
        let b = [0x02u8; 16];
        reg.register(make_record(a, None, 0)).unwrap();
        reg.register(make_record(b, Some(a), 1)).unwrap();
        assert_eq!(reg.agents.get(&b).unwrap().depth, 1);
    }

    #[test]
    fn direct_cycle_rejected() {
        let reg = AgentRegistry::new();
        let a = [0xAAu8; 16];
        reg.register(make_record(a, None, 0)).unwrap();
        // A tries to register again with itself as parent — validate_lineage detects cycle.
        let err = reg.validate_lineage(&a, &a, DEFAULT_MAX_AGENT_DEPTH).unwrap_err();
        assert!(matches!(err, LineageError::CircularDelegation { .. }));
    }

    #[test]
    fn indirect_cycle_rejected() {
        let reg = AgentRegistry::new();
        let a = [0x01u8; 16];
        let b = [0x02u8; 16];
        let c = [0x03u8; 16];
        reg.register(make_record(a, None, 0)).unwrap();
        reg.register(make_record(b, Some(a), 1)).unwrap();
        reg.register(make_record(c, Some(b), 2)).unwrap();
        // Try to register A with parent C — forms A→B→C→A cycle.
        let err = reg.validate_lineage(&a, &c, DEFAULT_MAX_AGENT_DEPTH).unwrap_err();
        match err {
            LineageError::CircularDelegation { ref cycle } => {
                assert!(cycle.contains(&a), "cycle path must contain agent A");
            }
            other => panic!("expected CircularDelegation, got {other:?}"),
        }
    }

    #[test]
    fn max_depth_exceeded_rejected() {
        let reg = AgentRegistry::new();
        // Build a chain of DEFAULT_MAX_AGENT_DEPTH agents (depth 0..DEFAULT_MAX_AGENT_DEPTH-1).
        let mut prev_id = [0x00u8; 16];
        prev_id[0] = 0;
        reg.register(make_record(prev_id, None, 0)).unwrap();

        for i in 1u8..=(DEFAULT_MAX_AGENT_DEPTH as u8) {
            let mut id = [0x00u8; 16];
            id[0] = i;
            let parent = prev_id;
            if i == DEFAULT_MAX_AGENT_DEPTH as u8 {
                // This agent would be at depth DEFAULT_MAX_AGENT_DEPTH, exceeding limit.
                let err = reg.validate_lineage(&id, &parent, DEFAULT_MAX_AGENT_DEPTH).unwrap_err();
                assert!(
                    matches!(err, LineageError::MaxDepthExceeded { depth, max } if depth >= max),
                    "expected MaxDepthExceeded"
                );
                break;
            }
            reg.register(make_record(id, Some(parent), i as u32)).unwrap();
            prev_id = id;
        }
    }

    #[test]
    fn toctou_mutual_parent_cycle_rejected() {
        use std::sync::Arc;
        let reg = Arc::new(AgentRegistry::new());
        let a = [0xAAu8; 16];
        let b = [0xBBu8; 16];

        // Thread 1: register A with parent B
        // Thread 2: register B with parent A
        // The registration_lock serialises these. The second thread to run will find
        // the first agent in the registry with a parent_key pointing back, detecting the cycle.
        let reg1 = Arc::clone(&reg);
        let reg2 = Arc::clone(&reg);

        let h1 = std::thread::spawn(move || reg1.register(make_record(a, Some(b), 1)));
        let h2 = std::thread::spawn(move || reg2.register(make_record(b, Some(a), 1)));

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();

        // With the registration_lock, the second registration must see the first agent's
        // parent_key and detect the cycle. Exactly one succeeds.
        let successes = [r1.is_ok(), r2.is_ok()].iter().filter(|&&x| x).count();
        assert_eq!(
            successes, 1,
            "exactly one of the mutual-parent registrations should succeed"
        );
    }
}

#[cfg(test)]
mod cascade_tests {
    use super::*;
    use crate::registry::{AgentStatus, SuspendReason};

    const ROOT: [u8; 16] = [1u8; 16];
    const CHILD: [u8; 16] = [2u8; 16];
    const GRANDCHILD: [u8; 16] = [3u8; 16];
    const SIBLING: [u8; 16] = [4u8; 16];

    fn make_record(id: [u8; 16], parent_key: Option<[u8; 16]>, depth: u32) -> AgentRecord {
        AgentRecord {
            agent_id: id,
            name: "agent".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: "deadbeef".into(),
            credential_token: "tok".into(),
            metadata: Default::default(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: Default::default(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: None,
            depth,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key,
        }
    }

    fn build_tree() -> AgentRegistry {
        let reg = AgentRegistry::new();
        reg.register(make_record(ROOT, None, 0)).unwrap();
        reg.register(make_record(CHILD, Some(ROOT), 1)).unwrap();
        reg.register(make_record(GRANDCHILD, Some(CHILD), 2)).unwrap();
        reg
    }

    #[test]
    fn cascade_suspends_direct_child() {
        let reg = AgentRegistry::new();
        reg.register(make_record(ROOT, None, 0)).unwrap();
        reg.register(make_record(CHILD, Some(ROOT), 1)).unwrap();

        let events = reg.suspend_with_cascade(&ROOT, SuspendReason::Manual).unwrap();

        assert_eq!(
            reg.agent_status(&ROOT).unwrap(),
            AgentStatus::Suspended(SuspendReason::Manual)
        );
        assert_eq!(
            reg.agent_status(&CHILD).unwrap(),
            AgentStatus::Suspended(SuspendReason::ParentSuspended { parent_agent_id: ROOT })
        );
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn cascade_suspends_grandchild() {
        let reg = build_tree();
        reg.suspend_with_cascade(&ROOT, SuspendReason::Manual).unwrap();

        assert_eq!(
            reg.agent_status(&GRANDCHILD).unwrap(),
            AgentStatus::Suspended(SuspendReason::ParentSuspended { parent_agent_id: CHILD })
        );
    }

    #[test]
    fn cascade_events_emitted_for_each_affected_agent() {
        let reg = build_tree();
        let events = reg.suspend_with_cascade(&ROOT, SuspendReason::Manual).unwrap();

        // root + child + grandchild all transition from Active → Suspended
        assert_eq!(events.len(), 3);
        let ids: Vec<_> = events.iter().map(|e| e.agent_id).collect();
        assert!(ids.contains(&ROOT));
        assert!(ids.contains(&CHILD));
        assert!(ids.contains(&GRANDCHILD));
    }

    #[test]
    fn resume_does_not_cascade_to_children() {
        let reg = build_tree();
        reg.suspend_with_cascade(&ROOT, SuspendReason::Manual).unwrap();

        // Explicitly resume only root.
        reg.resume_agent(&ROOT).unwrap();

        assert_eq!(reg.agent_status(&ROOT).unwrap(), AgentStatus::Active);
        // Children remain suspended.
        assert!(matches!(reg.agent_status(&CHILD).unwrap(), AgentStatus::Suspended(_)));
        assert!(matches!(
            reg.agent_status(&GRANDCHILD).unwrap(),
            AgentStatus::Suspended(_)
        ));
    }

    #[test]
    fn multiple_reasons_coexist_child_retains_budget_exceeded() {
        let reg = build_tree();

        // Child was already suspended for BudgetExceeded before cascade.
        reg.suspend_agent(&CHILD, SuspendReason::BudgetExceeded).unwrap();

        // Now cascade a parent suspension.
        reg.suspend_with_cascade(&ROOT, SuspendReason::Manual).unwrap();

        // Child's primary status must still reflect BudgetExceeded (it was set first).
        assert_eq!(
            reg.agent_status(&CHILD).unwrap(),
            AgentStatus::Suspended(SuspendReason::BudgetExceeded)
        );

        // Both reasons are tracked.
        let reasons = reg.get_suspend_reasons(&CHILD);
        assert!(reasons.contains(&SuspendReason::BudgetExceeded));
        assert!(reasons
            .iter()
            .any(|r| matches!(r, SuspendReason::ParentSuspended { .. })));
    }

    #[test]
    fn cascade_is_idempotent_for_already_suspended_child() {
        let reg = build_tree();

        reg.suspend_with_cascade(&ROOT, SuspendReason::Manual).unwrap();
        // Cascade again — should not produce duplicate reasons.
        reg.suspend_with_cascade(&ROOT, SuspendReason::Manual).unwrap();

        let root_reasons = reg.get_suspend_reasons(&ROOT);
        assert_eq!(root_reasons.iter().filter(|&&r| r == SuspendReason::Manual).count(), 1);

        let child_reasons = reg.get_suspend_reasons(&CHILD);
        assert_eq!(
            child_reasons
                .iter()
                .filter(|r| matches!(r, SuspendReason::ParentSuspended { parent_agent_id: ROOT }))
                .count(),
            1
        );
    }

    #[test]
    fn cascade_only_affects_descendants_not_siblings() {
        let reg = AgentRegistry::new();
        reg.register(make_record(ROOT, None, 0)).unwrap();
        reg.register(make_record(CHILD, Some(ROOT), 1)).unwrap();
        reg.register(make_record(SIBLING, None, 0)).unwrap(); // independent root

        reg.suspend_with_cascade(&ROOT, SuspendReason::Manual).unwrap();

        assert_eq!(reg.agent_status(&SIBLING).unwrap(), AgentStatus::Active);
    }
}
