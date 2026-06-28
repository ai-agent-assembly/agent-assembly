//! In-memory registry for in-flight operation lifecycle state.
//!
//! Tracks each op by its string ID through the state machine:
//!
//! ```text
//! Pending ──allow──▶ Running ──pause──▶ Paused ──resume──▶ Running
//!   │                  │                  │
//!   │                  └──complete──▶ Completing
//!   │                  │
//!   └──terminate──▶ Terminated ◀──terminate──┘
//! ```
//!
//! `Pending` is the entry state for ops ingested from a policy-check request
//! before the engine has decided; `Completing` is the post-success drain state
//! before the entry is swept. `Terminated` ops accept a second `terminate`
//! call (idempotent) but reject all other transitions with
//! `OpsError::InvalidTransition`. See
//! `docs/src/operations/ops-registry-architecture.md` for the full diagram.

pub mod publisher;

pub use publisher::{OpControlEnvelope, OpControlPublisher, SharedOpControlPublisher};

use aa_proto::assembly::common::v1::AgentId;
use aa_proto::assembly::policy::v1::OpControlSignal;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Lifecycle state of a registered in-flight operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OpState {
    /// Ingested from a policy-check request; awaiting the engine decision.
    Pending,
    /// Policy allowed; agent is actively executing.
    Running,
    /// Operator paused via `POST /api/v1/ops/{id}/pause`.
    Paused,
    /// Action signalled complete by the SDK; entry is draining.
    Completing,
    /// Operator terminated, or policy denied. Terminal.
    Terminated,
}

/// Snapshot of a registered operation returned by the registry and API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OpRecord {
    /// Stable identifier supplied at registration time.
    pub op_id: String,
    /// Current lifecycle state.
    pub state: OpState,
    /// RFC 3339 timestamp when the op was first registered.
    pub registered_at: String,
    /// RFC 3339 timestamp of the most recent state change.
    pub updated_at: String,
}

/// Errors returned by registry transition methods.
#[derive(Debug, PartialEq, Eq)]
pub enum OpsError {
    /// No op with the given ID is registered.
    NotFound,
    /// The requested transition is not valid from the op's current state.
    InvalidTransition,
}

/// Thread-safe in-memory store for in-flight operation lifecycle state.
///
/// Backed by [`DashMap`] for concurrent, lock-free read access and
/// shard-level writes during state transitions.
pub struct OpsRegistry {
    ops: DashMap<String, OpRecord>,
    /// Per-op routing key for [`OpControlPublisher`] (AAASM-1657).
    ///
    /// Populated by [`OpsRegistry::ingest_with_agent`] so the transition
    /// methods can address the corresponding SDK subscriber. Ops registered
    /// via [`OpsRegistry::register`] or [`OpsRegistry::ingest`] (without an
    /// agent id) silently skip publishing — preserving the pre-1657
    /// behaviour for the AAASM-1525 HTTP `POST /api/v1/ops` register path
    /// and any test fixtures that construct `OpsRegistry::new()` directly.
    agents: DashMap<String, AgentId>,
    /// Optional fan-out publisher for op-control signals (AAASM-1657).
    /// Wire via [`OpsRegistry::with_publisher`]. `None` means transitions
    /// only update local state — no SDK push happens.
    publisher: Option<SharedOpControlPublisher>,
}

impl Default for OpsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OpsRegistry {
    pub fn new() -> Self {
        Self {
            ops: DashMap::new(),
            agents: DashMap::new(),
            publisher: None,
        }
    }

    /// Attach an [`OpControlPublisher`] so subsequent transitions push
    /// the matching [`OpControlSignal`] to subscribed SDK clients.
    ///
    /// Only transitions on ops that were registered via
    /// [`OpsRegistry::ingest_with_agent`] trigger a publish — without an
    /// agent_id the publisher has nothing to route to.
    pub fn with_publisher(mut self, publisher: SharedOpControlPublisher) -> Self {
        self.publisher = Some(publisher);
        self
    }

    /// Register a new op in the `Running` state.
    ///
    /// Overwrites any existing record with the same `op_id` (idempotent
    /// re-registration resets state to `Running`).
    pub fn register(&self, op_id: String) -> OpRecord {
        let now = chrono::Utc::now().to_rfc3339();
        let record = OpRecord {
            op_id: op_id.clone(),
            state: OpState::Running,
            registered_at: now.clone(),
            updated_at: now,
        };
        self.ops.insert(op_id, record.clone());
        record
    }

    /// Ingest an op from a policy-check request in the `Pending` state.
    ///
    /// Called from `PolicyServiceImpl::check_action` *before* the engine
    /// decision so the op appears in the live-ops view even if evaluation
    /// takes time. Idempotent re-ingestion of an already-known `op_id`
    /// returns the existing record unchanged (preserves any later state
    /// transition that may have occurred since first ingest).
    pub fn ingest(&self, op_id: String) -> OpRecord {
        if let Some(existing) = self.ops.get(&op_id) {
            return existing.clone();
        }
        let now = chrono::Utc::now().to_rfc3339();
        let record = OpRecord {
            op_id: op_id.clone(),
            state: OpState::Pending,
            registered_at: now.clone(),
            updated_at: now,
        };
        self.ops.insert(op_id, record.clone());
        record
    }

    /// Like [`OpsRegistry::ingest`] but also records the owning `agent_id`
    /// so subsequent transitions can publish the matching `OpControlSignal`
    /// to that agent's subscribed SDK stream (AAASM-1657).
    ///
    /// Idempotent on the op_id like `ingest`; the agent_id mapping is
    /// inserted unconditionally (assumed stable per op_id).
    pub fn ingest_with_agent(&self, op_id: String, agent_id: AgentId) -> OpRecord {
        self.agents.insert(op_id.clone(), agent_id);
        self.ingest(op_id)
    }

    /// Internal helper: publish a signal if a publisher is attached AND the
    /// op has a recorded agent_id. Both must be present for a publish to
    /// happen — silently no-ops otherwise.
    fn maybe_publish(&self, op_id: &str, signal: OpControlSignal) {
        if let (Some(pub_), Some(agent)) = (self.publisher.as_ref(), self.agents.get(op_id)) {
            pub_.publish(agent.clone(), op_id.to_string(), signal);
        }
    }

    /// AAASM-3881: emit an **agent-wide** op-control halt under the reserved
    /// `agent:{agent_id}` op-id so it is enforced by every request the agent
    /// makes, regardless of any agent-supplied `trace_id` (AAASM-3873).
    ///
    /// Unlike the per-op transitions ([`pause`](Self::pause) etc.) this carries
    /// no lifecycle state — it is a pure operator-driven broadcast addressed to
    /// the agent identity. Returns `true` when a publisher is attached and the
    /// signal was emitted, `false` when no op-control channel is configured (so
    /// the caller can surface an explicit "channel unavailable" rather than a
    /// silent no-op).
    pub fn halt_agent(&self, agent_id: AgentId, signal: OpControlSignal) -> bool {
        match self.publisher.as_ref() {
            Some(pub_) => {
                pub_.publish_agent_halt(agent_id, signal);
                true
            }
            None => false,
        }
    }

    /// AAASM-3881: emit a **fleet-wide** op-control halt under the reserved
    /// global op-id `"*"`, delivered to every connected runtime.
    ///
    /// Returns `true` when a publisher is attached and the signal was emitted,
    /// `false` when no op-control channel is configured.
    pub fn halt_global(&self, signal: OpControlSignal) -> bool {
        match self.publisher.as_ref() {
            Some(pub_) => {
                pub_.publish_global_halt(signal);
                true
            }
            None => false,
        }
    }

    /// Return a snapshot of the named op, or `None` if it is not registered.
    pub fn get(&self, op_id: &str) -> Option<OpRecord> {
        self.ops.get(op_id).map(|r| r.clone())
    }

    /// Look up the owning `agent_id` for an op (AAASM-1657).
    ///
    /// Returns `None` for ops registered via the legacy `ingest` or
    /// `register` paths that didn't carry an agent id. Used by the
    /// `aa-api` route handlers when emitting `ops_change` WS events so
    /// the dashboard's per-agent filter can target them correctly.
    pub fn agent_for(&self, op_id: &str) -> Option<AgentId> {
        self.agents.get(op_id).map(|a| a.clone())
    }

    /// Return snapshots of all registered ops.
    pub fn list(&self) -> Vec<OpRecord> {
        self.ops.iter().map(|r| r.clone()).collect()
    }

    /// Transition `Pending → Running`.
    ///
    /// Called from `PolicyServiceImpl::check_action` after the engine
    /// returns an `Allow` decision for an op previously created via
    /// [`OpsRegistry::ingest`].
    ///
    /// Returns the updated record on success.
    /// Returns [`OpsError::NotFound`] if the ID is unknown.
    /// Returns [`OpsError::InvalidTransition`] if the op is not currently
    /// `Pending` (Running / Paused / Completing / Terminated all reject).
    pub fn allow(&self, op_id: &str) -> Result<OpRecord, OpsError> {
        let mut entry = self.ops.get_mut(op_id).ok_or(OpsError::NotFound)?;
        match entry.state {
            OpState::Pending => {
                entry.state = OpState::Running;
                entry.updated_at = chrono::Utc::now().to_rfc3339();
                Ok(entry.clone())
            }
            OpState::Running | OpState::Paused | OpState::Completing | OpState::Terminated => {
                Err(OpsError::InvalidTransition)
            }
        }
    }

    /// Transition `Running → Paused`.
    ///
    /// Returns the updated record on success.
    /// Returns [`OpsError::NotFound`] if the ID is unknown.
    /// Returns [`OpsError::InvalidTransition`] if the op is not currently
    /// `Running` (Pending / Paused / Completing / Terminated all reject).
    pub fn pause(&self, op_id: &str) -> Result<OpRecord, OpsError> {
        let updated = {
            let mut entry = self.ops.get_mut(op_id).ok_or(OpsError::NotFound)?;
            match entry.state {
                OpState::Running => {
                    entry.state = OpState::Paused;
                    entry.updated_at = chrono::Utc::now().to_rfc3339();
                    entry.clone()
                }
                OpState::Pending | OpState::Paused | OpState::Completing | OpState::Terminated => {
                    return Err(OpsError::InvalidTransition);
                }
            }
        };
        self.maybe_publish(op_id, OpControlSignal::Pause);
        Ok(updated)
    }

    /// Transition `Paused → Running`.
    ///
    /// Returns the updated record on success.
    /// Returns [`OpsError::NotFound`] if the ID is unknown.
    /// Returns [`OpsError::InvalidTransition`] if the op is not currently
    /// `Paused` (Pending / Running / Completing / Terminated all reject).
    pub fn resume(&self, op_id: &str) -> Result<OpRecord, OpsError> {
        let updated = {
            let mut entry = self.ops.get_mut(op_id).ok_or(OpsError::NotFound)?;
            match entry.state {
                OpState::Paused => {
                    entry.state = OpState::Running;
                    entry.updated_at = chrono::Utc::now().to_rfc3339();
                    entry.clone()
                }
                OpState::Pending | OpState::Running | OpState::Completing | OpState::Terminated => {
                    return Err(OpsError::InvalidTransition);
                }
            }
        };
        self.maybe_publish(op_id, OpControlSignal::Resume);
        Ok(updated)
    }

    /// Transition `Running → Completing`.
    ///
    /// Intended to be called from the SDK return-channel (PR-D…G) when
    /// the agent reports the action finished successfully. The entry stays
    /// in the registry briefly so the dashboard renders the completion;
    /// sweep policy is deferred to PR-H.
    ///
    /// Returns the updated record on success.
    /// Returns [`OpsError::NotFound`] if the ID is unknown.
    /// Returns [`OpsError::InvalidTransition`] if the op is not currently
    /// `Running` (Pending / Paused / Completing / Terminated all reject).
    pub fn complete(&self, op_id: &str) -> Result<OpRecord, OpsError> {
        let mut entry = self.ops.get_mut(op_id).ok_or(OpsError::NotFound)?;
        match entry.state {
            OpState::Running => {
                entry.state = OpState::Completing;
                entry.updated_at = chrono::Utc::now().to_rfc3339();
                Ok(entry.clone())
            }
            OpState::Pending | OpState::Paused | OpState::Completing | OpState::Terminated => {
                Err(OpsError::InvalidTransition)
            }
        }
    }

    /// Transition `Pending | Running | Paused → Terminated`.
    ///
    /// Idempotent on both terminal states: calling `terminate` on an op
    /// already in `Terminated` or `Completing` returns the existing record
    /// unchanged (no error).
    ///
    /// Returns [`OpsError::NotFound`] if the ID is unknown.
    pub fn terminate(&self, op_id: &str) -> Result<OpRecord, OpsError> {
        let (updated, was_active) = {
            let mut entry = self.ops.get_mut(op_id).ok_or(OpsError::NotFound)?;
            match entry.state {
                OpState::Pending | OpState::Running | OpState::Paused => {
                    entry.state = OpState::Terminated;
                    entry.updated_at = chrono::Utc::now().to_rfc3339();
                    (entry.clone(), true)
                }
                OpState::Completing | OpState::Terminated => (entry.clone(), false),
            }
        };
        if was_active {
            self.maybe_publish(op_id, OpControlSignal::Terminate);
        }
        Ok(updated)
    }

    /// Sweep `Completing` and `Terminated` entries older than `ttl_seconds`.
    ///
    /// Returns the number of entries removed. Intended to be called on a
    /// timer from a background tokio task (see [`spawn_sweep_task`]).
    /// AAASM-1657: keeps the registry from growing unbounded after the
    /// dashboard has had a chance to render the terminal state.
    pub fn sweep(&self, ttl_seconds: i64) -> usize {
        let now = chrono::Utc::now();
        let mut removed = 0usize;
        // Snapshot keys to avoid holding shards across the removal walk.
        let keys: Vec<String> = self
            .ops
            .iter()
            .filter(|r| matches!(r.state, OpState::Completing | OpState::Terminated))
            .map(|r| r.op_id.clone())
            .collect();
        for op_id in keys {
            let too_old = self
                .ops
                .get(&op_id)
                .and_then(|r| chrono::DateTime::parse_from_rfc3339(&r.updated_at).ok())
                .map(|ts| (now - ts.with_timezone(&chrono::Utc)).num_seconds() >= ttl_seconds)
                .unwrap_or(false);
            if too_old {
                self.ops.remove(&op_id);
                self.agents.remove(&op_id);
                removed += 1;
            }
        }
        removed
    }
}

/// Spawn a background tokio task that periodically calls
/// [`OpsRegistry::sweep`] with the configured TTL (AAASM-1657).
///
/// Default tick: every 10 s. Default TTL: 60 s. Returns the `JoinHandle`
/// so the caller can `.abort()` on shutdown if desired.
pub fn spawn_sweep_task(registry: std::sync::Arc<OpsRegistry>) -> tokio::task::JoinHandle<()> {
    spawn_sweep_task_with(registry, std::time::Duration::from_secs(10), 60)
}

/// Test-friendly variant of [`spawn_sweep_task`] with explicit tick + TTL.
pub fn spawn_sweep_task_with(
    registry: std::sync::Arc<OpsRegistry>,
    tick: std::time::Duration,
    ttl_seconds: i64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tick).await;
            let removed = registry.sweep(ttl_seconds);
            if removed > 0 {
                tracing::debug!(swept = removed, "OpsRegistry sweep dropped entries");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_creates_pending_entry() {
        let registry = OpsRegistry::new();
        let record = registry.ingest("trace-1:span-1".to_string());

        assert_eq!(record.op_id, "trace-1:span-1");
        assert_eq!(record.state, OpState::Pending);
        assert_eq!(registry.get("trace-1:span-1").unwrap().state, OpState::Pending);
    }

    #[test]
    fn ingest_is_idempotent_and_preserves_later_state() {
        let registry = OpsRegistry::new();
        let first = registry.ingest("op-1".to_string());
        registry.allow("op-1").unwrap();
        let second = registry.ingest("op-1".to_string());

        // Second ingest must not reset the op back to Pending — the policy
        // service may re-call ingest after the SDK retries the request.
        assert_eq!(second.state, OpState::Running);
        assert_eq!(second.registered_at, first.registered_at);
    }

    #[test]
    fn allow_transitions_pending_to_running() {
        let registry = OpsRegistry::new();
        registry.ingest("op-1".to_string());

        let updated = registry.allow("op-1").unwrap();

        assert_eq!(updated.state, OpState::Running);
    }

    #[test]
    fn allow_rejects_non_pending_states() {
        let registry = OpsRegistry::new();
        registry.register("running-op".to_string());
        registry.ingest("paused-op".to_string());
        registry.allow("paused-op").unwrap();
        registry.pause("paused-op").unwrap();

        assert_eq!(registry.allow("running-op").unwrap_err(), OpsError::InvalidTransition);
        assert_eq!(registry.allow("paused-op").unwrap_err(), OpsError::InvalidTransition);
    }

    #[test]
    fn allow_unknown_op_returns_not_found() {
        let registry = OpsRegistry::new();
        assert_eq!(registry.allow("never-ingested").unwrap_err(), OpsError::NotFound);
    }

    #[test]
    fn complete_transitions_running_to_completing() {
        let registry = OpsRegistry::new();
        registry.register("op-1".to_string());

        let updated = registry.complete("op-1").unwrap();

        assert_eq!(updated.state, OpState::Completing);
    }

    #[test]
    fn complete_rejects_non_running_states() {
        let registry = OpsRegistry::new();
        registry.ingest("pending-op".to_string());
        registry.register("paused-op".to_string());
        registry.pause("paused-op").unwrap();
        registry.register("terminated-op".to_string());
        registry.terminate("terminated-op").unwrap();

        assert_eq!(
            registry.complete("pending-op").unwrap_err(),
            OpsError::InvalidTransition
        );
        assert_eq!(registry.complete("paused-op").unwrap_err(), OpsError::InvalidTransition);
        assert_eq!(
            registry.complete("terminated-op").unwrap_err(),
            OpsError::InvalidTransition
        );
    }

    #[test]
    fn complete_unknown_op_returns_not_found() {
        let registry = OpsRegistry::new();
        assert_eq!(registry.complete("never-registered").unwrap_err(), OpsError::NotFound);
    }

    #[test]
    fn terminate_absorbs_pending_into_terminated() {
        // Important: a policy Deny path (PR-H) needs Pending → Terminated.
        let registry = OpsRegistry::new();
        registry.ingest("op-1".to_string());

        let updated = registry.terminate("op-1").unwrap();

        assert_eq!(updated.state, OpState::Terminated);
    }

    #[test]
    fn terminate_is_idempotent_on_completing() {
        let registry = OpsRegistry::new();
        registry.register("op-1".to_string());
        registry.complete("op-1").unwrap();

        let updated = registry.terminate("op-1").unwrap();

        // Completing is terminal — terminate is a no-op rather than an error.
        assert_eq!(updated.state, OpState::Completing);
    }

    // ── AAASM-1657: publisher + sweep ──────────────────────────────────────

    fn agent(id: &str) -> AgentId {
        AgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: id.into(),
        }
    }

    #[tokio::test]
    async fn pause_publishes_pause_signal_to_subscribed_agent() {
        let publisher = std::sync::Arc::new(OpControlPublisher::new());
        let registry = OpsRegistry::new().with_publisher(std::sync::Arc::clone(&publisher));
        let mut rx = publisher.subscribe();

        registry.ingest_with_agent("op-1".to_string(), agent("a1"));
        registry.allow("op-1").unwrap();
        registry.pause("op-1").unwrap();

        let envelope = rx.recv().await.unwrap();
        assert_eq!(envelope.message.op_id, "op-1");
        assert_eq!(envelope.message.signal, OpControlSignal::Pause as i32);
        assert_eq!(envelope.agent_id.agent_id, "a1");
    }

    #[tokio::test]
    async fn resume_publishes_resume_signal() {
        let publisher = std::sync::Arc::new(OpControlPublisher::new());
        let registry = OpsRegistry::new().with_publisher(std::sync::Arc::clone(&publisher));
        registry.ingest_with_agent("op-2".to_string(), agent("a1"));
        registry.allow("op-2").unwrap();
        registry.pause("op-2").unwrap();
        let mut rx = publisher.subscribe();

        registry.resume("op-2").unwrap();

        let envelope = rx.recv().await.unwrap();
        assert_eq!(envelope.message.signal, OpControlSignal::Resume as i32);
    }

    #[tokio::test]
    async fn terminate_publishes_terminate_signal_only_on_active_states() {
        let publisher = std::sync::Arc::new(OpControlPublisher::new());
        let registry = OpsRegistry::new().with_publisher(std::sync::Arc::clone(&publisher));
        registry.ingest_with_agent("op-3".to_string(), agent("a1"));
        registry.allow("op-3").unwrap();
        let mut rx = publisher.subscribe();

        registry.terminate("op-3").unwrap();
        let envelope = rx.recv().await.unwrap();
        assert_eq!(envelope.message.signal, OpControlSignal::Terminate as i32);

        // Calling terminate again on the now-Terminated op is idempotent
        // and must NOT re-publish.
        registry.terminate("op-3").unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
                .await
                .is_err(),
            "terminate on already-terminated op must not re-publish",
        );
    }

    #[tokio::test]
    async fn no_publish_when_op_has_no_agent_id() {
        // An op registered via the legacy `ingest` (no agent_id) has no
        // routing target — transitions must silently skip publishing.
        let publisher = std::sync::Arc::new(OpControlPublisher::new());
        let registry = OpsRegistry::new().with_publisher(std::sync::Arc::clone(&publisher));
        let mut rx = publisher.subscribe();

        registry.ingest("op-4".to_string());
        registry.allow("op-4").unwrap();
        registry.pause("op-4").unwrap();

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
                .await
                .is_err(),
            "transitions on agent-less ops must not publish",
        );
    }

    // ── AAASM-3881: operator agent-wide / global halt emission ─────────────

    #[tokio::test]
    async fn halt_agent_publishes_under_reserved_agent_op_id() {
        let publisher = std::sync::Arc::new(OpControlPublisher::new());
        let registry = OpsRegistry::new().with_publisher(std::sync::Arc::clone(&publisher));
        let mut rx = publisher.subscribe();

        let emitted = registry.halt_agent(agent("a1"), OpControlSignal::Terminate);
        assert!(emitted, "publisher attached — emission must report success");

        let envelope = rx.recv().await.unwrap();
        assert!(!envelope.global);
        assert_eq!(envelope.agent_id.agent_id, "a1");
        assert_eq!(envelope.message.op_id, "agent:a1");
        assert_eq!(envelope.message.signal, OpControlSignal::Terminate as i32);
    }

    #[tokio::test]
    async fn halt_global_publishes_under_reserved_global_op_id() {
        let publisher = std::sync::Arc::new(OpControlPublisher::new());
        let registry = OpsRegistry::new().with_publisher(std::sync::Arc::clone(&publisher));
        let mut rx = publisher.subscribe();

        let emitted = registry.halt_global(OpControlSignal::Pause);
        assert!(emitted);

        let envelope = rx.recv().await.unwrap();
        assert!(envelope.global);
        assert_eq!(envelope.message.op_id, "*");
        assert_eq!(envelope.message.signal, OpControlSignal::Pause as i32);
    }

    #[test]
    fn halt_without_publisher_reports_unconfigured() {
        // No publisher attached → the operator surface can return an explicit
        // "channel unavailable" instead of a silent no-op.
        let registry = OpsRegistry::new();
        assert!(!registry.halt_agent(agent("a1"), OpControlSignal::Terminate));
        assert!(!registry.halt_global(OpControlSignal::Terminate));
    }

    #[test]
    fn sweep_removes_terminated_entries_older_than_ttl() {
        let registry = OpsRegistry::new();
        registry.register("op-old".to_string());
        registry.terminate("op-old").unwrap();
        // Backdate the entry by 2 minutes so the 60s TTL window passes.
        let backdated = (chrono::Utc::now() - chrono::Duration::seconds(120)).to_rfc3339();
        registry.ops.alter("op-old", |_, mut r| {
            r.updated_at = backdated.clone();
            r
        });
        // A second entry within the window must NOT be swept.
        registry.register("op-fresh".to_string());
        registry.terminate("op-fresh").unwrap();

        let removed = registry.sweep(60);
        assert_eq!(removed, 1);
        assert!(registry.get("op-old").is_none());
        assert!(registry.get("op-fresh").is_some());
    }

    #[test]
    fn sweep_leaves_running_and_paused_alone() {
        let registry = OpsRegistry::new();
        registry.register("running".to_string());
        registry.register("paused".to_string());
        registry.pause("paused").unwrap();

        let removed = registry.sweep(0);
        assert_eq!(removed, 0);
        assert!(registry.get("running").is_some());
        assert!(registry.get("paused").is_some());
    }
}
