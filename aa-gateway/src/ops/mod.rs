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
}

impl Default for OpsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OpsRegistry {
    pub fn new() -> Self {
        Self { ops: DashMap::new() }
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

    /// Return a snapshot of the named op, or `None` if it is not registered.
    pub fn get(&self, op_id: &str) -> Option<OpRecord> {
        self.ops.get(op_id).map(|r| r.clone())
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
        let mut entry = self.ops.get_mut(op_id).ok_or(OpsError::NotFound)?;
        match entry.state {
            OpState::Running => {
                entry.state = OpState::Paused;
                entry.updated_at = chrono::Utc::now().to_rfc3339();
                Ok(entry.clone())
            }
            OpState::Pending | OpState::Paused | OpState::Completing | OpState::Terminated => {
                Err(OpsError::InvalidTransition)
            }
        }
    }

    /// Transition `Paused → Running`.
    ///
    /// Returns the updated record on success.
    /// Returns [`OpsError::NotFound`] if the ID is unknown.
    /// Returns [`OpsError::InvalidTransition`] if the op is not currently
    /// `Paused` (Pending / Running / Completing / Terminated all reject).
    pub fn resume(&self, op_id: &str) -> Result<OpRecord, OpsError> {
        let mut entry = self.ops.get_mut(op_id).ok_or(OpsError::NotFound)?;
        match entry.state {
            OpState::Paused => {
                entry.state = OpState::Running;
                entry.updated_at = chrono::Utc::now().to_rfc3339();
                Ok(entry.clone())
            }
            OpState::Pending | OpState::Running | OpState::Completing | OpState::Terminated => {
                Err(OpsError::InvalidTransition)
            }
        }
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
        let mut entry = self.ops.get_mut(op_id).ok_or(OpsError::NotFound)?;
        match entry.state {
            OpState::Pending | OpState::Running | OpState::Paused => {
                entry.state = OpState::Terminated;
                entry.updated_at = chrono::Utc::now().to_rfc3339();
                Ok(entry.clone())
            }
            OpState::Completing | OpState::Terminated => Ok(entry.clone()),
        }
    }
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
}
