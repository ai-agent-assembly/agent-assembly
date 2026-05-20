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
