//! Human-approval request queue for Agent Assembly governance.
//!
//! When the policy engine returns [`aa_core::PolicyResult::RequiresApproval`],
//! the runtime submits an [`ApprovalRequest`] here. The request stays pending
//! until a human operator calls [`ApprovalQueue::decide`], or the per-request
//! timeout elapses and the queue auto-resolves it as [`ApprovalDecision::TimedOut`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use uuid::Uuid;

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AuditEntry, AuditEventType};

/// Capacity of the internal approval event broadcast channel.
const APPROVAL_EVENT_CHANNEL_CAPACITY: usize = 64;

// ---------------------------------------------------------------------------
// Public type aliases
// ---------------------------------------------------------------------------

/// Opaque identifier for a single pending approval request.
pub type ApprovalRequestId = Uuid;

/// A one-shot receiver that resolves to the [`ApprovalDecision`] once a human
/// (or the timeout task) settles the request.
pub type ApprovalFuture = tokio::sync::oneshot::Receiver<ApprovalDecision>;

// ---------------------------------------------------------------------------
// ApprovalRequest
// ---------------------------------------------------------------------------

/// All data needed to present a pending action to a human operator.
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    /// Unique ID for this request (UUID v4).
    pub request_id: ApprovalRequestId,
    /// The agent that triggered the approval requirement.
    pub agent_id: String,
    /// Human-readable description of the action awaiting approval.
    pub action: String,
    /// Name or description of the policy condition that triggered this request.
    pub condition_triggered: String,
    /// Unix epoch timestamp (seconds) when the request was submitted.
    pub submitted_at: u64,
    /// Seconds before the queue auto-resolves the request as timed-out.
    pub timeout_secs: u64,
    /// Policy decision to apply if the request times out without a human decision.
    pub fallback: aa_core::PolicyResult,
    /// Team identifier extracted from the agent context; used for routing.
    pub team_id: Option<String>,
    /// Per-policy escalation timeout override in seconds.
    ///
    /// When set, overrides the team-level `escalation_timeout_secs` for the
    /// escalation window.  `None` defers to the team config.
    pub timeout_override_secs: Option<u64>,
    /// Per-policy escalation role override.
    ///
    /// When set, overrides the team-level `escalation_approvers` list.
    /// `None` defers to the team config.
    pub escalation_role_override: Option<String>,
}

// ---------------------------------------------------------------------------
// PendingApprovalRequest  (safe, outward-facing view — no channel or fallback)
// ---------------------------------------------------------------------------

/// A redacted, outward-facing snapshot of a pending request.
///
/// Returned by [`ApprovalQueue::list`] so callers cannot access the internal
/// one-shot sender or fallback policy.
#[derive(Debug, Clone)]
pub struct PendingApprovalRequest {
    /// Unique ID for this request.
    pub request_id: ApprovalRequestId,
    /// The agent that triggered the approval requirement.
    pub agent_id: String,
    /// Human-readable description of the action awaiting approval.
    pub action: String,
    /// Name or description of the policy condition that triggered this request.
    pub condition_triggered: String,
    /// Unix epoch timestamp (seconds) when the request was submitted.
    pub submitted_at: u64,
    /// Seconds before the request times out.
    pub timeout_secs: u64,
    /// Team identifier; `None` when the agent has no team affiliation.
    pub team_id: Option<String>,
    /// Current routing status (e.g. `"routed:team-x"`, `"escalated:org-admin"`).
    ///
    /// Set to `None` until a routing decision is recorded via
    /// [`ApprovalQueue::update_routing_status`].
    pub routing_status: Option<String>,
}

// ---------------------------------------------------------------------------
// ApprovalDecision  (placeholder — full definition added in next commit)
// ---------------------------------------------------------------------------

/// The outcome of a pending [`ApprovalRequest`].
#[derive(Debug, Clone)]
pub enum ApprovalDecision {
    /// A human operator approved the action.
    Approved {
        /// Identifier of the operator who approved.
        by: String,
        /// Optional free-text rationale.
        reason: Option<String>,
    },
    /// A human operator rejected the action.
    Rejected {
        /// Identifier of the operator who rejected.
        by: String,
        /// Mandatory explanation for the rejection.
        reason: String,
    },
    /// The timeout elapsed before a human decided; the fallback policy applies.
    TimedOut {
        /// The fallback [`aa_core::PolicyResult`] originally attached to the request.
        fallback: aa_core::PolicyResult,
    },
}

// ---------------------------------------------------------------------------
// ApprovalError
// ---------------------------------------------------------------------------

/// Errors returned by [`ApprovalQueue::decide`].
#[derive(Debug, PartialEq, Eq)]
pub enum ApprovalError {
    /// No pending request exists for the given ID (already resolved or never submitted).
    NotFound,
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "approval request not found"),
        }
    }
}

impl std::error::Error for ApprovalError {}

// ---------------------------------------------------------------------------
// ApprovalQueue
// ---------------------------------------------------------------------------

/// Concurrent, in-memory store of pending approval requests.
///
/// Constructed via [`ApprovalQueue::new`], which returns an [`Arc`] so the
/// queue can be cloned cheaply across tasks (e.g., the timeout spawner holds
/// a back-reference).
pub struct ApprovalQueue {
    pending: DashMap<ApprovalRequestId, (ApprovalRequest, oneshot::Sender<ApprovalDecision>)>,
    /// Mutable routing-status overrides; updated when escalation fires.
    routing_statuses: DashMap<ApprovalRequestId, String>,
    audit_tx: Option<mpsc::Sender<AuditEntry>>,
    audit_seq: AtomicU64,
    audit_last_hash: Mutex<[u8; 32]>,
    event_tx: broadcast::Sender<ApprovalRequest>,
}

/// Hash a string into a 16-byte identifier using SHA-256 truncation.
fn hash_to_16(s: &str) -> [u8; 16] {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

impl ApprovalQueue {
    /// Creates a new, empty queue wrapped in an [`Arc`].
    pub fn new() -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(APPROVAL_EVENT_CHANNEL_CAPACITY);
        Arc::new(Self {
            pending: DashMap::new(),
            routing_statuses: DashMap::new(),
            audit_tx: None,
            audit_seq: AtomicU64::new(0),
            audit_last_hash: Mutex::new([0u8; 32]),
            event_tx,
        })
    }

    /// Creates a new queue with audit logging enabled.
    ///
    /// Approval decisions (Approved, Rejected, TimedOut) will be recorded
    /// as `AuditEntry` values on the given channel.
    pub fn with_audit(audit_tx: mpsc::Sender<AuditEntry>, initial_hash: [u8; 32]) -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(APPROVAL_EVENT_CHANNEL_CAPACITY);
        Arc::new(Self {
            pending: DashMap::new(),
            routing_statuses: DashMap::new(),
            audit_tx: Some(audit_tx),
            audit_seq: AtomicU64::new(0),
            audit_last_hash: Mutex::new(initial_hash),
            event_tx,
        })
    }

    /// Subscribe to approval request events.
    ///
    /// Each call to [`submit`](Self::submit) broadcasts a clone of the
    /// [`ApprovalRequest`] to all active subscribers. Subscribers that fall
    /// behind receive a `RecvError::Lagged` indicating how many events were
    /// dropped.
    pub fn subscribe_events(&self) -> broadcast::Receiver<ApprovalRequest> {
        self.event_tx.subscribe()
    }

    /// Returns a snapshot of all currently pending requests.
    ///
    /// The snapshot is consistent at the moment of the call; entries submitted
    /// or resolved concurrently may not appear.
    pub fn list(&self) -> Vec<PendingApprovalRequest> {
        self.pending
            .iter()
            .map(|entry| {
                let req = &entry.value().0;
                let routing_status = self.routing_statuses.get(&req.request_id).map(|s| s.clone());
                PendingApprovalRequest {
                    request_id: req.request_id,
                    agent_id: req.agent_id.clone(),
                    action: req.action.clone(),
                    condition_triggered: req.condition_triggered.clone(),
                    submitted_at: req.submitted_at,
                    timeout_secs: req.timeout_secs,
                    team_id: req.team_id.clone(),
                    routing_status,
                }
            })
            .collect()
    }

    /// Record or update the routing status for a pending request.
    ///
    /// Used by the escalation handler to transition status from
    /// `"routed:{team}"` to `"escalated:{approvers}"` when the timer fires.
    /// Silently ignored when the request is no longer pending.
    pub fn update_routing_status(&self, id: ApprovalRequestId, status: String) {
        if self.pending.contains_key(&id) {
            self.routing_statuses.insert(id, status);
        }
    }

    /// Apply an [`ApprovalDecision`] to the request identified by `id`.
    ///
    /// Returns `Err(ApprovalError::NotFound)` if no pending request exists for
    /// `id` (already resolved, timed out, or never submitted).
    pub fn decide(&self, id: ApprovalRequestId, decision: ApprovalDecision) -> Result<(), ApprovalError> {
        if self.resolve(id, decision) {
            Ok(())
        } else {
            Err(ApprovalError::NotFound)
        }
    }

    /// Remove and settle the request identified by `id`.
    ///
    /// Returns `true` if the entry existed and the sender was consumed, `false`
    /// if the entry was already gone (idempotent — a second call for the same
    /// `id` is a safe no-op).
    fn resolve(&self, id: ApprovalRequestId, decision: ApprovalDecision) -> bool {
        self.routing_statuses.remove(&id);
        if let Some((_key, (req, tx))) = self.pending.remove(&id) {
            let (event_type_str, decided_by) = match &decision {
                ApprovalDecision::Approved { by, .. } => ("ApprovalGranted", by.clone()),
                ApprovalDecision::Rejected { by, .. } => ("ApprovalDenied", by.clone()),
                ApprovalDecision::TimedOut { .. } => ("ApprovalTimedOut", "timeout".to_string()),
            };
            tracing::info!(
                event_type = event_type_str,
                request_id = %req.request_id,
                agent_id = %req.agent_id,
                action = %req.action,
                decided_by = %decided_by,
                "approval decision recorded"
            );

            // Record an audit entry for the approval decision.
            if let Some(audit_tx) = &self.audit_tx {
                let audit_event_type = match &decision {
                    ApprovalDecision::Approved { .. } => AuditEventType::ApprovalGranted,
                    ApprovalDecision::Rejected { .. } => AuditEventType::ApprovalDenied,
                    ApprovalDecision::TimedOut { .. } => AuditEventType::ApprovalTimedOut,
                };
                let seq = self.audit_seq.fetch_add(1, Ordering::Relaxed);
                let agent_id = AgentId::from_bytes(hash_to_16(&req.agent_id));
                let session_id = SessionId::from_bytes(hash_to_16(&req.request_id.to_string()));
                let timestamp_ns = Timestamp::from(SystemTime::now()).as_nanos();

                let payload = serde_json::json!({
                    "request_id": req.request_id.to_string(),
                    "agent_id": &req.agent_id,
                    "action": &req.action,
                    "condition_triggered": &req.condition_triggered,
                    "decided_by": &decided_by,
                })
                .to_string();

                // Use try_lock to avoid blocking the resolve path; fall back to
                // a broken chain link rather than deadlocking.
                let (entry, hash_updated) = match self.audit_last_hash.try_lock() {
                    Ok(mut guard) => {
                        let entry = AuditEntry::new(
                            seq,
                            timestamp_ns,
                            audit_event_type,
                            agent_id,
                            session_id,
                            payload,
                            *guard,
                        );
                        *guard = *entry.entry_hash();
                        (entry, true)
                    }
                    Err(_) => {
                        let entry = AuditEntry::new(
                            seq,
                            timestamp_ns,
                            audit_event_type,
                            agent_id,
                            session_id,
                            payload,
                            [0u8; 32],
                        );
                        (entry, false)
                    }
                };

                if !hash_updated {
                    tracing::debug!(seq, "audit hash chain lock contended — entry uses zero previous_hash");
                }

                if let Err(e) = audit_tx.try_send(entry) {
                    match e {
                        mpsc::error::TrySendError::Full(_) => {
                            tracing::warn!(seq, "audit channel full — approval event dropped");
                        }
                        mpsc::error::TrySendError::Closed(_) => {
                            tracing::error!("audit channel closed — AuditWriter task has exited");
                        }
                    }
                }
            }

            // Ignore send errors: the receiver may have been dropped (caller
            // gave up waiting), which is not a failure on our side.
            let _ = tx.send(decision);
            true
        } else {
            false
        }
    }

    /// Submit a new approval request and start its timeout task.
    ///
    /// Returns the request's [`ApprovalRequestId`] and an [`ApprovalFuture`]
    /// that resolves when the request is settled (approved, rejected, or timed
    /// out).
    ///
    /// # Timeout behaviour
    ///
    /// A `tokio::spawn`ed task sleeps for `request.timeout_secs` seconds, then
    /// calls `resolve(TimedOut)`. Because [`resolve`] is idempotent, a human
    /// decision that arrives before the timeout simply wins the race; the
    /// timeout task's subsequent `resolve` call becomes a no-op.
    pub fn submit(self: &Arc<Self>, request: ApprovalRequest) -> (ApprovalRequestId, ApprovalFuture) {
        let id = request.request_id;
        let timeout_secs = request.timeout_secs;
        let fallback = request.fallback.clone();

        tracing::info!(
            event_type = "ApprovalRequested",
            request_id = %id,
            agent_id = %request.agent_id,
            action = %request.action,
            condition_triggered = %request.condition_triggered,
            timeout_secs,
            "approval requested"
        );

        // Record the submission as an ApprovalRequested audit entry.
        if let Some(audit_tx) = &self.audit_tx {
            let seq = self.audit_seq.fetch_add(1, Ordering::Relaxed);
            let agent_id = AgentId::from_bytes(hash_to_16(&request.agent_id));
            let session_id = SessionId::from_bytes(hash_to_16(&id.to_string()));
            let timestamp_ns = Timestamp::from(SystemTime::now()).as_nanos();

            let payload = serde_json::json!({
                "request_id": id.to_string(),
                "agent_id": &request.agent_id,
                "action": &request.action,
                "condition_triggered": &request.condition_triggered,
                "timeout_secs": request.timeout_secs,
            })
            .to_string();

            if let Ok(mut guard) = self.audit_last_hash.try_lock() {
                let entry = AuditEntry::new(
                    seq,
                    timestamp_ns,
                    AuditEventType::ApprovalRequested,
                    agent_id,
                    session_id,
                    payload,
                    *guard,
                );
                *guard = *entry.entry_hash();
                let _ = audit_tx.try_send(entry);
            }
        }

        let (tx, rx) = oneshot::channel();
        // Broadcast the request to event subscribers (webhook delivery, etc.).
        // Ignore send errors — no subscribers means no delivery needed.
        let _ = self.event_tx.send(request.clone());
        self.pending.insert(id, (request, tx));

        // Spawn the timeout enforcer.  The Arc clone keeps the queue alive
        // for the duration of the sleep even if all other holders drop.
        let queue = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(timeout_secs)).await;
            queue.resolve(id, ApprovalDecision::TimedOut { fallback });
        });

        (id, rx)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- type aliases ---

    #[test]
    fn approval_request_id_is_uuid() {
        let id: ApprovalRequestId = Uuid::new_v4();
        assert!(!id.is_nil());
    }

    // --- ApprovalRequest fields ---

    #[test]
    fn approval_request_fields_are_accessible() {
        let req = ApprovalRequest {
            request_id: Uuid::new_v4(),
            agent_id: "agent-1".to_string(),
            action: "read_file /etc/passwd".to_string(),
            condition_triggered: "sensitive-file-access".to_string(),
            submitted_at: 1_700_000_000,
            timeout_secs: 30,
            fallback: aa_core::PolicyResult::Deny {
                reason: "timed out".to_string(),
            },
            team_id: None,
            timeout_override_secs: None,
            escalation_role_override: None,
        };
        assert_eq!(req.agent_id, "agent-1");
        assert_eq!(req.timeout_secs, 30);
        assert!(!req.request_id.is_nil());
    }

    // --- ApprovalDecision ---

    #[test]
    fn approval_decision_approved_fields() {
        let d = ApprovalDecision::Approved {
            by: "alice".to_string(),
            reason: Some("looks safe".to_string()),
        };
        if let ApprovalDecision::Approved { by, reason } = d {
            assert_eq!(by, "alice");
            assert_eq!(reason, Some("looks safe".to_string()));
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn approval_decision_rejected_fields() {
        let d = ApprovalDecision::Rejected {
            by: "bob".to_string(),
            reason: "policy violation".to_string(),
        };
        if let ApprovalDecision::Rejected { by, reason } = d {
            assert_eq!(by, "bob");
            assert_eq!(reason, "policy violation");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn approval_decision_timed_out_carries_fallback() {
        let fallback = aa_core::PolicyResult::Deny {
            reason: "expired".to_string(),
        };
        let d = ApprovalDecision::TimedOut {
            fallback: fallback.clone(),
        };
        if let ApprovalDecision::TimedOut { fallback: f } = d {
            assert_eq!(f, fallback);
        } else {
            panic!("wrong variant");
        }
    }

    // --- ApprovalError ---

    #[test]
    fn approval_error_not_found_display() {
        let e = ApprovalError::NotFound;
        assert_eq!(e.to_string(), "approval request not found");
    }

    #[test]
    fn approval_error_not_found_eq() {
        assert_eq!(ApprovalError::NotFound, ApprovalError::NotFound);
    }

    // --- PendingApprovalRequest ---

    #[test]
    fn pending_approval_request_fields_match_source() {
        let id = Uuid::new_v4();
        let pending = PendingApprovalRequest {
            request_id: id,
            agent_id: "agent-1".to_string(),
            action: "read_file /etc/passwd".to_string(),
            condition_triggered: "sensitive-file-access".to_string(),
            submitted_at: 1_700_000_000,
            timeout_secs: 60,
            team_id: None,
            routing_status: None,
        };
        assert_eq!(pending.request_id, id);
        assert_eq!(pending.agent_id, "agent-1");
        assert_eq!(pending.timeout_secs, 60);
    }

    // --- ApprovalQueue::new and list ---

    #[test]
    fn new_queue_list_is_empty() {
        let q = ApprovalQueue::new();
        assert!(q.list().is_empty());
    }

    // --- ApprovalQueue::decide (no pending entry) ---

    #[test]
    fn decide_unknown_id_returns_not_found() {
        let q = ApprovalQueue::new();
        let result = q.decide(
            Uuid::new_v4(),
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: None,
            },
        );
        assert_eq!(result, Err(ApprovalError::NotFound));
    }

    fn make_request(timeout_secs: u64) -> ApprovalRequest {
        ApprovalRequest {
            request_id: Uuid::new_v4(),
            agent_id: "agent-1".to_string(),
            action: "read_file /etc/passwd".to_string(),
            condition_triggered: "sensitive-file-access".to_string(),
            submitted_at: 1_700_000_000,
            timeout_secs,
            fallback: aa_core::PolicyResult::Deny {
                reason: "timed out".to_string(),
            },
            team_id: None,
            timeout_override_secs: None,
            escalation_role_override: None,
        }
    }

    // --- ApprovalQueue::submit ---

    #[tokio::test]
    async fn submit_then_approve_resolves_future() {
        let q = ApprovalQueue::new();
        let req = make_request(60);
        let id = req.request_id;
        let (_rid, fut) = q.submit(req);

        q.decide(
            id,
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: None,
            },
        )
        .expect("decide should succeed");

        let decision = fut.await.expect("future should resolve");
        assert!(matches!(decision, ApprovalDecision::Approved { .. }));
    }

    #[tokio::test]
    async fn submit_then_reject_resolves_future() {
        let q = ApprovalQueue::new();
        let req = make_request(60);
        let id = req.request_id;
        let (_rid, fut) = q.submit(req);

        q.decide(
            id,
            ApprovalDecision::Rejected {
                by: "bob".to_string(),
                reason: "not allowed".to_string(),
            },
        )
        .expect("decide should succeed");

        let decision = fut.await.expect("future should resolve");
        assert!(matches!(decision, ApprovalDecision::Rejected { .. }));
    }

    #[tokio::test]
    async fn decide_after_resolve_returns_not_found() {
        let q = ApprovalQueue::new();
        let req = make_request(60);
        let id = req.request_id;
        let (_rid, _fut) = q.submit(req);

        q.decide(
            id,
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: None,
            },
        )
        .expect("first decide should succeed");

        let result = q.decide(
            id,
            ApprovalDecision::Rejected {
                by: "eve".to_string(),
                reason: "too late".to_string(),
            },
        );
        assert_eq!(result, Err(ApprovalError::NotFound));
    }

    #[tokio::test(start_paused = true)]
    async fn submit_times_out_after_timeout_secs() {
        let q = ApprovalQueue::new();
        let req = make_request(5);
        let (_rid, fut) = q.submit(req);

        tokio::time::advance(std::time::Duration::from_secs(6)).await;

        let decision = fut.await.expect("future should resolve after timeout");
        assert!(matches!(decision, ApprovalDecision::TimedOut { .. }));
    }

    #[tokio::test]
    async fn list_reflects_pending_and_clears_after_decide() {
        let q = ApprovalQueue::new();
        let req = make_request(60);
        let id = req.request_id;
        let (_rid, _fut) = q.submit(req);

        let pending = q.list();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, id);

        q.decide(
            id,
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: None,
            },
        )
        .expect("decide should succeed");

        assert!(q.list().is_empty());
    }

    #[tokio::test]
    async fn subscribe_events_receives_submitted_request() {
        let q = ApprovalQueue::new();
        let mut rx = q.subscribe_events();

        let req = make_request(60);
        let expected_id = req.request_id;
        let (_rid, _fut) = q.submit(req);

        let received = rx.recv().await.expect("should receive approval event");
        assert_eq!(received.request_id, expected_id);
        assert_eq!(received.agent_id, "agent-1");
    }

    #[tokio::test]
    async fn submit_100_concurrent_requests_all_resolve() {
        use std::collections::HashMap;

        let q = ApprovalQueue::new();
        let n = 100_usize;

        let mut futures_map = HashMap::new();
        for _ in 0..n {
            let req = make_request(60);
            let id = req.request_id;
            let (_rid, fut) = q.submit(req);
            futures_map.insert(id, fut);
        }

        assert_eq!(q.list().len(), n);

        let ids: Vec<_> = futures_map.keys().copied().collect();
        for id in &ids {
            q.decide(
                *id,
                ApprovalDecision::Approved {
                    by: "operator".to_string(),
                    reason: None,
                },
            )
            .expect("decide should succeed for each request");
        }

        for (_id, fut) in futures_map {
            let decision = fut.await.expect("future should resolve");
            assert!(matches!(decision, ApprovalDecision::Approved { .. }));
        }

        assert!(q.list().is_empty());
    }

    // --- Audit logging tests ---

    #[tokio::test]
    async fn submit_with_audit_emits_approval_requested_entry() {
        let (tx, mut rx) = mpsc::channel::<AuditEntry>(64);
        let q = ApprovalQueue::with_audit(tx, [0u8; 32]);

        let req = make_request(60);
        let _id = req.request_id;
        let (_rid, _fut) = q.submit(req);

        let entry = rx.try_recv().expect("should receive ApprovalRequested entry");
        assert_eq!(entry.event_type(), AuditEventType::ApprovalRequested);
        assert_eq!(entry.seq(), 0);
    }

    #[tokio::test]
    async fn decide_approved_emits_approval_granted_entry() {
        let (tx, mut rx) = mpsc::channel::<AuditEntry>(64);
        let q = ApprovalQueue::with_audit(tx, [0u8; 32]);

        let req = make_request(60);
        let id = req.request_id;
        let (_rid, _fut) = q.submit(req);

        // Drain the ApprovalRequested entry from submit.
        let _ = rx.try_recv().expect("submit entry");

        q.decide(
            id,
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: None,
            },
        )
        .expect("decide should succeed");

        let entry = rx.try_recv().expect("should receive ApprovalGranted entry");
        assert_eq!(entry.event_type(), AuditEventType::ApprovalGranted);
        assert_eq!(entry.seq(), 1);
    }

    #[tokio::test]
    async fn decide_rejected_emits_approval_denied_entry() {
        let (tx, mut rx) = mpsc::channel::<AuditEntry>(64);
        let q = ApprovalQueue::with_audit(tx, [0u8; 32]);

        let req = make_request(60);
        let id = req.request_id;
        let (_rid, _fut) = q.submit(req);

        let _ = rx.try_recv().expect("submit entry");

        q.decide(
            id,
            ApprovalDecision::Rejected {
                by: "bob".to_string(),
                reason: "not allowed".to_string(),
            },
        )
        .expect("decide should succeed");

        let entry = rx.try_recv().expect("should receive ApprovalDenied entry");
        assert_eq!(entry.event_type(), AuditEventType::ApprovalDenied);
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_emits_approval_timed_out_entry() {
        let (tx, mut rx) = mpsc::channel::<AuditEntry>(64);
        let q = ApprovalQueue::with_audit(tx, [0u8; 32]);

        let req = make_request(5);
        let (_rid, _fut) = q.submit(req);

        let _ = rx.try_recv().expect("submit entry");

        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        // Yield to let the spawned timeout task run after time advances.
        tokio::task::yield_now().await;

        let entry = rx.recv().await.expect("should receive ApprovalTimedOut entry");
        assert_eq!(entry.event_type(), AuditEventType::ApprovalTimedOut);
    }

    #[tokio::test]
    async fn audit_entries_form_hash_chain() {
        let (tx, mut rx) = mpsc::channel::<AuditEntry>(64);
        let q = ApprovalQueue::with_audit(tx, [0u8; 32]);

        let req = make_request(60);
        let id = req.request_id;
        let (_rid, _fut) = q.submit(req);

        q.decide(
            id,
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: None,
            },
        )
        .expect("decide should succeed");

        let entry0 = rx.try_recv().expect("first entry");
        let entry1 = rx.try_recv().expect("second entry");

        // First entry's previous_hash should be the initial hash (all zeros).
        assert_eq!(*entry0.previous_hash(), [0u8; 32]);
        // Second entry's previous_hash should equal the first entry's entry_hash.
        assert_eq!(entry1.previous_hash(), entry0.entry_hash());
        // Hash chain entries should have distinct hashes.
        assert_ne!(entry0.entry_hash(), entry1.entry_hash());
    }

    #[tokio::test]
    async fn no_audit_without_audit_channel() {
        // Using ApprovalQueue::new() (no audit channel) should not panic or fail.
        let q = ApprovalQueue::new();
        let req = make_request(60);
        let id = req.request_id;
        let (_rid, fut) = q.submit(req);

        q.decide(
            id,
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: None,
            },
        )
        .expect("decide should succeed");

        let decision = fut.await.expect("future should resolve");
        assert!(matches!(decision, ApprovalDecision::Approved { .. }));
    }
}
