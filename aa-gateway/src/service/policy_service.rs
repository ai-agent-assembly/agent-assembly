//! `PolicyService` tonic trait implementation wiring gRPC RPCs to `PolicyEngine`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use tokio::sync::{mpsc, Mutex};
use tonic::{Request, Response, Status};

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AuditEntry, AuditEventType};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse};

use aa_runtime::approval::{ApprovalQueue, ApprovalRequest};

use crate::engine::{DenyAction, EvaluationResult, PolicyEngine};
use crate::registry::convert::proto_agent_id_to_key;
use crate::registry::{AgentRegistry, SuspendReason};
use crate::service::convert;

/// gRPC service implementation wiring `CheckAction` / `BatchCheck` to [`PolicyEngine`].
pub struct PolicyServiceImpl {
    engine: Arc<PolicyEngine>,
    registry: Option<Arc<AgentRegistry>>,
    approval_queue: Option<Arc<ApprovalQueue>>,
    audit_tx: mpsc::Sender<AuditEntry>,
    audit_drops: Arc<AtomicU64>,
    seq: AtomicU64,
    last_hash: Mutex<[u8; 32]>,
}

impl PolicyServiceImpl {
    /// Create a new service backed by the given policy engine and audit channel.
    ///
    /// `initial_hash` should be the `entry_hash` of the last persisted audit entry
    /// (obtained via [`AuditWriter::read_last_hash`]) so the hash chain is maintained
    /// across process restarts. Pass `[0u8; 32]` for a fresh chain.
    pub fn new(
        engine: Arc<PolicyEngine>,
        audit_tx: mpsc::Sender<AuditEntry>,
        audit_drops: Arc<AtomicU64>,
        initial_hash: [u8; 32],
    ) -> Self {
        Self {
            engine,
            registry: None,
            approval_queue: None,
            audit_tx,
            audit_drops,
            seq: AtomicU64::new(0),
            last_hash: Mutex::new(initial_hash),
        }
    }

    /// Create a new service with an agent registry attached.
    ///
    /// When a registry is provided, the service can suspend agents when the
    /// policy engine returns `DenyAction::SuspendAgent` on budget exceeded.
    pub fn with_registry(
        engine: Arc<PolicyEngine>,
        registry: Arc<AgentRegistry>,
        audit_tx: mpsc::Sender<AuditEntry>,
        audit_drops: Arc<AtomicU64>,
        initial_hash: [u8; 32],
    ) -> Self {
        Self {
            engine,
            registry: Some(registry),
            approval_queue: None,
            audit_tx,
            audit_drops,
            seq: AtomicU64::new(0),
            last_hash: Mutex::new(initial_hash),
        }
    }

    /// Create a new service with both an agent registry and approval queue.
    ///
    /// When an approval queue is provided, actions that require human approval
    /// are submitted to the queue and the gRPC call blocks until the operator
    /// decides (or the timeout elapses).
    pub fn with_registry_and_approval(
        engine: Arc<PolicyEngine>,
        registry: Arc<AgentRegistry>,
        approval_queue: Arc<ApprovalQueue>,
        audit_tx: mpsc::Sender<AuditEntry>,
        audit_drops: Arc<AtomicU64>,
        initial_hash: [u8; 32],
    ) -> Self {
        Self {
            engine,
            registry: Some(registry),
            approval_queue: Some(approval_queue),
            audit_tx,
            audit_drops,
            seq: AtomicU64::new(0),
            last_hash: Mutex::new(initial_hash),
        }
    }

    /// Evaluate a single request against the engine, returning the raw
    /// evaluation result, measured latency, and the policy rule label.
    ///
    /// Callers are responsible for converting the [`EvaluationResult`] into a
    /// proto response — this allows `RequiresApproval` to be intercepted before
    /// the conversion.
    #[allow(clippy::result_large_err)] // tonic::Status is the standard gRPC error type
    fn evaluate_one(&self, req: &CheckActionRequest) -> Result<(EvaluationResult, i64, String), Status> {
        let (mut ctx, action) = convert::request_to_core(req).map_err(|e| {
            tracing::error!(error = %e, "failed to convert CheckActionRequest");
            Status::invalid_argument(e.to_string())
        })?;

        // Populate `ctx.governance_level` from the registered `AgentRecord`
        // so level-conditional policy rules (e.g. `governance_level >= L2`)
        // see the agent's actual level instead of the proto-default. Falls
        // back to whatever default `request_to_core` produced when the
        // registry is not attached or the agent is not registered.
        if let (Some(registry), Some(proto_agent)) = (&self.registry, req.agent_id.as_ref()) {
            let agent_key = proto_agent_id_to_key(proto_agent);
            if let Some(record) = registry.get(&agent_key) {
                ctx.governance_level = record.governance_level;
            }
        }

        let start = Instant::now();
        let eval = self.engine.evaluate(&ctx, &action);
        let latency_us = start.elapsed().as_micros() as i64;

        // Derive a policy_rule label from the deny/approval reason.
        let policy_rule = match &eval.decision {
            aa_core::PolicyResult::Allow => String::new(),
            aa_core::PolicyResult::Deny { reason } => reason.clone(),
            aa_core::PolicyResult::RequiresApproval { .. } => "requires_approval".to_string(),
        };

        Ok((eval, latency_us, policy_rule))
    }

    /// Execute the suspension side-effect when the engine signals `SuspendAgent`.
    ///
    /// Suspends the agent in the registry and sends a `SuspendCommand` via the
    /// control stream. Best-effort: if the registry is not attached or the agent
    /// is not found, the suspension is skipped (the deny response still applies).
    async fn maybe_suspend_agent(&self, req: &CheckActionRequest, deny_action: Option<DenyAction>) {
        if deny_action != Some(DenyAction::SuspendAgent) {
            return;
        }
        let registry = match &self.registry {
            Some(r) => r,
            None => return,
        };
        let proto_agent = match req.agent_id.as_ref() {
            Some(a) => a,
            None => return,
        };
        let agent_key = proto_agent_id_to_key(proto_agent);
        let reason_text = "budget limit exceeded";
        if let Err(e) = registry
            .suspend_and_notify(&agent_key, SuspendReason::BudgetExceeded, reason_text)
            .await
        {
            tracing::warn!(error = %e, "failed to suspend agent on budget exceeded");
        } else {
            tracing::info!(agent_id = ?proto_agent.agent_id, "agent suspended: {reason_text}");
        }
    }

    /// Build an [`ApprovalRequest`] from a gRPC request and the policy timeout.
    fn build_approval_request(req: &CheckActionRequest, timeout_secs: u32) -> ApprovalRequest {
        let agent_id = req.agent_id.as_ref().map(|a| a.agent_id.clone()).unwrap_or_default();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ApprovalRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_id,
            action: format!("action_type={}", req.action_type),
            condition_triggered: "requires_approval".to_string(),
            submitted_at: now,
            timeout_secs: u64::from(timeout_secs),
            fallback: aa_core::PolicyResult::Deny {
                reason: "approval timed out".to_string(),
            },
            team_id: None,
        }
    }

    /// Submit a `RequiresApproval` evaluation to the approval queue, await
    /// the human decision (with timeout), and return the final response.
    ///
    /// Returns `Some(response)` when the evaluation was `RequiresApproval` and
    /// the queue was available. Returns `None` when the evaluation is not
    /// `RequiresApproval` or the queue is absent (degraded mode — caller falls
    /// through to the normal conversion path).
    async fn maybe_submit_approval(
        &self,
        req: &CheckActionRequest,
        eval: &EvaluationResult,
        latency_us: i64,
        policy_rule: &str,
    ) -> Option<CheckActionResponse> {
        let timeout_secs = match &eval.decision {
            aa_core::PolicyResult::RequiresApproval { timeout_secs } => *timeout_secs,
            _ => return None,
        };

        let queue = match &self.approval_queue {
            Some(q) => q,
            None => {
                tracing::warn!(
                    "RequiresApproval decision but no approval_queue attached — \
                     returning Pending without queue submission (degraded mode)"
                );
                return None;
            }
        };

        let approval_req = Self::build_approval_request(req, timeout_secs);
        let approval_id = approval_req.request_id;

        tracing::info!(
            approval_id = %approval_id,
            agent_id = %approval_req.agent_id,
            action = %approval_req.action,
            timeout_secs,
            "submitting to approval queue"
        );

        let (_id, future) = queue.submit(approval_req);

        // Await the operator's decision with a timeout guard.
        // The ApprovalQueue also spawns its own timeout task, so both race;
        // whichever fires first wins (the queue's resolve is idempotent).
        let timeout_duration = std::time::Duration::from_secs(u64::from(timeout_secs));
        let decision = match tokio::time::timeout(timeout_duration, future).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_recv_err)) => {
                // Oneshot sender was dropped — the queue entry was removed
                // externally (should not happen in normal operation).
                tracing::warn!(approval_id = %approval_id, "approval channel closed unexpectedly");
                aa_runtime::approval::ApprovalDecision::Rejected {
                    by: "system".to_string(),
                    reason: "approval channel closed".to_string(),
                }
            }
            Err(_elapsed) => {
                // Our timeout fired before the queue's timeout task.
                tracing::info!(approval_id = %approval_id, "approval timed out");
                aa_runtime::approval::ApprovalDecision::TimedOut {
                    fallback: aa_core::PolicyResult::Deny {
                        reason: "approval timed out".to_string(),
                    },
                }
            }
        };

        Some(convert::approval_decision_to_response(
            &decision,
            &approval_id,
            latency_us,
            policy_rule,
        ))
    }

    /// Build an `AuditEntry` from a request and evaluation result, then fire-and-forget
    /// via `try_send`. Maintains the hash chain by reading and updating `last_hash`.
    /// Never blocks the caller beyond the brief mutex acquisition.
    async fn record_audit(&self, req: &CheckActionRequest, response: &CheckActionResponse) {
        let proto_agent = match req.agent_id.as_ref() {
            Some(a) => a,
            None => return, // No agent identity — cannot construct entry.
        };
        let agent_id = AgentId::from_bytes(convert::hash_to_16(&proto_agent.agent_id));
        let session_id = SessionId::from_bytes(convert::hash_to_16(&req.trace_id));
        let event_type = Self::decision_to_event_type_from_response(response.decision);
        let timestamp_ns = Timestamp::from(SystemTime::now()).as_nanos();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);

        let payload = serde_json::json!({
            "action_type": req.action_type,
            "decision": response.decision,
            "reason": &response.reason,
            "policy_rule": &response.policy_rule,
            "latency_us": response.decision_latency_us,
        })
        .to_string();

        let mut last_hash = self.last_hash.lock().await;

        let entry = AuditEntry::new(seq, timestamp_ns, event_type, agent_id, session_id, payload, *last_hash);

        // Update the chain head before sending — even if try_send fails (the entry
        // is dropped), we advance the chain so subsequent entries don't duplicate
        // the previous_hash and produce a misleading "valid" chain with a gap.
        *last_hash = *entry.entry_hash();
        drop(last_hash);

        if let Err(e) = self.audit_tx.try_send(entry) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(seq, "audit channel full — entry dropped");
                    self.audit_drops.fetch_add(1, Ordering::Relaxed);
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!("audit channel closed — AuditWriter task has exited");
                }
            }
        }
    }

    /// Map a proto `Decision` i32 to `AuditEventType`.
    fn decision_to_event_type_from_response(decision: i32) -> AuditEventType {
        use aa_proto::assembly::common::v1::Decision;
        match Decision::try_from(decision) {
            Ok(Decision::Allow) => AuditEventType::ToolCallIntercepted,
            Ok(Decision::Deny) => AuditEventType::PolicyViolation,
            Ok(Decision::Redact) => AuditEventType::CredentialLeakBlocked,
            Ok(Decision::Pending) => AuditEventType::ApprovalRequested,
            _ => AuditEventType::PolicyViolation, // fallback for unknown
        }
    }
}

#[tonic::async_trait]
impl PolicyService for PolicyServiceImpl {
    async fn check_action(
        &self,
        request: Request<CheckActionRequest>,
    ) -> Result<Response<CheckActionResponse>, Status> {
        let req = request.into_inner();

        tracing::debug!(
            agent_id = ?req.agent_id.as_ref().map(|a| &a.agent_id),
            action_type = req.action_type,
            trace_id = %req.trace_id,
            "check_action request"
        );

        let (eval, latency_us, policy_rule) = self.evaluate_one(&req)?;
        let deny_action = eval.deny_action;

        // If RequiresApproval, submit to the queue and block until decided.
        let response =
            if let Some(approval_response) = self.maybe_submit_approval(&req, &eval, latency_us, &policy_rule).await {
                approval_response
            } else {
                convert::eval_result_to_response(&eval, latency_us, &policy_rule)
            };

        tracing::debug!(
            decision = response.decision,
            latency_us = response.decision_latency_us,
            "check_action response"
        );

        if response.decision != aa_proto::assembly::common::v1::Decision::Allow as i32 {
            tracing::warn!(
                decision = response.decision,
                reason = %response.reason,
                policy_rule = %response.policy_rule,
                "non-allow decision"
            );
        }

        // Suspend the agent if the engine signaled SuspendAgent.
        self.maybe_suspend_agent(&req, deny_action).await;

        // Fire-and-forget audit entry — never blocks the response.
        self.record_audit(&req, &response).await;

        Ok(Response::new(response))
    }

    async fn batch_check(&self, request: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
        let batch = request.into_inner();
        let mut responses = Vec::with_capacity(batch.requests.len());

        for req in &batch.requests {
            let (eval, latency_us, policy_rule) = self.evaluate_one(req)?;
            let deny_action = eval.deny_action;
            let resp = if let Some(approval_response) =
                self.maybe_submit_approval(req, &eval, latency_us, &policy_rule).await
            {
                approval_response
            } else {
                convert::eval_result_to_response(&eval, latency_us, &policy_rule)
            };
            self.maybe_suspend_agent(req, deny_action).await;
            self.record_audit(req, &resp).await;
            responses.push(resp);
        }

        Ok(Response::new(BatchCheckResponse { responses }))
    }
}
