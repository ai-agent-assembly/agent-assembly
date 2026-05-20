//! `PolicyService` tonic trait implementation wiring gRPC RPCs to `PolicyEngine`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use tokio::sync::{broadcast, mpsc, Mutex};
use tonic::{Request, Response, Status};

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, AuditEntry, AuditEventType, GovernanceLevel, Lineage, Redaction};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse};

use aa_runtime::approval::{ApprovalQueue, ApprovalRequest};

use crate::alerts::SecretAlert;
use crate::approval::db_escalation_scheduler::DbEscalationScheduler;
use crate::approval::escalation::EscalationScheduler;
use crate::approval::router::ApprovalRouter;
use crate::approval::routing_config::RoutingConfigStore;
use crate::engine::{DenyAction, EvaluationResult, PolicyEngine};
use crate::ops::OpsRegistry;
use crate::registry::convert::proto_agent_id_to_key;
use crate::registry::{AgentRegistry, SuspendReason};
use crate::service::convert;

/// gRPC service implementation wiring `CheckAction` / `BatchCheck` to [`PolicyEngine`].
pub struct PolicyServiceImpl {
    engine: Arc<PolicyEngine>,
    registry: Option<Arc<AgentRegistry>>,
    approval_queue: Option<Arc<ApprovalQueue>>,
    escalation_scheduler: Option<Arc<EscalationScheduler>>,
    db_escalation_scheduler: Option<Arc<DbEscalationScheduler>>,
    routing_store: Option<Arc<RoutingConfigStore>>,
    router: Option<Arc<ApprovalRouter>>,
    audit_tx: mpsc::Sender<AuditEntry>,
    audit_drops: Arc<AtomicU64>,
    seq: AtomicU64,
    last_hash: Mutex<[u8; 32]>,
    /// Optional broadcast sender for secret-detection alerts. When set,
    /// the service publishes a [`SecretAlert`] each time a CheckAction
    /// produces non-empty `credential_findings` (AAASM-1545). `None`
    /// disables emission — used by unit tests that don't need alerts.
    secret_alert_tx: Option<broadcast::Sender<SecretAlert>>,
    /// Optional in-flight ops registry. When set, every `check_action`
    /// call ingests an op keyed by `"{trace_id}:{span_id}"` and transitions
    /// it on the engine decision (AAASM-1422). `None` disables ingestion,
    /// matching the pre-1422 behaviour expected by unit tests that
    /// construct the service directly.
    ops_registry: Option<Arc<OpsRegistry>>,
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
            escalation_scheduler: None,
            db_escalation_scheduler: None,
            routing_store: None,
            router: None,
            audit_tx,
            audit_drops,
            seq: AtomicU64::new(0),
            last_hash: Mutex::new(initial_hash),
            secret_alert_tx: None,
            ops_registry: None,
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
            escalation_scheduler: None,
            db_escalation_scheduler: None,
            routing_store: None,
            router: None,
            audit_tx,
            audit_drops,
            seq: AtomicU64::new(0),
            last_hash: Mutex::new(initial_hash),
            secret_alert_tx: None,
            ops_registry: None,
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
            escalation_scheduler: None,
            db_escalation_scheduler: None,
            routing_store: None,
            router: None,
            audit_tx,
            audit_drops,
            seq: AtomicU64::new(0),
            last_hash: Mutex::new(initial_hash),
            secret_alert_tx: None,
            ops_registry: None,
        }
    }

    /// Create a new service with an agent registry, approval queue, escalation scheduler,
    /// and routing store loaded from the default path.
    ///
    /// When a scheduler is provided, approved requests are registered for escalation
    /// and the `ApprovalRouted` audit event is emitted when a team is identified.
    pub fn with_registry_approval_and_escalation(
        engine: Arc<PolicyEngine>,
        registry: Arc<AgentRegistry>,
        approval_queue: Arc<ApprovalQueue>,
        escalation_scheduler: Option<Arc<EscalationScheduler>>,
        audit_tx: mpsc::Sender<AuditEntry>,
        audit_drops: Arc<AtomicU64>,
        initial_hash: [u8; 32],
    ) -> Self {
        // Load the default routing config store so we can look up escalation settings.
        let routing_store = RoutingConfigStore::load(crate::approval::routing_config::default_routing_config_path())
            .ok()
            .map(Arc::new);
        Self {
            engine,
            registry: Some(registry),
            approval_queue: Some(approval_queue),
            escalation_scheduler,
            db_escalation_scheduler: None,
            routing_store,
            router: None,
            audit_tx,
            audit_drops,
            seq: AtomicU64::new(0),
            last_hash: Mutex::new(initial_hash),
            secret_alert_tx: None,
            ops_registry: None,
        }
    }

    /// Attach a [`DbEscalationScheduler`] to this service.
    ///
    /// When present, the DB scheduler is called alongside the file-based scheduler
    /// to persist escalation state in `pending_escalations`.
    pub fn with_db_scheduler(mut self, scheduler: Option<Arc<DbEscalationScheduler>>) -> Self {
        self.db_escalation_scheduler = scheduler;
        self
    }

    /// Attach an [`ApprovalRouter`] to this service.
    ///
    /// When present, the router is called on every `RequiresApproval` decision to
    /// resolve the canonical routing target and escalation parameters, and to write
    /// `routing_status` on the in-flight approval queue entry (AC2 / AC3).
    pub fn with_router(mut self, router: Arc<ApprovalRouter>) -> Self {
        self.router = Some(router);
        self
    }

    /// Attach a broadcast sender for secret-detection alerts (AAASM-1545).
    ///
    /// When present, the service publishes a [`SecretAlert`] each time a
    /// `CheckAction` produces non-empty `credential_findings`. Callers
    /// (e.g. `aa-api`) typically pair this with
    /// `spawn_secret_alert_capture` to persist the alerts into the store.
    pub fn with_secret_alert_tx(mut self, tx: broadcast::Sender<SecretAlert>) -> Self {
        self.secret_alert_tx = Some(tx);
        self
    }

    /// Attach an [`OpsRegistry`] for in-flight operation tracking (AAASM-1422).
    ///
    /// When present, every `check_action` call ingests an op keyed by
    /// `"{trace_id}:{span_id}"` and transitions it on the engine decision:
    /// `Pending → Running` on `Allow`. The terminate-on-deny path and WS
    /// `OpStateChanged` emission are deferred to PR-H.
    pub fn with_ops_registry(mut self, registry: Arc<OpsRegistry>) -> Self {
        self.ops_registry = Some(registry);
        self
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

    /// Build an [`ApprovalRequest`] from a gRPC request, the policy timeout,
    /// and an optional team identifier resolved from the agent registry.
    fn build_approval_request(
        req: &CheckActionRequest,
        timeout_secs: u32,
        team_id: Option<String>,
        request_id: uuid::Uuid,
        timeout_override_secs: Option<u64>,
        escalation_role_override: Option<String>,
    ) -> ApprovalRequest {
        let agent_id = req.agent_id.as_ref().map(|a| a.agent_id.clone()).unwrap_or_default();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ApprovalRequest {
            request_id,
            agent_id,
            action: format!("action_type={}", req.action_type),
            condition_triggered: "requires_approval".to_string(),
            submitted_at: now,
            timeout_secs: u64::from(timeout_secs),
            fallback: aa_core::PolicyResult::Deny {
                reason: "approval timed out".to_string(),
            },
            team_id,
            timeout_override_secs,
            escalation_role_override,
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

        // Resolve the agent's team_id from the registry so the router can
        // direct the request to the correct approver queue.
        let team_id = req.agent_id.as_ref().and_then(|proto_agent| {
            self.registry.as_ref().and_then(|registry| {
                registry
                    .get(&crate::registry::convert::proto_agent_id_to_key(proto_agent))
                    .and_then(|record| record.team_id.clone())
            })
        });

        // Pre-generate the request ID so it can be included in the ApprovalRouted audit event.
        let approval_request_id = uuid::Uuid::new_v4();

        // Extract agent identity for the chain-hashed audit entry and the router context.
        let proto_agent = req.agent_id.as_ref();
        let agent_id_val = proto_agent
            .map(|a| AgentId::from_bytes(convert::hash_to_16(&a.agent_id)))
            .unwrap_or_else(|| AgentId::from_bytes([0u8; 16]));
        let session_id_val = SessionId::from_bytes(convert::hash_to_16(&req.trace_id));

        // Emit ApprovalRouted audit event (chain-hashed WORM log) when a team is identified.
        if let Some(ref tid) = team_id {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let payload = serde_json::json!({
                "team_id": tid,
                "action_type": req.action_type,
                "approval_id": approval_request_id.to_string(),
            })
            .to_string();
            let mut last_hash = self.last_hash.lock().await;
            let entry = AuditEntry::new(
                seq,
                now,
                AuditEventType::ApprovalRouted,
                agent_id_val,
                session_id_val,
                payload,
                *last_hash,
            );
            *last_hash = *entry.entry_hash();
            drop(last_hash);
            if let Err(e) = self.audit_tx.try_send(entry) {
                match e {
                    mpsc::error::TrySendError::Full(_) => {
                        tracing::warn!(seq, "audit channel full — ApprovalRouted entry dropped");
                        self.audit_drops.fetch_add(1, Ordering::Relaxed);
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        tracing::error!("audit channel closed — AuditWriter task has exited");
                    }
                }
            }
        }

        let (timeout_override, role_override) = self.engine.approval_escalation_overrides();
        let approval_req = Self::build_approval_request(
            req,
            timeout_secs,
            team_id.clone(),
            approval_request_id,
            timeout_override,
            role_override.clone(),
        );
        let approval_id = approval_req.request_id;

        tracing::info!(
            approval_id = %approval_id,
            agent_id = %approval_req.agent_id,
            action = %approval_req.action,
            timeout_secs,
            "submitting to approval queue"
        );

        // Build AgentContext so the router can resolve team_id → routing target.
        // Only team_id is consumed by the router; the other fields are populated from
        // what is available at this call site.
        let agent_ctx = AgentContext {
            agent_id: agent_id_val,
            session_id: session_id_val,
            pid: 0,
            started_at: Timestamp::from_nanos(0),
            metadata: Default::default(),
            governance_level: GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: team_id.clone(),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
        };

        // AC3: resolve routing decision via ApprovalRouter when available;
        // fall back to the legacy RoutingConfigStore path when the router is absent.
        let routing_decision = if let Some(ref router) = self.router {
            router.route(&approval_req, &agent_ctx).await.map_or_else(
                |e| {
                    tracing::warn!(error = %e, "ApprovalRouter failed — falling back to legacy routing");
                    None
                },
                Some,
            )
        } else {
            None
        };

        // Register the pending escalation with the scheduler.
        if let Some(ref decision) = routing_decision {
            // Router-driven path: use the decision's escalation_role and escalate_at.
            if let (Some(ref team_id_val), Some(ref scheduler)) = (&decision.team_id, &self.escalation_scheduler) {
                let now_secs = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let esc_timeout = decision.escalate_at.saturating_sub(now_secs);
                let approvers = vec![decision.escalation_role.clone()];
                if let Err(e) = scheduler.register(approval_id, team_id_val.clone(), approvers, esc_timeout) {
                    tracing::warn!(error = %e, "failed to register escalation for approval {}", approval_id);
                }
            }
            if let Some(ref db_scheduler) = self.db_escalation_scheduler {
                if let Some(ref team_id_val) = decision.team_id {
                    if let Err(e) = db_scheduler
                        .register(
                            approval_id,
                            team_id_val.clone(),
                            decision.escalation_role.clone(),
                            "TeamAdmin".to_string(),
                            decision.escalate_at,
                        )
                        .await
                    {
                        tracing::warn!(error = %e, "failed to register DB escalation for approval {}", approval_id);
                    }
                }
            }
        } else if let (Some(ref tid), Some(ref scheduler)) = (&team_id, &self.escalation_scheduler) {
            // Legacy path: resolve escalation config from the RoutingConfigStore.
            let effective_timeout = timeout_override.unwrap_or(u64::from(timeout_secs));
            let escalation_approvers = self
                .routing_store
                .as_ref()
                .and_then(|store| store.get(tid))
                .map(|cfg| {
                    if let Some(ref role) = role_override {
                        vec![role.clone()]
                    } else {
                        cfg.escalation_approvers.clone()
                    }
                })
                .unwrap_or_default();
            if let Err(e) = scheduler.register(approval_id, tid.clone(), escalation_approvers, effective_timeout) {
                tracing::warn!(error = %e, "failed to register escalation for approval {}", approval_id);
            }
        }

        let (_id, future) = queue.submit(approval_req);

        // AC2: persist structured routing metadata on the in-flight queue entry
        // so operators and the escalation event stream can observe the routing outcome.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (routing_status, target_role, escalate_at_ts) = routing_decision
            .as_ref()
            .map(|d| {
                let status = if d.target_role == "TeamAdmin" {
                    "routed_to_team_admin".to_string()
                } else {
                    "routed_to_org_admin".to_string()
                };
                (status, Some(d.target_role.clone()), Some(d.escalate_at))
            })
            .unwrap_or_else(|| {
                let status = if team_id.is_some() {
                    "routed_to_team_admin".to_string()
                } else {
                    "routed_to_org_admin".to_string()
                };
                (status, None, None)
            });
        let history_entry = aa_runtime::approval::RoutingHistoryEntry {
            at: now_secs,
            action: "routed".to_string(),
            from_role: None,
            to_role: target_role.clone().unwrap_or_else(|| routing_status.clone()),
        };
        queue.record_routing(
            approval_id,
            routing_status,
            target_role,
            Some(now_secs),
            escalate_at_ts,
            Some(history_entry),
        );

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
    async fn record_audit(&self, req: &CheckActionRequest, response: &CheckActionResponse, eval: &EvaluationResult) {
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

        // When the credential scanner produced findings, attach them (and the
        // redacted payload) to the audit entry via the redaction-aware constructor.
        // Both fields carry the [REDACTED:<kind>] form only — the raw secret bytes
        // never reach the audit pipeline.
        let entry = if eval.credential_findings.is_empty() {
            AuditEntry::new(seq, timestamp_ns, event_type, agent_id, session_id, payload, *last_hash)
        } else {
            let redaction = Redaction {
                credential_findings: eval.credential_findings.clone(),
                redacted_payload: eval.redacted_payload.clone(),
            };
            AuditEntry::new_with_lineage_and_redaction(
                seq,
                timestamp_ns,
                event_type,
                agent_id,
                session_id,
                payload,
                *last_hash,
                Lineage::default(),
                redaction,
            )
        };

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

impl PolicyServiceImpl {
    /// Publish a [`SecretAlert`] when the evaluation produced one or more
    /// credential findings and a broadcast sender is attached. The alert
    /// carries only kind tags and counts — never any byte of the original
    /// secret. Failure to send (no receivers) is logged at trace level
    /// and does not propagate (AAASM-1545).
    fn maybe_emit_secret_alert(&self, req: &CheckActionRequest, eval: &EvaluationResult) {
        if eval.credential_findings.is_empty() {
            return;
        }
        let Some(tx) = self.secret_alert_tx.as_ref() else {
            return;
        };
        let Some(proto_agent) = req.agent_id.as_ref() else {
            return;
        };

        let agent_id = AgentId::from_bytes(proto_agent_id_to_key(proto_agent));
        let team_id = if proto_agent.team_id.is_empty() {
            None
        } else {
            Some(proto_agent.team_id.clone())
        };

        // Distinct kinds (preserve first-seen order) for the alert payload.
        let mut kinds = Vec::new();
        for f in &eval.credential_findings {
            if !kinds.iter().any(|k| k == &f.kind) {
                kinds.push(f.kind.clone());
            }
        }

        let alert = SecretAlert {
            agent_id,
            team_id,
            kinds,
            finding_count: eval.credential_findings.len(),
        };

        if let Err(err) = tx.send(alert) {
            tracing::trace!(error = %err, "no subscribers for SecretAlert broadcast");
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
        self.maybe_emit_secret_alert(&req, &eval);
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
        self.record_audit(&req, &response, &eval).await;

        Ok(Response::new(response))
    }

    async fn batch_check(&self, request: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
        let batch = request.into_inner();
        let mut responses = Vec::with_capacity(batch.requests.len());

        for req in &batch.requests {
            let (eval, latency_us, policy_rule) = self.evaluate_one(req)?;
            self.maybe_emit_secret_alert(req, &eval);
            let deny_action = eval.deny_action;
            let resp = if let Some(approval_response) =
                self.maybe_submit_approval(req, &eval, latency_us, &policy_rule).await
            {
                approval_response
            } else {
                convert::eval_result_to_response(&eval, latency_us, &policy_rule)
            };
            self.maybe_suspend_agent(req, deny_action).await;
            self.record_audit(req, &resp, &eval).await;
            responses.push(resp);
        }

        Ok(Response::new(BatchCheckResponse { responses }))
    }
}
