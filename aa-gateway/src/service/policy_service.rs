//! `PolicyService` tonic trait implementation wiring gRPC RPCs to `PolicyEngine`.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use tokio_stream::Stream;

use tokio::sync::{broadcast, mpsc, Mutex};
use tonic::{Request, Response, Status};

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, AuditEntry, AuditEventType, GovernanceLevel, Lineage};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{
    BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
    OpControlSubscribeRequest,
};
use aa_security::Redaction;

use aa_runtime::approval::{ApprovalQueue, ApprovalRequest};

use crate::alerts::SecretAlert;
use crate::anomaly::{AnomalyDetector, AnomalyEvent, AnomalyResponder};
use crate::approval::db_escalation_scheduler::DbEscalationScheduler;
use crate::approval::escalation::EscalationScheduler;
use crate::approval::router::ApprovalRouter;
use crate::approval::routing_config::RoutingConfigStore;
use crate::engine::{
    resolve_enforcement_mode, transform_for_observe_mode, DenyAction, EvaluationResult, PolicyEngine, ShadowEvent,
};
use crate::ops::{OpsRegistry, SharedOpControlPublisher};
use crate::registry::convert::proto_agent_id_to_key;
use crate::registry::{AgentRegistry, SuspendReason};
use crate::service::convert;

/// Live anomaly-detection wiring for the `CheckAction` / `BatchCheck` flow
/// (AAASM-3378).
///
/// The `aa-gateway::anomaly` engine was fully implemented and unit-tested but
/// had zero non-test instantiations — it never ran against live traffic, so no
/// `AnomalyEvent` could ever fire at runtime. This hook feeds every evaluated
/// action through [`AnomalyDetector::detect`] and runs [`AnomalyResponder`] on
/// any detection, broadcasting the resulting [`AnomalyEvent`] to subscribers.
#[derive(Clone)]
pub struct AnomalyHook {
    detector: Arc<AnomalyDetector>,
    event_tx: broadcast::Sender<AnomalyEvent>,
}

impl AnomalyHook {
    /// Build a hook around the given detector and event broadcast sender.
    pub fn new(detector: Arc<AnomalyDetector>, event_tx: broadcast::Sender<AnomalyEvent>) -> Self {
        Self { detector, event_tx }
    }

    /// Shared handle to the underlying detector (for stateful checks/tests).
    pub fn detector(&self) -> Arc<AnomalyDetector> {
        Arc::clone(&self.detector)
    }
}

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
    /// Optional broadcast publisher for op-control signals (AAASM-1653).
    /// When set, the `op_control_stream` RPC subscribes here and forwards
    /// every envelope matching the subscriber's agent_id. `None` rejects
    /// new subscriptions with `Unavailable`. PR-H will pair this with
    /// `OpsRegistry` transition call sites that drive `publish()`.
    ops_publisher: Option<SharedOpControlPublisher>,
    /// Optional live anomaly-detection hook (AAASM-3378). When set, every
    /// `check_action` / `batch_check` evaluation is run through the anomaly
    /// detector and any detection triggers the responder + an `AnomalyEvent`
    /// broadcast. `None` disables detection — the default for unit tests and
    /// any caller that does not opt in via [`with_anomaly_detection`].
    anomaly: Option<AnomalyHook>,
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
            ops_publisher: None,
            anomaly: None,
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
            ops_publisher: None,
            anomaly: None,
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
            ops_publisher: None,
            anomaly: None,
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
            ops_publisher: None,
            anomaly: None,
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

    /// Seed the audit `seq` counter so sequence numbers continue monotonically
    /// across process restarts (AAASM-3356).
    ///
    /// `initial_seq` should be the *next* sequence number to emit — i.e.
    /// `last_persisted_seq + 1`, obtained from
    /// [`AuditWriter::read_last_seq`](crate::audit::AuditWriter::read_last_seq).
    /// Without this, the counter restarts at `0` and produces duplicate `seq`
    /// values after a restart, breaking the WORM log's per-entry uniqueness.
    /// Mirrors the `initial_hash` recovery already done for the hash chain.
    pub fn with_initial_seq(self, initial_seq: u64) -> Self {
        self.seq.store(initial_seq, Ordering::Relaxed);
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

    /// Attach an [`OpControlPublisher`] for the SDK return-channel (AAASM-1653).
    ///
    /// When present, [`PolicyService::op_control_stream`] subscribes to the
    /// publisher and forwards every envelope whose `agent_id` matches the
    /// subscriber's `OpControlSubscribeRequest.agent_id`. Without a
    /// publisher attached, subscription requests are rejected with
    /// `Status::unavailable("op control channel not configured")`.
    ///
    /// [`OpControlPublisher`]: crate::ops::OpControlPublisher
    pub fn with_ops_publisher(mut self, publisher: SharedOpControlPublisher) -> Self {
        self.ops_publisher = Some(publisher);
        self
    }

    /// Attach a live anomaly-detection hook (AAASM-3378).
    ///
    /// Wires the previously-unwired `aa-gateway::anomaly` engine into the live
    /// `check_action` / `batch_check` path. With a hook attached, every
    /// evaluated action updates the per-agent behavioral baseline, runs through
    /// [`AnomalyDetector::detect`], and — on a detection — executes
    /// [`AnomalyResponder::respond`] and broadcasts the resulting
    /// [`AnomalyEvent`]. Without a hook, behavior is unchanged.
    pub fn with_anomaly_detection(
        mut self,
        detector: Arc<AnomalyDetector>,
        event_tx: broadcast::Sender<AnomalyEvent>,
    ) -> Self {
        self.anomaly = Some(AnomalyHook::new(detector, event_tx));
        self
    }

    /// Look up the per-agent `enforcement_mode` override for the request's agent.
    ///
    /// Returns `Some(_)` when the request's agent is registered AND its record
    /// carries an explicit override; `None` in every other case (no registry
    /// attached, agent unregistered, agent registered with no override). The
    /// resolver in [`crate::engine::resolve_enforcement_mode`] treats `None` as
    /// "inherit from policy default", so an unknown / unregistered agent
    /// transparently falls back to live enforcement.
    fn lookup_agent_enforcement_override(&self, req: &CheckActionRequest) -> Option<aa_core::EnforcementMode> {
        let registry = self.registry.as_ref()?;
        let proto_agent = req.agent_id.as_ref()?;
        let agent_key = proto_agent_id_to_key(proto_agent);
        registry.get(&agent_key)?.enforcement_mode
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

        // AAASM-3751: anchor `ctx.governance_level` AND the policy-cascade /
        // budget lineage to the agent that OWNS the presented credential token,
        // never to the client-supplied (forgeable) `agent_id` triple.
        //
        // Looking the record up by the *claimed* composite key
        // (`proto_agent_id_to_key`) is useless against forgery: a forged
        // `org_id` changes the key and simply misses the registry, while a
        // key-HIT means the claimed org already equals the registered org
        // (tautological). Either way the engine's `authoritative_lineage` /
        // `authoritative_tenancy` fall back to the client-supplied `ctx`
        // values. `validate_credential_token` (run before evaluation) already
        // rejects a forged triple presented with a valid token as
        // impersonation, so the reported cross-tenant downgrade is not
        // exploitable by a credentialed caller. This deposit is therefore
        // DEFENSE-IN-DEPTH: resolve the owner from the credential token and
        // deposit ITS registered `governance_level` / `org_id` / `team_id`,
        // overwriting any client-supplied lineage, so a credentialed agent is
        // always evaluated against its registered owner's cascade (AAASM-3729)
        // and budget tenancy (AAASM-3138).
        //
        // `ctx.agent_id` is left untouched so `PolicyScope::Agent` matching and
        // the eval cache key stay correct. A tokenless request, or one whose
        // token owns no registered agent, keeps the existing client-supplied
        // fallback (untenanted / unregistered deployments — the parked
        // AAASM-3416 residual); it is NOT denied here.
        if let Some(registry) = &self.registry {
            if !req.credential_token.is_empty() {
                if let Some(record) = registry
                    .find_by_credential_token(&req.credential_token)
                    .and_then(|owner_key| registry.get(&owner_key))
                {
                    ctx.governance_level = record.governance_level;
                    match record.org_id {
                        Some(org) => {
                            ctx.metadata.insert("org_id".into(), org);
                        }
                        None => {
                            ctx.metadata.remove("org_id");
                        }
                    }
                    match record.team_id {
                        Some(team) => {
                            ctx.team_id = Some(team.clone());
                            ctx.metadata.insert("team_id".into(), team);
                        }
                        None => {
                            ctx.team_id = None;
                            ctx.metadata.remove("team_id");
                        }
                    }
                }
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

    /// Emit a chain-hashed `ApprovalRouted` WORM audit entry for a routed
    /// approval. Fire-and-forget over `audit_tx`; a full/closed channel is
    /// logged (and counted as a drop) rather than blocking the approval path.
    async fn emit_approval_routed_audit(
        &self,
        req: &CheckActionRequest,
        team_id: &str,
        approval_request_id: uuid::Uuid,
        agent_id_val: AgentId,
        session_id_val: SessionId,
    ) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let payload = serde_json::json!({
            "team_id": team_id,
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

    /// Register the pending escalation for `approval_id` with the in-memory (and,
    /// when present, DB) escalation scheduler.
    ///
    /// Router-driven path (`routing_decision` is `Some`): use the decision's
    /// `escalation_role` and `escalate_at`. Legacy path: resolve escalation
    /// approvers and timeout from the `RoutingConfigStore`. Registration
    /// failures are logged and do not abort the approval submission.
    async fn register_escalation(
        &self,
        approval_id: uuid::Uuid,
        routing_decision: Option<&crate::approval::RoutingDecision>,
        team_id: &Option<String>,
        timeout_secs: u32,
        timeout_override: Option<u64>,
        role_override: Option<&String>,
    ) {
        match routing_decision {
            Some(decision) => self.register_router_escalation(approval_id, decision).await,
            None => {
                self.register_legacy_escalation(approval_id, team_id, timeout_secs, timeout_override, role_override)
            }
        }
    }

    /// Router-driven escalation: register the in-memory scheduler (when a team
    /// and scheduler are present) and the DB scheduler (when present) using the
    /// decision's `escalation_role` and `escalate_at`. Failures are logged only.
    async fn register_router_escalation(&self, approval_id: uuid::Uuid, decision: &crate::approval::RoutingDecision) {
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
        if let (Some(ref db_scheduler), Some(ref team_id_val)) = (&self.db_escalation_scheduler, &decision.team_id) {
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

    /// Legacy escalation: resolve escalation approvers and timeout from the
    /// `RoutingConfigStore` (or `role_override`) and register the in-memory
    /// scheduler. No-op without a team and scheduler. Failures are logged only.
    fn register_legacy_escalation(
        &self,
        approval_id: uuid::Uuid,
        team_id: &Option<String>,
        timeout_secs: u32,
        timeout_override: Option<u64>,
        role_override: Option<&String>,
    ) {
        let (Some(tid), Some(scheduler)) = (team_id.as_ref(), self.escalation_scheduler.as_ref()) else {
            return;
        };
        let effective_timeout = timeout_override.unwrap_or(u64::from(timeout_secs));
        let escalation_approvers = self
            .routing_store
            .as_ref()
            .and_then(|store| store.get(tid))
            .map(|cfg| match role_override {
                Some(role) => vec![role.clone()],
                None => cfg.escalation_approvers.clone(),
            })
            .unwrap_or_default();
        if let Err(e) = scheduler.register(approval_id, tid.clone(), escalation_approvers, effective_timeout) {
            tracing::warn!(error = %e, "failed to register escalation for approval {}", approval_id);
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
            self.emit_approval_routed_audit(req, tid, approval_request_id, agent_id_val, session_id_val)
                .await;
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
        self.register_escalation(
            approval_id,
            routing_decision.as_ref(),
            &team_id,
            timeout_secs,
            timeout_override,
            role_override.as_ref(),
        )
        .await;

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
    ///
    /// When `shadow` is `Some`, observe-mode evaluation suppressed a non-Allow
    /// decision; the payload carries `dry_run: true` plus the original
    /// `shadow_decision` and matched rule so the audit reader can render the
    /// would-be event distinctly from live enforcement records.
    async fn record_audit(
        &self,
        req: &CheckActionRequest,
        response: &CheckActionResponse,
        eval: &EvaluationResult,
        shadow: Option<&ShadowEvent>,
    ) {
        let proto_agent = match req.agent_id.as_ref() {
            Some(a) => a,
            None => return, // No agent identity — cannot construct entry.
        };
        let agent_id = AgentId::from_bytes(convert::hash_to_16(&proto_agent.agent_id));
        let session_id = SessionId::from_bytes(convert::hash_to_16(&req.trace_id));

        // AAASM-1944: when the request carries `caller_agent_id` and it
        // differs from `agent_id`, the call is an agent-to-agent (A2A)
        // dispatch — emit the dedicated A2ACallIntercepted event for Allow
        // decisions so reviewers can reconstruct cross-agent delegation
        // graphs. Deny / Redact / Pending decisions continue to flow
        // through the existing variants per `decision_to_event_type_from_response`.
        let caller_agent_id_str: Option<&str> = req.caller_agent_id.as_ref().and_then(|c| {
            if c.agent_id.is_empty() || c.agent_id == proto_agent.agent_id {
                None
            } else {
                Some(c.agent_id.as_str())
            }
        });
        let is_a2a_allow = caller_agent_id_str.is_some()
            && response.decision == aa_proto::assembly::common::v1::Decision::Allow as i32;
        let event_type = if is_a2a_allow {
            AuditEventType::A2ACallIntercepted
        } else {
            Self::decision_to_event_type_from_response(response.decision)
        };

        let timestamp_ns = Timestamp::from(SystemTime::now()).as_nanos();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);

        // AAASM-2008 — resolve the agent's org_id from the registry so the
        // audit entry carries it in the Lineage. Lets `/api/v1/logs?org_id=…`
        // and `aasm audit compliance-export` filter by tenant. Falls back to
        // an empty Lineage when the registry is absent (lightweight test
        // fixtures) or the agent is not registered.
        let lineage = self
            .registry
            .as_ref()
            .and_then(|r| r.lineage(&proto_agent_id_to_key(proto_agent)))
            .map(|reg_lineage| Lineage {
                org_id: reg_lineage.org_id,
                team_id: reg_lineage.team_id,
                // AAASM-3377 — carry the full delegation lineage now sourced by
                // `AgentRegistry::lineage()` so a child agent's audit entry no
                // longer drops root / parent / depth / delegation_reason /
                // spawned_by_tool.
                root_agent_id: reg_lineage.root_agent_id.map(AgentId::from_bytes),
                parent_agent_id: reg_lineage.parent_agent_id.map(AgentId::from_bytes),
                depth: reg_lineage.depth,
                delegation_reason: reg_lineage.delegation_reason,
                spawned_by_tool: reg_lineage.spawned_by_tool,
            })
            .unwrap_or_default();

        // AAASM-3377 — the lineage above is persisted as top-level `AuditEntry`
        // fields, but consumers that read only the inner `payload` JSON (e.g.
        // `/api/v1/logs`, JSONL replay tooling) never saw the delegation chain.
        // Mirror the delegation lineage into the payload — alongside org/team —
        // so a child agent's persisted JSONL `payload` carries root / parent /
        // depth / delegation_reason / spawned_by_tool. Hex-encode the AgentId
        // fields so the payload value is a stable, human-readable string rather
        // than the raw byte array the top-level field serializes to.
        let root_agent_id_hex = lineage.root_agent_id.map(|id| hex::encode(id.as_bytes()));
        let parent_agent_id_hex = lineage.parent_agent_id.map(|id| hex::encode(id.as_bytes()));

        // AAASM-3376 — the session_id stored on the entry is SHA256(trace_id)[:16],
        // which is one-way: the raw trace_id and the per-action span_id are lost
        // once the entry is persisted. Carry both in the payload JSON so they
        // survive to the JSONL log / DB and let `/api/v1/traces/{trace_id}`
        // reconstruct spans. (A first-class column on `AuditEntry` is the proto /
        // core-type follow-up — see PR body.)
        let trace_id_str: Option<&str> = (!req.trace_id.is_empty()).then_some(req.trace_id.as_str());
        let span_id_str: Option<&str> = (!req.span_id.is_empty()).then_some(req.span_id.as_str());
        let payload = match shadow {
            Some(s) => serde_json::json!({
                "action_type": req.action_type,
                "decision": response.decision,
                "reason": &response.reason,
                "policy_rule": &response.policy_rule,
                "latency_us": response.decision_latency_us,
                "dry_run": true,
                "shadow_decision": &s.shadow_decision,
                "shadow_reason": &s.reason,
                "caller_agent_id": caller_agent_id_str,
                "callee_agent_id": caller_agent_id_str.map(|_| proto_agent.agent_id.as_str()),
                "trace_id": trace_id_str,
                "span_id": span_id_str,
                "org_id": &lineage.org_id,
                "team_id": &lineage.team_id,
                "root_agent_id": &root_agent_id_hex,
                "parent_agent_id": &parent_agent_id_hex,
                "depth": lineage.depth,
                "delegation_reason": &lineage.delegation_reason,
                "spawned_by_tool": &lineage.spawned_by_tool,
            }),
            None => serde_json::json!({
                "action_type": req.action_type,
                "decision": response.decision,
                "reason": &response.reason,
                "policy_rule": &response.policy_rule,
                "latency_us": response.decision_latency_us,
                "caller_agent_id": caller_agent_id_str,
                "callee_agent_id": caller_agent_id_str.map(|_| proto_agent.agent_id.as_str()),
                "trace_id": trace_id_str,
                "span_id": span_id_str,
                "org_id": &lineage.org_id,
                "team_id": &lineage.team_id,
                "root_agent_id": &root_agent_id_hex,
                "parent_agent_id": &parent_agent_id_hex,
                "depth": lineage.depth,
                "delegation_reason": &lineage.delegation_reason,
                "spawned_by_tool": &lineage.spawned_by_tool,
            }),
        }
        .to_string();

        let mut last_hash = self.last_hash.lock().await;

        // When the credential scanner produced findings, attach them (and the
        // redacted payload) to the audit entry via the redaction-aware constructor.
        // Both fields carry the [REDACTED:<kind>] form only — the raw secret bytes
        // never reach the audit pipeline.
        let entry = if eval.credential_findings.is_empty() {
            AuditEntry::new_with_lineage(
                seq,
                timestamp_ns,
                event_type,
                agent_id,
                session_id,
                payload,
                *last_hash,
                lineage,
            )
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
                lineage,
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

    /// AAASM-1944 — validate the supplied `credential_token` against the
    /// registered token for the claimed `agent_id`.
    ///
    /// Returns `Some(deny_response)` when the request must be rejected:
    ///
    /// * Empty `credential_token` for a registered agent → Deny with reason
    ///   `"missing credential token"`. Emits `A2AImpersonationAttempted`.
    /// * Non-empty `credential_token` that does not match the registered
    ///   token for the claimed `agent_id` → Deny with reason
    ///   `"credential token mismatch"`. Emits `A2AImpersonationAttempted`.
    ///
    /// Returns `None` (skip validation) when:
    ///
    /// * No `AgentRegistry` is attached (test fixtures that bypass the
    ///   registry layer continue to work unchanged).
    /// * `req.agent_id` is `None` (caller did not declare an identity —
    ///   handled by downstream evaluation).
    /// * The claimed agent is not registered (no fixture data to verify
    ///   against; the policy engine may or may not allow per its rules).
    ///
    /// Emitting the audit event is fire-and-forget — a full `Deny`
    /// response is always constructed and returned to the caller.
    async fn validate_credential_token(&self, req: &CheckActionRequest) -> Option<CheckActionResponse> {
        let registry = self.registry.as_ref()?;
        let proto_agent = req.agent_id.as_ref()?;
        let key = proto_agent_id_to_key(proto_agent);
        let record_opt = registry.get(&key);

        let reason = if let Some(record) = &record_opt {
            // The claimed agent is registered at the claimed (org, team, id)
            // triple. Standard validation: empty / mismatched token rejects.
            if req.credential_token.is_empty() {
                "missing credential token"
            } else if req.credential_token != record.credential_token {
                "credential token mismatch"
            } else {
                return None;
            }
        } else {
            // AAASM-2008 — the claimed agent is NOT registered at the
            // claimed triple. If the supplied credential_token is registered
            // to a DIFFERENT agent, this is a cross-org / cross-identity
            // impersonation attempt and must be rejected. (Empty token +
            // unregistered agent is the lightweight-fixture path — skip
            // validation so existing tests that bypass the registry layer
            // continue working.)
            if req.credential_token.is_empty() {
                return None;
            }
            if registry.find_by_credential_token(&req.credential_token).is_some() {
                "credential token registered to a different agent"
            } else {
                // Token doesn't belong to any registered agent; could be a
                // test fixture or an unregistered client. Existing behaviour
                // (skip) is preserved.
                return None;
            }
        };

        let response = CheckActionResponse {
            decision: aa_proto::assembly::common::v1::Decision::Deny as i32,
            reason: reason.into(),
            policy_rule: "a2a_identity_verification".into(),
            approval_id: String::new(),
            redact: None,
            decision_latency_us: 0,
        };

        self.record_impersonation_audit(req, &response).await;
        Some(response)
    }

    /// Emit a dedicated `A2AImpersonationAttempted` audit event for the
    /// rejected credential validation in `validate_credential_token`. Mirrors
    /// the chain-bookkeeping shape of [`PolicyServiceImpl::record_audit`].
    async fn record_impersonation_audit(&self, req: &CheckActionRequest, response: &CheckActionResponse) {
        let Some(proto_agent) = req.agent_id.as_ref() else {
            return;
        };
        let agent_id = AgentId::from_bytes(convert::hash_to_16(&proto_agent.agent_id));
        let session_id = SessionId::from_bytes(convert::hash_to_16(&req.trace_id));
        let timestamp_ns = Timestamp::from(SystemTime::now()).as_nanos();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);

        let payload = serde_json::json!({
            "action_type": req.action_type,
            "decision": response.decision,
            "reason": &response.reason,
            "policy_rule": &response.policy_rule,
            "claimed_agent_id": &proto_agent.agent_id,
            "claimed_org_id": &proto_agent.org_id,
            "credential_token_present": !req.credential_token.is_empty(),
        })
        .to_string();

        // AAASM-2008 — stamp the claimed org_id onto the impersonation
        // entry's Lineage so audit queries filtered by org_id surface the
        // attempt against the org it claimed. (For impersonation attempts
        // the claimed org is the one a reviewer would search by.)
        let claimed_org_lineage = if proto_agent.org_id.is_empty() {
            Lineage::default()
        } else {
            Lineage {
                org_id: Some(proto_agent.org_id.clone()),
                ..Lineage::default()
            }
        };

        let mut last_hash = self.last_hash.lock().await;
        let entry = AuditEntry::new_with_lineage(
            seq,
            timestamp_ns,
            AuditEventType::A2AImpersonationAttempted,
            agent_id,
            session_id,
            payload,
            *last_hash,
            claimed_org_lineage,
        );
        *last_hash = *entry.entry_hash();
        drop(last_hash);

        if let Err(e) = self.audit_tx.try_send(entry) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(seq, "audit channel full — impersonation entry dropped");
                    self.audit_drops.fetch_add(1, Ordering::Relaxed);
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!("audit channel closed — AuditWriter task has exited");
                }
            }
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

    /// AAASM-3353 — accrue the cost of a non-denied LLM call against the
    /// agent's budget so daily / monthly limits actually fire.
    ///
    /// The live `CheckAction` handler previously only called `engine.evaluate`,
    /// which *reads* accumulated spend (Stage 7) but never *records* it — so
    /// `record_spend` had no caller outside tests and limits never triggered.
    /// This closes the loop: after an Allow / Redact / Pending decision on an
    /// `LLM_CALL`, the call is priced from the model name (provider inferred,
    /// see [`crate::engine::PolicyEngine::llm_call_cost_usd`]) and accrued via
    /// the existing `engine.record_spend` budget path. A subsequent call then
    /// trips the Stage-7 budget check once the limit is exceeded.
    ///
    /// No-ops when:
    /// * the action is not an `LLM_CALL`;
    /// * the decision was a hard `Deny` (a denied call did not run, so it must
    ///   not be charged);
    /// * the model name is unrecognised (cost resolves to `0.0`).
    fn maybe_accrue_llm_spend(&self, req: &CheckActionRequest, response: &CheckActionResponse) {
        use aa_proto::assembly::policy::v1::action_context::Action;

        // A hard Deny means the call was blocked — do not accrue spend.
        if response.decision == aa_proto::assembly::common::v1::Decision::Deny as i32 {
            return;
        }

        let Some(Action::LlmCall(lc)) = req.context.as_ref().and_then(|c| c.action.as_ref()) else {
            return;
        };

        let input_tokens = lc.prompt_tokens.max(0) as u64;
        // The pre-execution check has no completion yet, so output tokens are 0.
        let cost = self.engine.llm_call_cost_usd(&lc.model, input_tokens, 0);
        if cost <= 0.0 {
            return;
        }

        // Rebuild the AgentContext for tenancy resolution. `record_spend` keys
        // budget on the agent's *registered* owner (AAASM-3138) and only uses
        // ctx tenancy as a fallback, so the governance_level override applied
        // in `evaluate_one` is irrelevant here.
        match convert::request_to_core(req) {
            Ok((ctx, _action)) => self.engine.record_spend(&ctx, cost),
            Err(e) => {
                tracing::warn!(error = %e, "failed to rebuild ctx for LLM spend accrual");
            }
        }
    }

    /// AAASM-3378 — run the live anomaly detector over an evaluated action.
    ///
    /// This is the wiring that the previously-unwired `aa-gateway::anomaly`
    /// engine was missing: the detector had a full API + unit tests but **no
    /// non-test caller**, so no `AnomalyEvent` could ever fire at runtime.
    ///
    /// Behaviour (no-op when no hook is attached):
    /// 1. Rebuild the core `(ctx, action)` from the request.
    /// 2. Update the per-agent baseline (`record_action`, and for tool calls
    ///    `record_tool_call`; one `record_credential_finding` per credential
    ///    finding the evaluation surfaced).
    /// 3. Run [`AnomalyDetector::detect`] with `has_pii` derived from the
    ///    evaluation's credential findings and the policy network allowlist.
    /// 4. On a detection, execute [`AnomalyResponder::respond`] (logs the
    ///    response action) and broadcast the [`AnomalyEvent`] so subscribers
    ///    (and tests) observe the live detection.
    ///
    /// Returns the detected [`AnomalyEvent`] (if any) so the caller can enforce
    /// a block-equivalent response as a hard `Deny` (AAASM-3384). Returns `None`
    /// when no hook is attached or no anomaly fired.
    fn maybe_detect_anomaly(&self, req: &CheckActionRequest, eval: &EvaluationResult) -> Option<AnomalyEvent> {
        let hook = self.anomaly.as_ref()?;
        let (ctx, action) = match convert::request_to_core(req) {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "failed to rebuild ctx for anomaly detection");
                return None;
            }
        };
        let agent_id = ctx.agent_id;
        let now_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Update the behavioral baseline before detection so spike / loop
        // checks see the current action.
        hook.detector.record_action(agent_id, now_ms);
        if let aa_core::GovernanceAction::ToolCall { name, args } = &action {
            hook.detector.record_tool_call(agent_id, name, args, now_ms);
        }
        for _ in 0..eval.credential_findings.len() {
            hook.detector.record_credential_finding(agent_id);
        }

        let has_pii = !eval.credential_findings.is_empty();
        let allowlist = self.engine.network_allowlist();
        let event = hook.detector.detect(agent_id, &action, has_pii, &allowlist, None)?;
        AnomalyResponder::respond(&event);
        if let Err(err) = hook.event_tx.send(event.clone()) {
            tracing::trace!(error = %err, "no subscribers for AnomalyEvent broadcast");
        }
        Some(event)
    }

    /// AAASM-3384 — turn a block-equivalent anomaly detection into a hard
    /// `Deny` on an otherwise-allowed action.
    ///
    /// Detection previously only logged + broadcast; a `Block` (or
    /// `Quarantine`) outcome did not actually stop the action. This applies the
    /// responder's enforcement intent to the live `CheckAction` response: if a
    /// blocking anomaly fired and the current decision is `Allow`, the response
    /// is rewritten to `Deny` with a clear, operator-readable reason.
    ///
    /// Non-Allow responses (already Deny / Redact / Pending) are left untouched
    /// — the action is already governed, and we never weaken an existing
    /// decision. Returns the (possibly rewritten) response.
    fn enforce_anomaly_block(
        &self,
        response: CheckActionResponse,
        event: Option<&AnomalyEvent>,
    ) -> CheckActionResponse {
        let Some(event) = event else {
            return response;
        };
        if !event.response.is_blocking() {
            return response;
        }
        if response.decision != aa_proto::assembly::common::v1::Decision::Allow as i32 {
            return response;
        }
        let reason = format!(
            "anomaly detected ({:?}): {} — blocked by anomaly responder",
            event.anomaly_type, event.description
        );
        tracing::warn!(
            anomaly_type = ?event.anomaly_type,
            response = ?event.response,
            reason = %reason,
            "enforcing anomaly block: rewriting Allow → Deny"
        );
        CheckActionResponse {
            decision: aa_proto::assembly::common::v1::Decision::Deny as i32,
            reason,
            policy_rule: "anomaly_detection".to_string(),
            approval_id: String::new(),
            redact: None,
            decision_latency_us: response.decision_latency_us,
        }
    }

    /// Compose the live-ops registry id and ingest if a registry is attached.
    ///
    /// Returns `Some(op_id)` when ingestion happened so the caller can drive
    /// later transitions; returns `None` when no registry is attached (the
    /// typical setup for unit tests that don't exercise the live-ops view) or
    /// when the request lacks a trace identifier (a malformed request the
    /// engine will reject anyway).
    fn ingest_op(&self, req: &CheckActionRequest) -> Option<String> {
        let registry = self.ops_registry.as_ref()?;
        if req.trace_id.is_empty() {
            return None;
        }
        let op_id = format!("{}:{}", req.trace_id, req.span_id);
        // AAASM-1657: thread the agent_id through to the registry so the
        // operator-driven transitions (pause/resume/terminate) can route
        // their OpControlSignal to the right SDK subscriber. Falls back
        // to the agent-less `ingest` if the request omits the field
        // (defensive — engine would reject anyway).
        if let Some(agent_id) = req.agent_id.clone() {
            registry.ingest_with_agent(op_id.clone(), agent_id);
        } else {
            registry.ingest(op_id.clone());
        }
        Some(op_id)
    }

    /// Transition `Pending → Running` for an op that was just allowed.
    ///
    /// Swallows `OpsError::InvalidTransition` because a re-issued check for
    /// an op already in `Running` is a valid no-op, not a bug. Logs but does
    /// not error on `NotFound` since that only happens if the registry is
    /// dropped between [`ingest_op`] and here, which is non-fatal.
    fn allow_op(&self, op_id: &str) {
        let Some(registry) = self.ops_registry.as_ref() else {
            return;
        };
        if let Err(err) = registry.allow(op_id) {
            tracing::trace!(op_id = %op_id, ?err, "ops_registry.allow no-op");
        }
    }

    /// AAASM-1657: transition `Pending → Terminated` for an op the engine
    /// just denied. Mirrors [`allow_op`] semantics — `NotFound` and
    /// `InvalidTransition` are logged but not propagated.
    fn terminate_op(&self, op_id: &str) {
        let Some(registry) = self.ops_registry.as_ref() else {
            return;
        };
        if let Err(err) = registry.terminate(op_id) {
            tracing::trace!(op_id = %op_id, ?err, "ops_registry.terminate no-op");
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

        // AAASM-1944: validate the supplied `credential_token` against the
        // registered token for the claimed `agent_id` before any policy
        // evaluation runs. When the token is empty or mismatched, short-
        // circuit with a Deny + the appropriate A2A audit event so an
        // impersonator never reaches the policy engine.
        //
        // Skipped silently when the registry is absent (test fixtures
        // without registration) or when the claimed agent is not
        // registered (allows existing detection-slice fixtures to continue
        // working unchanged). Registered agents always go through the
        // strict validation path — opt-in is by registering the agent.
        if let Some(rejection) = self.validate_credential_token(&req).await {
            return Ok(Response::new(rejection));
        }

        // AAASM-1422: ingest the op into the live-ops registry before
        // evaluation so the dashboard sees the in-flight check even when
        // the engine takes time to decide. Idempotent — a retry of the
        // same {trace_id}:{span_id} pair keeps the existing state.
        let ops_op_id = self.ingest_op(&req);

        let (eval, latency_us, policy_rule) = self.evaluate_one(&req)?;
        self.maybe_emit_secret_alert(&req, &eval);

        // AAASM-1564: apply observe-mode transform before the response is
        // constructed. Resolution order is agent override → policy default
        // (Enforce). When the transform returns a ShadowEvent, the decision
        // has been rewritten to Allow and the shadow metadata flows into
        // record_audit so the audit log captures the would-be decision.
        let agent_override = self.lookup_agent_enforcement_override(&req);
        let effective_mode = resolve_enforcement_mode(agent_override, aa_core::EnforcementMode::Enforce);
        let (eval, shadow_event) = transform_for_observe_mode(eval, effective_mode);
        let deny_action = eval.deny_action;

        // If RequiresApproval, submit to the queue and block until decided.
        let response =
            if let Some(approval_response) = self.maybe_submit_approval(&req, &eval, latency_us, &policy_rule).await {
                approval_response
            } else {
                convert::eval_result_to_response(&eval, latency_us, &policy_rule)
            };

        // AAASM-3378 / AAASM-3384: run the live anomaly detector over the
        // evaluated action, then enforce a block-equivalent detection as a hard
        // Deny before the ops transition / audit observe the final decision.
        let anomaly_event = self.maybe_detect_anomaly(&req, &eval);
        let response = self.enforce_anomaly_block(response, anomaly_event.as_ref());

        // AAASM-1422 / AAASM-1657: transition the registry op to match the
        // final policy decision. Allow → Running, Deny → Terminated.
        // RequiresApproval is handled by the approval queue path above and
        // leaves the op in Pending until the operator decides.
        if let Some(op_id) = ops_op_id.as_deref() {
            let decision = response.decision;
            if decision == aa_proto::assembly::common::v1::Decision::Allow as i32 {
                self.allow_op(op_id);
            } else if decision == aa_proto::assembly::common::v1::Decision::Deny as i32 {
                self.terminate_op(op_id);
            }
        }

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

        // AAASM-3353: accrue LLM-call cost so daily / monthly budget limits fire.
        self.maybe_accrue_llm_spend(&req, &response);

        // Fire-and-forget audit entry — never blocks the response.
        self.record_audit(&req, &response, &eval, shadow_event.as_ref()).await;

        Ok(Response::new(response))
    }

    async fn batch_check(&self, request: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
        let batch = request.into_inner();
        let mut responses = Vec::with_capacity(batch.requests.len());

        for req in &batch.requests {
            // AAASM-3888: validate the supplied `credential_token` against the
            // registered token for the claimed `agent_id` BEFORE any evaluation
            // or side-effect (audit / spend / suspend), exactly as `check_action`
            // does. PolicyService runs under the non-rejecting `enrich`
            // interceptor, so the request-body `{org,team,agent}` triple and
            // `credential_token` are attacker-controlled; without this check a
            // peer at :50051 could forge a victim identity per batch entry and
            // drive forged audit, budget-exhaustion spend, or agent suspension
            // against the victim. On rejection, push the Deny and skip all
            // side-effects for this request — `evaluate_one`'s tenancy-anchoring
            // invariant (which assumes validation already ran) is thereby upheld.
            if let Some(rejection) = self.validate_credential_token(req).await {
                responses.push(rejection);
                continue;
            }

            let (eval, latency_us, policy_rule) = self.evaluate_one(req)?;
            self.maybe_emit_secret_alert(req, &eval);

            // AAASM-1564: same observe-mode transform as check_action above,
            // applied per-request inside the batch so each request honours its
            // agent's mode independently.
            let agent_override = self.lookup_agent_enforcement_override(req);
            let effective_mode = resolve_enforcement_mode(agent_override, aa_core::EnforcementMode::Enforce);
            let (eval, shadow_event) = transform_for_observe_mode(eval, effective_mode);
            let deny_action = eval.deny_action;

            let resp = if let Some(approval_response) =
                self.maybe_submit_approval(req, &eval, latency_us, &policy_rule).await
            {
                approval_response
            } else {
                convert::eval_result_to_response(&eval, latency_us, &policy_rule)
            };
            // AAASM-3378 / AAASM-3384: detect + enforce a block-equivalent
            // anomaly as a hard Deny in batch mode too.
            let anomaly_event = self.maybe_detect_anomaly(req, &eval);
            let resp = self.enforce_anomaly_block(resp, anomaly_event.as_ref());
            self.maybe_suspend_agent(req, deny_action).await;
            // AAASM-3353: accrue LLM-call cost so budget limits fire in batch mode too.
            self.maybe_accrue_llm_spend(req, &resp);
            self.record_audit(req, &resp, &eval, shadow_event.as_ref()).await;
            responses.push(resp);
        }

        Ok(Response::new(BatchCheckResponse { responses }))
    }

    type OpControlStreamStream = Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send + 'static>>;

    /// AAASM-1653: gateway → SDK push channel for op-lifecycle signals.
    ///
    /// Subscribes the caller to the configured [`OpControlPublisher`] and
    /// forwards every envelope whose `agent_id` matches the request's
    /// `agent_id`. The stream stays open until either the client cancels
    /// (`Closed` from the broadcast receiver) or the publisher is dropped.
    ///
    /// Lagged subscribers (those that fall behind the broadcast capacity)
    /// skip the missed envelopes and continue — the SDK reconciles via
    /// the next steady-state transition rather than replaying history.
    ///
    /// Returns `Status::unavailable` when no publisher is attached to the
    /// service (tests / partial wiring), and `Status::invalid_argument`
    /// when the request omits `agent_id`.
    async fn op_control_stream(
        &self,
        request: Request<OpControlSubscribeRequest>,
    ) -> Result<Response<Self::OpControlStreamStream>, Status> {
        let req = request.into_inner();
        let Some(agent_id) = req.agent_id else {
            return Err(Status::invalid_argument("agent_id is required"));
        };
        let Some(publisher) = self.ops_publisher.clone() else {
            return Err(Status::unavailable("op control channel not configured"));
        };

        let target_agent_id = agent_id.agent_id.clone();
        let target_team_id = agent_id.team_id.clone();
        let target_org_id = agent_id.org_id.clone();
        let mut rx = publisher.subscribe();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(envelope) => {
                        // AAASM-3881: a global halt (reserved op-id "*") is
                        // delivered to every subscriber unconditionally — it is
                        // the fleet-wide kill switch and is not addressed to a
                        // single agent. Per-agent envelopes still match on the
                        // composite id triple to avoid cross-org / cross-team
                        // agent_id collisions.
                        if !envelope.global
                            && (envelope.agent_id.agent_id != target_agent_id
                                || envelope.agent_id.team_id != target_team_id
                                || envelope.agent_id.org_id != target_org_id)
                        {
                            continue;
                        }
                        yield Ok(envelope.message);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, agent_id = %target_agent_id, "OpControlStream subscriber lagged");
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}
