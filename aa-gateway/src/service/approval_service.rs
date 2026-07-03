//! `ApprovalService` tonic trait implementation wiring gRPC RPCs to `ApprovalQueue`.

use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use aa_proto::assembly::approval::v1::approval_service_server::ApprovalService;
use aa_proto::assembly::approval::v1::{
    ApprovalEvent, DecideRequest, DecideResponse, ListPendingRequest, ListPendingResponse, WatchApprovalsRequest,
};
use aa_runtime::approval::{ApprovalLookup, ApprovalQueue, ApprovalRequestId};

use crate::approval::db_escalation_scheduler::DbEscalationScheduler;
use crate::approval::escalation::EscalationScheduler;
use crate::iam::VerifiedCaller;
use crate::service::convert;
use crate::service::TenancyMode;

/// Tenant-authorization rule for an approval action (AAASM-3788, AAASM-4021).
///
/// A credentialed caller may act on an approval only when the caller and the
/// approval are not in *different* tenants. When both the caller and the
/// approval carry a `team_id`, they must match. If either side is untenanted
/// the action is allowed — the untenanted/single-tenant deployment fallback,
/// mirroring the policy-service tenancy residual under AAASM-3416.
///
/// AAASM-4021: that fallback is safe in an [`Untenanted`](TenancyMode::Untenanted)
/// deployment, but in a [`Tenanted`](TenancyMode::Tenanted) one it would let a
/// registered but *team-less* caller act on any tenant's approval. So when
/// tenancy is enforced, a team-less caller acting on a *tenanted* approval is
/// denied; the permissive fallback is preserved for every untenanted case
/// (untenanted resource, or untenanted deployment). The interceptor has already
/// guaranteed the caller is authenticated.
fn caller_may_act_on(caller: &VerifiedCaller, approval_team: Option<&str>, mode: TenancyMode) -> bool {
    match (caller.team_id.as_deref(), approval_team) {
        (Some(caller_team), Some(approval_team)) => caller_team == approval_team,
        // Team-less caller vs a tenanted approval: permissive only when tenancy
        // is not being enforced (AAASM-4021).
        (None, Some(_)) => mode == TenancyMode::Untenanted,
        // Untenanted approval (shared/global) — unchanged fallback.
        _ => true,
    }
}

/// gRPC service implementation wiring approval RPCs to [`ApprovalQueue`].
pub struct ApprovalServiceImpl {
    queue: Arc<ApprovalQueue>,
    escalation_scheduler: Option<Arc<EscalationScheduler>>,
    db_escalation_scheduler: Option<Arc<DbEscalationScheduler>>,
    /// Deployment tenancy posture for the cross-tenant guard (AAASM-4021).
    /// Defaults to [`TenancyMode::Untenanted`] so OSS/single-tenant deployments
    /// keep the permissive fallback.
    tenancy_mode: TenancyMode,
}

impl ApprovalServiceImpl {
    /// Create a new service backed by the given approval queue.
    pub fn new(queue: Arc<ApprovalQueue>) -> Self {
        Self {
            queue,
            escalation_scheduler: None,
            db_escalation_scheduler: None,
            tenancy_mode: TenancyMode::default(),
        }
    }

    /// Create a new service backed by the given approval queue and escalation scheduler.
    ///
    /// When a scheduler is provided, `decide()` cancels the pending escalation timer.
    pub fn new_with_escalation(
        queue: Arc<ApprovalQueue>,
        escalation_scheduler: Option<Arc<EscalationScheduler>>,
    ) -> Self {
        Self {
            queue,
            escalation_scheduler,
            db_escalation_scheduler: None,
            tenancy_mode: TenancyMode::default(),
        }
    }

    /// Attach a [`DbEscalationScheduler`] to this service.
    ///
    /// When present, `decide()` also cancels the DB-backed escalation row.
    pub fn with_db_scheduler(mut self, scheduler: Option<Arc<DbEscalationScheduler>>) -> Self {
        self.db_escalation_scheduler = scheduler;
        self
    }

    /// Set the deployment tenancy posture (AAASM-4021).
    ///
    /// In [`TenancyMode::Tenanted`] a team-less caller can no longer act on a
    /// tenanted approval via the untenanted fallback.
    pub fn with_tenancy_mode(mut self, mode: TenancyMode) -> Self {
        self.tenancy_mode = mode;
        self
    }

    /// Reject a cross-tenant `decide`: when the caller is tenanted and the target
    /// approval belongs to a *different* tenant, deny with `permission_denied`
    /// (the governance-bypass primary impact of AAASM-3788). An unparseable id or
    /// an absent pending row is intentionally a no-op — the later
    /// `convert`/`queue.decide` path surfaces those — preserving the original
    /// inline fall-through behavior exactly.
    fn enforce_decide_tenancy(&self, caller: &VerifiedCaller, request_id: &str) -> Result<(), Status> {
        if let Ok(id) = request_id.parse::<ApprovalRequestId>() {
            if let Some(ApprovalLookup::Pending(pending)) = self.queue.get_by_id(id) {
                if !caller_may_act_on(caller, pending.team_id.as_deref(), self.tenancy_mode) {
                    return Err(Status::permission_denied("approval belongs to a different tenant"));
                }
            }
        }
        Ok(())
    }

    /// Cancel any pending in-memory escalation timer for a decided request.
    /// Best-effort: logs on failure, never errors the RPC.
    fn cancel_escalation_timer(&self, id: ApprovalRequestId) {
        if let Some(scheduler) = &self.escalation_scheduler {
            match scheduler.cancel(id) {
                Ok(true) => tracing::debug!(approval_id = %id, "escalation timer cancelled"),
                Ok(false) => {} // already fired or never registered
                Err(e) => tracing::warn!(error = %e, approval_id = %id, "failed to cancel escalation timer"),
            }
        }
    }

    /// Cancel any DB-backed escalation row for a decided request.
    /// Best-effort: logs on failure, never errors the RPC.
    async fn cancel_db_escalation_row(&self, id: ApprovalRequestId) {
        if let Some(db_scheduler) = &self.db_escalation_scheduler {
            match db_scheduler.cancel(id).await {
                Ok(true) => tracing::debug!(approval_id = %id, "DB escalation row cancelled"),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, approval_id = %id, "failed to cancel DB escalation row"),
            }
        }
    }
}

#[tonic::async_trait]
impl ApprovalService for ApprovalServiceImpl {
    type WatchApprovalsStream = Pin<Box<dyn Stream<Item = Result<ApprovalEvent, Status>> + Send + 'static>>;

    async fn list_pending(
        &self,
        request: Request<ListPendingRequest>,
    ) -> Result<Response<ListPendingResponse>, Status> {
        // AAASM-3788 — when an authenticated caller is present (the production
        // interceptor guarantees it), scope the listing to the caller's tenant
        // so one team cannot enumerate another team's pending approvals.
        let caller = request.extensions().get::<VerifiedCaller>().cloned();
        let pending = self.queue.list();
        let requests = pending
            .iter()
            .filter(|p| match &caller {
                Some(c) => caller_may_act_on(c, p.team_id.as_deref(), self.tenancy_mode),
                None => true,
            })
            .map(convert::pending_to_proto)
            .collect();
        Ok(Response::new(ListPendingResponse { requests }))
    }

    async fn decide(&self, request: Request<DecideRequest>) -> Result<Response<DecideResponse>, Status> {
        // AAASM-3788 — read the verified caller (injected by the auth
        // interceptor) before consuming the request.
        let caller = request.extensions().get::<VerifiedCaller>().cloned();
        let mut req = request.into_inner();

        if let Some(caller) = &caller {
            // Bind the decision to the authenticated approver's tenant: reject a
            // cross-tenant decide (the governance-bypass primary impact).
            self.enforce_decide_tenancy(caller, &req.request_id)?;
            // `decided_by` is derived from the authenticated caller, never
            // trusted from the request body (which an attacker could forge to
            // attribute the decision to a spoofed operator in the audit trail).
            req.decided_by = caller.agent_id_str();
        }

        let (id, decision) =
            convert::decide_request_to_core(&req).map_err(|e| Status::invalid_argument(e.to_string()))?;

        match self.queue.decide(id, decision) {
            Ok(()) => {
                // Cancel any pending escalation now that a decision has been made.
                self.cancel_escalation_timer(id);
                self.cancel_db_escalation_row(id).await;
                Ok(Response::new(DecideResponse {
                    success: true,
                    error_message: String::new(),
                }))
            }
            Err(e) => Ok(Response::new(DecideResponse {
                success: false,
                error_message: e.to_string(),
            })),
        }
    }

    async fn watch_approvals(
        &self,
        _request: Request<WatchApprovalsRequest>,
    ) -> Result<Response<Self::WatchApprovalsStream>, Status> {
        let mut rx = self.queue.subscribe_events();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(approval_request) => {
                        yield Ok(convert::approval_event_to_proto(&approval_request));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "WatchApprovals subscriber lagged");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::broadcast;
    use uuid::Uuid;

    use aa_core::PolicyResult;
    use aa_proto::assembly::approval::v1::{ApprovalDecisionType, DecideRequest};
    use aa_runtime::approval::{ApprovalQueue, ApprovalRequest};

    use crate::approval::escalation::EscalationScheduler;

    fn temp_path(suffix: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("approval_svc_test_{}_{}.json", suffix, Uuid::new_v4()));
        p
    }

    fn make_scheduler(suffix: &str) -> Arc<EscalationScheduler> {
        let path = temp_path(suffix);
        let (tx, _rx) = broadcast::channel::<crate::approval::escalation::EscalationEvent>(4);
        Arc::new(EscalationScheduler::new(path, tx, Duration::from_millis(50)).unwrap())
    }

    fn make_approval_request(id: Uuid) -> ApprovalRequest {
        ApprovalRequest {
            request_id: id,
            agent_id: "agent-1".to_string(),
            action: "tool_call".to_string(),
            condition_triggered: "requires_approval".to_string(),
            submitted_at: 1_700_000_000,
            timeout_secs: 300,
            fallback: PolicyResult::Deny {
                reason: "timed out".to_string(),
            },
            team_id: None,
            timeout_override_secs: None,
            escalation_role_override: None,
        }
    }

    #[tokio::test]
    async fn decide_without_escalation_scheduler_returns_success() {
        let queue = Arc::new(ApprovalQueue::new());
        let service = ApprovalServiceImpl::new(Arc::clone(&queue));
        let id = Uuid::new_v4();
        queue.submit(make_approval_request(id));

        let req = tonic::Request::new(DecideRequest {
            request_id: id.to_string(),
            decision: ApprovalDecisionType::Approved.into(),
            decided_by: "alice".to_string(),
            reason: String::new(),
        });
        let resp = service.decide(req).await.unwrap().into_inner();
        assert!(resp.success);
    }

    #[tokio::test]
    async fn decide_with_escalation_scheduler_cancels_timer_on_success() {
        let queue = Arc::new(ApprovalQueue::new());
        let scheduler = make_scheduler("cancel_path");
        let service = ApprovalServiceImpl::new_with_escalation(Arc::clone(&queue), Some(Arc::clone(&scheduler)));

        let id = Uuid::new_v4();
        queue.submit(make_approval_request(id));
        // Register escalation so cancel has something to remove.
        scheduler.register(id, "team-z".to_string(), vec![], 3600).unwrap();

        let req = tonic::Request::new(DecideRequest {
            request_id: id.to_string(),
            decision: ApprovalDecisionType::Approved.into(),
            decided_by: "alice".to_string(),
            reason: String::new(),
        });
        let resp = service.decide(req).await.unwrap().into_inner();
        assert!(resp.success);
        // After decide(), the escalation entry must be gone.
        assert!(
            !scheduler.cancel(id).unwrap(),
            "entry should have been removed by decide()"
        );
    }

    fn make_approval_request_with_team(id: Uuid, team: Option<&str>) -> ApprovalRequest {
        let mut r = make_approval_request(id);
        r.team_id = team.map(|s| s.to_owned());
        r
    }

    fn verified_caller(team: Option<&str>) -> VerifiedCaller {
        VerifiedCaller {
            agent_key: [1u8; 16],
            team_id: team.map(|s| s.to_owned()),
            org_id: None,
        }
    }

    // Behavior lock for the cross-tenant authorization extracted into
    // `enforce_decide_tenancy` (AAASM-3823 S3776 refactor must not change it).
    #[tokio::test]
    async fn decide_cross_tenant_is_permission_denied() {
        let queue = Arc::new(ApprovalQueue::new());
        let service = ApprovalServiceImpl::new(Arc::clone(&queue));
        let id = Uuid::new_v4();
        queue.submit(make_approval_request_with_team(id, Some("team-b")));

        let mut req = tonic::Request::new(DecideRequest {
            request_id: id.to_string(),
            decision: ApprovalDecisionType::Approved.into(),
            decided_by: "attacker".to_string(),
            reason: String::new(),
        });
        req.extensions_mut().insert(verified_caller(Some("team-a")));

        let err = service.decide(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn decide_same_tenant_is_allowed() {
        let queue = Arc::new(ApprovalQueue::new());
        let service = ApprovalServiceImpl::new(Arc::clone(&queue));
        let id = Uuid::new_v4();
        queue.submit(make_approval_request_with_team(id, Some("team-a")));

        let mut req = tonic::Request::new(DecideRequest {
            request_id: id.to_string(),
            decision: ApprovalDecisionType::Approved.into(),
            decided_by: "ignored".to_string(),
            reason: String::new(),
        });
        req.extensions_mut().insert(verified_caller(Some("team-a")));

        let resp = service.decide(req).await.unwrap().into_inner();
        assert!(resp.success);
    }

    #[tokio::test]
    async fn decide_untenanted_caller_allowed_cross_team() {
        // Untenanted caller falls back to allow (single-tenant deployment).
        let queue = Arc::new(ApprovalQueue::new());
        let service = ApprovalServiceImpl::new(Arc::clone(&queue));
        let id = Uuid::new_v4();
        queue.submit(make_approval_request_with_team(id, Some("team-b")));

        let mut req = tonic::Request::new(DecideRequest {
            request_id: id.to_string(),
            decision: ApprovalDecisionType::Approved.into(),
            decided_by: "ops".to_string(),
            reason: String::new(),
        });
        req.extensions_mut().insert(verified_caller(None));

        let resp = service.decide(req).await.unwrap().into_inner();
        assert!(resp.success);
    }

    // AAASM-4021 — the untenanted fallback must not let a registered but
    // team-less caller act on a tenanted approval once tenancy is enforced.
    #[tokio::test]
    async fn decide_tenanted_mode_teamless_caller_denied_on_tenanted_approval() {
        let queue = Arc::new(ApprovalQueue::new());
        let service = ApprovalServiceImpl::new(Arc::clone(&queue)).with_tenancy_mode(TenancyMode::Tenanted);
        let id = Uuid::new_v4();
        queue.submit(make_approval_request_with_team(id, Some("team-b")));

        let mut req = tonic::Request::new(DecideRequest {
            request_id: id.to_string(),
            decision: ApprovalDecisionType::Approved.into(),
            decided_by: "teamless".to_string(),
            reason: String::new(),
        });
        req.extensions_mut().insert(verified_caller(None));

        let err = service.decide(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn caller_may_act_on_tenancy_matrix() {
        // Same-tenant match / mismatch is mode-independent.
        assert!(caller_may_act_on(
            &verified_caller(Some("t")),
            Some("t"),
            TenancyMode::Tenanted
        ));
        assert!(!caller_may_act_on(
            &verified_caller(Some("t")),
            Some("u"),
            TenancyMode::Untenanted
        ));
        // Team-less caller vs tenanted approval: permissive only when untenanted.
        assert!(caller_may_act_on(
            &verified_caller(None),
            Some("t"),
            TenancyMode::Untenanted
        ));
        assert!(!caller_may_act_on(
            &verified_caller(None),
            Some("t"),
            TenancyMode::Tenanted
        ));
        // Untenanted approval stays permissive in either mode.
        assert!(caller_may_act_on(
            &verified_caller(Some("t")),
            None,
            TenancyMode::Tenanted
        ));
        assert!(caller_may_act_on(&verified_caller(None), None, TenancyMode::Tenanted));
    }

    #[tokio::test]
    async fn decide_queue_not_found_returns_failure_response() {
        let queue = Arc::new(ApprovalQueue::new());
        let service = ApprovalServiceImpl::new(Arc::clone(&queue));

        let req = tonic::Request::new(DecideRequest {
            request_id: Uuid::new_v4().to_string(),
            decision: ApprovalDecisionType::Approved.into(),
            decided_by: "alice".to_string(),
            reason: String::new(),
        });
        let resp = service.decide(req).await.unwrap().into_inner();
        assert!(!resp.success);
        assert!(!resp.error_message.is_empty());
    }
}
