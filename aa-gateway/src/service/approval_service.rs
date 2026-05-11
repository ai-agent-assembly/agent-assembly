//! `ApprovalService` tonic trait implementation wiring gRPC RPCs to `ApprovalQueue`.

use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use aa_proto::assembly::approval::v1::approval_service_server::ApprovalService;
use aa_proto::assembly::approval::v1::{
    ApprovalEvent, DecideRequest, DecideResponse, ListPendingRequest, ListPendingResponse, WatchApprovalsRequest,
};
use aa_runtime::approval::ApprovalQueue;

use crate::approval::db_escalation_scheduler::DbEscalationScheduler;
use crate::approval::escalation::EscalationScheduler;
use crate::service::convert;

/// gRPC service implementation wiring approval RPCs to [`ApprovalQueue`].
pub struct ApprovalServiceImpl {
    queue: Arc<ApprovalQueue>,
    escalation_scheduler: Option<Arc<EscalationScheduler>>,
    db_escalation_scheduler: Option<Arc<DbEscalationScheduler>>,
}

impl ApprovalServiceImpl {
    /// Create a new service backed by the given approval queue.
    pub fn new(queue: Arc<ApprovalQueue>) -> Self {
        Self {
            queue,
            escalation_scheduler: None,
            db_escalation_scheduler: None,
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
        }
    }

    /// Attach a [`DbEscalationScheduler`] to this service.
    ///
    /// When present, `decide()` also cancels the DB-backed escalation row.
    pub fn with_db_scheduler(mut self, scheduler: Option<Arc<DbEscalationScheduler>>) -> Self {
        self.db_escalation_scheduler = scheduler;
        self
    }
}

#[tonic::async_trait]
impl ApprovalService for ApprovalServiceImpl {
    type WatchApprovalsStream = Pin<Box<dyn Stream<Item = Result<ApprovalEvent, Status>> + Send + 'static>>;

    async fn list_pending(
        &self,
        _request: Request<ListPendingRequest>,
    ) -> Result<Response<ListPendingResponse>, Status> {
        let pending = self.queue.list();
        let requests = pending.iter().map(convert::pending_to_proto).collect();
        Ok(Response::new(ListPendingResponse { requests }))
    }

    async fn decide(&self, request: Request<DecideRequest>) -> Result<Response<DecideResponse>, Status> {
        let req = request.into_inner();

        let (id, decision) =
            convert::decide_request_to_core(&req).map_err(|e| Status::invalid_argument(e.to_string()))?;

        match self.queue.decide(id, decision) {
            Ok(()) => {
                // Cancel any pending escalation timer for this request now that a
                // decision has been made — best-effort, log on failure.
                if let Some(scheduler) = &self.escalation_scheduler {
                    match scheduler.cancel(id) {
                        Ok(true) => tracing::debug!(approval_id = %id, "escalation timer cancelled"),
                        Ok(false) => {} // already fired or never registered
                        Err(e) => tracing::warn!(error = %e, approval_id = %id, "failed to cancel escalation timer"),
                    }
                }
                if let Some(db_scheduler) = &self.db_escalation_scheduler {
                    match db_scheduler.cancel(id).await {
                        Ok(true) => tracing::debug!(approval_id = %id, "DB escalation row cancelled"),
                        Ok(false) => {}
                        Err(e) => tracing::warn!(error = %e, approval_id = %id, "failed to cancel DB escalation row"),
                    }
                }
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
