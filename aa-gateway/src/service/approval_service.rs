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

use crate::approval::escalation::EscalationScheduler;
use crate::service::convert;

/// gRPC service implementation wiring approval RPCs to [`ApprovalQueue`].
pub struct ApprovalServiceImpl {
    queue: Arc<ApprovalQueue>,
    escalation_scheduler: Option<Arc<EscalationScheduler>>,
}

impl ApprovalServiceImpl {
    /// Create a new service backed by the given approval queue.
    pub fn new(queue: Arc<ApprovalQueue>) -> Self {
        Self {
            queue,
            escalation_scheduler: None,
        }
    }

    /// Create a new service backed by the given approval queue and escalation scheduler.
    ///
    /// When a scheduler is provided, `decide()` cancels the pending escalation timer.
    pub fn new_with_escalation(queue: Arc<ApprovalQueue>, escalation_scheduler: Option<Arc<EscalationScheduler>>) -> Self {
        Self {
            queue,
            escalation_scheduler,
        }
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
