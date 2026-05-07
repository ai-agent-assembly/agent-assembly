//! `AuditService` tonic trait implementation wiring gRPC RPCs to [`AuditWriter`].
//!
//! [`AuditWriter`]: crate::audit::AuditWriter

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use tonic::{Request, Response, Status};

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AuditEntry, AuditEventType, Lineage};
use aa_proto::assembly::audit::v1::audit_service_server::AuditService;
use aa_proto::assembly::audit::v1::{AuditEvent, ReportEventsRequest, ReportEventsResponse, StreamEventsResponse};
use aa_proto::assembly::common::v1::Decision;

use crate::registry::{convert as registry_convert, AgentRegistry};
use crate::service::convert;

/// gRPC service implementation wiring `ReportEvents` / `StreamEvents` to the
/// audit writer channel.
pub struct AuditServiceImpl {
    audit_tx: mpsc::Sender<AuditEntry>,
    audit_drops: Arc<AtomicU64>,
    seq: AtomicU64,
    last_hash: Mutex<[u8; 32]>,
    registry: Option<Arc<AgentRegistry>>,
}

impl AuditServiceImpl {
    /// Create a new service backed by the given audit channel.
    ///
    /// `initial_hash` seeds the hash chain — pass `[0u8; 32]` for a fresh chain,
    /// or the last persisted hash to continue an existing chain.
    pub fn new(audit_tx: mpsc::Sender<AuditEntry>, audit_drops: Arc<AtomicU64>, initial_hash: [u8; 32]) -> Self {
        Self {
            audit_tx,
            audit_drops,
            seq: AtomicU64::new(0),
            last_hash: Mutex::new(initial_hash),
            registry: None,
        }
    }

    /// Create a new service backed by the given audit channel, with access to
    /// the agent registry for lineage enrichment.
    pub fn new_with_registry(
        audit_tx: mpsc::Sender<AuditEntry>,
        audit_drops: Arc<AtomicU64>,
        initial_hash: [u8; 32],
        registry: Arc<AgentRegistry>,
    ) -> Self {
        Self {
            audit_tx,
            audit_drops,
            seq: AtomicU64::new(0),
            last_hash: Mutex::new(initial_hash),
            registry: Some(registry),
        }
    }

    /// Convert a proto `AuditEvent` into a core `AuditEntry` and send via try_send.
    ///
    /// Maintains the hash chain by reading and updating `last_hash`.
    /// Returns the event_id on success, or the event_id even if the entry was dropped.
    async fn ingest_event(&self, event: &AuditEvent) -> String {
        let event_id = event.event_id.clone();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);

        // agent_id_bytes: hash of just the agent_id string (existing AuditEntry convention).
        let agent_id_bytes = event
            .agent_id
            .as_ref()
            .map(|a| convert::hash_to_16(&a.agent_id))
            .unwrap_or([0u8; 16]);
        let agent_id = AgentId::from_bytes(agent_id_bytes);

        // registry_key: composite hash (org/team/agent_id) matching the lifecycle-service
        // registration path — must use proto_agent_id_to_key to find the correct record.
        let registry_key = event
            .agent_id
            .as_ref()
            .map(registry_convert::proto_agent_id_to_key)
            .unwrap_or([0u8; 16]);

        let session_id = if event.trace_id.is_empty() {
            SessionId::from_bytes([0u8; 16])
        } else {
            SessionId::from_bytes(convert::hash_to_16(&event.trace_id))
        };

        let timestamp_ns = event
            .occurred_at
            .as_ref()
            .map(|t| (t.unix_ms as u64).saturating_mul(1_000_000))
            .unwrap_or(0);

        let event_type = decision_to_audit_event_type(event.decision);

        let payload = serde_json::json!({
            "event_id": &event.event_id,
            "action_type": event.action_type,
            "span_id": &event.span_id,
            "parent_span_id": &event.parent_span_id,
        })
        .to_string();

        let lineage = self
            .registry
            .as_ref()
            .and_then(|r| r.get(&registry_key))
            .map(|record| Lineage {
                root_agent_id: record.root_agent_id.map(AgentId::from_bytes),
                // parent_agent_id is stored as Option<String> in AgentRecord (the raw
                // string from the registration proto). Converting it to AgentId bytes
                // requires a separate registry lookup by name — deferred to a follow-up.
                parent_agent_id: None,
                team_id: record.team_id.clone(),
                delegation_reason: record.delegation_reason.clone(),
                spawned_by_tool: record.spawned_by_tool.clone(),
                depth: Some(record.depth),
            })
            .unwrap_or_default();

        let mut last_hash = self.last_hash.lock().await;

        let entry = AuditEntry::new_with_lineage(seq, timestamp_ns, event_type, agent_id, session_id, payload, *last_hash, lineage);

        *last_hash = *entry.entry_hash();
        drop(last_hash);

        if let Err(e) = self.audit_tx.try_send(entry) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(seq, "audit channel full — event dropped");
                    self.audit_drops.fetch_add(1, Ordering::Relaxed);
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!("audit channel closed — AuditWriter task has exited");
                }
            }
        }

        event_id
    }
}

/// Map a proto `Decision` i32 to `AuditEventType`.
fn decision_to_audit_event_type(decision: i32) -> AuditEventType {
    match Decision::try_from(decision) {
        Ok(Decision::Allow) => AuditEventType::ToolCallIntercepted,
        Ok(Decision::Deny) => AuditEventType::PolicyViolation,
        Ok(Decision::Redact) => AuditEventType::CredentialLeakBlocked,
        Ok(Decision::Pending) => AuditEventType::ApprovalRequested,
        _ => AuditEventType::PolicyViolation,
    }
}

#[tonic::async_trait]
impl AuditService for AuditServiceImpl {
    async fn report_events(
        &self,
        request: Request<ReportEventsRequest>,
    ) -> Result<Response<ReportEventsResponse>, Status> {
        let batch = request.into_inner();
        let mut event_ids = Vec::with_capacity(batch.events.len());

        for event in &batch.events {
            let id = self.ingest_event(event).await;
            event_ids.push(id);
        }

        Ok(Response::new(ReportEventsResponse { event_ids }))
    }

    async fn stream_events(
        &self,
        request: Request<tonic::Streaming<AuditEvent>>,
    ) -> Result<Response<StreamEventsResponse>, Status> {
        let mut stream = request.into_inner();
        let mut events_received: i64 = 0;

        while let Some(event) = stream.message().await.map_err(|e| {
            tracing::error!(error = %e, "stream_events receive error");
            Status::internal(format!("stream receive error: {e}"))
        })? {
            self.ingest_event(&event).await;
            events_received += 1;
        }

        Ok(Response::new(StreamEventsResponse { events_received }))
    }
}
