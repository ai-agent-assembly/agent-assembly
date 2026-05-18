#![allow(unused_imports)]
//! AAASM-1497 / F122 ST-P — live-gateway integration tests for `GET /api/v1/ws/events`.
//!
//! ## Endpoint under test
//!
//! `GET /api/v1/ws/events` — WebSocket upgrade endpoint that streams `GovernanceEvent`
//! JSON text frames from the gateway's `EventBroadcast` channel. Supports replay
//! via `?since=<id>` and type filtering via `?types=<csv>`.
//!
//! ## Divergences from the ticket AC
//!
//! | Ticket expectation | Actual behaviour |
//! |---|---|
//! | Filter param `event_types=` | Actual param is `types=` (from `WsQueryParams`) |
//! | `?types=garbage` → 400 | 101 upgrade + silent empty stream; `EventType::parse_filter` drops unknowns |
//! | `AuthMode::ApiKey` variant | Auth mode is `AuthMode::On`; `start_with_auth` already exists |
//! | Replay buffer capacity unspecified | Confirmed 1000 events (circular, oldest dropped) |

mod common;

use std::time::Duration;

use aa_api::models::{EventType, GovernanceEvent};
use aa_core::{AgentId, PolicyResult};
use aa_gateway::budget::types::BudgetAlert;
use aa_runtime::approval::ApprovalRequest;
use aa_runtime::pipeline::event::{EnrichedEvent, EventSource, PipelineEvent};
use chrono::Utc;
use common::TopologyTestEnv;
use futures::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

/// Read the next WebSocket text frame and deserialise it as a `GovernanceEvent`.
/// Panics if the 2-second timeout expires or the frame cannot be parsed.
#[allow(dead_code)]
async fn recv_event(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
) -> GovernanceEvent {
    let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timeout waiting for WS message")
        .expect("stream closed unexpectedly")
        .expect("ws error");
    serde_json::from_str(&msg.into_text().unwrap()).unwrap()
}

#[allow(dead_code)]
fn make_pipeline_event(agent_id: &str) -> PipelineEvent {
    PipelineEvent::Audit(Box::new(EnrichedEvent {
        inner: Default::default(),
        received_at_ms: 0,
        source: EventSource::Sdk,
        agent_id: agent_id.to_string(),
        connection_id: 0,
        sequence_number: 0,
    }))
}

#[allow(dead_code)]
fn make_approval_request() -> ApprovalRequest {
    ApprovalRequest {
        request_id: Uuid::new_v4(),
        agent_id: "test-agent".into(),
        action: "test-action".into(),
        condition_triggered: "test-condition".into(),
        submitted_at: 0,
        timeout_secs: 60,
        fallback: PolicyResult::Deny {
            reason: "timeout".into(),
        },
        team_id: None,
        timeout_override_secs: None,
        escalation_role_override: None,
    }
}

#[allow(dead_code)]
fn make_budget_alert() -> BudgetAlert {
    BudgetAlert {
        agent_id: AgentId::from_bytes([0u8; 16]),
        team_id: None,
        threshold_pct: 80,
        spent_usd: 8.0,
        limit_usd: 10.0,
    }
}

#[allow(dead_code)]
fn make_governance_event(id: u64) -> GovernanceEvent {
    GovernanceEvent {
        id,
        event_type: EventType::Violation,
        agent_id: "test-agent".to_string(),
        payload: serde_json::json!({}),
        timestamp: Utc::now(),
    }
}
