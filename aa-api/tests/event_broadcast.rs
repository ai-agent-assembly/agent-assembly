//! Tests for the EventBroadcast unified event bus.

use aa_api::events::EventBroadcast;
use aa_gateway::budget::types::BudgetAlert;
use aa_runtime::pipeline::event::{LayerDegradationInfo, PipelineEvent};

#[tokio::test]
async fn subscribe_pipeline_receives_published_event() {
    let bus = EventBroadcast::new(16);
    let mut rx = bus.subscribe_pipeline();
    let tx = bus.pipeline_sender();

    let event = PipelineEvent::LayerDegradation(LayerDegradationInfo {
        layer: "test".to_string(),
        reason: "unit test".to_string(),
        remaining_layers: vec![],
    });

    tx.send(event).unwrap();
    let received = rx.recv().await.unwrap();
    assert!(matches!(received, PipelineEvent::LayerDegradation(_)));
}

#[tokio::test]
async fn subscribe_approvals_receives_published_event() {
    let bus = EventBroadcast::new(16);
    let mut rx = bus.subscribe_approvals();
    let tx = bus.approval_sender();

    let request = aa_runtime::approval::ApprovalRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_id: "test-agent".to_string(),
        action: "test action".to_string(),
        condition_triggered: "test condition".to_string(),
        submitted_at: 0,
        timeout_secs: 60,
        fallback: aa_core::PolicyResult::Deny {
            reason: "test".to_string(),
        },
    };

    tx.send(request).unwrap();
    let received = rx.recv().await.unwrap();
    assert_eq!(received.agent_id, "test-agent");
}

#[tokio::test]
async fn subscribe_budget_receives_published_alert() {
    let bus = EventBroadcast::new(16);
    let mut rx = bus.subscribe_budget();
    let tx = bus.budget_sender();

    let alert = BudgetAlert {
        agent_id: aa_core::AgentId::from_bytes([1; 16]),
        team_id: None,
        threshold_pct: 80,
        spent_usd: 8.0,
        limit_usd: 10.0,
    };

    tx.send(alert).unwrap();
    let received = rx.recv().await.unwrap();
    assert_eq!(received.threshold_pct, 80);
}
