//! Tests for the ReplayBuffer circular buffer.

use aa_api::models::{EventType, GovernanceEvent};
use aa_api::replay::ReplayBuffer;
use chrono::Utc;

fn make_event(id: u64, event_type: EventType) -> GovernanceEvent {
    GovernanceEvent {
        id,
        event_type,
        agent_id: "test-agent".to_string(),
        payload: serde_json::json!({"test": true}),
        timestamp: Utc::now(),
        team_id: None,
        org_id: None,
    }
}

#[test]
fn push_and_retrieve_events_since() {
    let buf = ReplayBuffer::new();
    buf.push(make_event(1, EventType::Violation));
    buf.push(make_event(2, EventType::Approval));
    buf.push(make_event(3, EventType::Budget));

    let events = buf.events_since(1);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].id, 2);
    assert_eq!(events[1].id, 3);
}

#[test]
fn events_since_zero_returns_all() {
    let buf = ReplayBuffer::new();
    buf.push(make_event(1, EventType::Violation));
    buf.push(make_event(2, EventType::Approval));

    let events = buf.events_since(0);
    assert_eq!(events.len(), 2);
}

#[test]
fn events_since_beyond_latest_returns_empty() {
    let buf = ReplayBuffer::new();
    buf.push(make_event(1, EventType::Violation));

    let events = buf.events_since(99);
    assert!(events.is_empty());
}

#[test]
fn empty_buffer_returns_empty() {
    let buf = ReplayBuffer::new();
    let events = buf.events_since(0);
    assert!(events.is_empty());
}

#[test]
fn buffer_caps_at_1000_entries() {
    let buf = ReplayBuffer::new();
    for i in 1..=1100 {
        buf.push(make_event(i, EventType::Violation));
    }

    // Should only have the last 1000 (ids 101..=1100).
    let all = buf.events_since(0);
    assert_eq!(all.len(), 1000);
    assert_eq!(all.first().unwrap().id, 101);
    assert_eq!(all.last().unwrap().id, 1100);
}
