//! Circular replay buffer for reconnecting WebSocket clients.
//!
//! Stores the most recent [`MAX_CAPACITY`] governance events so that a
//! client reconnecting with `since=<event_id>` can catch up on events
//! it missed while disconnected.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::models::{EventId, GovernanceEvent};

/// Maximum number of events retained in the replay buffer.
const MAX_CAPACITY: usize = 1_000;

/// Thread-safe circular buffer of recent governance events.
#[derive(Debug, Clone)]
pub struct ReplayBuffer {
    inner: Arc<Mutex<VecDeque<GovernanceEvent>>>,
}

impl ReplayBuffer {
    /// Create a new empty replay buffer.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_CAPACITY))),
        }
    }

    /// Push an event into the buffer, evicting the oldest if at capacity.
    pub fn push(&self, event: GovernanceEvent) {
        let mut buf = self.inner.lock().expect("replay buffer lock poisoned");
        if buf.len() >= MAX_CAPACITY {
            buf.pop_front();
        }
        buf.push_back(event);
    }

    /// Return all events with an id strictly greater than `since_id`.
    ///
    /// Returns an empty vec if `since_id` is beyond the newest event
    /// or the buffer is empty.
    pub fn events_since(&self, since_id: EventId) -> Vec<GovernanceEvent> {
        let buf = self.inner.lock().expect("replay buffer lock poisoned");
        buf.iter().filter(|e| e.id > since_id).cloned().collect()
    }
}

impl Default for ReplayBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::event_type::EventType;

    fn event(id: EventId) -> GovernanceEvent {
        GovernanceEvent {
            id,
            event_type: EventType::Violation,
            agent_id: "agent-a".to_string(),
            payload: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn default_matches_new_empty_buffer() {
        let buf = ReplayBuffer::default();
        // events_since(0) on an empty buffer yields nothing to replay.
        assert!(buf.events_since(0).is_empty());
    }

    #[test]
    fn events_since_returns_only_newer_events() {
        let buf = ReplayBuffer::new();
        for id in 1..=5 {
            buf.push(event(id));
        }
        let replayed: Vec<EventId> = buf.events_since(2).into_iter().map(|e| e.id).collect();
        assert_eq!(replayed, vec![3, 4, 5]);
    }

    #[test]
    fn events_since_newest_id_is_empty() {
        let buf = ReplayBuffer::new();
        buf.push(event(1));
        buf.push(event(2));
        // since_id at or beyond the newest event yields nothing.
        assert!(buf.events_since(2).is_empty());
        assert!(buf.events_since(99).is_empty());
    }

    #[test]
    fn push_evicts_oldest_when_at_capacity() {
        let buf = ReplayBuffer::new();
        // Fill beyond capacity; the oldest events must be evicted, so a
        // reconnecting client asking for everything only sees the tail.
        for id in 1..=(MAX_CAPACITY as u64 + 5) {
            buf.push(event(id));
        }
        let all = buf.events_since(0);
        assert_eq!(all.len(), MAX_CAPACITY);
        // Oldest surviving event is id=6 (first 5 evicted).
        assert_eq!(all.first().map(|e| e.id), Some(6));
        assert_eq!(all.last().map(|e| e.id), Some(MAX_CAPACITY as u64 + 5));
    }

    #[test]
    fn clone_shares_backing_buffer() {
        let buf = ReplayBuffer::new();
        let clone = buf.clone();
        // Clone shares the Arc<Mutex<..>>, so a push via one is visible via the other.
        buf.push(event(7));
        assert_eq!(clone.events_since(0).len(), 1);
    }
}
