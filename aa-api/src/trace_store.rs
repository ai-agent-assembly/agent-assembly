//! Session trace storage trait and in-memory implementation.
//!
//! Provides a [`TraceStore`] trait for recording and querying trace spans
//! indexed by session ID, plus an [`InMemoryTraceStore`] backed by `DashMap`.

use std::collections::VecDeque;

use dashmap::DashMap;

use crate::models::trace::TraceSpan;

/// Maximum number of sessions retained in the in-memory store.
const DEFAULT_MAX_SESSIONS: usize = 10_000;

/// Maximum number of spans retained per session.
const DEFAULT_MAX_SPANS_PER_SESSION: usize = 1_000;

/// Trait for session trace storage.
///
/// Implementations must be safe to share across threads and async tasks.
pub trait TraceStore: Send + Sync {
    /// Record a span for the given session.
    fn record_span(&self, session_id: &str, agent_id: &str, span: TraceSpan) -> Result<(), TraceStoreError>;

    /// Retrieve the full trace for a session, with spans in chronological order.
    fn get_trace(&self, session_id: &str) -> Result<Option<SessionTrace>, TraceStoreError>;

    /// List session IDs with recorded traces, most recent first.
    fn list_sessions(&self, limit: usize) -> Result<Vec<String>, TraceStoreError>;
}

/// Metadata for a stored session trace.
#[derive(Debug, Clone)]
pub struct SessionTrace {
    /// Agent that produced this trace.
    pub agent_id: String,
    /// Ordered list of spans in the session.
    pub spans: Vec<TraceSpan>,
}

/// Errors from trace store operations.
#[derive(Debug, thiserror::Error)]
pub enum TraceStoreError {
    /// An internal storage error.
    #[error("trace store internal error: {0}")]
    Internal(String),
}

/// Thread-safe in-memory trace store backed by `DashMap`.
pub struct InMemoryTraceStore {
    /// Map from session_id to (agent_id, spans).
    sessions: DashMap<String, (String, VecDeque<TraceSpan>)>,
    /// Insertion-ordered session IDs for LRU eviction and listing.
    session_order: std::sync::Mutex<VecDeque<String>>,
    max_sessions: usize,
    max_spans_per_session: usize,
}

impl InMemoryTraceStore {
    /// Create a new in-memory trace store with default capacity limits.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_SESSIONS, DEFAULT_MAX_SPANS_PER_SESSION)
    }

    /// Create a new in-memory trace store with custom capacity limits.
    pub fn with_capacity(max_sessions: usize, max_spans_per_session: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            session_order: std::sync::Mutex::new(VecDeque::with_capacity(max_sessions)),
            max_sessions,
            max_spans_per_session,
        }
    }
}

impl Default for InMemoryTraceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceStore for InMemoryTraceStore {
    fn record_span(&self, session_id: &str, agent_id: &str, span: TraceSpan) -> Result<(), TraceStoreError> {
        let is_new_session = !self.sessions.contains_key(session_id);

        if is_new_session {
            // Evict oldest session if at capacity.
            let mut order = self.session_order.lock().unwrap_or_else(|e| e.into_inner());
            if order.len() >= self.max_sessions {
                if let Some(oldest) = order.pop_front() {
                    self.sessions.remove(&oldest);
                }
            }
            order.push_back(session_id.to_string());
        }

        let mut entry = self.sessions.entry(session_id.to_string()).or_insert_with(|| {
            (
                agent_id.to_string(),
                VecDeque::with_capacity(self.max_spans_per_session),
            )
        });

        let (_, spans) = entry.value_mut();
        if spans.len() >= self.max_spans_per_session {
            spans.pop_front();
        }
        spans.push_back(span);

        Ok(())
    }

    fn get_trace(&self, session_id: &str) -> Result<Option<SessionTrace>, TraceStoreError> {
        let Some(entry) = self.sessions.get(session_id) else {
            return Ok(None);
        };

        let (agent_id, spans) = entry.value();
        let mut sorted_spans: Vec<TraceSpan> = spans.iter().cloned().collect();
        sorted_spans.sort_by_key(|s| s.start_time);

        Ok(Some(SessionTrace {
            agent_id: agent_id.clone(),
            spans: sorted_spans,
        }))
    }

    fn list_sessions(&self, limit: usize) -> Result<Vec<String>, TraceStoreError> {
        let order = self.session_order.lock().unwrap_or_else(|e| e.into_inner());
        // Return most recent first.
        Ok(order.iter().rev().take(limit).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn span(span_id: &str, start_secs: i64) -> TraceSpan {
        TraceSpan {
            span_id: span_id.to_string(),
            parent_span_id: None,
            operation: "op".to_string(),
            decision: None,
            start_time: Utc.timestamp_opt(start_secs, 0).unwrap(),
            end_time: None,
        }
    }

    #[test]
    fn default_constructs_empty_store() {
        let store = InMemoryTraceStore::default();
        // A fresh store has no trace for any session.
        assert!(store.get_trace("unknown-session").unwrap().is_none());
    }

    #[test]
    fn get_trace_returns_spans_sorted_by_start_time() {
        let store = InMemoryTraceStore::new();
        // Record out of chronological order; get_trace must sort by start_time.
        store.record_span("s1", "agent-a", span("late", 200)).unwrap();
        store.record_span("s1", "agent-a", span("early", 100)).unwrap();

        let trace = store.get_trace("s1").unwrap().expect("session exists");
        assert_eq!(trace.agent_id, "agent-a");
        let ids: Vec<&str> = trace.spans.iter().map(|s| s.span_id.as_str()).collect();
        assert_eq!(ids, vec!["early", "late"]);
    }

    #[test]
    fn record_span_evicts_oldest_span_at_capacity() {
        // One span per session capacity: the second span evicts the first.
        let store = InMemoryTraceStore::with_capacity(10, 1);
        store.record_span("s1", "agent-a", span("first", 100)).unwrap();
        store.record_span("s1", "agent-a", span("second", 200)).unwrap();

        let trace = store.get_trace("s1").unwrap().expect("session exists");
        let ids: Vec<&str> = trace.spans.iter().map(|s| s.span_id.as_str()).collect();
        assert_eq!(ids, vec!["second"]);
    }

    #[test]
    fn record_span_evicts_oldest_session_at_capacity() {
        // Capacity of one session: recording a second session evicts the first.
        let store = InMemoryTraceStore::with_capacity(1, 10);
        store.record_span("s1", "agent-a", span("a", 100)).unwrap();
        store.record_span("s2", "agent-b", span("b", 100)).unwrap();

        assert!(store.get_trace("s1").unwrap().is_none());
        assert!(store.get_trace("s2").unwrap().is_some());
    }

    #[test]
    fn list_sessions_returns_most_recent_first_and_respects_limit() {
        let store = InMemoryTraceStore::new();
        store.record_span("s1", "agent-a", span("a", 100)).unwrap();
        store.record_span("s2", "agent-a", span("b", 100)).unwrap();
        store.record_span("s3", "agent-a", span("c", 100)).unwrap();

        assert_eq!(store.list_sessions(10).unwrap(), vec!["s3", "s2", "s1"]);
        assert_eq!(store.list_sessions(2).unwrap(), vec!["s3", "s2"]);
    }

    #[test]
    fn trace_store_error_display_includes_message() {
        let err = TraceStoreError::Internal("boom".to_string());
        assert_eq!(err.to_string(), "trace store internal error: boom");
    }
}
