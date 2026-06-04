//! Shared test fixtures for the SQLite event-buffer integration tests.
#![allow(dead_code)] // not every test file uses every fixture

use std::sync::{Arc, Mutex};

use aa_core::audit::{AuditEntry, AuditEventType};
use aa_core::identity::{AgentId, SessionId};
use aa_core::storage::{AuditSink, Result, StorageError};
use async_trait::async_trait;

/// Build a deterministic [`AuditEntry`] carrying `payload`, tagged with `seq`.
pub fn sample_entry(seq: u64, payload: &str) -> AuditEntry {
    AuditEntry::new(
        seq,
        1_000 + seq,
        AuditEventType::ToolCallIntercepted,
        AgentId::from_bytes([1u8; 16]),
        SessionId::from_bytes([2u8; 16]),
        payload.to_string(),
        [0u8; 32],
    )
}

/// An [`AuditSink`] that records every entry it receives, in order.
#[derive(Clone, Default)]
pub struct CollectingSink {
    pub received: Arc<Mutex<Vec<AuditEntry>>>,
}

impl CollectingSink {
    /// Snapshot the entries received so far.
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.received.lock().expect("sink mutex poisoned").clone()
    }
}

#[async_trait]
impl AuditSink for CollectingSink {
    async fn emit(&self, event: AuditEntry) -> Result<()> {
        self.received.lock().expect("sink mutex poisoned").push(event);
        Ok(())
    }
}

/// An [`AuditSink`] that accepts the first `fail_after` entries, then fails
/// every subsequent `emit` — modelling an upstream that goes unreachable
/// part-way through a flush.
#[derive(Clone)]
pub struct FlakySink {
    pub received: Arc<Mutex<Vec<AuditEntry>>>,
    pub fail_after: usize,
}

impl FlakySink {
    /// Create a sink that succeeds for the first `fail_after` emits.
    pub fn new(fail_after: usize) -> Self {
        Self {
            received: Arc::new(Mutex::new(Vec::new())),
            fail_after,
        }
    }

    /// Snapshot the entries accepted so far.
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.received.lock().expect("sink mutex poisoned").clone()
    }
}

#[async_trait]
impl AuditSink for FlakySink {
    async fn emit(&self, event: AuditEntry) -> Result<()> {
        let mut received = self.received.lock().expect("sink mutex poisoned");
        if received.len() >= self.fail_after {
            return Err(StorageError::Backend("upstream unreachable".into()));
        }
        received.push(event);
        Ok(())
    }
}
