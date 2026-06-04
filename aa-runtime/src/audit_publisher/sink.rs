//! NATS-backed [`AuditSink`] implementation.

use aa_core::storage::{AuditEntry, AuditSink, Result, StorageError};
use async_trait::async_trait;

use super::config::NatsConfig;
use super::subject::subject_for;

/// An [`AuditSink`] that publishes each entry to its
/// `assembly.audit.<tenant>.<agent>` subject over NATS.
///
/// The sink serializes the entry to JSON and publishes it fire-and-forget. When
/// the underlying connection is not established, [`emit`](AuditSink::emit)
/// returns a [`StorageError::Backend`] so the caller can divert the event to
/// the local buffer instead of blocking on a dead connection.
pub struct NatsAuditSink {
    client: async_nats::Client,
}

impl NatsAuditSink {
    /// Wrap an already-connected NATS client.
    #[must_use]
    pub fn new(client: async_nats::Client) -> Self {
        Self { client }
    }

    /// Connect to the server described by `config` and wrap the client.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] when the initial connection fails.
    pub async fn connect(config: &NatsConfig) -> Result<Self> {
        let client = config
            .connect()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(Self::new(client))
    }

    /// Whether the wrapped client currently has an established connection.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.client.connection_state() == async_nats::connection::State::Connected
    }
}

#[async_trait]
impl AuditSink for NatsAuditSink {
    async fn emit(&self, event: AuditEntry) -> Result<()> {
        if !self.is_connected() {
            return Err(StorageError::Backend("nats connection is not established".to_string()));
        }
        let subject = subject_for(&event);
        let payload = serde_json::to_vec(&event).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.client
            .publish(subject, payload.into())
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }
}
