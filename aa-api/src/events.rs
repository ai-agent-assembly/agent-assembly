//! Unified event broadcast bus for the API layer.
//!
//! Aggregates the individual `tokio::sync::broadcast` channels from the
//! runtime, gateway, and proxy crates into a single struct that the API
//! layer (and downstream WebSocket streaming) can subscribe to.

use aa_gateway::alerts::SecretAlert;
use aa_gateway::budget::types::BudgetAlert;
use aa_runtime::approval::ApprovalRequest;
use aa_runtime::pipeline::event::PipelineEvent;
use tokio::sync::broadcast;

/// Default channel capacity for each event broadcast.
const DEFAULT_CHANNEL_CAPACITY: usize = 256;

/// Unified event broadcast bus.
///
/// Holds one `broadcast::Sender` per event domain so that API consumers
/// (e.g. the WebSocket streaming endpoint) can subscribe to any
/// combination without reaching into individual subsystem internals.
pub struct EventBroadcast {
    pipeline_tx: broadcast::Sender<PipelineEvent>,
    approval_tx: broadcast::Sender<ApprovalRequest>,
    /// Mirror of `ApprovalQueue.expiry_event_tx` for the API layer.
    /// Fires when a pending request auto-expires (AAASM-1453).
    approval_expiry_tx: broadcast::Sender<ApprovalRequest>,
    budget_tx: broadcast::Sender<BudgetAlert>,
    /// Secret-detection alerts emitted when the gateway's credential
    /// scanner produces a non-empty findings list (AAASM-1545).
    secret_tx: broadcast::Sender<SecretAlert>,
}

impl EventBroadcast {
    /// Create a new `EventBroadcast` with the given per-channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (pipeline_tx, _) = broadcast::channel(capacity);
        let (approval_tx, _) = broadcast::channel(capacity);
        let (approval_expiry_tx, _) = broadcast::channel(capacity);
        let (budget_tx, _) = broadcast::channel(capacity);
        let (secret_tx, _) = broadcast::channel(capacity);
        Self {
            pipeline_tx,
            approval_tx,
            approval_expiry_tx,
            budget_tx,
            secret_tx,
        }
    }

    /// Subscribe to pipeline audit events.
    pub fn subscribe_pipeline(&self) -> broadcast::Receiver<PipelineEvent> {
        self.pipeline_tx.subscribe()
    }

    /// Subscribe to human-approval request events.
    pub fn subscribe_approvals(&self) -> broadcast::Receiver<ApprovalRequest> {
        self.approval_tx.subscribe()
    }

    /// Subscribe to approval auto-expiration events (AAASM-1453).
    ///
    /// Fires when a pending request's per-request timeout elapses before
    /// any human decision arrives. The WS dispatch loop forwards these
    /// to the client as `approval` events with `status: "expired"`.
    pub fn subscribe_approval_expirations(&self) -> broadcast::Receiver<ApprovalRequest> {
        self.approval_expiry_tx.subscribe()
    }

    /// Subscribe to budget threshold alerts.
    pub fn subscribe_budget(&self) -> broadcast::Receiver<BudgetAlert> {
        self.budget_tx.subscribe()
    }

    /// Get a clone of the pipeline event sender.
    pub fn pipeline_sender(&self) -> broadcast::Sender<PipelineEvent> {
        self.pipeline_tx.clone()
    }

    /// Get a clone of the approval event sender.
    pub fn approval_sender(&self) -> broadcast::Sender<ApprovalRequest> {
        self.approval_tx.clone()
    }

    /// Get a clone of the approval-expiration event sender (AAASM-1453).
    pub fn approval_expiry_sender(&self) -> broadcast::Sender<ApprovalRequest> {
        self.approval_expiry_tx.clone()
    }

    /// Get a clone of the budget alert sender.
    pub fn budget_sender(&self) -> broadcast::Sender<BudgetAlert> {
        self.budget_tx.clone()
    }

    /// Subscribe to secret-detection alerts (AAASM-1545).
    pub fn subscribe_secret(&self) -> broadcast::Receiver<SecretAlert> {
        self.secret_tx.subscribe()
    }

    /// Get a clone of the secret-detection alert sender (AAASM-1545).
    pub fn secret_sender(&self) -> broadcast::Sender<SecretAlert> {
        self.secret_tx.clone()
    }
}

impl Default for EventBroadcast {
    fn default() -> Self {
        Self::new(DEFAULT_CHANNEL_CAPACITY)
    }
}
