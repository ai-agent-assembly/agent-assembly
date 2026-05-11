//! Gateway-side message router with policy enforcement.
//!
//! [`MessageRouter::enforce`] accepts a [`PolicyDecision`] produced by the
//! cascade evaluation layer and either passes or blocks the message. On block,
//! it emits a hash-chained [`AuditEntry`] with [`AuditEventType::MessageBlocked`].

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AuditEntry, AuditEventType, GovernanceAction};

use crate::engine::decision::PolicyDecision;

/// Returned when a message is blocked by policy.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageBlockedError {
    /// Human-readable reason from the policy decision.
    pub reason: String,
}

impl core::fmt::Display for MessageBlockedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "message blocked: {}", self.reason)
    }
}

/// Routes inter-team messages and enforces policy decisions.
///
/// Call [`MessageRouter::enforce`] with the result of
/// [`crate::engine::decision::merge_decisions`]. `Allow` passes through;
/// `RequireApproval` and `Deny` emit a `MessageBlocked` audit entry and
/// return [`MessageBlockedError`].
pub struct MessageRouter {
    audit_tx: Option<mpsc::Sender<AuditEntry>>,
    audit_seq: Arc<AtomicU64>,
    audit_last_hash: Arc<Mutex<[u8; 32]>>,
}

impl MessageRouter {
    /// Create a router with no audit sink.
    pub fn new() -> Self {
        Self {
            audit_tx: None,
            audit_seq: Arc::new(AtomicU64::new(0)),
            audit_last_hash: Arc::new(Mutex::new([0u8; 32])),
        }
    }

    /// Attach an mpsc sender so blocked messages emit `MessageBlocked` audit entries.
    pub fn with_audit_tx(mut self, tx: mpsc::Sender<AuditEntry>) -> Self {
        self.audit_tx = Some(tx);
        self
    }

    /// Enforce the policy decision for a `SendMessage` action.
    ///
    /// Returns `Ok(())` for `Allow`. For `RequireApproval` or `Deny`, emits a
    /// `MessageBlocked` audit entry (if an audit sink is configured) and
    /// returns `Err(MessageBlockedError)`.
    pub fn enforce(
        &self,
        decision: PolicyDecision,
        sender_agent_id: AgentId,
        action: &GovernanceAction,
    ) -> Result<(), MessageBlockedError> {
        let block_reason = match &decision {
            PolicyDecision::Allow => return Ok(()),
            PolicyDecision::RequireApproval { .. } => "cross_team_unallowed_channel".to_string(),
            PolicyDecision::Deny { reason, .. } => reason.clone(),
        };

        if let Some(ref tx) = self.audit_tx {
            let timestamp_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let seq = self.audit_seq.fetch_add(1, Ordering::Relaxed);
            let mut last_hash = self.audit_last_hash.lock().unwrap_or_else(|e| e.into_inner());

            let (channel_id, source_team_id, target_team_id) = match action {
                GovernanceAction::SendMessage {
                    channel_id,
                    source_team_id,
                    target_team_id,
                } => (
                    channel_id.as_deref().unwrap_or("unknown").to_string(),
                    source_team_id.as_deref().unwrap_or("unknown").to_string(),
                    target_team_id.as_deref().unwrap_or("unknown").to_string(),
                ),
                _ => ("unknown".to_string(), "unknown".to_string(), "unknown".to_string()),
            };

            let payload = format!(
                r#"{{"reason":"{}","channel_id":"{}","source_team_id":"{}","target_team_id":"{}"}}"#,
                block_reason, channel_id, source_team_id, target_team_id
            );

            let entry = AuditEntry::new(
                seq,
                timestamp_ns,
                AuditEventType::MessageBlocked,
                sender_agent_id,
                SessionId::from_bytes([0u8; 16]),
                payload,
                *last_hash,
            );
            *last_hash = *entry.entry_hash();
            drop(last_hash);
            let _ = tx.try_send(entry);
        }

        Err(MessageBlockedError { reason: block_reason })
    }
}

impl Default for MessageRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::decision::PolicyDecision;
    use crate::policy::scope::PolicyScope;
    use aa_core::identity::AgentId;
    use aa_core::{AuditEventType, GovernanceAction};

    fn sender_id() -> AgentId {
        AgentId::from_bytes([1u8; 16])
    }

    fn send_msg(channel: &str) -> GovernanceAction {
        GovernanceAction::SendMessage {
            source_team_id: Some("team-alpha".into()),
            target_team_id: Some("team-beta".into()),
            channel_id: Some(channel.into()),
        }
    }

    #[test]
    fn allow_decision_passes_through() {
        let router = MessageRouter::new();
        let result = router.enforce(PolicyDecision::Allow, sender_id(), &send_msg("ops"));
        assert!(result.is_ok());
    }

    #[test]
    fn require_approval_returns_blocked_error() {
        let router = MessageRouter::new();
        let decision = PolicyDecision::RequireApproval {
            reason: "channel policy".into(),
            timeout_secs: 300,
        };
        let result = router.enforce(decision, sender_id(), &send_msg("private"));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().reason, "cross_team_unallowed_channel");
    }

    #[test]
    fn deny_decision_returns_blocked_error_with_policy_reason() {
        let router = MessageRouter::new();
        let decision = PolicyDecision::Deny {
            reason: "channel denied".into(),
            source_scope: PolicyScope::Global,
        };
        let result = router.enforce(decision, sender_id(), &send_msg("private"));
        assert_eq!(result.unwrap_err().reason, "channel denied");
    }

    #[test]
    fn blocked_message_emits_audit_entry() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let router = MessageRouter::new().with_audit_tx(tx);
        let decision = PolicyDecision::RequireApproval {
            reason: "cross-team channel policy".into(),
            timeout_secs: 300,
        };
        let _ = router.enforce(decision, sender_id(), &send_msg("private"));

        let entry = rx.try_recv().expect("expected audit entry");
        assert_eq!(entry.event_type(), AuditEventType::MessageBlocked);
        assert!(entry.payload().contains("cross_team_unallowed_channel"));
        assert!(entry.payload().contains("private"));
        assert!(entry.payload().contains("team-alpha"));
        assert!(entry.payload().contains("team-beta"));
    }

    #[test]
    fn allow_decision_emits_no_audit_entry() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let router = MessageRouter::new().with_audit_tx(tx);
        let _ = router.enforce(PolicyDecision::Allow, sender_id(), &send_msg("ops"));
        assert!(rx.try_recv().is_err(), "no audit entry expected for Allow");
    }
}
