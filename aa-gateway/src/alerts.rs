//! Security alert events emitted by the gateway.
//!
//! Currently hosts [`SecretAlert`] — fired when the policy engine's
//! credential scanner produces a non-empty `credential_findings` list
//! for an outbound payload (AAASM-1545).
//!
//! Security invariant: this struct stores only [`CredentialKind`] tags
//! and finding counts. The raw matched bytes never appear here and must
//! not be added to any field.

use aa_core::AgentId;
use aa_security::CredentialKind;

/// Broadcast event raised when one or more credential / sensitive-value
/// patterns are detected in an evaluated payload.
///
/// Consumers (e.g. `aa-api::alerts::capture::spawn_secret_alert_capture`)
/// turn this into a persistent `StoredAlert` for the public alerts API.
#[derive(Debug, Clone)]
pub struct SecretAlert {
    /// The agent whose outbound payload triggered the scanner.
    pub agent_id: AgentId,
    /// Team attribution propagated from the request context, when present.
    pub team_id: Option<String>,
    /// The originating `RedactionEvent.event_id` for an alert that crossed
    /// the proxy -> aa-api telemetry hop (AAASM-5871), so an operator can
    /// correlate a dashboard alert back to the specific cross-process
    /// redaction event that produced it (AAASM-5905). `None` for alerts
    /// raised directly by the gateway's own policy-evaluation path, which
    /// has no separate proxy-side event to correlate against.
    pub event_id: Option<String>,
    /// All distinct credential kinds detected in the payload, in the
    /// order returned by the scanner pass. Always non-empty when emitted.
    pub kinds: Vec<CredentialKind>,
    /// Total number of credential findings produced by the scanner pass.
    /// May exceed `kinds.len()` when the same kind matches more than once.
    pub finding_count: usize,
}

impl SecretAlert {
    /// The primary detected pattern kind, used as the alert's
    /// `detected_pattern_type` in the public API. Falls back to the
    /// generic [`CredentialKind::Custom`] only if the kinds list is
    /// empty — which should never happen in practice since the gateway
    /// only emits this alert when findings are non-empty.
    pub fn primary_kind(&self) -> CredentialKind {
        self.kinds.first().cloned().unwrap_or(CredentialKind::Custom)
    }

    /// The `[REDACTED:<Kind>]` label corresponding to `primary_kind`.
    /// Never contains any byte of the original secret.
    pub fn redacted_label(&self) -> String {
        format!("[REDACTED:{}]", self.primary_kind().as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> AgentId {
        AgentId::from_bytes([0x42; 16])
    }

    #[test]
    fn primary_kind_returns_first() {
        let alert = SecretAlert {
            agent_id: agent(),
            team_id: None,
            event_id: None,
            kinds: vec![CredentialKind::AwsAccessKey, CredentialKind::OpenAiKey],
            finding_count: 2,
        };
        assert_eq!(alert.primary_kind(), CredentialKind::AwsAccessKey);
    }

    #[test]
    fn redacted_label_uses_primary_kind() {
        let alert = SecretAlert {
            agent_id: agent(),
            team_id: Some("team-x".to_string()),
            event_id: None,
            kinds: vec![CredentialKind::GitHubPat],
            finding_count: 1,
        };
        assert_eq!(alert.redacted_label(), "[REDACTED:GitHubPat]");
    }

    #[test]
    fn primary_kind_falls_back_to_custom_when_empty() {
        let alert = SecretAlert {
            agent_id: agent(),
            team_id: None,
            event_id: None,
            kinds: vec![],
            finding_count: 0,
        };
        assert_eq!(alert.primary_kind(), CredentialKind::Custom);
    }
}
