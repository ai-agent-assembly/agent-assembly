//! Core domain types for the anomaly detection engine.

/// Classification of anomalous agent behavior.
///
/// Each variant corresponds to one of the seven anomaly types defined in the
/// Governance Gateway epic (AAASM-8 AC #5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Action rate suddenly exceeds historical baseline (e.g. 5/hr to 200/hr).
    BehaviorSpike,
    /// Agent attempts connection to a host/IP not in the network allowlist.
    UnknownExternalConnection,
    /// Repeated credential patterns detected in agent payloads.
    CredentialLeakAttempt,
    /// Agent spawns a child process (e.g. `bash -c "curl ..."`).
    ChildProcessExecution,
    /// PII detected in a payload destined for an external API.
    DataExfiltrationAttempt,
    /// Same tool+args invoked repeatedly within a short window.
    LoopRunaway,
    /// Agent A presents credentials belonging to Agent B.
    CrossAgentIdentitySpoofing,
}

impl AnomalyType {
    /// Human-readable description of this anomaly type.
    pub fn description(&self) -> &'static str {
        match self {
            Self::BehaviorSpike => "Action rate spike exceeding behavioral baseline",
            Self::UnknownExternalConnection => "Connection attempt to host not in network allowlist",
            Self::CredentialLeakAttempt => "Credential pattern detected in agent payload",
            Self::ChildProcessExecution => "Unauthorized child process execution",
            Self::DataExfiltrationAttempt => "PII detected in payload to external API",
            Self::LoopRunaway => "Repeated identical tool invocations in short window",
            Self::CrossAgentIdentitySpoofing => "Agent presenting another agent's credentials",
        }
    }
}

/// Automated response action triggered when an anomaly is detected.
///
/// Each response maps to an enforcement action that the gateway executes
/// without human intervention. The mapping from [`AnomalyType`] to default
/// response follows the Governance Gateway epic anomaly table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyResponse {
    /// Temporarily suspend the agent; it can be resumed after review.
    Pause,
    /// Immediately block the current action and deny further actions.
    Block,
    /// Emit an alert notification without interrupting the agent.
    Alert,
    /// Isolate the agent: block all actions and flag for security review.
    Quarantine,
}

impl AnomalyResponse {
    /// Returns the default response for a given anomaly type, per the epic
    /// anomaly table (AAASM-8).
    ///
    /// | Anomaly | Default Response |
    /// |---------|-----------------|
    /// | BehaviorSpike | Pause |
    /// | UnknownExternalConnection | Block |
    /// | CredentialLeakAttempt | Alert |
    /// | ChildProcessExecution | Block |
    /// | DataExfiltrationAttempt | Block |
    /// | LoopRunaway | Pause |
    /// | CrossAgentIdentitySpoofing | Alert |
    pub fn default_for(anomaly_type: AnomalyType) -> Self {
        match anomaly_type {
            AnomalyType::BehaviorSpike => Self::Pause,
            AnomalyType::UnknownExternalConnection => Self::Block,
            AnomalyType::CredentialLeakAttempt => Self::Alert,
            AnomalyType::ChildProcessExecution => Self::Block,
            AnomalyType::DataExfiltrationAttempt => Self::Block,
            AnomalyType::LoopRunaway => Self::Pause,
            AnomalyType::CrossAgentIdentitySpoofing => Self::Alert,
        }
    }

    /// Whether this response must block the current action (turn an otherwise
    /// `Allow` decision into a hard `Deny`).
    ///
    /// `Block` and `Quarantine` both deny the in-flight action — `Quarantine`
    /// additionally isolates the agent. `Pause` and `Alert` do not block the
    /// current action (`Pause` suspends future actions; `Alert` only notifies),
    /// so they are not block-equivalent here. AAASM-3384.
    pub fn is_blocking(self) -> bool {
        matches!(self, Self::Block | Self::Quarantine)
    }
}

/// An anomaly detection event emitted when the engine identifies suspicious
/// agent behavior.
///
/// Carries the anomaly classification, the chosen response action, and enough
/// context to populate an [`AlertTriggered`](proto) message once the event bus
/// (AAASM-141) is wired up.
#[derive(Debug, Clone)]
pub struct AnomalyEvent {
    /// What kind of anomaly was detected.
    pub anomaly_type: AnomalyType,
    /// The response action that was (or will be) executed.
    pub response: AnomalyResponse,
    /// The agent that triggered the anomaly.
    pub agent_id: aa_core::AgentId,
    /// Human-readable explanation of the detection.
    pub description: String,
    /// When the anomaly was detected.
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

/// Configuration for anomaly detection thresholds.
///
/// All thresholds are configurable to allow tuning per deployment environment.
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// Sliding window duration for baseline computation (default: 3600s = 1 hour).
    pub baseline_window_secs: u64,
    /// Standard deviation multiplier for behavior spike detection (default: 3.0).
    pub spike_stddev_multiplier: f64,
    /// Number of identical tool+args calls within `loop_window_secs` before
    /// triggering a loop runaway anomaly (default: 50).
    pub loop_threshold: u32,
    /// Window duration for loop runaway detection (default: 300s = 5 minutes).
    pub loop_window_secs: u64,
    /// Number of credential findings within the baseline window before
    /// triggering a credential leak anomaly (default: 3).
    pub credential_leak_threshold: u32,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            baseline_window_secs: 3600,
            spike_stddev_multiplier: 3.0,
            loop_threshold: 50,
            loop_window_secs: 300,
            credential_leak_threshold: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anomaly_type_variants_are_distinct() {
        let variants = [
            AnomalyType::BehaviorSpike,
            AnomalyType::UnknownExternalConnection,
            AnomalyType::CredentialLeakAttempt,
            AnomalyType::ChildProcessExecution,
            AnomalyType::DataExfiltrationAttempt,
            AnomalyType::LoopRunaway,
            AnomalyType::CrossAgentIdentitySpoofing,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn anomaly_type_has_seven_variants() {
        let variants = [
            AnomalyType::BehaviorSpike,
            AnomalyType::UnknownExternalConnection,
            AnomalyType::CredentialLeakAttempt,
            AnomalyType::ChildProcessExecution,
            AnomalyType::DataExfiltrationAttempt,
            AnomalyType::LoopRunaway,
            AnomalyType::CrossAgentIdentitySpoofing,
        ];
        assert_eq!(variants.len(), 7);
    }

    #[test]
    fn anomaly_type_description_is_non_empty() {
        let variants = [
            AnomalyType::BehaviorSpike,
            AnomalyType::UnknownExternalConnection,
            AnomalyType::CredentialLeakAttempt,
            AnomalyType::ChildProcessExecution,
            AnomalyType::DataExfiltrationAttempt,
            AnomalyType::LoopRunaway,
            AnomalyType::CrossAgentIdentitySpoofing,
        ];
        for v in &variants {
            assert!(!v.description().is_empty(), "{:?} has empty description", v);
        }
    }

    #[test]
    fn anomaly_response_variants_are_distinct() {
        let variants = [
            AnomalyResponse::Pause,
            AnomalyResponse::Block,
            AnomalyResponse::Alert,
            AnomalyResponse::Quarantine,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn default_response_matches_epic_table() {
        assert_eq!(
            AnomalyResponse::default_for(AnomalyType::BehaviorSpike),
            AnomalyResponse::Pause,
        );
        assert_eq!(
            AnomalyResponse::default_for(AnomalyType::UnknownExternalConnection),
            AnomalyResponse::Block,
        );
        assert_eq!(
            AnomalyResponse::default_for(AnomalyType::CredentialLeakAttempt),
            AnomalyResponse::Alert,
        );
        assert_eq!(
            AnomalyResponse::default_for(AnomalyType::ChildProcessExecution),
            AnomalyResponse::Block,
        );
        assert_eq!(
            AnomalyResponse::default_for(AnomalyType::DataExfiltrationAttempt),
            AnomalyResponse::Block,
        );
        assert_eq!(
            AnomalyResponse::default_for(AnomalyType::LoopRunaway),
            AnomalyResponse::Pause,
        );
        assert_eq!(
            AnomalyResponse::default_for(AnomalyType::CrossAgentIdentitySpoofing),
            AnomalyResponse::Alert,
        );
    }

    #[test]
    fn anomaly_event_stores_fields() {
        use aa_core::AgentId;
        let event = AnomalyEvent {
            anomaly_type: AnomalyType::BehaviorSpike,
            response: AnomalyResponse::Pause,
            agent_id: AgentId::from_bytes([1u8; 16]),
            description: "rate exceeded baseline".to_string(),
            detected_at: chrono::Utc::now(),
        };
        assert_eq!(event.anomaly_type, AnomalyType::BehaviorSpike);
        assert_eq!(event.response, AnomalyResponse::Pause);
        assert_eq!(event.description, "rate exceeded baseline");
    }
}
