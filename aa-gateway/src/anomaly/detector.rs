//! Anomaly detection logic.
//!
//! Compares current agent activity against the per-agent behavioral baseline
//! to identify each of the seven anomaly types defined in the Governance
//! Gateway epic (AAASM-8 AC #5).

use dashmap::DashMap;
use sha2::{Digest, Sha256};

use aa_core::AgentId;

use super::baseline::AgentBaseline;
use super::types::{AnomalyConfig, AnomalyEvent, AnomalyResponse, AnomalyType};

/// Anomaly detection engine maintaining per-agent baselines.
///
/// Thread-safe: all methods take `&self`. Per-agent state is stored in a
/// `DashMap` (same pattern as `BudgetTracker`).
pub struct AnomalyDetector {
    baselines: DashMap<AgentId, AgentBaseline>,
    config: AnomalyConfig,
}

impl AnomalyDetector {
    /// Create a new detector with the given configuration.
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            baselines: DashMap::new(),
            config,
        }
    }

    /// Record an action for an agent, updating its baseline.
    pub fn record_action(&self, agent_id: AgentId, now_ms: u64) {
        self.baselines
            .entry(agent_id)
            .or_insert_with(|| AgentBaseline::new(self.config.baseline_window_secs))
            .record_action(now_ms);
    }

    /// Record a tool call for an agent, updating its baseline with the
    /// tool+args hash.
    pub fn record_tool_call(&self, agent_id: AgentId, tool_name: &str, args: &str, now_ms: u64) {
        let tool_hash = Self::hash_tool_call(tool_name, args);
        self.baselines
            .entry(agent_id)
            .or_insert_with(|| AgentBaseline::new(self.config.baseline_window_secs))
            .record_tool_call(tool_hash, now_ms);
    }

    /// Record a credential finding for an agent.
    pub fn record_credential_finding(&self, agent_id: AgentId) {
        self.baselines
            .entry(agent_id)
            .or_insert_with(|| AgentBaseline::new(self.config.baseline_window_secs))
            .record_credential_finding();
    }

    // ── Detection methods ─────────────────────────────────────────────

    /// Detect behavior spike: current action rate exceeds baseline mean + N*stddev.
    ///
    /// Returns `Some(AnomalyEvent)` with [`AnomalyResponse::Pause`] when the
    /// agent's recent action count significantly exceeds its historical baseline.
    /// Requires at least 2 prior actions to establish a meaningful baseline.
    pub fn check_behavior_spike(&self, agent_id: AgentId) -> Option<AnomalyEvent> {
        let baseline = self.baselines.get(&agent_id)?;
        let (mean, stddev) = baseline.action_mean_stddev();
        if mean == 0.0 {
            return None;
        }
        let threshold = mean + self.config.spike_stddev_multiplier * stddev;
        let current = baseline.latest_bucket_count();
        if current > threshold && stddev > 0.0 {
            Some(AnomalyEvent {
                anomaly_type: AnomalyType::BehaviorSpike,
                response: AnomalyResponse::default_for(AnomalyType::BehaviorSpike),
                agent_id,
                description: format!(
                    "Latest bucket count {current} exceeds threshold {threshold:.1} (mean={mean:.1}, stddev={stddev:.1})"
                ),
                detected_at: chrono::Utc::now(),
            })
        } else {
            None
        }
    }

    /// Detect unknown external connection: host not in the network allowlist.
    ///
    /// Returns `Some(AnomalyEvent)` with [`AnomalyResponse::Block`] when the
    /// URL's host is not present in the provided allowlist. An empty allowlist
    /// means all hosts are allowed (open policy).
    pub fn check_unknown_connection(&self, agent_id: AgentId, url: &str, allowlist: &[String]) -> Option<AnomalyEvent> {
        if allowlist.is_empty() {
            return None;
        }
        let host_port = url
            .split_once("://")
            .map(|x| x.1)
            .unwrap_or(url)
            .split('/')
            .next()
            .unwrap_or("");
        // AAASM-3367: `convert.rs` builds the URL as `proto://host:port`, so the
        // authority extracted above still carries the `:port` suffix. Allowlist
        // entries are bare hosts, so comparing `host:port` against them always
        // failed. Strip a trailing numeric `:port` before the allowlist compare,
        // mirroring the engine network stage (AAASM-3350, `engine/decision.rs`).
        let host = match host_port.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => host_port,
        };
        if allowlist.iter().any(|entry| entry == host) {
            return None;
        }
        Some(AnomalyEvent {
            anomaly_type: AnomalyType::UnknownExternalConnection,
            response: AnomalyResponse::default_for(AnomalyType::UnknownExternalConnection),
            agent_id,
            description: format!("Connection to host '{host}' not in network allowlist"),
            detected_at: chrono::Utc::now(),
        })
    }

    /// Detect credential leak attempt: accumulated findings exceed threshold.
    ///
    /// Returns `Some(AnomalyEvent)` with [`AnomalyResponse::Alert`] when the
    /// agent has accumulated more credential findings in the current window
    /// than the configured threshold.
    pub fn check_credential_leak(&self, agent_id: AgentId) -> Option<AnomalyEvent> {
        let baseline = self.baselines.get(&agent_id)?;
        let count = baseline.credential_findings_count();
        if count >= self.config.credential_leak_threshold {
            Some(AnomalyEvent {
                anomaly_type: AnomalyType::CredentialLeakAttempt,
                response: AnomalyResponse::default_for(AnomalyType::CredentialLeakAttempt),
                agent_id,
                description: format!(
                    "Credential findings count {count} exceeds threshold {}",
                    self.config.credential_leak_threshold
                ),
                detected_at: chrono::Utc::now(),
            })
        } else {
            None
        }
    }

    /// Detect child process execution: any `ProcessExec` action is flagged.
    ///
    /// Returns `Some(AnomalyEvent)` with [`AnomalyResponse::Block`]. Child
    /// process execution is default-deny — agents should not spawn subprocesses
    /// unless explicitly allowed by policy.
    pub fn check_child_process(&self, agent_id: AgentId, command: &str) -> Option<AnomalyEvent> {
        Some(AnomalyEvent {
            anomaly_type: AnomalyType::ChildProcessExecution,
            response: AnomalyResponse::default_for(AnomalyType::ChildProcessExecution),
            agent_id,
            description: format!("Unauthorized child process execution: {command}"),
            detected_at: chrono::Utc::now(),
        })
    }

    /// Detect data exfiltration attempt: PII/credential findings present in a
    /// payload that is being sent to an external host via `NetworkRequest`.
    ///
    /// Returns `Some(AnomalyEvent)` with [`AnomalyResponse::Block`] when
    /// sensitive data is detected in outbound network traffic.
    pub fn check_data_exfiltration(&self, agent_id: AgentId, has_pii: bool, url: &str) -> Option<AnomalyEvent> {
        if !has_pii {
            return None;
        }
        Some(AnomalyEvent {
            anomaly_type: AnomalyType::DataExfiltrationAttempt,
            response: AnomalyResponse::default_for(AnomalyType::DataExfiltrationAttempt),
            agent_id,
            description: format!("PII detected in payload destined for external host: {url}"),
            detected_at: chrono::Utc::now(),
        })
    }

    /// Detect loop runaway: same tool+args called more than N times within
    /// the sliding window.
    ///
    /// Returns `Some(AnomalyEvent)` with [`AnomalyResponse::Pause`] when
    /// identical tool invocations exceed the configured threshold.
    pub fn check_loop_runaway(&self, agent_id: AgentId, tool_name: &str, args: &str) -> Option<AnomalyEvent> {
        let tool_hash = Self::hash_tool_call(tool_name, args);
        let baseline = self.baselines.get(&agent_id)?;
        let count = baseline.tool_call_count(tool_hash);
        if count >= self.config.loop_threshold {
            Some(AnomalyEvent {
                anomaly_type: AnomalyType::LoopRunaway,
                response: AnomalyResponse::default_for(AnomalyType::LoopRunaway),
                agent_id,
                description: format!(
                    "Tool '{tool_name}' called {count} times (threshold: {})",
                    self.config.loop_threshold
                ),
                detected_at: chrono::Utc::now(),
            })
        } else {
            None
        }
    }

    /// Detect cross-agent identity spoofing: the claimed agent ID does not
    /// match the credential owner's agent ID.
    ///
    /// Returns `Some(AnomalyEvent)` with [`AnomalyResponse::Alert`] when
    /// an agent presents credentials belonging to a different agent.
    pub fn check_identity_spoofing(
        &self,
        claimed_agent_id: AgentId,
        credential_owner_id: AgentId,
    ) -> Option<AnomalyEvent> {
        if claimed_agent_id == credential_owner_id {
            return None;
        }
        Some(AnomalyEvent {
            anomaly_type: AnomalyType::CrossAgentIdentitySpoofing,
            response: AnomalyResponse::default_for(AnomalyType::CrossAgentIdentitySpoofing),
            agent_id: claimed_agent_id,
            description: format!(
                "Agent {:?} presented credentials belonging to agent {:?}",
                claimed_agent_id.as_bytes(),
                credential_owner_id.as_bytes()
            ),
            detected_at: chrono::Utc::now(),
        })
    }

    /// Run all applicable anomaly checks for the given action and return the
    /// first detected anomaly (short-circuit, highest severity first).
    ///
    /// Checks are ordered by severity: Block responses before Pause before Alert.
    ///
    /// # Arguments
    ///
    /// * `agent_id` — the agent performing the action
    /// * `action` — the governance action being evaluated
    /// * `has_pii` — whether PII/credential findings were detected in the payload
    /// * `network_allowlist` — the agent's network allowlist from policy
    /// * `credential_owner_id` — if known, the agent ID that owns the credential
    pub fn detect(
        &self,
        agent_id: AgentId,
        action: &aa_core::GovernanceAction,
        has_pii: bool,
        network_allowlist: &[String],
        credential_owner_id: Option<AgentId>,
    ) -> Option<AnomalyEvent> {
        // Checks 1-4 are action-shape-specific (Block, then Pause).
        if let Some(event) = self.detect_for_action(agent_id, action, has_pii, network_allowlist) {
            return Some(event);
        }

        // 5. Behavior spike (Pause)
        if let Some(event) = self.check_behavior_spike(agent_id) {
            return Some(event);
        }

        // 6. Credential leak attempt (Alert)
        if let Some(event) = self.check_credential_leak(agent_id) {
            return Some(event);
        }

        // 7. Identity spoofing (Alert)
        if let Some(owner_id) = credential_owner_id {
            if let Some(event) = self.check_identity_spoofing(agent_id, owner_id) {
                return Some(event);
            }
        }

        None
    }

    /// Run the action-shape-specific anomaly checks (process exec, unknown
    /// connection, data exfiltration, loop runaway), short-circuiting on the
    /// first detected anomaly in severity order (Block before Pause).
    fn detect_for_action(
        &self,
        agent_id: AgentId,
        action: &aa_core::GovernanceAction,
        has_pii: bool,
        network_allowlist: &[String],
    ) -> Option<AnomalyEvent> {
        match action {
            // Child process execution (Block) — highest priority.
            aa_core::GovernanceAction::ProcessExec { command } => self.check_child_process(agent_id, command),
            // Unknown external connection (Block), then data exfiltration (Block).
            aa_core::GovernanceAction::NetworkRequest { url, .. } => self
                .check_unknown_connection(agent_id, url, network_allowlist)
                .or_else(|| self.check_data_exfiltration(agent_id, has_pii, url)),
            // Loop runaway (Pause).
            aa_core::GovernanceAction::ToolCall { name, args } => self.check_loop_runaway(agent_id, name, args),
            _ => None,
        }
    }

    /// Compute a stable hash for a (tool_name, args) pair.
    fn hash_tool_call(tool_name: &str, args: &str) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(tool_name.as_bytes());
        hasher.update(b":");
        hasher.update(args.as_bytes());
        let result = hasher.finalize();
        u64::from_le_bytes(result[..8].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::AgentId;

    fn agent(b: u8) -> AgentId {
        AgentId::from_bytes([b; 16])
    }

    fn default_detector() -> AnomalyDetector {
        AnomalyDetector::new(AnomalyConfig::default())
    }

    // ── 1. Behavior spike ────────────────────────────────────────────

    #[test]
    fn behavior_spike_detected_when_rate_exceeds_baseline() {
        let config = AnomalyConfig {
            baseline_window_secs: 60,
            spike_stddev_multiplier: 2.0,
            ..AnomalyConfig::default()
        };
        let detector = AnomalyDetector::new(config);
        let id = agent(1);

        // Establish a low, uniform baseline: 1 action per second for 10 seconds.
        for i in 0..10 {
            detector.record_action(id, 1000 + i * 1000);
        }

        // Inject a massive burst: 200 actions at the same timestamp.
        for _ in 0..200 {
            detector.record_action(id, 11000);
        }

        let result = detector.check_behavior_spike(id);
        assert!(result.is_some(), "expected behavior spike anomaly");
        let event = result.unwrap();
        assert_eq!(event.anomaly_type, AnomalyType::BehaviorSpike);
        assert_eq!(event.response, AnomalyResponse::Pause);
    }

    #[test]
    fn behavior_spike_not_detected_for_uniform_rate() {
        let detector = default_detector();
        let id = agent(2);

        // Uniform rate: 10 actions evenly spaced.
        for i in 0..10 {
            detector.record_action(id, 1000 + i * 1000);
        }

        assert!(detector.check_behavior_spike(id).is_none());
    }

    // ── 2. Unknown external connection ───────────────────────────────

    #[test]
    fn unknown_connection_detected_when_host_not_in_allowlist() {
        let detector = default_detector();
        let id = agent(3);
        let allowlist = vec!["api.openai.com".to_string()];

        let result = detector.check_unknown_connection(id, "https://evil.com/data", &allowlist);
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.anomaly_type, AnomalyType::UnknownExternalConnection);
        assert_eq!(event.response, AnomalyResponse::Block);
    }

    #[test]
    fn unknown_connection_not_detected_when_host_in_allowlist() {
        let detector = default_detector();
        let id = agent(4);
        let allowlist = vec!["api.openai.com".to_string()];

        assert!(detector
            .check_unknown_connection(id, "https://api.openai.com/v1", &allowlist)
            .is_none());
    }

    #[test]
    fn unknown_connection_not_detected_when_allowlist_empty() {
        let detector = default_detector();
        let id = agent(5);

        assert!(detector
            .check_unknown_connection(id, "https://anything.com", &[])
            .is_none());
    }

    // ── 3. Credential leak ───────────────────────────────────────────

    #[test]
    fn credential_leak_detected_when_threshold_exceeded() {
        let config = AnomalyConfig {
            credential_leak_threshold: 3,
            ..AnomalyConfig::default()
        };
        let detector = AnomalyDetector::new(config);
        let id = agent(6);

        detector.record_credential_finding(id);
        detector.record_credential_finding(id);
        assert!(detector.check_credential_leak(id).is_none());

        detector.record_credential_finding(id);
        let result = detector.check_credential_leak(id);
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.anomaly_type, AnomalyType::CredentialLeakAttempt);
        assert_eq!(event.response, AnomalyResponse::Alert);
    }

    // ── 4. Child process ─────────────────────────────────────────────

    #[test]
    fn child_process_always_detected() {
        let detector = default_detector();
        let id = agent(7);

        let result = detector.check_child_process(id, "uname -a");
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.anomaly_type, AnomalyType::ChildProcessExecution);
        assert_eq!(event.response, AnomalyResponse::Block);
    }

    // ── 5. Data exfiltration ─────────────────────────────────────────

    #[test]
    fn data_exfiltration_detected_when_pii_in_network_request() {
        let detector = default_detector();
        let id = agent(8);

        let result = detector.check_data_exfiltration(id, true, "https://external.com/api");
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.anomaly_type, AnomalyType::DataExfiltrationAttempt);
        assert_eq!(event.response, AnomalyResponse::Block);
    }

    #[test]
    fn data_exfiltration_not_detected_when_no_pii() {
        let detector = default_detector();
        let id = agent(9);

        assert!(detector
            .check_data_exfiltration(id, false, "https://external.com/api")
            .is_none());
    }

    // ── 6. Loop runaway ──────────────────────────────────────────────

    #[test]
    fn loop_runaway_detected_when_threshold_exceeded() {
        let config = AnomalyConfig {
            loop_threshold: 5, // low threshold for testing
            ..AnomalyConfig::default()
        };
        let detector = AnomalyDetector::new(config);
        let id = agent(10);

        for i in 0..5 {
            detector.record_tool_call(id, "search", "query=foo", 1000 + i * 100);
        }

        let result = detector.check_loop_runaway(id, "search", "query=foo");
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.anomaly_type, AnomalyType::LoopRunaway);
        assert_eq!(event.response, AnomalyResponse::Pause);
    }

    #[test]
    fn loop_runaway_not_detected_below_threshold() {
        let config = AnomalyConfig {
            loop_threshold: 5,
            ..AnomalyConfig::default()
        };
        let detector = AnomalyDetector::new(config);
        let id = agent(11);

        for i in 0..4 {
            detector.record_tool_call(id, "search", "query=foo", 1000 + i * 100);
        }

        assert!(detector.check_loop_runaway(id, "search", "query=foo").is_none());
    }

    #[test]
    fn loop_runaway_different_args_not_counted_together() {
        let config = AnomalyConfig {
            loop_threshold: 5,
            ..AnomalyConfig::default()
        };
        let detector = AnomalyDetector::new(config);
        let id = agent(12);

        for i in 0..3 {
            detector.record_tool_call(id, "search", "query=foo", 1000 + i * 100);
        }
        for i in 0..3 {
            detector.record_tool_call(id, "search", "query=bar", 2000 + i * 100);
        }

        assert!(detector.check_loop_runaway(id, "search", "query=foo").is_none());
        assert!(detector.check_loop_runaway(id, "search", "query=bar").is_none());
    }

    // ── 7. Identity spoofing ─────────────────────────────────────────

    #[test]
    fn identity_spoofing_detected_when_ids_mismatch() {
        let detector = default_detector();

        let result = detector.check_identity_spoofing(agent(13), agent(14));
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.anomaly_type, AnomalyType::CrossAgentIdentitySpoofing);
        assert_eq!(event.response, AnomalyResponse::Alert);
    }

    #[test]
    fn identity_spoofing_not_detected_when_ids_match() {
        let detector = default_detector();

        assert!(detector.check_identity_spoofing(agent(15), agent(15)).is_none());
    }

    // ── detect() facade ──────────────────────────────────────────────

    #[test]
    fn detect_returns_none_for_clean_tool_call() {
        let detector = default_detector();
        let id = agent(20);
        let action = aa_core::GovernanceAction::ToolCall {
            name: "search".to_string(),
            args: "query=hello".to_string(),
        };

        assert!(detector.detect(id, &action, false, &[], None).is_none());
    }

    #[test]
    fn detect_returns_block_for_process_exec() {
        let detector = default_detector();
        let id = agent(21);
        let action = aa_core::GovernanceAction::ProcessExec {
            command: "uname -a".to_string(),
        };

        let result = detector.detect(id, &action, false, &[], None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().response, AnomalyResponse::Block);
    }

    #[test]
    fn detect_prioritizes_block_over_pause() {
        let detector = default_detector();
        let id = agent(22);

        // Establish spike conditions
        for i in 0..10 {
            detector.record_action(id, 1000 + i * 1000);
        }
        for _ in 0..200 {
            detector.record_action(id, 11000);
        }

        let action = aa_core::GovernanceAction::ProcessExec {
            command: "ls".to_string(),
        };
        let result = detector.detect(id, &action, false, &[], None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().anomaly_type, AnomalyType::ChildProcessExecution);
    }
}
