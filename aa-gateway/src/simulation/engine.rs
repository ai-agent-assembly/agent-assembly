//! Dry-run policy evaluation engine.

use std::collections::BTreeMap;
use std::sync::Arc;

use aa_core::{AgentContext, GovernanceAction, PolicyResult};

use crate::PolicyEngine;

use super::replay::SimulationEvent;
use super::report::{EventOutcome, SimulationReport};

/// A simulation engine that evaluates events against a policy without enforcing decisions.
///
/// Wraps a [`PolicyEngine`] in dry-run mode — reuses the full 7-step evaluation
/// pipeline (schedule, network, tool allow/deny, rate limit, approval condition,
/// data pattern scan, budget) but suppresses all side effects: no audit log writes,
/// no alert triggers, no approval queue entries.
pub struct SimulationEngine {
    /// The real policy engine whose evaluate() pipeline is reused in dry-run mode.
    engine: Arc<PolicyEngine>,
}

impl SimulationEngine {
    /// Create a new simulation engine wrapping the given policy engine.
    ///
    /// The engine is shared via `Arc` so callers can retain a reference to the
    /// same engine used by the live enforcement path.
    pub fn new(engine: Arc<PolicyEngine>) -> Self {
        Self { engine }
    }

    /// Returns a reference to the underlying policy engine.
    pub fn engine(&self) -> &PolicyEngine {
        &self.engine
    }

    /// Evaluate a single event against the loaded policy in dry-run mode.
    ///
    /// Returns the outcome without writing to the audit log or triggering alerts.
    pub fn simulate_event(&self, index: usize, event: &SimulationEvent) -> EventOutcome {
        let action: GovernanceAction = match serde_json::from_str(&event.payload) {
            Ok(a) => a,
            Err(e) => {
                return EventOutcome {
                    event_index: index,
                    action: format!("(unparseable: {})", event.event_type),
                    decision: "error".to_string(),
                    reason: format!("failed to parse payload: {e}"),
                };
            }
        };

        let action_label = action_summary(&action);

        let ctx = AgentContext {
            agent_id: aa_core::AgentId::from_bytes([0; 16]),
            session_id: aa_core::SessionId::from_bytes([0; 16]),
            pid: 0,
            started_at: aa_core::time::Timestamp::from_nanos(0),
            metadata: BTreeMap::new(),
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
        };

        let result = self.engine.evaluate(&ctx, &action);

        let (decision, reason) = match result.decision {
            PolicyResult::Allow => ("allow".to_string(), "allowed by policy".to_string()),
            PolicyResult::Deny { reason } => ("deny".to_string(), reason),
            PolicyResult::RequiresApproval { timeout_secs } => (
                "requires_approval".to_string(),
                format!("requires human approval (timeout: {timeout_secs}s)"),
            ),
        };

        EventOutcome {
            event_index: index,
            action: action_label,
            decision,
            reason,
        }
    }

    /// Run the simulation against a sequence of events, producing an aggregate report.
    pub fn run(&self, events: &[SimulationEvent]) -> SimulationReport {
        let mut allowed = 0usize;
        let mut denied = 0usize;
        let mut approval_required = 0usize;
        let mut flagged_outcomes = Vec::new();

        for (i, event) in events.iter().enumerate() {
            let outcome = self.simulate_event(i, event);
            match outcome.decision.as_str() {
                "allow" => allowed += 1,
                "deny" => {
                    denied += 1;
                    flagged_outcomes.push(outcome);
                }
                "requires_approval" => {
                    approval_required += 1;
                    flagged_outcomes.push(outcome);
                }
                _ => {
                    // "error" or unknown — treat as flagged
                    flagged_outcomes.push(outcome);
                }
            }
        }

        SimulationReport {
            total_events: events.len(),
            denied,
            allowed,
            approval_required,
            budget_impact_usd: None,
            flagged_outcomes,
        }
    }
}

/// Produce a short human-readable label for a governance action.
fn action_summary(action: &GovernanceAction) -> String {
    match action {
        GovernanceAction::ToolCall { name, .. } => format!("tool:{name}"),
        GovernanceAction::FileAccess { path, mode } => format!("file:{mode:?}:{path}"),
        GovernanceAction::NetworkRequest { url, method, .. } => format!("net:{method}:{url}"),
        GovernanceAction::ProcessExec { command, .. } => format!("exec:{command}"),
        GovernanceAction::SendMessage { channel_id, .. } => {
            format!("msg:{}", channel_id.as_deref().unwrap_or(""))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_engine(policy_yaml: &str) -> SimulationEngine {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(policy_yaml.as_bytes()).unwrap();
        tmp.flush().unwrap();
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let engine = PolicyEngine::load_from_file(tmp.path(), tx).unwrap();
        SimulationEngine::new(Arc::new(engine))
    }

    fn tool_call_event(name: &str) -> SimulationEvent {
        SimulationEvent {
            event_type: "ToolCallIntercepted".to_string(),
            agent_id: "test-agent".to_string(),
            payload: serde_json::to_string(&GovernanceAction::ToolCall {
                name: name.to_string(),
                args: "{}".to_string(),
            })
            .unwrap(),
        }
    }

    const ALLOW_ALL_POLICY: &str = r#"
        tier: low
        rules:
          - id: allow-all
            description: Allow everything
            match:
              actions: ["*"]
            effect: allow
            audit: true
    "#;

    #[test]
    fn simulate_event_allow() {
        let sim = make_engine(ALLOW_ALL_POLICY);
        let event = tool_call_event("read_file");
        let outcome = sim.simulate_event(0, &event);
        assert_eq!(outcome.decision, "allow");
        assert_eq!(outcome.event_index, 0);
        assert!(outcome.action.contains("read_file"));
    }

    #[test]
    fn simulate_event_unparseable_payload() {
        let sim = make_engine(ALLOW_ALL_POLICY);
        let event = SimulationEvent {
            event_type: "ToolCallIntercepted".to_string(),
            agent_id: "agent-1".to_string(),
            payload: "not valid json".to_string(),
        };
        let outcome = sim.simulate_event(0, &event);
        assert_eq!(outcome.decision, "error");
        assert!(outcome.reason.contains("failed to parse"));
    }

    #[test]
    fn run_empty_events() {
        let sim = make_engine(ALLOW_ALL_POLICY);
        let report = sim.run(&[]);
        assert_eq!(report.total_events, 0);
        assert_eq!(report.allowed, 0);
        assert_eq!(report.denied, 0);
        assert!(report.flagged_outcomes.is_empty());
    }

    #[test]
    fn run_all_allowed() {
        let sim = make_engine(ALLOW_ALL_POLICY);
        let events = vec![tool_call_event("read"), tool_call_event("write")];
        let report = sim.run(&events);
        assert_eq!(report.total_events, 2);
        assert_eq!(report.allowed, 2);
        assert_eq!(report.denied, 0);
        assert!(report.flagged_outcomes.is_empty());
    }
}
