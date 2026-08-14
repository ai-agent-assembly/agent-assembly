//! Orchestrator that ties together sliding window, PID lineage, and config.
//!
//! The [`CorrelationEngine`] is the main entry point for the causal correlation
//! subsystem. It is intentionally synchronous — the caller (the Tokio event
//! loop in aa-runtime) handles channel I/O; the engine handles pure logic.

use std::collections::HashSet;

use uuid::Uuid;

use super::config::CorrelationConfig;
use super::event::CorrelationEvent;
use super::outcome::{CausalCorrelation, CorrelationOutcome};
use super::pid::PidLineage;
use super::window::SlidingWindow;

/// Maps a syscall name to an action keyword category.
///
/// Returns the canonical action keyword that corresponds to the given syscall,
/// allowing the correlation algorithm to match an intent's `action_keyword`
/// against an observed syscall. Returns `None` for unknown syscalls.
fn syscall_to_keyword(syscall: &str) -> Option<&'static str> {
    match syscall {
        "unlink" | "unlinkat" | "rmdir" => Some("file_delete"),
        "openat" | "open" | "creat" => Some("file_write"),
        "read" | "readv" | "pread64" => Some("file_read"),
        "rename" | "renameat" | "renameat2" => Some("file_rename"),
        "connect" => Some("network_connect"),
        "sendto" | "sendmsg" | "write" => Some("network_send"),
        "execve" | "execveat" => Some("process_exec"),
        "fork" | "clone" | "clone3" => Some("process_spawn"),
        "kill" | "tkill" | "tgkill" => Some("process_signal"),
        "chmod" | "fchmod" | "fchmodat" => Some("file_permission"),
        "chown" | "fchown" | "fchownat" | "lchown" => Some("file_owner"),
        _ => None,
    }
}

/// The causal correlation engine.
///
/// Ingests intent events (from LLM responses) and action events (from eBPF
/// kernel probes), stores them in a sliding time window, and produces
/// [`CorrelationOutcome`] results by matching intents to actions using PID
/// lineage and configurable time windows.
#[derive(Debug)]
pub struct CorrelationEngine {
    config: CorrelationConfig,
    window: SlidingWindow,
    lineage: PidLineage,
}

impl CorrelationEngine {
    /// Create a new correlation engine with the given configuration.
    pub fn new(config: CorrelationConfig) -> Self {
        let window = SlidingWindow::new(config.window_ms, config.max_window_size);
        Self {
            config,
            window,
            lineage: PidLineage::new(),
        }
    }

    /// Ingest a correlation event into the sliding window.
    ///
    /// This is a synchronous operation — no I/O, just an insertion into the
    /// in-memory window.
    pub fn ingest(&mut self, event: CorrelationEvent) {
        self.window.insert(event);
    }

    /// Run the correlation algorithm over the current window contents.
    ///
    /// For each action, finds the best matching intent by:
    /// 1. Keyword match — the intent's `action_keyword` must equal the syscall's
    ///    canonical keyword (via [`syscall_to_keyword`]).
    /// 2. PID lineage — the intent PID and action PID must belong to the same
    ///    causal group (via [`PidLineage::is_same_family`]).
    /// 3. Temporal ordering — the intent must precede the action.
    ///
    /// Among matching intents, the closest in time is selected (smallest delta).
    /// Correlation strength decays linearly from 1.0 at delta=0 to 0.0 at the
    /// window boundary.
    ///
    /// Returns all correlation outcomes: matched pairs, unexpected actions
    /// (no matching intent), and intents without a subsequent action.
    pub fn correlate(&self) -> Vec<CorrelationOutcome> {
        let intents = self.window.intents();
        let actions = self.window.actions();

        let mut results = Vec::new();
        let mut matched_intent_ids: HashSet<Uuid> = HashSet::new();
        let mut matched_action_ids: HashSet<Uuid> = HashSet::new();

        for action in &actions {
            let action_keyword = match syscall_to_keyword(&action.syscall) {
                Some(kw) => kw,
                None => continue,
            };

            let best_intent = self.find_best_intent(action, action_keyword, &intents);

            if let Some((intent, delta)) = best_intent {
                let strength = 1.0 - (delta as f64 / self.config.window_ms as f64).min(1.0);
                results.push(CorrelationOutcome::Matched(CausalCorrelation {
                    intent_event_id: intent.event_id,
                    action_event_id: action.event_id,
                    correlation_strength: strength,
                    time_delta_ms: delta,
                }));
                matched_intent_ids.insert(intent.event_id);
                matched_action_ids.insert(action.event_id);
            }
        }

        // Actions with no matching intent → UnexpectedAction.
        for action in &actions {
            if syscall_to_keyword(&action.syscall).is_none() {
                continue;
            }
            if !matched_action_ids.contains(&action.event_id) {
                results.push(CorrelationOutcome::UnexpectedAction {
                    action_event_id: action.event_id,
                });
            }
        }

        // Intents with no matching action → IntentWithoutAction.
        for intent in &intents {
            if !matched_intent_ids.contains(&intent.event_id) {
                results.push(CorrelationOutcome::IntentWithoutAction {
                    intent_event_id: intent.event_id,
                });
            }
        }

        results
    }

    /// Find the intent that best correlates with `action`: same keyword, same
    /// causal PID family, preceding in time, and closest in time (smallest
    /// delta). Returns the matched intent and its time delta in ms.
    fn find_best_intent<'a>(
        &self,
        action: &super::event::ActionEvent,
        action_keyword: &str,
        intents: &[&'a super::event::IntentEvent],
    ) -> Option<(&'a super::event::IntentEvent, u64)> {
        let mut best_intent: Option<(&'a super::event::IntentEvent, u64)> = None;
        for intent in intents {
            // Keyword must match.
            if intent.action_keyword != action_keyword {
                continue;
            }
            // Intent must precede the action.
            if intent.timestamp_ms >= action.timestamp_ms {
                continue;
            }
            // PIDs must be in the same causal group.
            if !self.lineage.is_same_family(intent.pid, action.pid) {
                continue;
            }

            let delta = action.timestamp_ms - intent.timestamp_ms;
            match &best_intent {
                Some((_, best_delta)) if delta >= *best_delta => {}
                _ => best_intent = Some((intent, delta)),
            }
        }
        best_intent
    }

    /// Evict events older than the configured time window.
    ///
    /// Should be called periodically by the runtime at `config.eviction_interval_ms`.
    pub fn evict(&mut self, now_ms: u64) {
        self.window.evict(now_ms);
    }

    /// Register a PID parent-child relationship for lineage tracking.
    pub fn register_pid(&mut self, child_pid: u32, parent_pid: u32) {
        self.lineage.register(child_pid, parent_pid);
    }

    /// Returns a reference to the current configuration.
    pub fn config(&self) -> &CorrelationConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::event::{ActionEvent, IntentEvent};
    use uuid::Uuid;

    #[test]
    fn engine_constructs_with_default_config() {
        let engine = CorrelationEngine::new(CorrelationConfig::default());
        assert_eq!(engine.config().window_ms, 5_000);
    }

    #[test]
    fn ingest_adds_event_to_window() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        let event = CorrelationEvent::Intent(IntentEvent {
            event_id: Uuid::new_v4(),
            timestamp_ms: 1000,
            pid: 1,
            intent_text: "test".to_string(),
            action_keyword: "test".to_string(),
        });
        engine.ingest(event);
        // Window is not directly accessible, but we can verify no panic occurred
        // and eviction works after ingest.
        engine.evict(2000);
    }

    #[test]
    fn register_pid_does_not_panic() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.register_pid(100, 1);
        engine.register_pid(200, 100);
    }

    #[test]
    fn evict_on_empty_engine_does_not_panic() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        engine.evict(10_000);
    }

    #[test]
    fn syscall_to_keyword_maps_file_delete() {
        assert_eq!(syscall_to_keyword("unlink"), Some("file_delete"));
        assert_eq!(syscall_to_keyword("unlinkat"), Some("file_delete"));
        assert_eq!(syscall_to_keyword("rmdir"), Some("file_delete"));
    }

    #[test]
    fn syscall_to_keyword_maps_file_write() {
        assert_eq!(syscall_to_keyword("openat"), Some("file_write"));
        assert_eq!(syscall_to_keyword("open"), Some("file_write"));
        assert_eq!(syscall_to_keyword("creat"), Some("file_write"));
    }

    #[test]
    fn syscall_to_keyword_maps_network() {
        assert_eq!(syscall_to_keyword("connect"), Some("network_connect"));
        assert_eq!(syscall_to_keyword("sendto"), Some("network_send"));
    }

    #[test]
    fn syscall_to_keyword_maps_process() {
        assert_eq!(syscall_to_keyword("execve"), Some("process_exec"));
        assert_eq!(syscall_to_keyword("fork"), Some("process_spawn"));
        assert_eq!(syscall_to_keyword("kill"), Some("process_signal"));
    }

    #[test]
    fn syscall_to_keyword_returns_none_for_unknown() {
        assert_eq!(syscall_to_keyword("unknown_syscall"), None);
    }

    #[test]
    fn correlate_matches_intent_to_action_same_pid() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        let intent_id = Uuid::new_v4();
        let action_id = Uuid::new_v4();

        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: intent_id,
            timestamp_ms: 1000,
            pid: 1,
            intent_text: "delete /tmp/foo".to_string(),
            action_keyword: "file_delete".to_string(),
        }));
        engine.ingest(CorrelationEvent::Action(ActionEvent {
            event_id: action_id,
            timestamp_ms: 1500,
            pid: 1,
            syscall: "unlink".to_string(),
            details: "/tmp/foo".to_string(),
        }));

        let outcomes = engine.correlate();
        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            CorrelationOutcome::Matched(c) => {
                assert_eq!(c.intent_event_id, intent_id);
                assert_eq!(c.action_event_id, action_id);
                assert_eq!(c.time_delta_ms, 500);
                assert!(c.correlation_strength > 0.0);
                assert!(c.correlation_strength <= 1.0);
            }
            other => panic!("expected Matched, got {:?}", other),
        }
    }

    #[test]
    fn correlate_matches_intent_to_action_via_pid_lineage() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        // PID 100 is a child of PID 1.
        engine.register_pid(100, 1);

        let intent_id = Uuid::new_v4();
        let action_id = Uuid::new_v4();

        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: intent_id,
            timestamp_ms: 1000,
            pid: 1,
            intent_text: "exec /bin/ls".to_string(),
            action_keyword: "process_exec".to_string(),
        }));
        engine.ingest(CorrelationEvent::Action(ActionEvent {
            event_id: action_id,
            timestamp_ms: 1200,
            pid: 100,
            syscall: "execve".to_string(),
            details: "/bin/ls".to_string(),
        }));

        let outcomes = engine.correlate();
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(&outcomes[0], CorrelationOutcome::Matched(c) if c.intent_event_id == intent_id));
    }

    #[test]
    fn correlate_picks_closest_intent() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        let far_intent_id = Uuid::new_v4();
        let near_intent_id = Uuid::new_v4();
        let action_id = Uuid::new_v4();

        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: far_intent_id,
            timestamp_ms: 1000,
            pid: 1,
            intent_text: "delete file".to_string(),
            action_keyword: "file_delete".to_string(),
        }));
        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: near_intent_id,
            timestamp_ms: 1800,
            pid: 1,
            intent_text: "delete file".to_string(),
            action_keyword: "file_delete".to_string(),
        }));
        engine.ingest(CorrelationEvent::Action(ActionEvent {
            event_id: action_id,
            timestamp_ms: 2000,
            pid: 1,
            syscall: "unlink".to_string(),
            details: "/tmp/foo".to_string(),
        }));

        let outcomes = engine.correlate();
        // Should match the near intent (delta=200) not the far one (delta=1000).
        let matched: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o, CorrelationOutcome::Matched(_)))
            .collect();
        assert_eq!(matched.len(), 1);
        match &matched[0] {
            CorrelationOutcome::Matched(c) => {
                assert_eq!(c.intent_event_id, near_intent_id);
                assert_eq!(c.time_delta_ms, 200);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn correlate_strength_decays_with_time_delta() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());

        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: Uuid::new_v4(),
            timestamp_ms: 1000,
            pid: 1,
            intent_text: "delete".to_string(),
            action_keyword: "file_delete".to_string(),
        }));
        engine.ingest(CorrelationEvent::Action(ActionEvent {
            event_id: Uuid::new_v4(),
            timestamp_ms: 3500, // delta = 2500, window = 5000 → strength = 0.5
            pid: 1,
            syscall: "unlink".to_string(),
            details: "/tmp/foo".to_string(),
        }));

        let outcomes = engine.correlate();
        match &outcomes[0] {
            CorrelationOutcome::Matched(c) => {
                assert!((c.correlation_strength - 0.5).abs() < 0.01);
            }
            other => panic!("expected Matched, got {:?}", other),
        }
    }

    #[test]
    fn correlate_unexpected_action_when_no_intent() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        let action_id = Uuid::new_v4();

        // Action with no preceding intent.
        engine.ingest(CorrelationEvent::Action(ActionEvent {
            event_id: action_id,
            timestamp_ms: 1000,
            pid: 1,
            syscall: "unlink".to_string(),
            details: "/tmp/foo".to_string(),
        }));

        let outcomes = engine.correlate();
        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            CorrelationOutcome::UnexpectedAction { action_event_id } => {
                assert_eq!(*action_event_id, action_id);
            }
            other => panic!("expected UnexpectedAction, got {:?}", other),
        }
    }

    #[test]
    fn correlate_unexpected_action_when_keyword_mismatch() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        let action_id = Uuid::new_v4();

        // Intent for file_delete, but action is process_exec.
        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: Uuid::new_v4(),
            timestamp_ms: 1000,
            pid: 1,
            intent_text: "delete file".to_string(),
            action_keyword: "file_delete".to_string(),
        }));
        engine.ingest(CorrelationEvent::Action(ActionEvent {
            event_id: action_id,
            timestamp_ms: 1500,
            pid: 1,
            syscall: "execve".to_string(),
            details: "/bin/sh".to_string(),
        }));

        let outcomes = engine.correlate();
        let unexpected: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o, CorrelationOutcome::UnexpectedAction { .. }))
            .collect();
        assert_eq!(unexpected.len(), 1);
        match &unexpected[0] {
            CorrelationOutcome::UnexpectedAction { action_event_id } => {
                assert_eq!(*action_event_id, action_id);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn correlate_unexpected_action_when_different_pid_family() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        let action_id = Uuid::new_v4();

        // Intent from PID 1, action from PID 2 (unrelated).
        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: Uuid::new_v4(),
            timestamp_ms: 1000,
            pid: 1,
            intent_text: "delete file".to_string(),
            action_keyword: "file_delete".to_string(),
        }));
        engine.ingest(CorrelationEvent::Action(ActionEvent {
            event_id: action_id,
            timestamp_ms: 1500,
            pid: 2,
            syscall: "unlink".to_string(),
            details: "/tmp/foo".to_string(),
        }));

        let outcomes = engine.correlate();
        let unexpected: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o, CorrelationOutcome::UnexpectedAction { .. }))
            .collect();
        assert_eq!(unexpected.len(), 1);
    }

    #[test]
    fn correlate_intent_without_action_when_no_action() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        let intent_id = Uuid::new_v4();

        // Intent with no subsequent action.
        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: intent_id,
            timestamp_ms: 1000,
            pid: 1,
            intent_text: "delete file".to_string(),
            action_keyword: "file_delete".to_string(),
        }));

        let outcomes = engine.correlate();
        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            CorrelationOutcome::IntentWithoutAction { intent_event_id } => {
                assert_eq!(*intent_event_id, intent_id);
            }
            other => panic!("expected IntentWithoutAction, got {:?}", other),
        }
    }

    #[test]
    fn correlate_intent_without_action_when_action_precedes_intent() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());
        let intent_id = Uuid::new_v4();

        // Action at t=1000, intent at t=2000 — action happened before intent.
        engine.ingest(CorrelationEvent::Action(ActionEvent {
            event_id: Uuid::new_v4(),
            timestamp_ms: 1000,
            pid: 1,
            syscall: "unlink".to_string(),
            details: "/tmp/foo".to_string(),
        }));
        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: intent_id,
            timestamp_ms: 2000,
            pid: 1,
            intent_text: "delete file".to_string(),
            action_keyword: "file_delete".to_string(),
        }));

        let outcomes = engine.correlate();
        let intent_without: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o, CorrelationOutcome::IntentWithoutAction { .. }))
            .collect();
        assert_eq!(intent_without.len(), 1);
        match &intent_without[0] {
            CorrelationOutcome::IntentWithoutAction { intent_event_id } => {
                assert_eq!(*intent_event_id, intent_id);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn correlate_empty_window_returns_empty() {
        let engine = CorrelationEngine::new(CorrelationConfig::default());
        assert!(engine.correlate().is_empty());
    }

    #[test]
    fn eviction_removes_intent_preventing_match() {
        let mut engine = CorrelationEngine::new(CorrelationConfig::default());

        // Intent at t=1000.
        engine.ingest(CorrelationEvent::Intent(IntentEvent {
            event_id: Uuid::new_v4(),
            timestamp_ms: 1000,
            pid: 1,
            intent_text: "delete file".to_string(),
            action_keyword: "file_delete".to_string(),
        }));

        // Action at t=7000 (within window of 5000 from now=7000, but intent at
        // t=1000 is outside the window).
        let action_id = Uuid::new_v4();
        engine.ingest(CorrelationEvent::Action(ActionEvent {
            event_id: action_id,
            timestamp_ms: 7000,
            pid: 1,
            syscall: "unlink".to_string(),
            details: "/tmp/foo".to_string(),
        }));

        // Evict with now=7000 → cutoff=2000 → intent at 1000 is evicted.
        engine.evict(7000);

        let outcomes = engine.correlate();
        // Intent was evicted, so action is unexpected.
        let unexpected: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o, CorrelationOutcome::UnexpectedAction { .. }))
            .collect();
        assert_eq!(unexpected.len(), 1);
        // No matched outcomes.
        let matched: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o, CorrelationOutcome::Matched(_)))
            .collect();
        assert!(matched.is_empty());
    }
}
