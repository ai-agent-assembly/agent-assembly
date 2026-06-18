//! Live traffic simulation — observe real agent events in dry-run mode.
//!
//! Subscribes to the event stream with a read-only view, evaluates each
//! event against a policy without enforcing decisions or producing side effects.

use std::time::Duration;

use super::engine::SimulationEngine;
use super::error::SimulationError;
use super::report::SimulationReport;

/// Observes live agent traffic and evaluates events against a policy in dry-run mode.
///
/// Unlike [`super::replay::HistoricalReplay`], which reads from a static JSONL file,
/// `LiveSimulation` subscribes to the real-time event stream and runs for a
/// configurable duration before producing a report.
pub struct LiveSimulation {
    /// The simulation engine used to evaluate each observed event.
    engine: SimulationEngine,
    /// How long to observe before stopping and producing the report.
    duration: Duration,
}

impl LiveSimulation {
    /// Create a new live simulation with the given engine and observation duration.
    pub fn new(engine: SimulationEngine, duration: Duration) -> Self {
        Self { engine, duration }
    }

    /// Returns the configured observation duration.
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns a reference to the underlying simulation engine.
    pub fn engine(&self) -> &SimulationEngine {
        &self.engine
    }

    /// Run the live simulation, observing events for the configured duration.
    ///
    /// Currently returns an empty report after sleeping for the configured
    /// duration. Full event-stream subscription will be added when the
    /// gateway event bus exposes a broadcast receiver for live traffic.
    pub async fn run(&self) -> Result<SimulationReport, SimulationError> {
        tokio::time::sleep(self.duration).await;

        Ok(SimulationReport {
            total_events: 0,
            denied: 0,
            allowed: 0,
            approval_required: 0,
            budget_impact_usd: None,
            flagged_outcomes: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;

    use crate::PolicyEngine;

    fn make_live_sim(duration: Duration) -> LiveSimulation {
        // AAASM-3351: a minimal valid section-based document allows by default
        // (no section restricts any action). Previously this fixture used the
        // unsupported top-level `rules:` schema, now rejected by the validator.
        let policy_yaml = "version: \"1.0\"\n";
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(policy_yaml.as_bytes()).unwrap();
        tmp.flush().unwrap();
        let (tx, _rx) = tokio::sync::broadcast::channel(16);
        let engine = PolicyEngine::load_from_file(tmp.path(), tx).unwrap();
        let sim_engine = SimulationEngine::new(Arc::new(engine));
        LiveSimulation::new(sim_engine, duration)
    }

    #[test]
    fn accessors() {
        let sim = make_live_sim(Duration::from_secs(5));
        assert_eq!(sim.duration(), Duration::from_secs(5));
        // Verify the engine is accessible through the accessor chain.
        let _ = sim.engine().engine();
    }

    #[tokio::test]
    async fn run_returns_empty_report() {
        let sim = make_live_sim(Duration::from_millis(10));
        let report = sim.run().await.unwrap();
        assert_eq!(report.total_events, 0);
        assert_eq!(report.allowed, 0);
        assert_eq!(report.denied, 0);
        assert_eq!(report.approval_required, 0);
        assert!(report.flagged_outcomes.is_empty());
    }
}
