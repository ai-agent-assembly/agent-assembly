//! `aasm policy simulate` — dry-run policy evaluation.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Args;

use aa_gateway::simulation::{HistoricalReplay, SimulationEngine, SimulationReport};
use aa_gateway::PolicyEngine;

use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm policy simulate`.
#[derive(Args)]
pub struct SimulateArgs {
    /// Path to the policy YAML file to simulate.
    #[arg(long)]
    pub policy: PathBuf,

    /// Path to an audit log JSONL file to replay against the policy.
    #[arg(long)]
    pub against: Option<PathBuf>,

    /// Observe live agent traffic instead of replaying a file.
    #[arg(long, default_value_t = false)]
    pub live: bool,

    /// Duration for live simulation (e.g. "60s", "5m").
    #[arg(long)]
    pub duration: Option<String>,

    /// Path to write the simulation report JSON.
    ///
    /// Named `--output-file` (not `--output`) to avoid collision with the
    /// top-level global `--output <OutputFormat>` flag.
    #[arg(long)]
    pub output_file: Option<PathBuf>,
}

/// Execute the simulate command.
///
/// Returns [`ExitCode::SUCCESS`] only when every event evaluated cleanly with no
/// denials. Returns [`ExitCode::FAILURE`] if the simulation detected policy
/// violations **or** any event could not be evaluated (e.g. an unparseable /
/// schema-drifted audit log) — otherwise a fully-broken log would gate as PASS.
/// This allows CI pipelines to gate on `aasm policy simulate` exit status.
pub fn run(args: SimulateArgs) -> ExitCode {
    // Load the policy engine from the provided YAML file.
    let (budget_tx, _budget_rx) = tokio::sync::broadcast::channel(16);
    let engine = match PolicyEngine::load_from_file(&args.policy, budget_tx) {
        Ok(e) => Arc::new(e),
        Err(e) => {
            eprintln!("error: failed to load policy: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let sim_engine = SimulationEngine::new(engine);

    if args.live {
        eprintln!("error: live simulation is not yet supported (requires AAASM-73)");
        return ExitCode::FAILURE;
    }

    let log_path = match &args.against {
        Some(p) => p,
        None => {
            eprintln!("error: --against <log-file> is required for file-based simulation");
            return ExitCode::FAILURE;
        }
    };

    let replay = match HistoricalReplay::from_file(log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to read audit log: {e}");
            return ExitCode::FAILURE;
        }
    };

    let report = sim_engine.run(replay.events());

    // Write report to file if --output-file is provided.
    if let Some(ref output_path) = args.output_file {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                if let Err(e) = std::fs::write(output_path, &json) {
                    eprintln!("error: failed to write report to {}: {e}", output_path.display());
                    return ExitCode::FAILURE;
                }
            }
            Err(e) => {
                eprintln!("error: failed to serialize report: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    print_report(&report);

    // An event that could not be evaluated (e.g. an unparseable / schema-drifted
    // payload) must fail the run loudly: a simulation that could not actually
    // evaluate its input is not a PASS, so CI gating on the exit status catches a
    // malformed audit log instead of treating it as SUCCESS.
    if report.errored > 0 {
        eprintln!(
            "error: {} event(s) failed to parse and could not be evaluated",
            report.errored
        );
    }

    if report.denied > 0 || report.errored > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Print a tabular summary of the simulation report.
fn print_report(report: &SimulationReport) {
    println!("Simulation Report");
    println!("{}", "-".repeat(50));
    println!("Total events:       {}", report.total_events);
    println!("Allowed:            {}", report.allowed);
    println!("Denied:             {}", report.denied);
    println!("Approval required:  {}", report.approval_required);
    if let Some(budget) = report.budget_impact_usd {
        println!("Budget impact:      ${budget:.2}");
    }

    if !report.flagged_outcomes.is_empty() {
        println!();
        println!("{:<8} {:<20} {:<12} REASON", "EVENT#", "ACTION", "DECISION");
        println!("{}", "-".repeat(70));
        for outcome in &report.flagged_outcomes {
            // action/reason derive from replayed agent events and decision is
            // the engine verdict; strip terminal escapes from all three.
            let action = sanitize_terminal(&outcome.action);
            let decision = sanitize_terminal(&outcome.decision);
            let reason = sanitize_terminal(&outcome.reason);
            println!("{:<8} {action:<20} {decision:<12} {reason}", outcome.event_index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_policy_file_exits_failure() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp, b"not: valid: policy: [[[").unwrap();

        let args = SimulateArgs {
            policy: tmp.path().to_path_buf(),
            against: None,
            live: false,
            duration: None,
            output_file: None,
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }

    #[test]
    fn missing_policy_file_exits_failure() {
        let args = SimulateArgs {
            policy: PathBuf::from("/tmp/nonexistent-policy-simulate.yaml"),
            against: None,
            live: false,
            duration: None,
            output_file: None,
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }

    #[test]
    fn missing_against_flag_exits_failure() {
        // Create a valid policy file but don't provide --against
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut tmp,
            br#"apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: sim-test
spec:
  tier: low
  rules:
    - id: allow-all
      description: Allow all
      match:
        actions: ["*"]
      effect: allow
      audit: true
"#,
        )
        .unwrap();

        let args = SimulateArgs {
            policy: tmp.path().to_path_buf(),
            against: None,
            live: false,
            duration: None,
            output_file: None,
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }

    #[test]
    fn live_mode_exits_failure_not_implemented() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut tmp,
            br#"apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: sim-test
spec:
  tier: low
  rules:
    - id: allow-all
      description: Allow all
      match:
        actions: ["*"]
      effect: allow
      audit: true
"#,
        )
        .unwrap();

        let args = SimulateArgs {
            policy: tmp.path().to_path_buf(),
            against: None,
            live: true,
            duration: Some("30s".to_string()),
            output_file: None,
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }
}
