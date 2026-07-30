//! `aasm integrations repair` — restore AASM-owned state that drifted.
//!
//! # What repair touches
//!
//! Only the keys the receipt claims. A user who changed their own editor theme
//! in the same file has drift in the report and an intact integration; repair
//! rewrites the managed keys and leaves theirs alone. That boundary is the
//! engine's, not this command's — which is why `unresolved` below reports what
//! was deliberately not touched rather than omitting it. "We did not change
//! your edits" is information; silence reads as "there was nothing else".
//!
//! # Preview first
//!
//! `--dry-run` shows what drifted and stops. Without it the drift is shown and
//! a confirmation is asked for, so the destructive-looking half never happens
//! before the user has seen what it will rewrite.

use std::process::ExitCode;

use clap::Args;

use crate::output::OutputFormat;

use super::model::{RepairReport, RuntimeInfo, StatusReport, UnsupportedRow};
use super::render::emit;
use super::session::SessionOptions;
use super::{confirm, exit::Outcome, open, resolve_tool, run_blocking, verb_failure};

/// `aasm integrations repair` arguments.
#[derive(Args)]
pub struct RepairArgs {
    /// The tool to repair, as `aasm integrations list` reports it.
    pub tool: String,

    /// Show what drifted and stop.
    #[arg(long)]
    pub dry_run: bool,

    /// Repair without asking. Required for non-interactive and `--output json`
    /// runs.
    #[arg(long)]
    pub yes: bool,
}

/// Run `aasm integrations repair`.
pub fn run(args: RepairArgs, options: SessionOptions, output: OutputFormat) -> ExitCode {
    run_blocking(async move {
        let mut session = open(options).await?;
        let summary = resolve_tool(&mut session, &args.tool, true).await?;
        let runtime = RuntimeInfo::from_session(&session);

        // Read the drift first, so the preview and the confirmation describe
        // the state that is actually being repaired.
        let before = session.client.status(&args.tool).await.map_err(verb_failure)?;
        let drifted = before.drift_mismatched.clone();

        if args.dry_run {
            emit(
                &RepairReport {
                    runtime: runtime.clone(),
                    tool_id: args.tool.clone(),
                    dry_run: true,
                    drifted: drifted.clone(),
                    repaired: Vec::new(),
                    unresolved: Vec::new(),
                    status: Some(Box::new(StatusReport::from_view(runtime, &before, Some(&summary)))),
                },
                output,
            );
            return Ok(if drifted.is_empty() {
                Outcome::Success
            } else {
                Outcome::Drifted
            });
        }

        if drifted.is_empty() {
            // Nothing to do is a success, and saying so beats performing a
            // no-op rewrite that would churn the receipt for no reason.
            emit(
                &RepairReport {
                    runtime: runtime.clone(),
                    tool_id: args.tool.clone(),
                    dry_run: false,
                    drifted,
                    repaired: Vec::new(),
                    unresolved: Vec::new(),
                    status: Some(Box::new(StatusReport::from_view(runtime, &before, Some(&summary)))),
                },
                output,
            );
            return Ok(Outcome::Success);
        }

        eprintln!("Drifted AASM-owned state for {}:", args.tool);
        for artifact in &drifted {
            eprintln!("  - {artifact}");
        }
        confirm(
            args.yes,
            output,
            &format!("Rewrite the {} AASM-owned artifact(s) above?", drifted.len()),
        )?;

        let view = session.client.repair(&args.tool).await.map_err(verb_failure)?;
        let unresolved: Vec<UnsupportedRow> = view.unrepairable.iter().map(UnsupportedRow::from).collect();
        let status = view
            .status
            .as_ref()
            .map(|s| Box::new(StatusReport::from_view(runtime.clone(), s, Some(&summary))));
        // Repair re-established configuration; it did not re-exercise traffic.
        // Whatever the status now says is what the evidence supports, and if
        // something is still degraded the exit code has to say so.
        let outcome = match status.as_ref().map(|s| s.state.as_str()) {
            Some("drifted") => Outcome::Drifted,
            Some("incompatible") => Outcome::Incompatible,
            _ if !unresolved.is_empty() => Outcome::Drifted,
            _ => Outcome::Success,
        };

        emit(
            &RepairReport {
                runtime,
                tool_id: args.tool.clone(),
                dry_run: false,
                drifted,
                repaired: view.repaired.clone(),
                unresolved,
                status,
            },
            output,
        );
        Ok(outcome)
    })
}
