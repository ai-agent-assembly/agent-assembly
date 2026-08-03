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
//!
//! # Repairing nothing exits `0`, and says so (AAASM-5455)
//!
//! Two states repair nothing: no receipt accounts for the tool, and the
//! AASM-owned state already matches the receipt it has. Both exit `0`, because
//! [`Outcome::Success`](super::exit::Outcome::Success) means "the command did
//! what it was asked to do" and neither state is a failure of the command —
//! the same reading that makes a second `remove` a success rather than an
//! error. The distinction they need is carried by the output, not the code:
//! `nothing_to_repair` states which of the two happened, on the report's
//! always-printed first line and in `--output json`.
//!
//! No *new* exit code is minted for the uninstalled case, and no existing one
//! is borrowed for it. `unsupported` is about a tool, mechanism or verb this
//! host does not have, which an uninstalled-but-detected tool is not; `aborted`
//! is about a decision nobody made here; `internal_error` is about a failure
//! that did not happen. Widening [`Outcome`](super::exit::Outcome) is a change
//! to a documented contract that `--help` prints and a test pins, so it is a
//! product decision rather than a bug fix's to take.

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

        // Repair can only act on state a receipt accounts for, and the service
        // agrees: the Repair verb refuses outright with "no integration receipt
        // records <tool> at <scope> scope; run an install first". That refusal
        // never used to be seen, because the `drifted.is_empty()` branch below
        // returned success before the verb was ever sent — a tool with no
        // receipt has no drift to report, so "nothing drifted" and "nothing is
        // installed" arrived at this command as the same empty list and left it
        // as the same silent success (AAASM-5455).
        //
        // They are different facts and are answered differently here. Decided
        // from the lifecycle *phase* rather than by spending a round trip on a
        // refusal — the same way `remove` decides it, and for the same reason:
        // prose is for people. The allowlist is closed on purpose, so a phase
        // this build does not recognise is one this mutating command declines
        // to act on rather than guesses about.
        if !matches!(
            before.phase.as_str(),
            "installed" | "partially_installed" | "removal_pending"
        ) {
            let reason = format!(
                "{} has no Agent Assembly integration to repair (lifecycle phase: {})",
                args.tool, before.phase
            );
            eprintln!("{reason}.");
            emit(
                &RepairReport {
                    runtime: runtime.clone(),
                    tool_id: args.tool.clone(),
                    dry_run: args.dry_run,
                    drifted: Vec::new(),
                    repaired: Vec::new(),
                    unresolved: Vec::new(),
                    nothing_to_repair: Some(reason),
                    status: Some(Box::new(StatusReport::from_view(runtime, &before, Some(&summary)))),
                },
                output,
            );
            return Ok(Outcome::Success);
        }

        if args.dry_run {
            emit(
                &RepairReport {
                    runtime: runtime.clone(),
                    tool_id: args.tool.clone(),
                    dry_run: true,
                    drifted: drifted.clone(),
                    repaired: Vec::new(),
                    unresolved: Vec::new(),
                    // A preview reports what *would* be restored; it is not
                    // itself a run that repaired nothing.
                    nothing_to_repair: None,
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
            // no-op rewrite that would churn the receipt for no reason. An
            // installed tool whose state matches its receipt reaches here — a
            // different fact from the uninstalled case handled above, so it
            // carries its own reason rather than sharing that one's wording.
            emit(
                &RepairReport {
                    runtime: runtime.clone(),
                    tool_id: args.tool.clone(),
                    dry_run: false,
                    drifted,
                    repaired: Vec::new(),
                    unresolved: Vec::new(),
                    nothing_to_repair: Some(format!(
                        "AASM-owned state for {} already matches its receipt",
                        args.tool
                    )),
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
                // The repair verb ran. Whether it restored anything is what
                // `repaired` says; this field is for runs that never got here.
                nothing_to_repair: None,
                status,
            },
            output,
        );
        Ok(outcome)
    })
}
