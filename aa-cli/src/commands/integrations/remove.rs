//! `aasm integrations remove` — undo an integration, restoring what it replaced.
//!
//! # Preview, then execute — over one verb
//!
//! The DI-API's verb space is closed, so there is no "removal plan" verb and no
//! second surface to invent for one (forbidden design 11). The `Remove` verb
//! carries an optional plan id and the service reads it as the distinction:
//! **no id authors** the reversal and mutates nothing, **an id executes** the
//! reversal that was authored. This command uses both halves in that order, so
//! a user cannot approve restoration steps they were never shown.
//!
//! # What is restored, and what is not
//!
//! The receipt records what each step replaced, so removal puts the user's own
//! values back rather than deleting the file. Anything AASM cannot prove it can
//! restore is reported in `residual` and the receipt is *kept*, so a user whose
//! configuration was not fully restored can still see what is left behind.
//!
//! # Removing nothing has no plan, and says so (AAASM-5629, AAASM-5499)
//!
//! A tool with no integration is short-circuited below, before either half of
//! the verb is sent. That is not a removal whose plan went unnamed: the service
//! authors a reversal *from a receipt* and refuses outright when it holds none,
//! so no plan is ever authored for this state. The report says so —
//! [`RemoveReport::plan_id`](super::model::RemoveReport::plan_id) is `None`,
//! which renders as `nothing to remove` for a person and `null` for a script —
//! rather than carrying an empty id that both surfaces have to guess about.
//!
//! Removing twice is a success both times, and since the contract was ratified
//! (AAASM-5499) the two runs are no longer told apart only by a plan id a
//! reader has to know how to interpret: the first reports `changed` and the
//! second `unchanged`, on the result's first line and as `outcome` in
//! `--output json`. No exit code moved — both are `0`, because both reached
//! the end state the caller asked for.
//!
//! # `--force`
//!
//! `--force` does not skip the preview and does not widen what removal touches.
//! It only proceeds when the reversal is known to be incomplete — the case the
//! command otherwise refuses, because leaving a half-removed integration behind
//! without a decision is worse than stopping.

use std::process::ExitCode;

use clap::Args;

use crate::output::OutputFormat;

use super::model::{RemoveReport, RuntimeInfo};
use super::render::{emit, Report};
use super::session::{Failure, SessionOptions};
use super::target::Target;
use super::{confirm, exit::Outcome, open, resolve_tool, run_blocking, verb_failure};

/// What `remove` reports, and why a teardown loop does not need to special-case
/// its second run.
const OUTCOME_HELP: &str = "\
OUTCOME:
    Removing an integration that is already gone is a success and exits 0, so
    the exit code cannot tell the first run from the second. What can is the
    outcome on the result's first line, and `outcome` in --output json:

        changed     the reversal ran and restored what the integration replaced
        unchanged   there was no integration to remove; `plan_id` is null

    A --dry-run of a real removal reports no outcome: it authored the reversal
    without performing it, and authoring establishes nothing about whether the
    end state already holds.

    Non-zero means the removal did NOT happen — including the refusal to leave
    items behind without --force, which exits 9 and reports `refused`.
";

/// `aasm integrations remove` arguments.
#[derive(Args)]
#[command(after_long_help = OUTCOME_HELP)]
pub struct RemoveArgs {
    /// The tool to remove the integration from.
    pub tool: String,

    /// Show the restoration actions and stop.
    #[arg(long)]
    pub dry_run: bool,

    /// Remove without asking. Required for non-interactive and `--output json`
    /// runs.
    #[arg(long)]
    pub yes: bool,

    /// Proceed even when the reversal is known to be incomplete.
    ///
    /// The residual actions are printed first, every time. This flag only
    /// answers "yes, remove anyway and leave those behind"; it never removes
    /// anything the plan above did not name.
    #[arg(long)]
    pub force: bool,
}

/// Run `aasm integrations remove`.
pub fn run(args: RemoveArgs, options: SessionOptions, output: OutputFormat) -> ExitCode {
    run_blocking(async move {
        let mut session = open(options).await?;
        // Removal must work for a tool that has since been uninstalled — the
        // configuration it wrote is still there — so detection is not required.
        let target = Target::here()?;
        resolve_tool(&mut session, &args.tool, false).await?;
        let runtime = RuntimeInfo::from_session(&session);

        // Removing twice is a success, not an error: a caller that has already
        // removed the integration got what it asked for, and a script that
        // tears down in a loop should not have to special-case the second run.
        // Decided from the lifecycle *phase* rather than by reading the error
        // the service would otherwise return — prose is for people.
        let status = session
            .client
            .status(&args.tool, target.as_request())
            .await
            .map_err(verb_failure)?;
        if !matches!(
            status.phase.as_str(),
            "installed" | "partially_installed" | "removal_pending"
        ) {
            eprintln!(
                "{} has no Agent Assembly integration to remove (lifecycle phase: {}).",
                args.tool, status.phase
            );
            emit(
                &RemoveReport::nothing_to_remove(
                    runtime,
                    &args.tool,
                    args.dry_run,
                    "nothing was installed, so nothing was removed".to_string(),
                ),
                output,
            );
            return Ok(Outcome::Success);
        }

        // Author first: no plan id means the service returns the reversal
        // without performing it.
        let preview = session
            .client
            .remove(&args.tool, "", target.as_request())
            .await
            .map_err(verb_failure)?;
        let preview_report = RemoveReport::from_view(runtime.clone(), &preview, true);

        if args.dry_run {
            emit(&preview_report, output);
            return Ok(Outcome::Success);
        }

        match output {
            OutputFormat::Table => print!("{}", preview_report.render_human()),
            _ => eprint!("{}", preview_report.render_human()),
        }

        if !preview.residual.is_empty() && !args.force {
            return Err(Failure::new(
                Outcome::Aborted,
                format!(
                    "nothing was changed: removal cannot fully restore {} — {} item(s) would be left behind",
                    args.tool,
                    preview.residual.len()
                ),
                "review the 'Left behind' list above; pass --force to remove anyway and keep the receipt, \
                 or restore those items by hand first",
            ));
        }
        if !preview.residual.is_empty() {
            eprintln!(
                "warning: --force — {} item(s) above will be left behind, and the integration receipt \
                 will be kept so you can still see them.",
                preview.residual.len()
            );
        }

        confirm(
            args.yes,
            output,
            &format!("Remove the Agent Assembly integration from {}?", args.tool),
        )?;

        let removed = session
            .client
            .remove(&args.tool, &preview.plan_id, target.as_request())
            .await
            .map_err(verb_failure)?;
        emit(&RemoveReport::from_view(runtime, &removed, false), output);
        Ok(Outcome::Success)
    })
}
