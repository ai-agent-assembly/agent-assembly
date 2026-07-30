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
use super::{confirm, exit::Outcome, open, resolve_tool, run_blocking, verb_failure};

/// `aasm integrations remove` arguments.
#[derive(Args)]
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
        resolve_tool(&mut session, &args.tool, false).await?;
        let runtime = RuntimeInfo::from_session(&session);

        // Author first: no plan id means the service returns the reversal
        // without performing it.
        let preview = session.client.remove(&args.tool, "").await.map_err(verb_failure)?;
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
            .remove(&args.tool, &preview.plan_id)
            .await
            .map_err(verb_failure)?;
        emit(&RemoveReport::from_view(runtime, &removed, false), output);
        Ok(Outcome::Success)
    })
}
