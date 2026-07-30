//! `aasm integrations install` — apply an integration, after showing what it
//! will change and what it needs permission to do.
//!
//! # Order of operations, and why it is this order
//!
//! Plan → present → confirm → apply. The plan is authored by the same code path
//! as `aasm integrations plan`, so what the user reviews is the plan that gets
//! applied rather than a second description of it. Presenting *before* asking
//! is the point: a confirmation prompt that appears before the material changes
//! is a rubber stamp.
//!
//! # Idempotence
//!
//! Applying twice is safe, and the report says which it was: `mutated` is
//! `false` when the target already held exactly what the plan describes. The
//! engine decides that (it compares canonical forms), so this command reports
//! it rather than guessing from whether a file's mtime moved.

use std::process::ExitCode;

use clap::Args;

use crate::output::OutputFormat;

use super::model::{InstallReport, StepOutcomeRow};
use super::plan::PlanArgs;
use super::render::{emit, Report};
use super::session::SessionOptions;
use super::{confirm, exit::Outcome, open, run_blocking, verb_failure, ProfileArg, ScopeArg};

/// `aasm integrations install` arguments.
#[derive(Args)]
pub struct InstallArgs {
    /// The tool to integrate, as `aasm integrations list` reports it.
    pub tool: String,

    /// Which protection profile to install.
    #[arg(long, value_enum, default_value_t = ProfileArg::Recommended)]
    pub profile: ProfileArg,

    /// Which configuration surface to write.
    #[arg(long, value_enum, default_value_t = ScopeArg::User)]
    pub scope: ScopeArg,

    /// The policy profile to resolve, by name.
    #[arg(long, default_value = "")]
    pub policy_profile: String,

    /// Include steps that change host state. Each one states, in the plan
    /// above, exactly what it will do before you are asked.
    #[arg(long)]
    pub allow_privileged_host_steps: bool,

    /// Apply without asking. Required for non-interactive and `--output json`
    /// runs, which have no way to answer a prompt.
    #[arg(long)]
    pub yes: bool,

    /// Show the plan and stop, exactly as `aasm integrations plan` does.
    #[arg(long)]
    pub dry_run: bool,
}

/// Run `aasm integrations install`.
pub fn run(args: InstallArgs, options: SessionOptions, output: OutputFormat) -> ExitCode {
    run_blocking(async move {
        let mut session = open(options).await?;
        let plan_args = PlanArgs {
            tool: args.tool.clone(),
            profile: args.profile,
            scope: args.scope,
            policy_profile: args.policy_profile.clone(),
            allow_privileged_host_steps: args.allow_privileged_host_steps,
        };
        let plan = super::plan::author(&mut session, &plan_args).await?;

        if args.dry_run {
            emit(&plan, output);
            return Ok(Outcome::Success);
        }

        // Present before asking. In JSON mode the plan is not printed to stdout
        // here — that stream carries the final report — so the review copy goes
        // to stderr, where a human running `| jq` still sees it.
        match output {
            OutputFormat::Table => print!("{}", plan.render_human()),
            _ => eprint!("{}", plan.render_human()),
        }

        let prompt = if plan.required_permissions.is_empty() {
            format!("Apply this plan to {}?", args.tool)
        } else {
            format!(
                "Apply this plan to {}, including {} permission(s) that change host state?",
                args.tool,
                plan.required_permissions.len()
            )
        };
        confirm(args.yes, output, &prompt)?;

        let applied = session
            .client
            .apply(&args.tool, &plan.plan_id)
            .await
            .map_err(verb_failure)?;

        let mutated = applied.steps.iter().any(|s| s.outcome == "applied");
        let report = InstallReport {
            receipt_id: applied.receipt_id.clone(),
            applied_at_unix_secs: applied.applied_at_unix_secs,
            steps: applied
                .steps
                .iter()
                .map(|s| StepOutcomeRow {
                    step_id: s.step_id.clone(),
                    outcome: s.outcome.clone(),
                    fingerprint: (!s.fingerprint.is_empty()).then(|| s.fingerprint.clone()),
                })
                .collect(),
            planned_level: applied.planned_level.clone(),
            achieved_level: applied.achieved_level.clone(),
            mutated,
            plan: super::model::PlanReport { mutated, ..plan },
        };

        // A step that failed is a partial install, and the user has to be told
        // which one — an exit code of 0 here would leave them believing an
        // integration exists that only half does.
        let failed: Vec<&StepOutcomeRow> = report.steps.iter().filter(|s| s.outcome == "failed").collect();
        let outcome = if failed.is_empty() {
            Outcome::Success
        } else {
            Outcome::InternalError
        };
        if !failed.is_empty() {
            eprintln!(
                "error: the install is partial — {} step(s) failed: {}\n  → run `aasm integrations status {}` \
                 to see what is in place, then `aasm integrations repair {}` or `remove {}`",
                failed.len(),
                failed.iter().map(|s| s.step_id.as_str()).collect::<Vec<_>>().join(", "),
                args.tool,
                args.tool,
                args.tool
            );
        }
        emit(&report, output);
        Ok(outcome)
    })
}
