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
//! # Idempotence, and how the no-op is reported
//!
//! Applying twice is safe: the engine compares canonical forms and leaves a
//! target that already matches the plan exactly as it is. Since AAASM-5674 the
//! runtime *states* which of the two happened, and this command reports that
//! answer — `changed` or `unchanged` — on the result and as `outcome` in
//! `--output json`.
//!
//! It is reported, never derived. A runtime older than DI-API 5 does not carry
//! the field, and its absence means "this peer cannot say", not "nothing
//! changed": the report then carries `outcome: null` with `outcome_unknown`
//! explaining why. Inventing an answer from the receipt id (reused across a
//! no-op reapply), from `applied_at_unix_secs` (second-granularity and
//! cross-process), from a status read before the apply, or from "a step is
//! recorded as applied" would each report a wrong `changed` or a wrong
//! `unchanged` on some run — and a wrong `unchanged` is a success claim nobody
//! made.

use std::process::ExitCode;

use clap::Args;

use crate::output::OutputFormat;

use super::model::InstallReport;
use super::plan::PlanArgs;
use super::render::{emit, Report};
use super::session::SessionOptions;
use super::target::Target;
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

    /// Install the tool's administrator-managed settings file, asking for
    /// administrator authorization for that one file write.
    ///
    /// Off by default; the default install is fully unprivileged and cannot
    /// reach `Host Enforced`. See `aasm integrations plan --help`.
    #[arg(long)]
    pub install_managed_settings: bool,

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
            install_managed_settings: args.install_managed_settings,
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

        // The prompt names what is being authorized. A privileged step that
        // reached the confirmation as an unremarkable "Apply this plan?" would
        // be consent in form and not in substance — the disclosure above is what
        // makes it informed, and this line is what makes it deliberate.
        let prompt = if plan.required_permissions.is_empty() {
            format!("Apply this plan to {}?", args.tool)
        } else {
            format!(
                "Apply this plan to {}, including {} permission(s) that change host state \
                 and will ask for administrator authorization?",
                args.tool,
                plan.required_permissions.len()
            )
        };
        confirm(args.yes, output, &prompt)?;

        // Resolved again here, in this process, rather than carried forward from
        // the plan: the point of naming it is that *this* invocation says where
        // it is, and a value threaded through the report would be one more thing
        // that could arrive stale. It is the same directory the plan named
        // moments ago — same process, same rule (`Target::here`) — so the
        // service's comparison passes for the caller who authored the plan and
        // fails for one presenting it from somewhere else.
        let applied = session
            .client
            .apply(&args.tool, &plan.plan_id, Target::here()?.as_request())
            .await
            .map_err(verb_failure)?;

        // Read through the negotiated connection, which is where the DI-API
        // version gate lives. An older runtime states no outcome, and this
        // command reports that rather than guessing one (AAASM-5674).
        let mutation = session.client.negotiated().apply_mutation(&applied);
        let (report, outcome) =
            InstallReport::from_applied(super::model::PlanReport { applied: true, ..plan }, &applied, &mutation);

        // A step that failed is a partial install, and the user has to be told
        // which one — an exit code of 0 here would leave them believing an
        // integration exists that only half does.
        let failed = report.failed_steps();
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
