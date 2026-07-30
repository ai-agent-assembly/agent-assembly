//! `aasm integrations plan` — the dry run.
//!
//! # The one property this command has
//!
//! It changes nothing. Not a settings file, not a receipt, not the receipt
//! store's directory. That is a property of the DI-API's `Plan` verb, which
//! reaches an adapter's authoring method and never the engine's executor, and
//! it is pinned by a test that runs this command against a real service and
//! then asserts the filesystem is untouched.
//!
//! Everything `install` shows before applying is produced here, by the same
//! code path — so what a user reviews and what a user approves cannot differ.

use std::process::ExitCode;

use clap::Args;

use crate::output::OutputFormat;

use super::model::{PlanReport, RuntimeInfo};
use super::render::emit;
use super::session::{Failure, Session, SessionOptions};
use super::{exit::Outcome, open, resolve_tool, run_blocking, verb_failure, ProfileArg, ScopeArg};

/// `aasm integrations plan` arguments.
#[derive(Args)]
pub struct PlanArgs {
    /// The tool to plan for, as `aasm integrations list` reports it.
    pub tool: String,

    /// Which protection profile to plan for.
    #[arg(long, value_enum, default_value_t = ProfileArg::Recommended)]
    pub profile: ProfileArg,

    /// Which configuration surface to write.
    ///
    /// Explicit and never inferred from the working directory: a plan that
    /// guessed its destination could write a project's configuration when the
    /// user meant their own.
    #[arg(long, value_enum, default_value_t = ScopeArg::User)]
    pub scope: ScopeArg,

    /// The policy profile to resolve, by name. The document itself never
    /// crosses this boundary.
    #[arg(long, default_value = "")]
    pub policy_profile: String,

    /// Include steps that change host state (trust stores, launch agents).
    ///
    /// Off by default. A privileged step is never implied by a profile, and a
    /// plan that contains one cannot be applied unless it was planned with
    /// this flag — the plan is the record of what was consented to.
    #[arg(long)]
    pub allow_privileged_host_steps: bool,
}

/// Run `aasm integrations plan`.
pub fn run(args: PlanArgs, options: SessionOptions, output: OutputFormat) -> ExitCode {
    run_blocking(async move {
        let mut session = open(options).await?;
        let report = author(&mut session, &args).await?;
        emit(&report, output);
        Ok(Outcome::Success)
    })
}

/// Author a plan and project it, without applying anything.
///
/// Shared with `install` so the preview a user approves is byte-for-byte the
/// plan that gets applied — two independent renderings of "what will change"
/// is how a user ends up consenting to something they were not shown.
pub(crate) async fn author(session: &mut Session, args: &PlanArgs) -> Result<PlanReport, Failure> {
    resolve_tool(session, &args.tool, true).await?;
    let runtime = RuntimeInfo::from_session(session);
    let view = session
        .client
        .plan(
            &args.tool,
            args.profile.as_wire(),
            args.scope.as_wire(),
            &args.policy_profile,
            args.allow_privileged_host_steps,
        )
        .await
        .map_err(verb_failure)?;
    Ok(PlanReport::from_view(runtime, &view))
}
