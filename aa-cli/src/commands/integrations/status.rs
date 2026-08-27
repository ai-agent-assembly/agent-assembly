//! `aasm integrations status` — the level, and the evidence behind it.
//!
//! # What "evidence-backed" means here
//!
//! Every claim this command prints carries where it came from and when:
//!
//! * **Mechanisms** — which are installed, and which the adapter declares it
//!   cannot substantiate at all.
//! * **Runtime connectivity** — the core version and DI-API version that
//!   answered, so a status is attributable to a running thing.
//! * **Last verification** — the newest observation's timestamp, so "verified
//!   at T" is legible rather than implied.
//! * **Drift and repair availability** — what no longer matches, and whether
//!   there is something `repair` can do about it.
//! * **The ladder** — every rung, including the ones this host cannot reach.
//!   `Host Enforced` is *rendered as unavailable*, never omitted: silence there
//!   reads as "there is nothing above what I have" (product brief §7.3).
//! * **Exercised vs read-back evidence**, kept apart, because a claim about
//!   traffic and a claim about a file are not the same claim (§7.4).
//!
//! Nothing is computed locally. `aasm` renders what the service derived
//! (ADR 0030 forbidden design 10).

use std::process::ExitCode;

use clap::Args;

use crate::output::OutputFormat;

use super::model::{RuntimeInfo, StatusReport};
use super::render::emit;
use super::session::SessionOptions;
use super::target::Target;
use super::{exit::Outcome, open, resolve_tool, run_blocking, verb_failure};

/// `aasm integrations status` arguments.
#[derive(Args)]
pub struct StatusArgs {
    /// The tool to report on, as `aasm integrations list` reports it.
    pub tool: String,
}

/// Run `aasm integrations status`.
pub fn run(args: StatusArgs, options: SessionOptions, output: OutputFormat) -> ExitCode {
    run_blocking(async move {
        let mut session = open(options).await?;
        // A tool that is registered but absent is a legitimate thing to ask
        // about — "not installed" is an answer, not a failure — so detection is
        // not required here.
        let target = Target::here()?;
        let summary = resolve_tool(&mut session, &args.tool, false).await?;
        let runtime = RuntimeInfo::from_session(&session);
        let view = session
            .client
            .status(&args.tool, target.as_request())
            .await
            .map_err(verb_failure)?;
        let report = StatusReport::from_view(runtime, &view, Some(&summary));

        // The state the service derived decides the exit code. Drift and
        // incompatibility call for different next steps, and a caller that got
        // 0 for both would have to parse the report to tell them apart.
        let outcome = match report.state.as_str() {
            "drifted" => Outcome::Drifted,
            "incompatible" => Outcome::Incompatible,
            _ => Outcome::Success,
        };
        emit(&report, output);
        Ok(outcome)
    })
}
