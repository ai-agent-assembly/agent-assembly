//! `aasm integrations verify` — run the protection test and say what it proved.
//!
//! # The failure mode this command exists to prevent
//!
//! The easiest wrong implementation of `verify` reads the settings file back,
//! finds the managed keys where the receipt says they should be, and prints
//! "verified". That is a statement about a file. Protection is a statement
//! about behaviour, and the only evidence for it is traffic that was produced
//! and adjudicated by the core (ADR 0030 §4.1, forbidden design 4).
//!
//! So this command reports success **only** when the service's outcome is
//! `passed` *and* the protected path was actually exercised. A pass with
//! nothing exercised exits [`Outcome::VerificationFailed`] and says, in words,
//! that it is not a protection measurement. That rule lives in
//! [`VerifyReport::established_protection`](super::model::VerifyReport::established_protection)
//! and is pinned by a test that watches it fail when the rule is weakened.
//!
//! # No real secret, ever
//!
//! The probe is the service's to run, and its descriptor names a *synthetic*
//! secret. This command never constructs one, never reads one, and prints
//! neither: the evidence it renders carries an outcome token and a mechanism,
//! and the wire type it comes from has no field a secret could be in.

use std::process::ExitCode;

use clap::Args;

use crate::output::OutputFormat;

use super::model::{RuntimeInfo, VerifyReport};
use super::render::emit;
use super::session::SessionOptions;
use super::target::Target;
use super::{exit::Outcome, open, resolve_tool, run_blocking, verb_failure};

/// `aasm integrations verify` arguments.
#[derive(Args)]
pub struct VerifyArgs {
    /// The tool to verify, as `aasm integrations list` reports it.
    pub tool: String,
}

/// Run `aasm integrations verify`.
pub fn run(args: VerifyArgs, options: SessionOptions, output: OutputFormat) -> ExitCode {
    run_blocking(async move {
        let mut session = open(options).await?;
        let target = Target::here()?;
        resolve_tool(&mut session, &args.tool, true).await?;
        let runtime = RuntimeInfo::from_session(&session);
        let view = session
            .client
            .verify(&args.tool, target.as_request())
            .await
            .map_err(verb_failure)?;
        let report = VerifyReport::from_view(runtime, &args.tool, &view);

        let outcome = if report.established_protection() {
            Outcome::Success
        } else {
            Outcome::VerificationFailed
        };
        emit(&report, output);
        Ok(outcome)
    })
}
