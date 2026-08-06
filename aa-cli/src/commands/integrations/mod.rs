//! `aasm integrations …` — the Developer Integration lifecycle from the CLI
//! (AAASM-5280).
//!
//! # What this command family is
//!
//! A **client** of the Developer Integration API and nothing more (ADR 0030
//! §7.1). It does not know what a Claude Code settings file looks like, what
//! keys any tool owns, or how to merge one — every per-tool fact arrives over
//! the DI-API from an adapter inside the trusted runtime, and every mutation is
//! performed there. That is why adding a tool needs no change in this
//! directory: the CLI's vocabulary is the closed verb space, not the tool set.
//!
//! It also never derives a protection state. What `status` prints is what the
//! service computed, rearranged for reading (forbidden design 10); the
//! rearranging lives in [`model`], and both the human table and `--output json`
//! come out of the same value (see [`render::Report`]).
//!
//! # The three things a reader should know before changing anything here
//!
//! 1. **A missing socket is a bootstrap action, not an error.** [`session`]
//!    starts the runtime, says so on stderr, and waits. `--no-autostart`
//!    suppresses it for CI.
//! 2. **Exit codes are a contract.** [`exit::Outcome`] is what a script
//!    branches on; `--help` prints the table, and a test pins it.
//! 3. **Mutating commands preview first.** `install`, `repair` and `remove`
//!    show the material changes and the permissions they need before doing
//!    anything, and refuse to proceed non-interactively without `--yes`.

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{Args, Subcommand, ValueEnum};

use crate::output::OutputFormat;

pub mod exit;
pub mod install;
pub mod list;
pub mod model;
pub mod plan;
pub mod remove;
pub mod render;
pub mod repair;
pub mod session;
pub mod status;
pub mod verify;

use exit::Outcome;
use session::{Failure, Sensitivity, Session, SessionOptions};

/// The protection profile an install asks for.
///
/// A profile is what the user chose; a *level* is what the system can prove it
/// is doing. They are separate on purpose, and `status` reports the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProfileArg {
    /// Enforce, redact sensitive findings and proceed, approve where policy
    /// asks. The default for every persona unless org policy says otherwise.
    Recommended,
    /// Enforce, with a narrower egress allowlist and approval required for
    /// destructive tool classes.
    Strict,
    /// Compute and audit every decision; apply none of them. **Never displayed
    /// as protection** — status says monitoring.
    ObserveOnly,
}

impl ProfileArg {
    /// The wire token the DI-API expects.
    pub const fn as_wire(self) -> &'static str {
        match self {
            ProfileArg::Recommended => "recommended",
            ProfileArg::Strict => "strict",
            ProfileArg::ObserveOnly => "observe_only",
        }
    }
}

/// Which configuration surface a plan writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScopeArg {
    /// The user's own configuration.
    User,
    /// The current project's configuration.
    Project,
    /// An administrator-managed surface.
    Managed,
}

impl ScopeArg {
    /// The wire token the DI-API expects.
    pub const fn as_wire(self) -> &'static str {
        match self {
            ScopeArg::User => "user",
            ScopeArg::Project => "project",
            ScopeArg::Managed => "managed",
        }
    }
}

/// `aasm integrations` — manage Developer Integrations for AI dev tools.
#[derive(Args)]
#[command(after_long_help = long_help())]
pub struct IntegrationsArgs {
    #[command(subcommand)]
    pub command: IntegrationsCommands,

    /// Report a stopped runtime instead of starting one.
    ///
    /// Lifecycle commands need a running Agent Assembly runtime; there is no
    /// in-process fallback, by design. By default `aasm` starts one. Pass this
    /// in CI, where leaving a daemon behind is worse than failing.
    #[arg(long, global = true)]
    pub no_autostart: bool,

    /// Proceed even when the runtime that answers cannot be shown to be this
    /// build.
    ///
    /// By default `aasm` refuses rather than report what an unidentified
    /// runtime said: exit 10 when the runtime was *shown* to be another build,
    /// exit 11 when its identity could not be established at all and the
    /// command writes state or claims enforcement. A runtime from another
    /// checkout, or one whose executable has been deleted, answers perfectly
    /// well and describes *its* host — which is how a healthy tool got reported
    /// as not installed (AAASM-5628).
    ///
    /// It also disarms the **multiplicity** refusal, which is not an identity
    /// cause at all: with more than one runtime reachable the command proceeds
    /// against whichever one it connected to, and the others are never
    /// consulted. Two runtimes compiled from one commit have identical
    /// identities, so no identity check can notice there are two — the reported
    /// standing is what carries it, and it never reads `verified` while
    /// `reachable_runtimes` is above one.
    ///
    /// Pass this only for a deliberately mixed installation. It changes whether
    /// the command proceeds, never what it reports: the standing appears in
    /// `--output json` and above the result in the table rendering, so a result
    /// recorded through it stays marked as unverified.
    #[arg(long, global = true)]
    pub allow_unverified_runtime: bool,
}

/// The Developer Integration lifecycle, one subcommand per stage.
#[derive(Subcommand)]
pub enum IntegrationsCommands {
    /// List detected tools, their compatibility and what is protecting them.
    List(list::ListArgs),
    /// Show exactly what an install would change. Mutates nothing.
    Plan(plan::PlanArgs),
    /// Apply an integration after showing its changes and permissions.
    Install(install::InstallArgs),
    /// Show the protection level and the evidence behind it.
    Status(status::StatusArgs),
    /// Run the protection test and report what it established.
    Verify(verify::VerifyArgs),
    /// Restore AASM-owned state that drifted.
    Repair(repair::RepairArgs),
    /// Remove an integration and restore what it replaced.
    Remove(remove::RemoveArgs),
}

/// Dispatch an `aasm integrations` subcommand.
pub fn dispatch(args: IntegrationsArgs, output: OutputFormat) -> ExitCode {
    let options = |sensitivity| SessionOptions {
        no_autostart: args.no_autostart,
        allow_unverified_runtime: args.allow_unverified_runtime,
        sensitivity,
        ..Default::default()
    };
    // AAASM-5628: which subcommand may proceed against a runtime whose identity
    // cannot be established. `list`, `plan` and `status` read and report;
    // everything else either writes host state (`install`, `repair`, `remove`)
    // or asserts that enforcement is established (`verify`), and an assertion
    // about a build that cannot be identified is unfounded rather than merely
    // weak. See `session::Sensitivity`.
    match args.command {
        IntegrationsCommands::List(a) => list::run(a, options(Sensitivity::ReadOnly), output),
        IntegrationsCommands::Plan(a) => plan::run(a, options(Sensitivity::ReadOnly), output),
        IntegrationsCommands::Status(a) => status::run(a, options(Sensitivity::ReadOnly), output),
        IntegrationsCommands::Install(a) => install::run(a, options(Sensitivity::Privileged), output),
        IntegrationsCommands::Verify(a) => verify::run(a, options(Sensitivity::Privileged), output),
        IntegrationsCommands::Repair(a) => repair::run(a, options(Sensitivity::Privileged), output),
        IntegrationsCommands::Remove(a) => remove::run(a, options(Sensitivity::Privileged), output),
    }
}

/// The long help: the journey, an example per stage, and the exit-code table.
fn long_help() -> String {
    format!(
        "\
THE JOURNEY:
    aasm integrations list                    what is here, and what is protecting it
    aasm integrations plan claude-code        what an install would change — mutates nothing
    aasm integrations install claude-code     apply it, after showing the changes
    aasm integrations verify claude-code      prove the protected path is actually protected
    aasm integrations status claude-code      the level, and the evidence behind it
    aasm integrations repair claude-code      restore AASM-owned state that drifted
    aasm integrations remove claude-code      undo it, restoring what it replaced

EXAMPLES:
    # Preview a strict install into the project surface, as JSON, without prompting.
    aasm integrations plan claude-code --profile strict --scope project --output json

    # Install non-interactively in CI, failing rather than starting a runtime.
    aasm integrations install claude-code --yes --no-autostart

    # Branch on the outcome rather than on the message.
    aasm integrations verify claude-code || case $? in
      6) echo 'not protected' ;;
      5) aasm integrations repair claude-code --yes ;;
    esac

NOTES:
    Lifecycle commands run inside the Agent Assembly runtime, which owns the
    only audited implementation of them. There is no in-process fallback; when
    no runtime is listening, aasm starts one and says so on stderr.

    Every command reports which build answered — version, commit, pid and
    executable. A reachable socket is not evidence that the right thing
    answered: a runtime from another checkout, or one whose executable has been
    deleted, answers perfectly well and describes ITS host.

    If the runtime is SHOWN not to be this build — a different commit, a deleted
    executable, or more than one listening — every command refuses (exit 10).

    If its identity simply cannot be established, list/plan/status still answer
    and report the standing as `unverifiable` (never as verified), while
    install/verify/repair/remove refuse (exit 11), because each of those either
    changes host state or asserts that enforcement is established.

    Pass --allow-unverified-runtime to downgrade both refusals to a warning.
    That includes the more-than-one-listening refusal, which is not an identity
    cause: the command then answers from whichever runtime it reached and the
    others are never consulted. The reported standing carries it either way.

{}",
        exit::help_table()
    )
}

/// Run an async command body on a current-thread runtime and turn its outcome
/// into an exit code.
///
/// Failures print to **stderr** in two lines — what happened, then what to do
/// about it — so `--output json` on stdout stays parseable even when the
/// command failed.
pub(crate) fn run_blocking<F>(body: F) -> ExitCode
where
    F: std::future::Future<Output = Result<Outcome, Failure>>,
{
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: could not start an async runtime: {e}");
            return Outcome::InternalError.into();
        }
    };
    match runtime.block_on(body) {
        Ok(outcome) => outcome.into(),
        Err(failure) => {
            eprintln!("error: {failure}");
            failure.outcome.into()
        }
    }
}

/// Open a session, starting the runtime if that is what is missing.
pub(crate) async fn open(options: SessionOptions) -> Result<Session, Failure> {
    session::connect(options).await
}

/// Map a per-verb client failure onto an actionable message and an exit code.
///
/// The DI-API's deny codes are deliberately coarse (§5.3), so this maps what
/// the wire *does* distinguish and never tries to infer more by reading the
/// message text — prose is for people, and a caller that branched on it would
/// break the next time the wording improved.
pub(crate) fn verb_failure(error: aa_runtime::devint::ClientError) -> Failure {
    use aa_proto::assembly::devint::v1 as wire;
    use aa_runtime::devint::ClientError;

    match error {
        ClientError::Denied(denied) => {
            let code = wire::DenyCode::try_from(denied.code).unwrap_or(wire::DenyCode::Unspecified);
            let outcome = match code {
                wire::DenyCode::UnknownTool => Outcome::Unsupported,
                wire::DenyCode::UnavailableAtVersion => Outcome::Incompatible,
                wire::DenyCode::Unauthenticated | wire::DenyCode::TokenExpired | wire::DenyCode::OutOfScope => {
                    Outcome::Denied
                }
                _ => Outcome::InternalError,
            };
            // `DENY_CODE_LIFECYCLE_ERROR` carries the service's own sentence
            // and no remediation (§5.3 keeps deny codes coarse), so the
            // remediation is supplied here — and it points at `status`, which
            // is the one command that can say what is actually in place after a
            // half-finished operation.
            let remediation = if denied.remediation.is_empty() {
                default_remediation(outcome).to_string()
            } else {
                denied.remediation
            };
            Failure::new(outcome, denied.message, remediation)
        }
        ClientError::Incompatible(incompatible) => {
            Failure::new(Outcome::Incompatible, incompatible.reason, incompatible.remediation)
        }
        ClientError::RuntimeNotRunning { path } => Failure::new(
            Outcome::RuntimeUnavailable,
            format!("the Agent Assembly runtime stopped mid-command ({})", path.display()),
            "re-run the command; aasm will start the runtime again",
        ),
        other => Failure::new(
            Outcome::InternalError,
            other.to_string(),
            "re-run the command; if it persists, check the runtime's logs",
        ),
    }
}

const fn default_remediation(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Unsupported => "run `aasm integrations list` to see the tools this build knows about",
        Outcome::Incompatible => "upgrade aasm and the Agent Assembly runtime together — they ship as one unit",
        Outcome::Denied => "restart the Agent Assembly runtime to re-enrol this client",
        _ => {
            "run `aasm integrations status <tool>` to see what is in place; \
              the Agent Assembly runtime's log carries the detail"
        }
    }
}

/// Look a tool up in the runtime's own registry, refusing what cannot work.
///
/// Every per-tool precondition is decided from **structured** fields — is it
/// registered, was it detected, does its version fall in the adapter's range —
/// rather than from a message. `require_detected` is `false` for the read-only
/// commands, because "Codex: not installed" is a legitimate answer to `status`
/// and a legitimate row in `list`.
pub(crate) async fn resolve_tool(
    session: &mut Session,
    tool_id: &str,
    require_detected: bool,
) -> Result<aa_proto::assembly::devint::v1::ToolSummary, Failure> {
    let tools = session.client.list_tools().await.map_err(verb_failure)?;
    let known: Vec<String> = tools.tools.iter().map(|t| t.tool_id.clone()).collect();
    let summary = tools.tools.into_iter().find(|t| t.tool_id == tool_id).ok_or_else(|| {
        Failure::new(
            Outcome::Unsupported,
            format!("no adapter in this build knows the tool {tool_id:?}"),
            format!("known tools: {}", known.join(", ")),
        )
    })?;

    if summary.compatibility == "incompatible" {
        return Err(Failure::new(
            Outcome::Incompatible,
            format!(
                "{} {} is outside the range this adapter supports",
                summary.display_name,
                if summary.detected_version.is_empty() {
                    "(version unknown)"
                } else {
                    &summary.detected_version
                }
            ),
            "upgrade the tool, or upgrade Agent Assembly — the adapter ships with the runtime",
        ));
    }

    if require_detected && !summary.detected {
        return Err(Failure::new(
            Outcome::Unsupported,
            format!("{} is not installed on this host", summary.display_name),
            "install the tool first, then re-run; `aasm integrations list` shows what was detected",
        ));
    }

    Ok(summary)
}

/// Ask the user to approve a mutation that has already been shown to them.
///
/// Returns `false` when the answer is no *or* when there is no way to ask. A
/// mutating command must never proceed on silence: a pipeline that did not
/// consent has not consented, and `--yes` is how a pipeline says otherwise.
pub(crate) fn confirm(assume_yes: bool, output: OutputFormat, prompt: &str) -> Result<(), Failure> {
    if assume_yes {
        return Ok(());
    }
    // JSON and YAML exist to be parsed by something that cannot answer a
    // question, so prompting into that stream would hang a script rather than
    // ask it anything.
    let machine_readable = !matches!(output, OutputFormat::Table);
    if machine_readable || !std::io::stdin().is_terminal() {
        return Err(Failure::new(
            Outcome::Aborted,
            "nothing was changed: this command needs confirmation and there is no terminal to ask on",
            "re-run with --yes once you have reviewed the changes above",
        ));
    }

    eprint!("{prompt} [y/N] ");
    use std::io::Write;
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return Err(Failure::new(
            Outcome::Aborted,
            "nothing was changed: the confirmation could not be read",
            "re-run with --yes once you have reviewed the changes above",
        ));
    }
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(Failure::new(
            Outcome::Aborted,
            "nothing was changed",
            "re-run and answer y, or pass --yes, to apply the changes shown above",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Harness {
        #[command(subcommand)]
        command: crate::commands::Commands,
    }

    fn parse(args: &[&str]) -> IntegrationsArgs {
        let parsed = Harness::try_parse_from(args).expect("parse");
        match parsed.command {
            crate::commands::Commands::Integrations(a) => a,
            _ => panic!("expected the integrations subcommand"),
        }
    }

    /// Every stage of the journey must exist; a family missing one of these is
    /// a family a user has to leave to finish the job by hand.
    #[test]
    fn the_whole_command_family_parses() {
        for verb in ["plan", "install", "status", "verify", "repair", "remove"] {
            let args = parse(&["aasm", "integrations", verb, "claude-code"]);
            assert!(matches!(
                (verb, &args.command),
                ("plan", IntegrationsCommands::Plan(_))
                    | ("install", IntegrationsCommands::Install(_))
                    | ("status", IntegrationsCommands::Status(_))
                    | ("verify", IntegrationsCommands::Verify(_))
                    | ("repair", IntegrationsCommands::Repair(_))
                    | ("remove", IntegrationsCommands::Remove(_))
            ));
        }
        assert!(matches!(
            parse(&["aasm", "integrations", "list"]).command,
            IntegrationsCommands::List(_)
        ));
    }

    #[test]
    fn no_autostart_is_accepted_on_every_subcommand() {
        assert!(parse(&["aasm", "integrations", "list", "--no-autostart"]).no_autostart);
        assert!(parse(&["aasm", "integrations", "status", "claude-code", "--no-autostart"]).no_autostart);
    }

    /// The profile tokens are a wire contract with the service; a rename here
    /// would be rejected by the server as an unrecognised profile.
    #[test]
    fn profile_tokens_match_the_wire() {
        assert_eq!(ProfileArg::Recommended.as_wire(), "recommended");
        assert_eq!(ProfileArg::Strict.as_wire(), "strict");
        assert_eq!(ProfileArg::ObserveOnly.as_wire(), "observe_only");
    }

    #[test]
    fn scope_tokens_match_the_wire() {
        assert_eq!(ScopeArg::User.as_wire(), "user");
        assert_eq!(ScopeArg::Project.as_wire(), "project");
        assert_eq!(ScopeArg::Managed.as_wire(), "managed");
    }

    /// The exit-code table has to reach the user, or the codes are a private
    /// convention rather than a contract.
    #[test]
    fn the_long_help_documents_the_exit_codes_and_the_journey() {
        let help = long_help();
        for outcome in Outcome::ALL {
            assert!(help.contains(outcome.as_str()), "{} is undocumented", outcome.as_str());
        }
        for verb in ["list", "plan", "install", "status", "verify", "repair", "remove"] {
            assert!(help.contains(verb), "{verb} is missing from the journey");
        }
    }

    /// A machine-readable run cannot answer a prompt, so it must abort rather
    /// than block — and must not be treated as consent.
    #[test]
    fn a_json_run_without_yes_aborts_instead_of_prompting() {
        let failure = confirm(false, OutputFormat::Json, "Apply?").expect_err("must not prompt");
        assert_eq!(failure.outcome, Outcome::Aborted);
        assert!(failure.remediation.contains("--yes"), "{failure}");
    }

    #[test]
    fn yes_is_how_automation_consents() {
        assert!(confirm(true, OutputFormat::Json, "Apply?").is_ok());
        assert!(confirm(true, OutputFormat::Table, "Apply?").is_ok());
    }
}
