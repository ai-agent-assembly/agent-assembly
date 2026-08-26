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

use aa_runtime::devint::PlanRequest;
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

    /// Install the tool's administrator-managed settings file, asking for
    /// administrator authorization for that one file write.
    ///
    /// **Off by default, and the default install stays fully unprivileged.**
    /// This is the only route to `Host Enforced`: it writes the one settings
    /// surface the tool treats as non-overridable, which is owned by the
    /// administrator. The plan states the exact path, the exact content, the
    /// diff against what is there, any conflict, and the backup and rollback
    /// behaviour — all before you are asked to approve anything.
    ///
    /// Implies `--scope managed` and the privileged-step consent, because that
    /// is precisely what this flag is consent *to*. `aasm integrations remove`
    /// reverses it.
    #[arg(long)]
    pub install_managed_settings: bool,
}

/// The level a plan asks for, as the wire spells it.
///
/// Empty means "the service's default", which is `GatewayProtected`. Only the
/// explicit managed-settings install asks for higher, and even then the adapter
/// caps the answer at what it can substantiate.
fn requested_level(install_managed_settings: bool) -> &'static str {
    if install_managed_settings {
        "host_enforced"
    } else {
        ""
    }
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
    let scope = resolve_scope(args)?;
    let project_root = resolve_project_root(scope)?;
    resolve_tool(session, &args.tool, true).await?;
    let runtime = RuntimeInfo::from_session(session);
    let view = session
        .client
        .plan(PlanRequest {
            tool_id: &args.tool,
            profile: args.profile.as_wire(),
            settings_scope: scope,
            policy_profile_id: &args.policy_profile,
            // The flag *is* the consent to the one privileged step; requiring a
            // second flag for the same decision would train users to pass both
            // without reading either.
            allow_privileged_host_steps: args.allow_privileged_host_steps || args.install_managed_settings,
            requested_level: requested_level(args.install_managed_settings),
            project_root: &project_root,
        })
        .await
        .map_err(verb_failure)?;
    Ok(PlanReport::from_view(runtime, &view))
}

/// The project this invocation is in, resolved **here** rather than by the
/// service (AAASM-5913).
///
/// # Why the client, and why per invocation
///
/// "The project" means the directory the user ran this command from. Only this
/// process knows that. The service on the other end of the socket is a daemon
/// shared by every client on the host and started once, from whichever directory
/// happened to launch it — so a service that resolved the project itself was
/// answering a different question and writing to a repository the user never
/// named. Resolving it here, on every invocation, is what makes two callers in
/// two projects reach two projects.
///
/// It is sent at every scope, not only `project`. At `user` and `managed` scope
/// the service uses it for one thing: disclosing in the plan that a project
/// configuration exists nearby and will be left alone. That warning was
/// previously computed against the *daemon's* directory, which made it a
/// statement about a repository the user was not in.
///
/// An unreadable working directory is reported, not silently dropped: at
/// `project` scope the service refuses, and a user who is told "the project could
/// not be determined" can act, where a user told nothing cannot.
///
/// # Why a path that is not UTF-8 is refused rather than displayed
///
/// The wire field is a proto `string`, so the path has to be valid UTF-8 to
/// cross it. [`Path::display`](std::path::Path::display) will always produce
/// *something* — it substitutes `U+FFFD` for each byte it cannot decode — and
/// the something it produces is still absolute, still existing-looking, and a
/// **different directory**. The service would accept it and write into a
/// phantom sibling of the project the user is actually in. Refusing is the only
/// answer that does not act on a path nobody named.
fn resolve_project_root(scope: &str) -> Result<String, Failure> {
    let dir = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(_) if scope != ScopeArg::Project.as_wire() => return Ok(String::new()),
        Err(e) => {
            return Err(Failure::new(
                Outcome::Aborted,
                format!("nothing was changed: this project's directory could not be determined ({e})"),
                "run the command from an existing, readable directory, or choose --scope user",
            ))
        }
    };
    nameable_on_the_wire(&dir)
}

/// `dir` as the wire can carry it, or a refusal.
///
/// Split out from [`resolve_project_root`] so the refusal can be tested against
/// a synthetic path: a process cannot portably put itself in a directory whose
/// name is not UTF-8.
fn nameable_on_the_wire(dir: &std::path::Path) -> Result<String, Failure> {
    dir.to_str().map(str::to_string).ok_or_else(|| {
        Failure::new(
            Outcome::Aborted,
            format!(
                "nothing was changed: this directory's name is not valid UTF-8 ({}), so it cannot be \
                 named to the service without changing which directory it refers to",
                dir.display()
            ),
            "run the command from a directory whose path is valid UTF-8",
        )
    })
}

/// The scope this plan writes, refusing the administrator surface unless it was
/// asked for by name.
///
/// `--scope managed` on its own is not the explicit opt-in the privileged write
/// requires: it reads like a third choice alongside `user` and `project`, and
/// nothing about it says "this will ask for your administrator password".
fn resolve_scope(args: &PlanArgs) -> Result<&'static str, Failure> {
    if args.install_managed_settings {
        return Ok(ScopeArg::Managed.as_wire());
    }
    if matches!(args.scope, ScopeArg::Managed) {
        return Err(Failure::new(
            Outcome::Aborted,
            "nothing was changed: writing the administrator-managed settings surface needs an explicit opt-in",
            "re-run with --install-managed-settings, which shows the exact file, its content, the diff and \
             the rollback before asking for administrator authorization",
        ));
    }
    Ok(args.scope.as_wire())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(scope: ScopeArg, install_managed_settings: bool) -> PlanArgs {
        PlanArgs {
            tool: "claude-code".to_string(),
            profile: ProfileArg::Recommended,
            scope,
            policy_profile: String::new(),
            allow_privileged_host_steps: false,
            install_managed_settings,
        }
    }

    #[test]
    fn the_default_plan_is_unprivileged_and_asks_for_no_particular_level() {
        let args = args(ScopeArg::User, false);
        assert_eq!(resolve_scope(&args).expect("user scope"), "user");
        assert_eq!(requested_level(false), "");
        assert!(
            !args.allow_privileged_host_steps,
            "the default install must consent to nothing"
        );
    }

    #[test]
    fn the_managed_surface_needs_the_flag_that_names_it() {
        // `--scope managed` reads like a third choice next to user and project,
        // and nothing about it says "this asks for your administrator password".
        let failure = resolve_scope(&args(ScopeArg::Managed, false)).expect_err("must refuse");
        assert_eq!(failure.outcome, Outcome::Aborted);
        assert!(failure.remediation.contains("--install-managed-settings"), "{failure}");
        assert!(failure.to_string().contains("nothing was changed"), "{failure}");
    }

    #[test]
    fn a_directory_that_cannot_be_named_on_the_wire_is_refused_not_approximated() {
        use std::os::unix::ffi::OsStrExt;

        let ordinary = std::path::Path::new("/synthetic/project");
        assert_eq!(
            nameable_on_the_wire(ordinary).expect("UTF-8 crosses the wire"),
            "/synthetic/project"
        );

        // `Path::display` would happily render this as `/synthetic/proje?ct`,
        // which is absolute, plausible, and a *different* directory — the
        // service would accept it and write into a phantom sibling.
        let undisplayable = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/synthetic/proje\xffct"));
        assert!(undisplayable.to_str().is_none(), "the fixture must not be UTF-8");
        let failure = nameable_on_the_wire(undisplayable).expect_err("must refuse");
        assert_eq!(failure.outcome, Outcome::Aborted);
        assert!(failure.to_string().contains("nothing was changed"), "{failure}");
        assert!(failure.to_string().contains("not valid UTF-8"), "{failure}");
    }

    #[test]
    fn the_flag_selects_the_managed_surface_and_asks_for_host_enforcement() {
        assert_eq!(resolve_scope(&args(ScopeArg::User, true)).expect("managed"), "managed");
        assert_eq!(requested_level(true), "host_enforced");
    }
}
