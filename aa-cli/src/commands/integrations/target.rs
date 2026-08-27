//! Which project this invocation is in, and who is allowed to decide that
//! (AAASM-5913).
//!
//! # Why the client answers this and the service cannot
//!
//! "The project" means the directory the user ran `aasm` from. Only this process
//! knows it. The runtime on the other end of the socket is a daemon: started
//! once, from whichever directory happened to launch it, and shared by every
//! client on the host. A service that resolved the project itself was answering
//! a different question — `plan` wrote a repository the user never named, and
//! `status`, `verify`, `repair` and `remove` reported on, restored and reversed
//! configuration in it.
//!
//! So every command that means a project resolves it here, on every invocation.
//! That is what makes two callers in two projects reach two projects.
//!
//! # Two shapes, one root
//!
//! [`project_root_for_plan`] answers "where should this write go", and a plan
//! that cannot name its project at `project` scope aborts before sending —
//! there is no safe default destination. [`Target::here`] answers the narrower
//! "which existing installation is this about", and an unnameable directory is
//! sent as nothing at all: which installation exists is the service's to know,
//! so it is the service that says whether a project was needed. Neither shape
//! lets the service supply the answer.

use aa_runtime::devint::TargetRequest;

use super::session::Failure;
use super::{exit::Outcome, ScopeArg};

/// The installation a read-or-reverse command acts on, owned so it can outlive
/// the borrow the wire takes.
///
/// Constructed once per invocation and passed to every verb in it: `remove`
/// reads status before authoring the reversal, and the two must be about the
/// same installation or the preview describes something else.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Target {
    project_root: String,
    user_config_home: String,
}

impl Target {
    /// The installation reachable from *this* invocation's directory and
    /// environment.
    ///
    /// The scope is deliberately left unstated. These commands act on whatever
    /// is installed, and there is exactly one installation of a tool per scope
    /// on a host — so naming the surface would tell the service something it
    /// can already see, and naming it *wrongly* would turn "here is your
    /// integration" into "nothing is installed". Empty means "find the one that
    /// exists", and the service refuses rather than guesses if what it finds
    /// needs a project — or a configuration home (AAASM-5957) — this invocation
    /// did not name.
    ///
    /// A working directory or configuration home that cannot be determined is
    /// not an error here. Whichever *other* scope is actually installed is
    /// answerable without it, and the service says so precisely when it is
    /// not — where aborting locally would refuse `aasm integrations status` on
    /// a host with nothing user-scoped, or nothing project-scoped, on it.
    pub(crate) fn here() -> Result<Self, Failure> {
        let project_root = match std::env::current_dir() {
            Ok(dir) => nameable_on_the_wire(&dir)?,
            Err(_) => String::new(),
        };
        let user_config_home = match user_config_home_from_env() {
            Some(dir) => nameable_on_the_wire(&dir)?,
            None => String::new(),
        };
        Ok(Self {
            project_root,
            user_config_home,
        })
    }

    /// The borrowed form the client sends.
    pub(crate) fn as_request(&self) -> TargetRequest<'_> {
        TargetRequest {
            settings_scope: "",
            project_root: &self.project_root,
            user_config_home: &self.user_config_home,
        }
    }
}

/// The project a plan writes into, or a refusal.
///
/// Sent at every scope, not only `project`. At `user` and `managed` scope the
/// service uses it for one thing: disclosing in the plan that a project
/// configuration exists nearby and will be left alone. That warning was
/// previously computed against the *daemon's* directory, which made it a
/// statement about a repository the user was not in.
///
/// An unreadable working directory is reported, not silently dropped: at
/// `project` scope the service refuses, and a user who is told "the project
/// could not be determined" can act, where a user told nothing cannot.
pub(crate) fn project_root_for_plan(scope: &str) -> Result<String, Failure> {
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

/// The configuration home a plan writes into, or a refusal (AAASM-5957).
///
/// Sent at every scope, not only `user`, on the same terms as
/// [`project_root_for_plan`]: at `project` and `managed` scope the service
/// uses it only to disclose that a user configuration exists nearby and will
/// be left alone.
///
/// Unresolvable — `CLAUDE_CONFIG_DIR` and `HOME` both unset — is reported, not
/// silently dropped: at `user` scope the service refuses, and a user told
/// "nothing was changed: ... could not be determined" can act, where one told
/// nothing cannot.
pub(crate) fn user_config_home_for_plan(scope: &str) -> Result<String, Failure> {
    let Some(dir) = user_config_home_from_env() else {
        if scope != ScopeArg::User.as_wire() {
            return Ok(String::new());
        }
        return Err(Failure::new(
            Outcome::Aborted,
            "nothing was changed: this configuration home could not be determined (neither \
             CLAUDE_CONFIG_DIR nor HOME is set)"
                .to_string(),
            "set CLAUDE_CONFIG_DIR or HOME, or choose --scope project",
        ));
    };
    nameable_on_the_wire(&dir)
}

/// `$CLAUDE_CONFIG_DIR`, else `$HOME/.claude`, or neither (AAASM-5957).
///
/// Deliberately duplicated rather than called from
/// `aa_devtool_claude_code::scope::user_config_home_from` — that crate is
/// `publish = false` and only ever a dependency of `aa-cli` inside the
/// `strip-for-publish:begin devtool` region (`.ci/strip-for-publish.sh`),
/// which does not cover this file or `plan.rs`: both are compiled into the
/// published `aa-cli` crate unconditionally, the same as
/// [`project_root_for_plan`] below, which resolves its own root without
/// reaching into any `aa-devtool-*` crate for exactly this reason. The rule
/// itself — three lines — is worth restating here rather than worth a
/// held-back dependency.
fn user_config_home_from_env() -> Option<std::path::PathBuf> {
    std::env::var_os("CLAUDE_CONFIG_DIR")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|home| std::path::PathBuf::from(home).join(".claude"))
        })
}

/// `dir` as the wire can carry it, or a refusal.
///
/// # Why a path that is not UTF-8 is refused rather than displayed
///
/// The wire field is a proto `string`, so the path has to be valid UTF-8 to
/// cross it. [`Path::display`](std::path::Path::display) will always produce
/// *something* — it substitutes `U+FFFD` for each byte it cannot decode — and
/// the something it produces is still absolute, still existing-looking, and a
/// **different directory**. A plan would be authored into a phantom sibling of
/// the project the user is in; a status would be compared against it and report
/// the user's own project as somebody else's. Refusing is the only answer that
/// does not act on a path nobody named.
///
/// Split out so the refusal can be tested against a synthetic path: a process
/// cannot portably put itself in a directory whose name is not UTF-8.
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The target this process builds names the directory this process is in —
    /// not the one some other process happens to be in.
    #[test]
    fn the_target_names_the_invocation_s_own_directory() {
        let here = std::env::current_dir().expect("a readable cwd");
        let target = Target::here().expect("a nameable cwd");
        assert_eq!(target.as_request().project_root, here.to_str().expect("UTF-8 cwd"));
    }

    /// Naming no scope is what lets the service find the one installation that
    /// exists. A target that guessed `user` would report "not installed" for a
    /// project-scope integration that is sitting right there.
    #[test]
    fn a_target_states_a_project_and_never_a_scope() {
        assert_eq!(Target::default().as_request().settings_scope, "");
        assert_eq!(Target::here().expect("cwd").as_request().settings_scope, "");
    }

    /// An undeterminable directory leaves the project unstated, so the service
    /// can answer for a user-scope integration and refuse for a project-scope
    /// one. It must not become an empty *path*, which names the filesystem root.
    #[test]
    fn an_unstated_project_is_empty_not_a_root_path() {
        assert_eq!(Target::default().as_request().project_root, "");
    }
}
