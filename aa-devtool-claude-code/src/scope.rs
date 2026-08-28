//! Where Claude Code's configuration lives — decided, never inferred.
//!
//! # Why this module exists (AAASM-5276 condition C2)
//!
//! [`apply::DefaultSettingsPathResolver`](crate::apply) prefers
//! `<cwd>/.claude/settings.json` whenever a `.claude/` directory happens to
//! exist in the process's working directory, and falls back to
//! `$HOME/.claude/settings.json` otherwise. Which file gets written therefore
//! depends on where the process was started from. That is survivable for a
//! fire-and-forget `apply_settings`, and fatal for a lifecycle: a receipt that
//! cannot name the file it wrote cannot detect drift against it, cannot restore
//! it, and can surprise a user by mutating a checked-in project file they never
//! chose.
//!
//! [`ClaudeCodePaths`] takes the scope as an argument and has no
//! "whichever one exists" branch. Every settings-touching step the lifecycle
//! authors gets its path from here, and
//! [`IntegrationPlan::validate`](aa_devtool_contract::IntegrationPlan::validate)
//! rejects a plan whose steps disagree with the scope the request named.
//!
//! # The three surfaces, and the one this integration will not touch
//!
//! * **User** — `$CLAUDE_CONFIG_DIR/settings.json`, or `$HOME/.claude/settings.json`.
//!   `CLAUDE_CONFIG_DIR` is Claude Code's own redirection of its config home, so
//!   honouring it is both correct and what keeps a test out of a developer's
//!   real tree.
//! * **Project** — `<project root>/.claude/settings.json`. Checked in, shared,
//!   and workspace-trust gated; selectable, never a default.
//! * **Managed** — `/Library/Application Support/ClaudeCode/managed-settings.json`.
//!   Root-owned and absent on an unmanaged host. Since AAASM-5298 this scope
//!   *resolves* and is writable, but only through the explicitly authorized,
//!   read-back-verified path in [`managed_settings`](crate::managed_settings) —
//!   never as part of a default install. A caller that names this scope is
//!   asking for one administrator-authorized file write, and gets a refusal
//!   rather than a silent downgrade when that authorization is unavailable.
//!
//! # The managed-root test seam
//!
//! `AASM_CLAUDE_MANAGED_ROOT` (and [`ClaudeCodePaths::with_managed_root`])
//! redirect where the managed file is *addressed*. That cannot be used to
//! escalate: [`MacOsAdminAuthority`](crate::managed_settings::MacOsAdminAuthority)
//! refuses to elevate for any target that is not the canonical
//! [`MANAGED_SETTINGS_PATH`], so a redirected root makes the write ordinary and
//! unprivileged rather than pointing an authorized write somewhere else.

use std::path::{Path, PathBuf};

use aa_devtool_contract::SettingsScope;

pub use crate::managed_settings::{MANAGED_SETTINGS_DIR, MANAGED_SETTINGS_FILE, MANAGED_SETTINGS_PATH};

/// Directory Claude Code keeps its user configuration in, relative to `$HOME`.
pub const DOT_CLAUDE: &str = ".claude";

/// The settings file name at user and project scope.
pub const SETTINGS_FILE: &str = "settings.json";

/// Why a scope could not be turned into a path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeError {
    /// The root a scope is relative to is unknown on this host.
    #[error("the {scope} configuration scope cannot be resolved: {detail}")]
    Unresolvable {
        /// The scope that could not be resolved.
        scope: SettingsScope,
        /// What is missing.
        detail: String,
    },
    /// The scope resolves, and this integration refuses to write to it.
    #[error("{detail}")]
    Refused {
        /// The scope that was asked for.
        scope: SettingsScope,
        /// Why, in words a user can act on.
        detail: String,
    },
}

/// Every path the Claude Code integration reads or writes.
///
/// Not every root here is caller-supplied, and this doc says which is which
/// rather than let a reader assume "explicit roots" means all of them
/// (AAASM-5957 was exactly that assumption going unnoticed): the **project
/// root** and the **user-scope configuration home** are per-request, supplied
/// by the caller through [`with_project`](Self::with_project) and
/// [`with_config_dir`](Self::with_config_dir) — [`from_env`](Self::from_env)
/// never populates either. `$HOME` itself remains ambient: it still feeds
/// [`home()`](Self::home) (detection markers) and, independently, the state
/// root and CA source (`state_root`/`ca_source`, resolved from the daemon's
/// own environment because those roots are never the caller's to name).
///
/// Constructed with [`ClaudeCodePaths::from_env`] in production and with the
/// `with_*` builders in tests, so no test ever depends on the ambient
/// working directory, and no test that pins a destination ever depends on
/// ambient `$HOME` either — only tests exercising the detection-marker or
/// state/CA-source paths legitimately still do.
#[derive(Debug, Clone, Default)]
pub struct ClaudeCodePaths {
    /// `$CLAUDE_CONFIG_DIR`, when Claude Code's config home is redirected.
    config_dir: Option<PathBuf>,
    /// `$HOME`.
    home: Option<PathBuf>,
    /// The project root project-scope settings are relative to.
    project: Option<PathBuf>,
    /// Root for artifacts Agent Assembly owns outright.
    state: Option<PathBuf>,
    /// The proxy CA certificate this integration copies its trust material from.
    ca_source: Option<PathBuf>,
    /// The directory the endpoint managed-settings file lives in. `None` means
    /// the canonical OS location.
    managed_root: Option<PathBuf>,
}

impl ClaudeCodePaths {
    /// Resolve every root from the environment.
    ///
    /// Missing roots stay `None` rather than being guessed; the scope that
    /// needed one reports [`ScopeError::Unresolvable`] when it is asked for.
    ///
    /// # Why the project root is *not* among them (AAASM-5913)
    ///
    /// It used to be, read from `std::env::current_dir()`. That is only ever
    /// right when the process resolving it is the process the user invoked. The
    /// production caller of this constructor is the developer-integration daemon,
    /// constructed once at boot from whichever directory launched it, and shared
    /// by every client on the host — so the "current" directory belonged to some
    /// earlier caller, or to no project at all. It wrote Agent Assembly's managed
    /// keys into a repository the user had not named, and picked a different one
    /// after each daemon restart.
    ///
    /// So the project root is now supplied per request, by the client that knows
    /// it, through [`with_project`](Self::with_project). Nothing else here reads
    /// the working directory: the artifacts Agent Assembly owns
    /// ([`owned_root`](Self::owned_root) and everything derived from it) live
    /// under the state root, and only [`settings_path`](Self::settings_path) at
    /// [`Project`](SettingsScope::Project) scope and
    /// [`detected_surfaces`](Self::detected_surfaces) consult the project at all.
    ///
    /// # Why the user-scope configuration home is not among them either (AAASM-5957)
    ///
    /// The identical argument, one scope over: `config_dir` used to be read
    /// from this process's own `CLAUDE_CONFIG_DIR` here, which for the daemon
    /// is the daemon's environment, not the caller's — see
    /// [`with_config_dir`](Self::with_config_dir) for the full rationale. It is
    /// now supplied per request too. `$HOME` is *not* removed from this
    /// constructor, unlike the working directory above: [`home()`](Self::home)
    /// still feeds detection markers and [`state_root`]/[`ca_source`] still
    /// read it independently, so nulling it here would not close anything and
    /// would break both.
    pub fn from_env() -> Self {
        Self {
            config_dir: None,
            home: non_empty_var("HOME"),
            project: None,
            state: state_root(),
            ca_source: ca_source(),
            managed_root: non_empty_var("AASM_CLAUDE_MANAGED_ROOT"),
        }
    }

    /// Pin the user-scope configuration home.
    ///
    /// # Why `from_env` no longer reads `CLAUDE_CONFIG_DIR`/`$HOME` for this (AAASM-5957)
    ///
    /// It used to, the same way [`with_project`](Self::with_project)'s doc
    /// explains `project` used to be read from `current_dir()`: right only when
    /// the process resolving it is the process the user invoked. The production
    /// caller of `from_env` is the developer-integration daemon, whose
    /// `CLAUDE_CONFIG_DIR`/`$HOME` belong to whichever environment launched it —
    /// not to whichever client's request is being served. It wrote one caller's
    /// managed keys into a *different* user's real Claude Code configuration,
    /// silently, because `user_config_dir()` had no `None` to report and no way
    /// to notice the two identities had diverged.
    ///
    /// `$HOME` itself stays read here — [`home()`](Self::home) still feeds
    /// detection markers, and [`state_root`]/[`ca_source`] still read it
    /// independently — only the *user-scope configuration home* stops being
    /// derived from the daemon's own environment. So this constructor no
    /// longer resolves the whole of "where Claude Code's configuration lives"
    /// from explicit roots; see the corrected module doc.
    #[must_use]
    pub fn with_config_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config_dir = Some(dir.into());
        self
    }

    /// Pin `$HOME`.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Pin the project root.
    #[must_use]
    pub fn with_project(mut self, project: impl Into<PathBuf>) -> Self {
        self.project = Some(project.into());
        self
    }

    /// Pin the root for artifacts Agent Assembly owns.
    #[must_use]
    pub fn with_state(mut self, state: impl Into<PathBuf>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Pin the proxy CA certificate to copy trust material from.
    #[must_use]
    pub fn with_ca_source(mut self, ca: impl Into<PathBuf>) -> Self {
        self.ca_source = Some(ca.into());
        self
    }

    /// Pin the directory the endpoint managed-settings file is addressed in.
    ///
    /// A redirected root cannot escalate — see the module docs.
    #[must_use]
    pub fn with_managed_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.managed_root = Some(root.into());
        self
    }

    /// Whether the managed surface is addressed at its canonical OS location.
    ///
    /// The privileged authority elevates only for the canonical path, so a
    /// redirected root is a test seam and reported as such rather than being
    /// presented to a user as an endpoint-managed install.
    pub fn managed_root_is_canonical(&self) -> bool {
        // `Option::is_none_or` would read better but is stable only from 1.82;
        // this crate's floor is lower.
        match self.managed_root.as_deref() {
            Some(root) => root == Path::new(MANAGED_SETTINGS_DIR),
            None => true,
        }
    }

    /// The settings file for `scope`.
    ///
    /// # Errors
    ///
    /// [`ScopeError::Unresolvable`] when the scope's root is unknown on this
    /// host.
    pub fn settings_path(&self, scope: SettingsScope) -> Result<PathBuf, ScopeError> {
        match scope {
            SettingsScope::User => Ok(self.user_config_dir()?.join(SETTINGS_FILE)),
            SettingsScope::Project => {
                let project = self.project.as_ref().ok_or_else(|| ScopeError::Unresolvable {
                    scope,
                    // Deliberately not "so we used the working directory": the
                    // working directory of whatever process is asking is not the
                    // caller's project, and a message that admitted a fallback
                    // would be describing AAASM-5913.
                    detail: "no project root was given, and the project a change lands in is never taken \
                             from the working directory of the process resolving it"
                        .to_string(),
                })?;
                Ok(project.join(DOT_CLAUDE).join(SETTINGS_FILE))
            }
            SettingsScope::Managed => Ok(self.managed_settings_path()),
        }
    }

    /// The endpoint managed-settings file this host addresses.
    ///
    /// Always resolvable — the file's *absence* is what an unmanaged host looks
    /// like, and a path that could not be named could not be shown to a user
    /// before they authorize a write to it.
    pub fn managed_settings_path(&self) -> PathBuf {
        self.managed_root
            .clone()
            .unwrap_or_else(|| PathBuf::from(MANAGED_SETTINGS_DIR))
            .join(MANAGED_SETTINGS_FILE)
    }

    /// Claude Code's user configuration directory.
    ///
    /// # Why there is no `$HOME` fallback here any more (AAASM-5957)
    ///
    /// There used to be one: `self.home.join(DOT_CLAUDE)` when `config_dir` was
    /// unset. `home` is still populated by [`from_env`](Self::from_env), so
    /// that fallback would still fire — silently resolving against whichever
    /// process's `$HOME` called `from_env`, which for the daemon is not the
    /// caller's. There is no correct answer to guess here, so this reports
    /// [`ScopeError::Unresolvable`] instead of guessing one.
    fn user_config_dir(&self) -> Result<PathBuf, ScopeError> {
        self.config_dir.clone().ok_or_else(|| ScopeError::Unresolvable {
            scope: SettingsScope::User,
            // Deliberately not "so we used $HOME": $HOME of whatever process is
            // asking is not necessarily the caller's, and a message that
            // admitted a fallback would be describing AAASM-5957.
            detail: "no user configuration home was given, and the configuration home a change lands \
                     in is never taken from the environment of the process resolving it"
                .to_string(),
        })
    }

    /// Which configuration surfaces this host actually has, whoever wrote them.
    ///
    /// Reported so a user choosing a scope can see that a project file exists
    /// and would be left alone, rather than discovering it afterwards.
    pub fn detected_surfaces(&self) -> Vec<DetectedSurface> {
        [SettingsScope::User, SettingsScope::Project, SettingsScope::Managed]
            .into_iter()
            .filter_map(|scope| {
                let path = self.settings_path(scope).ok()?;
                path.is_file().then_some(DetectedSurface { scope, path })
            })
            .collect()
    }

    /// Root for the artifacts Agent Assembly owns for this scope.
    ///
    /// # Errors
    ///
    /// [`ScopeError::Unresolvable`] when no state root is known.
    pub fn owned_root(&self, scope: SettingsScope) -> Result<PathBuf, ScopeError> {
        let state = self.state.as_ref().ok_or_else(|| ScopeError::Unresolvable {
            scope,
            detail: "no Agent Assembly state directory is known; set AASM_STATE_DIR".to_string(),
        })?;
        Ok(state.join("claude-code").join(scope.to_string()))
    }

    /// Where the copy of the proxy CA this integration owns is written.
    ///
    /// A **copy**, not a reference to [`ca_source`](Self::ca_source): the step
    /// has to be fingerprinted, drift-checked and reversed, and reversing a
    /// reference would delete the proxy's own certificate authority.
    ///
    /// # Errors
    ///
    /// As [`owned_root`](Self::owned_root).
    pub fn proxy_ca_pem(&self, scope: SettingsScope) -> Result<PathBuf, ScopeError> {
        Ok(self.owned_root(scope)?.join("aasm-proxy-ca.pem"))
    }

    /// Directory holding the launch environment this integration injects.
    ///
    /// # Errors
    ///
    /// As [`owned_root`](Self::owned_root).
    pub fn launch_env_dir(&self, scope: SettingsScope) -> Result<PathBuf, ScopeError> {
        Ok(self.owned_root(scope)?.join("launch-env"))
    }

    /// The per-integration MitM host list the proxy unions into its own
    /// configuration (AAASM-5276 condition C5).
    ///
    /// One file per integration, so scoping one tool's side channels never
    /// changes what the proxy does for anything else on the machine.
    ///
    /// # Errors
    ///
    /// [`ScopeError::Unresolvable`] when no state root is known.
    pub fn mitm_hosts_file(&self, scope: SettingsScope) -> Result<PathBuf, ScopeError> {
        let state = self.state.as_ref().ok_or_else(|| ScopeError::Unresolvable {
            scope,
            detail: "no Agent Assembly state directory is known; set AASM_STATE_DIR".to_string(),
        })?;
        Ok(state
            .join(crate::MITM_HOSTS_DIR)
            .join(format!("claude-code--{scope}.hosts")))
    }

    /// The proxy CA certificate to copy trust material from, when one exists.
    pub fn ca_source(&self) -> Option<&Path> {
        self.ca_source.as_deref().filter(|p| p.is_file())
    }

    /// The path trust material would be copied from, whether or not it exists.
    pub fn ca_source_path(&self) -> Option<&Path> {
        self.ca_source.as_deref()
    }

    /// `$HOME`, for the legacy adapter's own detection markers.
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }
}

/// One configuration surface that exists on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedSurface {
    /// Which scope it is.
    pub scope: SettingsScope,
    /// The file that was found.
    pub path: PathBuf,
}

fn non_empty_var(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// `${AASM_STATE_DIR:-$HOME/.aasm}/integrations`, matching the receipt store's
/// own root so an integration's artifacts and its receipt share a lifetime.
///
/// `None` when neither root is known, which is what makes
/// [`ClaudeCodePaths::owned_root`]'s [`ScopeError::Unresolvable`] reachable.
fn state_root() -> Option<PathBuf> {
    state_root_from(non_empty_var("AASM_STATE_DIR"), non_empty_var("HOME"))
}

/// `${AA_CA_DIR:-$HOME/.aa/ca}/ca-cert.pem` — where `aa-proxy` persists the CA
/// it signs intercepted leaf certificates with.
///
/// `None` when neither root is known, which is what makes `read_ca_pem`'s
/// "location is unknown" error reachable.
fn ca_source() -> Option<PathBuf> {
    ca_source_from(non_empty_var("AA_CA_DIR"), non_empty_var("HOME"))
}

/// The resolution rule for [`state_root`], with the environment passed in.
///
/// # Why there is no `.` fallback
///
/// This used to end in `unwrap_or_else(|| PathBuf::from("."))`, so an unset
/// `HOME` produced `./.aasm/integrations` — resolved against the *daemon's*
/// spawn-time working directory, since [`ClaudeCodePaths::from_env`] runs once
/// at boot. Install receipts then landed somewhere a later `integrations remove`
/// resolving a different cwd would not find, leaving managed keys merged into a
/// user-owned settings file with no recorded `prior_state` to reverse: an
/// unreversible edit, arrived at silently (AAASM-5956, same root cause as
/// AAASM-5913).
///
/// Nothing legitimate is lost. `AASM_STATE_DIR` or `HOME` is set for every
/// ordinary invocation; when neither is, there is no correct answer to guess,
/// and the caller already has a fail-closed path for that.
///
/// # Why the environment is an argument
///
/// A function not *given* the process environment cannot resolve against it, so
/// the removed fallback cannot return by accident — and the rule stays assertable
/// without any test mutating process-global state.
fn state_root_from(override_dir: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    let base = override_dir.or_else(|| home.map(|home| home.join(".aasm")))?;
    Some(base.join("integrations"))
}

/// The resolution rule for [`ca_source`], with the environment passed in.
///
/// # Why there is no `.` fallback
///
/// The stakes here are higher than for [`state_root_from`]. `read_ca_pem` reads
/// this path and embeds its contents into the governed tool's settings as
/// **trust material**. With a `.` fallback that path was
/// `./.aa/ca/ca-cert.pem` relative to the daemon's cwd, so anyone able to write
/// a file into a directory the daemon might boot from could have a certificate
/// authority of their choosing installed as trusted by Claude Code — the
/// attacker-substitution shape of AAASM-4020 and AAASM-5937, on trust material
/// rather than on an executable.
///
/// The `is_file()` filter on [`ClaudeCodePaths::ca_source`] did not mitigate
/// that: it made an *absent* planted file report the capability unsupported,
/// while a *present* one reported Supported and was read. Removing the guessed
/// root is what closes the vector, because no relative path can be synthesised
/// at all.
fn ca_source_from(override_dir: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    let dir = override_dir.or_else(|| home.map(|home| home.join(".aa").join("ca")))?;
    Some(dir.join("ca-cert.pem"))
}

/// `$CLAUDE_CONFIG_DIR`, else `$HOME/.claude` — the precedence
/// [`ClaudeCodePaths::user_config_dir`] used to apply internally, before
/// AAASM-5957 removed the ability for it to read either variable itself.
///
/// `pub`, unlike [`state_root_from`]/[`ca_source_from`]: those are resolved
/// once, by this crate, from the daemon's own environment, because the state
/// root and CA source are never the caller's to name. This one is resolved by
/// whichever process **is** the caller — the `aasm` CLI, reading its own
/// environment — and carried into the request from there
/// ([`ClaudeCodePaths::with_config_dir`]), so it has to be reachable outside
/// this crate.
///
/// `None` when neither is known, which is what makes
/// [`ClaudeCodePaths::user_config_dir`]'s [`ScopeError::Unresolvable`]
/// reachable for a caller with nothing to state.
pub fn user_config_home_from(config_dir: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    config_dir.or_else(|| home.map(|home| home.join(DOT_CLAUDE)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &Path) -> ClaudeCodePaths {
        ClaudeCodePaths::default()
            .with_home(dir.join("home"))
            // AAASM-5957: `with_config_dir` no longer has a `$HOME`-derived
            // fallback to fall back to, so every fixture that exercises User
            // scope has to state this explicitly now — this is the caller
            // stating what used to be inferred, not a change in destination.
            .with_config_dir(dir.join("home").join(DOT_CLAUDE))
            .with_project(dir.join("repo"))
            .with_state(dir.join("state"))
            .with_ca_source(dir.join("ca").join("ca-cert.pem"))
    }

    #[test]
    fn a_project_directory_never_captures_a_user_scoped_write() {
        // The C2 regression in one assertion: a `.claude/` directory sitting in
        // the project root must not change where a user-scoped step writes.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("repo").join(DOT_CLAUDE)).unwrap();
        let paths = paths(dir.path());

        assert_eq!(
            paths.settings_path(SettingsScope::User).unwrap(),
            dir.path().join("home").join(DOT_CLAUDE).join(SETTINGS_FILE)
        );
        assert_eq!(
            paths.settings_path(SettingsScope::Project).unwrap(),
            dir.path().join("repo").join(DOT_CLAUDE).join(SETTINGS_FILE)
        );
    }

    #[test]
    fn claude_config_dir_wins_for_user_scope() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path()).with_config_dir(dir.path().join("elsewhere"));
        assert_eq!(
            paths.settings_path(SettingsScope::User).unwrap(),
            dir.path().join("elsewhere").join(SETTINGS_FILE)
        );
    }

    /// AAASM-5957 AC3/AC4, at the layer the defect actually lived in: a
    /// daemon whose own `home` is identity A must resolve a User-scope
    /// destination from the caller-supplied `config_dir` — identity B —
    /// only, and never fall back to A. Distinct from
    /// [`claude_config_dir_wins_for_user_scope`], which only checks that an
    /// *overridden* config_dir beats the default derived from the *same*
    /// home; this fixture gives `home` and `config_dir` unrelated identities
    /// so the two can never coincidentally agree.
    ///
    /// **Negative control (AC5):** against the pre-fix
    /// `user_config_dir()` — which fell back to `self.home.join(".claude")`
    /// when `config_dir` was unset — this assertion alone would not have
    /// caught the defect, because a fixture always states `config_dir`. What
    /// *would* have caught it is `from_env_derives_no_user_scope_destination_from_the_process_environment`
    /// below, which uses `from_env()`'s own resolution rather than a
    /// hand-built fixture; run that test against a checkout of
    /// `user_config_dir()` before this ticket's fix and it fails, because
    /// pre-fix `from_env()` populated `config_dir` from `$CLAUDE_CONFIG_DIR`
    /// itself.
    #[test]
    fn a_daemon_s_own_home_never_determines_a_callers_user_scope_destination() {
        let daemon_identity = tempfile::tempdir().unwrap();
        let caller_identity = tempfile::tempdir().unwrap();
        let paths = ClaudeCodePaths::default()
            .with_home(daemon_identity.path().to_path_buf())
            .with_config_dir(caller_identity.path().join(DOT_CLAUDE));

        let resolved = paths.settings_path(SettingsScope::User).unwrap();
        assert_eq!(resolved, caller_identity.path().join(DOT_CLAUDE).join(SETTINGS_FILE));
        assert!(
            !resolved.starts_with(daemon_identity.path()),
            "the daemon's own home leaked into a User-scope write: {}",
            resolved.display()
        );
    }

    /// AAASM-5957 AC1/AC4: `from_env()` must not itself read
    /// `$CLAUDE_CONFIG_DIR` (or derive from `$HOME`) into `config_dir` — that
    /// field starts unset and is populated only by
    /// [`ClaudeCodePaths::with_config_dir`], which the caller (the `aasm`
    /// CLI, reading its own environment, not the daemon's) calls. Asserted
    /// against the real process environment, whatever it happens to be,
    /// rather than a fixture — this is the property that makes the AC3/AC4
    /// scenario ("a daemon whose launching shell exported CLAUDE_CONFIG_DIR")
    /// structurally unreachable rather than merely untested.
    #[test]
    fn from_env_derives_no_user_scope_destination_from_the_process_environment() {
        assert_eq!(
            ClaudeCodePaths::from_env().settings_path(SettingsScope::User),
            Err(ScopeError::Unresolvable {
                scope: SettingsScope::User,
                detail: "no user configuration home was given, and the configuration home a change \
                         lands in is never taken from the environment of the process resolving it"
                    .to_string(),
            }),
            "from_env() must never resolve a User-scope destination from its own process environment"
        );
    }

    #[test]
    fn the_managed_surface_resolves_to_the_canonical_os_path_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert_eq!(
            p.settings_path(SettingsScope::Managed).unwrap(),
            PathBuf::from(MANAGED_SETTINGS_PATH)
        );
        assert!(p.managed_root_is_canonical());
    }

    #[test]
    fn a_redirected_managed_root_is_reported_as_not_canonical() {
        // The seam every test uses, and the reason a redirected install can
        // never be presented as an endpoint-managed one: the privileged
        // authority elevates only for the canonical path.
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path()).with_managed_root(dir.path().join("ClaudeCode"));
        assert_eq!(
            p.settings_path(SettingsScope::Managed).unwrap(),
            dir.path().join("ClaudeCode").join(MANAGED_SETTINGS_FILE)
        );
        assert!(!p.managed_root_is_canonical());
    }

    #[test]
    fn an_unresolvable_root_is_an_error_not_a_guess() {
        let bare = ClaudeCodePaths::default();
        assert!(matches!(
            bare.settings_path(SettingsScope::User),
            Err(ScopeError::Unresolvable { .. })
        ));
        assert!(matches!(
            bare.owned_root(SettingsScope::User),
            Err(ScopeError::Unresolvable { .. })
        ));
    }

    #[test]
    fn owned_artifacts_are_scope_separated() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert_ne!(
            p.proxy_ca_pem(SettingsScope::User).unwrap(),
            p.proxy_ca_pem(SettingsScope::Project).unwrap()
        );
        assert_ne!(
            p.mitm_hosts_file(SettingsScope::User).unwrap(),
            p.mitm_hosts_file(SettingsScope::Project).unwrap()
        );
    }

    #[test]
    fn detected_surfaces_report_what_is_on_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert!(p.detected_surfaces().is_empty());

        let user = p.settings_path(SettingsScope::User).unwrap();
        std::fs::create_dir_all(user.parent().unwrap()).unwrap();
        std::fs::write(&user, "{}").unwrap();
        let found = p.detected_surfaces();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].scope, SettingsScope::User);
        assert_eq!(found[0].path, user);
    }

    #[test]
    fn a_missing_ca_source_is_reported_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert!(p.ca_source().is_none());
        assert!(p.ca_source_path().is_some());

        let ca = dir.path().join("ca").join("ca-cert.pem");
        std::fs::create_dir_all(ca.parent().unwrap()).unwrap();
        std::fs::write(&ca, "-----BEGIN CERTIFICATE-----\n").unwrap();
        assert_eq!(p.ca_source(), Some(ca.as_path()));
    }

    /// Neither root helper may invent a root when it has none (AAASM-5956).
    ///
    /// This is the load-bearing test of the pair. `an_unresolvable_root_is_an_error_not_a_guess`
    /// above already proves that a `None` root *produces* `ScopeError::Unresolvable` —
    /// but before this fix `from_env` could never hand it a `None`, so that branch
    /// was unreachable and the assertion proved nothing about the shipped path.
    /// What was missing is the half asserted here: that the resolution rule
    /// itself yields nothing rather than `.`.
    ///
    /// Reverting either helper to `unwrap_or_else(|| PathBuf::from("."))` reddens
    /// exactly this test.
    #[test]
    fn neither_root_rule_synthesises_a_relative_root_when_nothing_is_set() {
        assert_eq!(
            state_root_from(None, None),
            None,
            "an unset AASM_STATE_DIR and HOME must yield no state root, not ./.aasm/integrations"
        );
        assert_eq!(
            ca_source_from(None, None),
            None,
            "an unset AA_CA_DIR and HOME must yield no CA path, not ./.aa/ca/ca-cert.pem"
        );
    }

    /// The resolution order and its results are unchanged whenever anything is
    /// set, which is every ordinary invocation (AC2 — no behaviour change).
    #[test]
    fn both_root_rules_are_unchanged_when_an_override_or_home_is_set() {
        let over = PathBuf::from("/o");
        let home = PathBuf::from("/h");

        // Override wins over HOME, for both.
        assert_eq!(
            state_root_from(Some(over.clone()), Some(home.clone())),
            Some(PathBuf::from("/o/integrations"))
        );
        assert_eq!(
            ca_source_from(Some(over.clone()), Some(home.clone())),
            Some(PathBuf::from("/o/ca-cert.pem"))
        );

        // HOME alone gives the documented default layout.
        assert_eq!(
            state_root_from(None, Some(home.clone())),
            Some(PathBuf::from("/h/.aasm/integrations"))
        );
        assert_eq!(
            ca_source_from(None, Some(home)),
            Some(PathBuf::from("/h/.aa/ca/ca-cert.pem"))
        );

        // An override alone works with no HOME at all.
        assert_eq!(
            state_root_from(Some(over.clone()), None),
            Some(PathBuf::from("/o/integrations"))
        );
        assert_eq!(ca_source_from(Some(over), None), Some(PathBuf::from("/o/ca-cert.pem")));
    }

    /// A CA certificate is reachable only when a root explicitly names it
    /// (AAASM-5956 AC6).
    ///
    /// The substitution vector needed one specific input — no `AA_CA_DIR` and no
    /// `HOME` — to make the resolver name a cwd-relative path. A real file is
    /// planted at exactly the layout the old code would have produced, and the
    /// test turns the root on and off around it: with a root, this very file is
    /// what the rule names, which is what makes the plant a faithful stand-in for
    /// the old `.` fallback's target rather than an arbitrary temporary file;
    /// with no root, that same file becomes unnameable, so no arrangement of the
    /// daemon's working directory can select it.
    ///
    /// Both halves are needed. Asserting only that nothing is named would hold
    /// just as well for a rule that had stopped resolving anything at all, and
    /// the plant would then be decorative — created, but causally absent from
    /// every assertion.
    ///
    /// The plant is deliberately a file that *exists*: `ClaudeCodePaths::ca_source`
    /// filters on `is_file()`, which meant an absent plant reported the
    /// capability unsupported while a present one reported Supported and was
    /// read. Testing with an absent file would therefore have tested the case
    /// that was never the problem.
    #[test]
    fn a_certificate_is_reachable_only_when_a_root_explicitly_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let planted = dir.path().join(".aa").join("ca").join("ca-cert.pem");
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::write(&planted, "-----BEGIN CERTIFICATE-----\nattacker\n").unwrap();
        assert!(planted.is_file(), "the plant must exist for this test to mean anything");

        assert_eq!(
            ca_source_from(None, Some(dir.path().to_path_buf())),
            Some(planted.clone()),
            "given a root, the rule must name exactly the planted layout — otherwise the \
             plant is not the file the old fallback would have selected"
        );

        assert_eq!(
            ca_source_from(None, None),
            None,
            "with no AA_CA_DIR and no HOME the resolver must name no CA path, so that same \
             file is unreachable from any working directory"
        );

        // And the same for the state root, whose guessed form was the sibling
        // `./.aasm/integrations` under that same directory.
        assert_eq!(
            state_root_from(None, Some(dir.path().to_path_buf())),
            Some(dir.path().join(".aasm").join("integrations"))
        );
        assert_eq!(state_root_from(None, None), None);
    }
}
