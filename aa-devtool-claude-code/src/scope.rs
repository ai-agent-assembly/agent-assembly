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
//!   Root-owned, absent on an unmanaged host, and **unmeasured**: the AAASM-5276
//!   spike deliberately made no privileged writes, so its managed-only keys
//!   (`disableBypassPermissionsMode`, `allowManagedPermissionRulesOnly`, …)
//!   remain unproven. [`ClaudeCodePaths::settings_path`] resolves it so the
//!   surface can be *named* in a refusal, and nothing in this crate writes to it.

use std::path::{Path, PathBuf};

use aa_devtool_contract::SettingsScope;

/// The macOS endpoint managed-settings file.
///
/// Named so a refusal can name it. Deliberately never written to — see the
/// module docs.
pub const MANAGED_SETTINGS_PATH: &str = "/Library/Application Support/ClaudeCode/managed-settings.json";

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

/// Every path the Claude Code integration reads or writes, resolved from
/// explicit roots.
///
/// Constructed with [`ClaudeCodePaths::from_env`] in production and with the
/// `with_*` builders in tests, so no test ever depends on the ambient `$HOME`
/// or working directory.
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
}

impl ClaudeCodePaths {
    /// Resolve every root from the environment.
    ///
    /// Missing roots stay `None` rather than being guessed; the scope that
    /// needed one reports [`ScopeError::Unresolvable`] when it is asked for.
    pub fn from_env() -> Self {
        Self {
            config_dir: non_empty_var("CLAUDE_CONFIG_DIR"),
            home: non_empty_var("HOME"),
            project: std::env::current_dir().ok(),
            state: Some(state_root()),
            ca_source: Some(ca_source()),
        }
    }

    /// Pin the user-scope configuration home (`CLAUDE_CONFIG_DIR`).
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

    /// The settings file for `scope`.
    ///
    /// # Errors
    ///
    /// [`ScopeError::Unresolvable`] when the scope's root is unknown on this
    /// host, and [`ScopeError::Refused`] for
    /// [`SettingsScope::Managed`] — see the module docs.
    pub fn settings_path(&self, scope: SettingsScope) -> Result<PathBuf, ScopeError> {
        match scope {
            SettingsScope::User => Ok(self.user_config_dir()?.join(SETTINGS_FILE)),
            SettingsScope::Project => {
                let project = self.project.as_ref().ok_or_else(|| ScopeError::Unresolvable {
                    scope,
                    detail: "no project root was given and the working directory could not be read".to_string(),
                })?;
                Ok(project.join(DOT_CLAUDE).join(SETTINGS_FILE))
            }
            SettingsScope::Managed => Err(ScopeError::Refused {
                scope,
                detail: format!(
                    "{MANAGED_SETTINGS_PATH} is administrator-owned and Agent Assembly will not write to it. \
                     Its enforcement keys are unmeasured and installing them needs a privileged step this \
                     integration deliberately does not take; choose --scope user or --scope project"
                ),
            }),
        }
    }

    /// Claude Code's user configuration directory.
    fn user_config_dir(&self) -> Result<PathBuf, ScopeError> {
        if let Some(dir) = &self.config_dir {
            return Ok(dir.clone());
        }
        let home = self.home.as_ref().ok_or_else(|| ScopeError::Unresolvable {
            scope: SettingsScope::User,
            detail: "neither CLAUDE_CONFIG_DIR nor HOME is set".to_string(),
        })?;
        Ok(home.join(DOT_CLAUDE))
    }

    /// Which configuration surfaces this host actually has, whoever wrote them.
    ///
    /// Reported so a user choosing a scope can see that a project file exists
    /// and would be left alone, rather than discovering it afterwards.
    pub fn detected_surfaces(&self) -> Vec<DetectedSurface> {
        [SettingsScope::User, SettingsScope::Project, SettingsScope::Managed]
            .into_iter()
            .filter_map(|scope| {
                let path = match scope {
                    SettingsScope::Managed => PathBuf::from(MANAGED_SETTINGS_PATH),
                    other => self.settings_path(other).ok()?,
                };
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
fn state_root() -> PathBuf {
    let base = non_empty_var("AASM_STATE_DIR").unwrap_or_else(|| {
        non_empty_var("HOME")
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".aasm")
    });
    base.join("integrations")
}

/// `${AA_CA_DIR:-$HOME/.aa/ca}/ca-cert.pem` — where `aa-proxy` persists the CA
/// it signs intercepted leaf certificates with.
fn ca_source() -> PathBuf {
    let dir = non_empty_var("AA_CA_DIR").unwrap_or_else(|| {
        non_empty_var("HOME")
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".aa")
            .join("ca")
    });
    dir.join("ca-cert.pem")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &Path) -> ClaudeCodePaths {
        ClaudeCodePaths::default()
            .with_home(dir.join("home"))
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

    #[test]
    fn the_managed_surface_is_named_and_refused() {
        let dir = tempfile::tempdir().unwrap();
        match paths(dir.path()).settings_path(SettingsScope::Managed) {
            Err(ScopeError::Refused { detail, .. }) => {
                assert!(detail.contains(MANAGED_SETTINGS_PATH), "{detail}");
                assert!(detail.contains("--scope user"), "{detail}");
            }
            other => panic!("managed scope must be refused, got {other:?}"),
        }
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
}
