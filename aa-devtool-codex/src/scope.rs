//! Where the artifacts this integration owns live — modeled on
//! `aa_devtool_claude_code::scope::ClaudeCodePaths`, but smaller.
//!
//! # Why smaller than Claude Code's (AAASM-5915)
//!
//! Claude Code's `ClaudeCodePaths` resolves three configuration surfaces
//! (user/project/managed), a `CLAUDE_CONFIG_DIR` redirection, an
//! administrator-authorized managed-settings root, and a per-integration MitM
//! hosts file. Codex has exactly one settings file the CLI itself reads
//! (`$HOME/.codex/config.json` — Codex has no project-scoped or
//! endpoint-managed config surface AASM can address), and this integration's
//! plan deliberately carries no side-channel/MitM-hosts step (AAASM-5917), so
//! there is no `mitm_hosts_file` to resolve either. What remains —
//! `owned_root`, `proxy_ca_pem`, `launch_env_dir` — is the same shape as
//! Claude's because it backs the identical mechanism: a copy of the proxy CA,
//! and the launch-environment store that injects `CODEX_CA_CERTIFICATE`.

use std::path::{Path, PathBuf};

use aa_devtool_contract::SettingsScope;

/// Why a root could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeError {
    /// The root a path is relative to is unknown on this host.
    #[error("the {scope} configuration scope cannot be resolved: {detail}")]
    Unresolvable {
        /// The scope that could not be resolved.
        scope: SettingsScope,
        /// What is missing.
        detail: String,
    },
}

/// Every path the Codex integration reads or writes, resolved from explicit
/// roots.
///
/// Constructed with [`CodexPaths::from_env`] in production and with the
/// `with_*` builders in tests, so no test ever depends on the ambient `$HOME`
/// or working directory.
#[derive(Debug, Clone, Default)]
pub struct CodexPaths {
    /// `$HOME`.
    home: Option<PathBuf>,
    /// Root for artifacts Agent Assembly owns outright.
    state: Option<PathBuf>,
    /// The proxy CA certificate this integration copies its trust material
    /// from.
    ca_source: Option<PathBuf>,
}

impl CodexPaths {
    /// Resolve every root from the environment.
    ///
    /// Missing roots stay `None` rather than being guessed; the scope that
    /// needed one reports [`ScopeError::Unresolvable`] when it is asked for.
    pub fn from_env() -> Self {
        Self {
            home: non_empty_var("HOME"),
            state: Some(state_root()),
            ca_source: Some(ca_source()),
        }
    }

    /// Pin `$HOME`.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
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

    /// The Codex CLI's own configuration file — `$HOME/.codex/config.json`.
    ///
    /// Unlike Claude Code's `settings_path`, this does not vary by `scope`:
    /// Codex has one configuration surface, not three. A caller still names a
    /// scope when authoring a plan step (`StepAction::WriteManagedSettings`
    /// carries one), and this always resolves to the same file regardless of
    /// which scope was asked for.
    ///
    /// # Errors
    ///
    /// [`ScopeError::Unresolvable`] when `$HOME` is unknown on this host.
    pub fn settings_path(&self) -> Result<PathBuf, ScopeError> {
        let home = self.home.as_ref().ok_or_else(|| ScopeError::Unresolvable {
            scope: SettingsScope::User,
            detail: "HOME is not set".to_string(),
        })?;
        Ok(home.join(".codex").join("config.json"))
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
        Ok(state.join("codex").join(scope.to_string()))
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

    /// Directory holding the launch environment this integration injects
    /// (`CODEX_CA_CERTIFICATE`, `HTTPS_PROXY`, `HTTP_PROXY`).
    ///
    /// # Errors
    ///
    /// As [`owned_root`](Self::owned_root).
    pub fn launch_env_dir(&self, scope: SettingsScope) -> Result<PathBuf, ScopeError> {
        Ok(self.owned_root(scope)?.join("launch-env"))
    }

    /// The proxy CA certificate to copy trust material from, when one exists.
    pub fn ca_source(&self) -> Option<&Path> {
        self.ca_source.as_deref().filter(|p| p.is_file())
    }

    /// The path trust material would be copied from, whether or not it exists.
    pub fn ca_source_path(&self) -> Option<&Path> {
        self.ca_source.as_deref()
    }

    /// `$HOME`, for detection markers and the adapter's own config resolution.
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }
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

    fn paths(dir: &Path) -> CodexPaths {
        CodexPaths::default()
            .with_home(dir.join("home"))
            .with_state(dir.join("state"))
            .with_ca_source(dir.join("ca").join("ca-cert.pem"))
    }

    #[test]
    fn settings_path_is_home_dot_codex_config_json() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert_eq!(
            p.settings_path().unwrap(),
            dir.path().join("home").join(".codex").join("config.json")
        );
    }

    #[test]
    fn an_unresolvable_root_is_an_error_not_a_guess() {
        let bare = CodexPaths::default();
        assert!(matches!(bare.settings_path(), Err(ScopeError::Unresolvable { .. })));
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
            p.launch_env_dir(SettingsScope::User).unwrap(),
            p.launch_env_dir(SettingsScope::Project).unwrap()
        );
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

    #[test]
    fn settings_path_does_not_vary_by_scope() {
        // Codex has one configuration surface, unlike Claude's three.
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let path = p.settings_path().unwrap();
        assert_eq!(path, p.settings_path().unwrap());
        assert!(path.ends_with(".codex/config.json"));
    }
}
