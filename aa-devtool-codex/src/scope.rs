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
            state: state_root(),
            ca_source: ca_source(),
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
///
/// `None` when neither root is known, which is what makes
/// [`CodexPaths::owned_root`]'s [`ScopeError::Unresolvable`] reachable.
fn state_root() -> Option<PathBuf> {
    state_root_from(non_empty_var("AASM_STATE_DIR"), non_empty_var("HOME"))
}

/// `${AA_CA_DIR:-$HOME/.aa/ca}/ca-cert.pem` — where `aa-proxy` persists the CA
/// it signs intercepted leaf certificates with.
///
/// `None` when neither root is known, which is what makes the
/// "location is unknown" refusal in `lifecycle` reachable.
fn ca_source() -> Option<PathBuf> {
    ca_source_from(non_empty_var("AA_CA_DIR"), non_empty_var("HOME"))
}

/// The resolution rule for [`state_root`], with the environment passed in.
///
/// # Why there is no `.` fallback
///
/// This used to end in `unwrap_or_else(|| PathBuf::from("."))`, so an unset
/// `HOME` produced `./.aasm/integrations` — resolved against the *daemon's*
/// spawn-time working directory, since [`CodexPaths::from_env`] runs once at
/// boot. Install receipts then landed somewhere a later `integrations remove`
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
/// The stakes here are higher than for [`state_root_from`]. `lifecycle` reads
/// this path and embeds its contents into the governed tool's configuration as
/// **trust material**. With a `.` fallback that path was
/// `./.aa/ca/ca-cert.pem` relative to the daemon's cwd, so anyone able to write
/// a file into a directory the daemon might boot from could have a certificate
/// authority of their choosing installed as trusted by Codex — the
/// attacker-substitution shape of AAASM-4020 and AAASM-5937, on trust material
/// rather than on an executable.
///
/// The `is_file()` filter on [`CodexPaths::ca_source`] did not mitigate that: it
/// made an *absent* planted file report the capability unsupported, while a
/// *present* one reported Supported and was read. Removing the guessed root is
/// what closes the vector, because no relative path can be synthesised at all.
fn ca_source_from(override_dir: Option<PathBuf>, home: Option<PathBuf>) -> Option<PathBuf> {
    let dir = override_dir.or_else(|| home.map(|home| home.join(".aa").join("ca")))?;
    Some(dir.join("ca-cert.pem"))
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

    /// A CA certificate planted at the *old* guessed location cannot be selected
    /// as trust material (AAASM-5956 AC6).
    ///
    /// The substitution vector needed one specific input — no `AA_CA_DIR` and no
    /// `HOME` — to make the resolver name a cwd-relative path. A real file is
    /// planted at exactly the layout the old code would have produced, and the
    /// assertion is that the resolver names nothing at all, so the plant cannot
    /// be reached however the daemon's working directory is arranged.
    ///
    /// The plant is deliberately a file that *exists*: [`CodexPaths::ca_source`]
    /// filters on `is_file()`, which meant an absent plant reported the
    /// capability unsupported while a present one reported Supported and was
    /// read. Testing with an absent file would therefore have tested the case
    /// that was never the problem.
    #[test]
    fn a_certificate_planted_at_the_old_guessed_location_cannot_be_selected() {
        let dir = tempfile::tempdir().unwrap();
        let planted = dir.path().join(".aa").join("ca").join("ca-cert.pem");
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::write(&planted, "-----BEGIN CERTIFICATE-----\nattacker\n").unwrap();
        assert!(planted.is_file(), "the plant must exist for this test to mean anything");

        assert_eq!(
            ca_source_from(None, None),
            None,
            "with no AA_CA_DIR and no HOME the resolver must name no CA path, so no \
             relative plant is reachable from any working directory"
        );

        // And the same for the state root, whose guessed form was the sibling
        // `./.aasm/integrations` under that same directory.
        assert_eq!(state_root_from(None, None), None);
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
