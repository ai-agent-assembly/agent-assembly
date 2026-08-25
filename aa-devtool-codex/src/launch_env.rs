//! Codex's use of the shared launch-environment store.
//!
//! Mirrors `aa_devtool_claude_code::launch_env`: the mechanism is the shared
//! `aa_core::integration::launch_env` store (AAASM-5914), and this module is
//! just Codex's precedence over its own scopes.

use std::collections::BTreeMap;

use aa_devtool_contract::SettingsScope;

use crate::scope::CodexPaths;

/// Every launch-environment variable an installed Codex integration owns,
/// across every scope it can be installed at.
///
/// User scope is read first and project scope second, so a project-scoped
/// install wins for a variable both set — the narrower installation is the
/// more specific answer for the directory the launch is happening in.
///
/// A scope with no installation contributes nothing, so a host where nothing
/// was installed produces an empty map and the launch is unchanged.
pub fn installed_environment(paths: &CodexPaths) -> BTreeMap<String, String> {
    let dirs = [SettingsScope::User, SettingsScope::Project, SettingsScope::Managed]
        .into_iter()
        .filter_map(|scope| paths.launch_env_dir(scope).ok());
    aa_devtool_contract::installed_environment(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_devtool_contract::LaunchEnvStore;

    fn paths(dir: &std::path::Path) -> CodexPaths {
        CodexPaths::default()
            .with_home(dir.join("home"))
            .with_state(dir.join("state"))
    }

    #[test]
    fn a_project_installation_wins_over_a_user_one_for_the_same_variable() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());

        LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::User).unwrap())
            .set("CODEX_CA_CERTIFICATE", "/user/ca.pem")
            .unwrap();
        LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::User).unwrap())
            .set("HTTPS_PROXY", "http://127.0.0.1:8899")
            .unwrap();
        LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::Project).unwrap())
            .set("CODEX_CA_CERTIFICATE", "/project/ca.pem")
            .unwrap();

        let env = installed_environment(&paths);
        assert_eq!(
            env.get("CODEX_CA_CERTIFICATE").map(String::as_str),
            Some("/project/ca.pem")
        );
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:8899")
        );
    }

    #[test]
    fn a_host_with_no_installation_injects_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(installed_environment(&paths(dir.path())).is_empty());
    }
}
