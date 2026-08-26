//! Claude Code's use of the shared launch-environment store.
//!
//! [`LaunchEnvStore`] and [`is_valid_var_name`] moved to
//! `aa_core::integration::launch_env` (AAASM-5914): nothing about them was
//! Claude-specific, and `aa-devtool-codex` needed the identical mechanism for
//! `CODEX_CA_CERTIFICATE`. Re-exported here rather than dropped —
//! [`crate::executor`] and `aa-cli`'s `cli_run_claude_launch_env.rs` both import
//! `aa_devtool_claude_code::launch_env::LaunchEnvStore`, and this keeps that
//! path working.

pub use aa_devtool_contract::{is_valid_var_name, LaunchEnvStore};

/// Every launch-environment variable an installed Claude Code integration owns,
/// across every scope it can be installed at.
///
/// User scope is read first and project scope second, so a project-scoped
/// install wins for a variable both set — the narrower installation is the more
/// specific answer for the directory the launch is happening in.
///
/// A scope with no installation contributes nothing, so a host where nothing was
/// installed produces an empty map and the launch is unchanged.
pub fn installed_environment(paths: &crate::scope::ClaudeCodePaths) -> std::collections::BTreeMap<String, String> {
    // Every scope an install can own, `Managed` included: the endpoint-managed
    // install still needs `NODE_EXTRA_CA_CERTS` and the proxy variables at
    // launch, and the artifacts that carry them are Agent Assembly's own files
    // under the state root — not the root-owned settings file.
    let dirs = [
        aa_devtool_contract::SettingsScope::User,
        aa_devtool_contract::SettingsScope::Project,
        aa_devtool_contract::SettingsScope::Managed,
    ]
    .into_iter()
    .filter_map(|scope| paths.launch_env_dir(scope).ok());
    aa_devtool_contract::installed_environment(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_project_installation_wins_over_a_user_one_for_the_same_variable() {
        use aa_devtool_contract::SettingsScope;
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::scope::ClaudeCodePaths::default()
            .with_home(dir.path().join("home"))
            .with_project(dir.path().join("repo"))
            .with_state(dir.path().join("state"));

        LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::User).unwrap())
            .set("NODE_EXTRA_CA_CERTS", "/user/ca.pem")
            .unwrap();
        LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::User).unwrap())
            .set("HTTPS_PROXY", "http://127.0.0.1:8899")
            .unwrap();
        LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::Project).unwrap())
            .set("NODE_EXTRA_CA_CERTS", "/project/ca.pem")
            .unwrap();

        let env = installed_environment(&paths);
        assert_eq!(
            env.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
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
        let paths = crate::scope::ClaudeCodePaths::default()
            .with_home(dir.path().join("home"))
            .with_project(dir.path().join("repo"))
            .with_state(dir.path().join("state"));
        assert!(installed_environment(&paths).is_empty());
    }
}
