//! The launch environment Agent Assembly injects, kept as an artifact it owns.
//!
//! # Why an artifact and not "the launcher just sets it"
//!
//! AAASM-5276 condition C1 is that `NODE_EXTRA_CA_CERTS` has to point at the
//! proxy CA for interception to work at all. A launcher that simply called
//! `cmd.env(...)` would satisfy the mechanism and none of the lifecycle: there
//! would be nothing to fingerprint, nothing for drift to compare, nothing for a
//! receipt to record and nothing for removal to reverse. Writing the variable to
//! a file Agent Assembly owns makes the injection a
//! [`StepAction::InjectLaunchEnvironment`](aa_devtool_contract::StepAction)
//! whose artifact behaves like every other one in the plan.
//!
//! # One file per variable
//!
//! Two steps writing into one document would each fingerprint the whole
//! document, so the second would invalidate the first's receipt and the next
//! drift check would report a change nobody made. A file per variable keeps each
//! step's artifact independent, which is what lets `ConfigureProxy` and
//! `InjectLaunchEnvironment` coexist in one plan.
//!
//! # Variable names are validated, not trusted
//!
//! A name becomes a file name. [`is_valid_var_name`] restricts it to the POSIX
//! environment-name shape, so a plan cannot address a path outside the store —
//! including via `..`.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// Whether `name` is a POSIX environment variable name.
///
/// `[A-Za-z_][A-Za-z0-9_]*`. Anything else is refused rather than sanitised: a
/// name this store cannot represent is a plan bug, and quietly rewriting it
/// would put the variable somewhere the receipt does not describe.
pub fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The launch-environment variables Agent Assembly owns for one scope.
#[derive(Debug, Clone)]
pub struct LaunchEnvStore {
    root: PathBuf,
}

impl LaunchEnvStore {
    /// A store rooted at `root`, created on first write.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory this store writes into.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where `name`'s value is kept.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] when `name` is not a valid environment
    /// variable name.
    pub fn path_for(&self, name: &str) -> io::Result<PathBuf> {
        if !is_valid_var_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name:?} is not a valid environment variable name"),
            ));
        }
        Ok(self.root.join(name))
    }

    /// Set `name` to `value`, returning whether anything on disk changed.
    ///
    /// The `false` case is the mechanical half of the idempotence guarantee: a
    /// reapply that would write the same bytes does not touch the file.
    ///
    /// # Errors
    ///
    /// As [`path_for`](Self::path_for), plus any filesystem failure.
    pub fn set(&self, name: &str, value: &str) -> io::Result<bool> {
        let path = self.path_for(name)?;
        if std::fs::read_to_string(&path).is_ok_and(|existing| existing == value) {
            return Ok(false);
        }
        std::fs::create_dir_all(&self.root)?;
        let tmp = path.with_extension("aasm-tmp");
        std::fs::write(&tmp, value)?;
        std::fs::rename(&tmp, &path)?;
        Ok(true)
    }

    /// The current value of `name`, or `None` when it is unset or unreadable.
    pub fn get(&self, name: &str) -> Option<String> {
        let path = self.path_for(name).ok()?;
        std::fs::read_to_string(path).ok()
    }

    /// Unset `name`. Succeeds when it was already unset — removal has to be
    /// safe to run twice.
    ///
    /// # Errors
    ///
    /// As [`path_for`](Self::path_for), plus any filesystem failure other than
    /// "not found".
    pub fn unset(&self, name: &str) -> io::Result<()> {
        let path = self.path_for(name)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // Leave no empty directory behind; an empty launch-env directory is an
        // artifact the user never had. A non-empty one simply refuses.
        let _ = std::fs::remove_dir(&self.root);
        Ok(())
    }

    /// Every variable this store currently holds, in name order.
    ///
    /// Entries whose file name is not a valid variable name are skipped rather
    /// than exported — a stray file must not become part of a child's
    /// environment.
    pub fn all(&self) -> BTreeMap<String, String> {
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return BTreeMap::new();
        };
        entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_str()?.to_owned();
                if !is_valid_var_name(&name) {
                    return None;
                }
                let value = std::fs::read_to_string(entry.path()).ok()?;
                Some((name, value))
            })
            .collect()
    }
}

/// Every launch-environment variable an installed integration owns, across
/// every scope it can be installed at.
///
/// User scope is read first and project scope second, so a project-scoped
/// install wins for a variable both set — the narrower installation is the more
/// specific answer for the directory the launch is happening in.
///
/// A scope with no installation contributes nothing, so a host where nothing was
/// installed produces an empty map and the launch is unchanged.
pub fn installed_environment(paths: &crate::scope::ClaudeCodePaths) -> BTreeMap<String, String> {
    let mut merged = BTreeMap::new();
    for scope in [
        aa_devtool_contract::SettingsScope::User,
        aa_devtool_contract::SettingsScope::Project,
    ] {
        let Ok(dir) = paths.launch_env_dir(scope) else {
            continue;
        };
        merged.extend(LaunchEnvStore::at(dir).all());
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, LaunchEnvStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = LaunchEnvStore::at(dir.path().join("launch-env"));
        (dir, store)
    }

    #[test]
    fn setting_a_variable_twice_mutates_once() {
        let (_dir, store) = store();
        assert!(store.set("NODE_EXTRA_CA_CERTS", "/tmp/ca.pem").unwrap());
        assert!(
            !store.set("NODE_EXTRA_CA_CERTS", "/tmp/ca.pem").unwrap(),
            "a rewrite of identical bytes must not report a mutation"
        );
        assert!(store.set("NODE_EXTRA_CA_CERTS", "/tmp/other.pem").unwrap());
        assert_eq!(store.get("NODE_EXTRA_CA_CERTS").as_deref(), Some("/tmp/other.pem"));
    }

    #[test]
    fn unsetting_is_idempotent_and_removes_the_directory() {
        let (_dir, store) = store();
        store.set("HTTPS_PROXY", "http://127.0.0.1:8899").unwrap();
        store.unset("HTTPS_PROXY").unwrap();
        store.unset("HTTPS_PROXY").unwrap();
        assert!(store.get("HTTPS_PROXY").is_none());
        assert!(!store.root().exists(), "an empty launch-env directory must not survive");
    }

    #[test]
    fn a_variable_name_cannot_address_a_path_outside_the_store() {
        let (_dir, store) = store();
        for evil in ["../escape", "a/b", "..", "", "1BAD", "WITH-DASH"] {
            assert!(
                store.path_for(evil).is_err(),
                "{evil:?} was accepted as a variable name"
            );
            assert!(store.set(evil, "x").is_err(), "{evil:?} was written");
        }
        assert!(store.path_for("NODE_EXTRA_CA_CERTS").is_ok());
        assert!(store.path_for("_private1").is_ok());
    }

    #[test]
    fn stray_files_are_not_exported_as_variables() {
        let (_dir, store) = store();
        store.set("HTTPS_PROXY", "http://127.0.0.1:8899").unwrap();
        std::fs::write(store.root().join("not-a-var"), "ignored").unwrap();
        let all = store.all();
        assert_eq!(all.len(), 1);
        assert_eq!(
            all.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:8899")
        );
    }

    #[test]
    fn an_absent_store_exports_nothing() {
        let (_dir, store) = store();
        assert!(store.all().is_empty());
    }

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
