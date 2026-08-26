//! The mutations only this integration knows how to perform.
//!
//! Modeled on `aa_devtool_claude_code::executor::ClaudeCodeStepExecutor`, minus
//! the one privileged path: Codex has no endpoint-managed settings surface
//! (AAASM-5917), so every `WriteManagedSettings` step here is an ordinary file
//! write and delegates to [`FilesystemExecutor`] like `MaterialiseTrustMaterial`
//! and `ManageArtifact` do. What remains to add is exactly
//! [`StepAction::InjectLaunchEnvironment`] and [`StepAction::ConfigureProxy`],
//! both backed by [`LaunchEnvStore`] — the same two mechanisms Claude Code's
//! executor adds, for the same reason: `FilesystemExecutor` deliberately
//! refuses them.

use std::collections::BTreeMap;
use std::path::PathBuf;

use aa_devtool_contract::{
    ArtifactObservation, EnvValue, ExecutionError, FilesystemExecutor, IntegrationStep, LaunchEnvStore, SettingsScope,
    StepAction, StepExecutor, StepOutcome, StepReceipt,
};

/// Prefix `aa-core` puts on every fingerprint. Reproduced rather than
/// re-exported: the executor has to produce values `observe` can compare
/// against, and the format is part of the receipt's wire shape.
const FINGERPRINT_PREFIX: &str = "sha256:";

/// The fingerprint of a raw (non-JSON) artifact.
fn raw_fingerprint(body: &str) -> String {
    format!("{FINGERPRINT_PREFIX}{}", aa_devtool_contract::sha256_hex(body))
}

/// The canonical rendering of a set of launch-environment assignments.
///
/// Sorted `NAME=value` lines, so a `ConfigureProxy` step that writes several
/// variables has one stable fingerprint regardless of map iteration order.
fn env_projection(pairs: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
        .iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect::<Vec<_>>()
        .concat()
}

/// Executes a Codex integration plan.
#[derive(Default)]
pub struct CodexStepExecutor {
    files: FilesystemExecutor,
    launch_env: BTreeMap<SettingsScope, LaunchEnvStore>,
}

impl std::fmt::Debug for CodexStepExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexStepExecutor")
            .field("scopes", &self.launch_env.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl CodexStepExecutor {
    /// An executor that knows no launch-environment directory yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Give this executor `scope`'s launch-environment directory.
    #[must_use]
    pub fn with_scope(mut self, scope: SettingsScope, launch_env_dir: impl Into<PathBuf>) -> Self {
        self.launch_env.insert(scope, LaunchEnvStore::at(launch_env_dir));
        self
    }

    /// Supply the content a step will write.
    #[must_use]
    pub fn with_content(mut self, step_id: impl Into<String>, content: impl Into<String>) -> Self {
        self.files = self.files.with_content(step_id, content);
        self
    }

    /// The launch-environment variables this integration injects at `scope`.
    pub fn injected_environment(&self, scope: SettingsScope) -> BTreeMap<String, String> {
        self.launch_env.get(&scope).map(LaunchEnvStore::all).unwrap_or_default()
    }

    fn store(&self, scope: SettingsScope) -> Result<&LaunchEnvStore, ExecutionError> {
        self.launch_env.get(&scope).ok_or_else(|| ExecutionError::Io {
            artifact: format!("the {scope}-scoped launch environment"),
            detail: format!("this executor holds no launch-environment directory for the {scope} scope"),
        })
    }

    /// Assignments an action describes, with the scope they belong to, or
    /// `None` when it is not an action this executor owns.
    fn assignments(action: &StepAction) -> Option<(SettingsScope, Vec<(String, String)>)> {
        match action {
            StepAction::InjectLaunchEnvironment { scope, variable, value } => {
                let rendered = match value {
                    EnvValue::Literal(v) => v.clone(),
                    EnvValue::ArtifactPath(p) => p.display().to_string(),
                    // `EnvValue` is non-exhaustive. A value shape this build
                    // cannot render is refused by falling through to the
                    // filesystem executor, which reports `Unsupported` — a
                    // guess would put the wrong bytes in the child's
                    // environment and record them in a receipt as correct.
                    _ => return None,
                };
                Some((*scope, vec![(variable.clone(), rendered)]))
            }
            StepAction::ConfigureProxy { scope, variables } => {
                Some((*scope, variables.iter().map(|(k, v)| (k.clone(), v.clone())).collect()))
            }
            _ => None,
        }
    }

    fn apply_assignments(
        &self,
        scope: SettingsScope,
        pairs: &[(String, String)],
        kind: &'static str,
    ) -> Result<StepOutcome, ExecutionError> {
        let store = self.store(scope)?;
        let mut mutated = false;
        for (name, value) in pairs {
            mutated |= store.set(name, value).map_err(|e| ExecutionError::Io {
                artifact: format!("{} ({kind})", store.root().join(name).display()),
                detail: e.to_string(),
            })?;
        }
        Ok(StepOutcome {
            fingerprint: Some(raw_fingerprint(&env_projection(pairs))),
            document_fingerprint: None,
            prior_state: None,
            mutated,
        })
    }

    fn observe_assignments(&self, scope: SettingsScope, pairs: &[(String, String)]) -> ArtifactObservation {
        let store = match self.store(scope) {
            Ok(store) => store,
            Err(e) => return ArtifactObservation::Unreadable { reason: e.to_string() },
        };
        let mut current = Vec::with_capacity(pairs.len());
        for (name, _) in pairs {
            match store.get(name) {
                Some(value) => current.push((name.clone(), value)),
                None => return ArtifactObservation::Missing,
            }
        }
        ArtifactObservation::Present {
            managed_fingerprint: raw_fingerprint(&env_projection(&current)),
            document_fingerprint: None,
        }
    }
}

impl StepExecutor for CodexStepExecutor {
    fn apply(&mut self, step: &IntegrationStep) -> Result<StepOutcome, ExecutionError> {
        match Self::assignments(&step.action) {
            Some((scope, pairs)) => self.apply_assignments(scope, &pairs, step.action.kind()),
            None => self.files.apply(step),
        }
    }

    fn reverse(&mut self, step: &StepReceipt) -> Result<(), ExecutionError> {
        match Self::assignments(&step.action) {
            Some((scope, pairs)) => {
                let store = self.store(scope)?;
                for (name, _) in &pairs {
                    store.unset(name).map_err(|e| ExecutionError::Io {
                        artifact: store.root().join(name).display().to_string(),
                        detail: e.to_string(),
                    })?;
                }
                Ok(())
            }
            None => self.files.reverse(step),
        }
    }

    fn observe(&self, step: &StepReceipt) -> ArtifactObservation {
        match Self::assignments(&step.action) {
            Some((scope, pairs)) => self.observe_assignments(scope, &pairs),
            None => self.files.observe(step),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_devtool_contract::sha256_hex;

    fn ca_env_step(pem: &std::path::Path) -> IntegrationStep {
        IntegrationStep::new(
            "codex-ca-certificate",
            StepAction::InjectLaunchEnvironment {
                scope: SettingsScope::User,
                variable: "CODEX_CA_CERTIFICATE".to_string(),
                value: EnvValue::ArtifactPath(pem.to_path_buf()),
            },
            "make Codex trust the Agent Assembly proxy CA",
        )
    }

    fn proxy_step() -> IntegrationStep {
        let mut variables = BTreeMap::new();
        variables.insert("HTTPS_PROXY".to_string(), "http://127.0.0.1:8899".to_string());
        variables.insert("HTTP_PROXY".to_string(), "http://127.0.0.1:8899".to_string());
        IntegrationStep::new(
            "proxy-env",
            StepAction::ConfigureProxy {
                scope: SettingsScope::User,
                variables,
            },
            "route Codex's traffic through the Agent Assembly proxy",
        )
    }

    fn receipt_for(step: &IntegrationStep, fingerprint: String) -> StepReceipt {
        StepReceipt::applied(step, Some(fingerprint))
    }

    #[test]
    fn injecting_the_ca_variable_writes_it_to_the_store_and_observe_matches() {
        let dir = tempfile::tempdir().unwrap();
        let pem = dir.path().join("ca.pem");
        std::fs::write(&pem, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let mut executor = CodexStepExecutor::new().with_scope(SettingsScope::User, dir.path().join("launch-env"));

        let step = ca_env_step(&pem);
        let outcome = executor.apply(&step).unwrap();
        assert!(outcome.mutated);
        let fp = outcome.fingerprint.clone().unwrap();

        let receipt = receipt_for(&step, fp.clone());
        match executor.observe(&receipt) {
            ArtifactObservation::Present {
                managed_fingerprint, ..
            } => assert_eq!(managed_fingerprint, fp),
            other => panic!("expected Present, got {other:?}"),
        }

        executor.reverse(&receipt).unwrap();
        assert!(matches!(executor.observe(&receipt), ArtifactObservation::Missing));
    }

    #[test]
    fn configuring_the_proxy_sets_both_variables() {
        let dir = tempfile::tempdir().unwrap();
        let mut executor = CodexStepExecutor::new().with_scope(SettingsScope::User, dir.path().join("launch-env"));
        let step = proxy_step();
        executor.apply(&step).unwrap();
        let env = executor.injected_environment(SettingsScope::User);
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:8899")
        );
        assert_eq!(env.get("HTTP_PROXY").map(String::as_str), Some("http://127.0.0.1:8899"));
    }

    #[test]
    fn a_step_for_a_scope_this_executor_holds_no_store_for_is_refused() {
        let mut executor = CodexStepExecutor::new();
        let pem = PathBuf::from("/tmp/does-not-matter.pem");
        let result = executor.apply(&ca_env_step(&pem));
        assert!(matches!(result, Err(ExecutionError::Io { .. })));
    }

    #[test]
    fn managed_settings_and_trust_material_delegate_to_the_filesystem_executor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let content = r#"{"sandbox_mode":"suggest"}"#.to_string();
        let step = IntegrationStep::new(
            "managed-settings",
            StepAction::WriteManagedSettings {
                scope: SettingsScope::User,
                path: path.clone(),
                managed_keys: vec!["sandbox_mode".to_string()],
                content_sha256: sha256_hex(&content),
                merge: aa_devtool_contract::SettingsMerge::MergeManagedKeys,
            },
            "write Codex's managed settings",
        );
        let mut executor = CodexStepExecutor::new().with_content("managed-settings", content);
        let outcome = executor.apply(&step).unwrap();
        assert!(outcome.mutated);
        assert!(path.is_file());
    }
}
