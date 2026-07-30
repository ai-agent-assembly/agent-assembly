//! The mutations only this tool's integration knows how to perform.
//!
//! # Why an executor lives in an adapter crate at all
//!
//! [`FilesystemExecutor`] covers every step whose mutation is "put these bytes
//! at this path" — managed settings, trust material, owned artifacts — and
//! deliberately refuses the rest with
//! [`ExecutionError::Unsupported`] rather than reporting a success nothing
//! performed. `aa-core`'s own note says why: launch-environment injection and
//! proxy variables need mechanism the filesystem cannot supply, and belong to
//! the adapter that knows its tool.
//!
//! [`ClaudeCodeStepExecutor`] is that adapter half. It delegates everything
//! `FilesystemExecutor` already does correctly and adds exactly two mechanisms:
//! [`StepAction::InjectLaunchEnvironment`] and [`StepAction::ConfigureProxy`],
//! both backed by [`LaunchEnvStore`]. Nothing else is added — a mechanism this
//! executor cannot perform still refuses.
//!
//! # Why it is scope-keyed rather than built for one scope
//!
//! Applying always has a plan, and a plan always names its scope. Observing and
//! reversing do not: the service builds an executor from a receipt, and a user
//! may have installed at project scope. Both launch-environment actions carry
//! their own scope, so the executor holds one store per scope it was given and
//! dispatches per step. A step naming a scope this executor holds no store for
//! is refused rather than written to the wrong one.

use std::collections::BTreeMap;
use std::path::PathBuf;

use aa_devtool_contract::{
    ArtifactObservation, EnvValue, ExecutionError, FilesystemExecutor, IntegrationStep, SettingsScope, StepAction,
    StepExecutor, StepOutcome, StepReceipt,
};

use crate::launch_env::LaunchEnvStore;

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

/// Executes a Claude Code integration plan.
#[derive(Default)]
pub struct ClaudeCodeStepExecutor {
    files: FilesystemExecutor,
    launch_env: BTreeMap<SettingsScope, LaunchEnvStore>,
}

impl std::fmt::Debug for ClaudeCodeStepExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaudeCodeStepExecutor")
            .field("scopes", &self.launch_env.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ClaudeCodeStepExecutor {
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

    /// Assignments an action describes, with the scope they belong to, or `None`
    /// when it is not an action this executor owns.
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

impl StepExecutor for ClaudeCodeStepExecutor {
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
    use aa_devtool_contract::ArtifactOperation;

    fn ca_env_step(pem: &std::path::Path) -> IntegrationStep {
        IntegrationStep::new(
            "node-extra-ca-certs",
            StepAction::InjectLaunchEnvironment {
                scope: SettingsScope::User,
                variable: "NODE_EXTRA_CA_CERTS".to_string(),
                value: EnvValue::ArtifactPath(pem.to_path_buf()),
            },
            "make Claude Code's Node runtime trust the Agent Assembly proxy CA",
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
            "route Claude Code's traffic through the Agent Assembly proxy",
        )
    }

    #[test]
    fn injecting_the_ca_variable_is_applied_observed_and_reversed() {
        let dir = tempfile::tempdir().unwrap();
        let pem = dir.path().join("aasm-proxy-ca.pem");
        let mut exec = ClaudeCodeStepExecutor::new().with_scope(SettingsScope::User, dir.path().join("launch-env"));
        let step = ca_env_step(&pem);

        let applied = exec.apply(&step).unwrap();
        assert!(applied.mutated);
        let fingerprint = applied.fingerprint.clone().expect("a launch-env step is fingerprinted");
        assert_eq!(
            exec.injected_environment(SettingsScope::User)
                .get("NODE_EXTRA_CA_CERTS")
                .map(String::as_str),
            Some(pem.display().to_string().as_str())
        );

        // Reapplying the same step changes nothing on the host.
        assert!(!exec.apply(&step).unwrap().mutated);

        let receipt = StepReceipt::applied(&step, Some(fingerprint.clone()));
        assert_eq!(
            exec.observe(&receipt),
            ArtifactObservation::Present {
                managed_fingerprint: fingerprint,
                document_fingerprint: None,
            }
        );

        exec.reverse(&receipt).unwrap();
        assert_eq!(exec.observe(&receipt), ArtifactObservation::Missing);
        // Reversal has to be safe to run twice.
        exec.reverse(&receipt).unwrap();
    }

    #[test]
    fn a_changed_value_is_observed_as_a_different_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let mut exec = ClaudeCodeStepExecutor::new().with_scope(SettingsScope::User, dir.path().join("launch-env"));
        let step = proxy_step();
        let applied = exec.apply(&step).unwrap();
        let receipt = StepReceipt::applied(&step, applied.fingerprint.clone());

        LaunchEnvStore::at(dir.path().join("launch-env"))
            .set("HTTPS_PROXY", "http://127.0.0.1:1")
            .unwrap();

        match exec.observe(&receipt) {
            ArtifactObservation::Present {
                managed_fingerprint, ..
            } => {
                assert_ne!(Some(managed_fingerprint), applied.fingerprint);
            }
            other => panic!("expected Present, got {other:?}"),
        }
    }

    #[test]
    fn file_steps_are_delegated_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join("owned.txt");
        let step = IntegrationStep::new(
            "artifact",
            StepAction::ManageArtifact {
                operation: ArtifactOperation::Create,
                path: artifact.clone(),
            },
            "write an owned artifact",
        );
        let mut exec = ClaudeCodeStepExecutor::new()
            .with_scope(SettingsScope::User, dir.path().join("launch-env"))
            .with_content("artifact", "hosts\n");

        assert!(exec.apply(&step).unwrap().mutated);
        assert_eq!(std::fs::read_to_string(&artifact).unwrap(), "hosts\n");
    }

    #[test]
    fn a_mechanism_this_executor_does_not_have_still_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let step = IntegrationStep::new(
            "ide",
            StepAction::RegisterIdeClient {
                host: "vscode".to_string(),
                client_id: "x".to_string(),
            },
            "register an IDE client",
        );
        let mut exec = ClaudeCodeStepExecutor::new().with_scope(SettingsScope::User, dir.path().join("launch-env"));
        assert!(matches!(
            exec.apply(&step),
            Err(ExecutionError::Unsupported {
                kind: "register-ide-client"
            })
        ));
    }
}
