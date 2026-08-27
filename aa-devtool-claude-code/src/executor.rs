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
//! # The one step that is not a file write
//!
//! A [`StepAction::WriteManagedSettings`] at [`SettingsScope::Managed`] is the
//! endpoint managed-settings file: root-owned, above every other scope in
//! Claude Code's precedence order, and writable only with administrator
//! authorization. It is routed to [`ManagedSettingsInstaller`] rather than to
//! [`FilesystemExecutor`], and an executor that was given no installer
//! **refuses** it. A silent fallback to an ordinary file write would produce a
//! receipt claiming an endpoint-managed install that never happened — and, on a
//! host where the user happens to own that directory, an "enforcement" file the
//! user can delete.
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
use std::sync::Arc;

use aa_devtool_contract::{
    sha256_hex, ArtifactObservation, EnvValue, ExecutionError, FilesystemExecutor, IntegrationStep, SettingsScope,
    StepAction, StepExecutor, StepOutcome, StepReceipt,
};

use crate::launch_env::LaunchEnvStore;
use crate::managed_settings::{ManagedSettingsError, ManagedSettingsInstaller};

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
    /// The installer for the one privileged step. `None` — the default — makes
    /// a managed-scope settings write refuse rather than fall back.
    managed: Option<Arc<ManagedSettingsInstaller>>,
    /// A second copy of the rendered content, because
    /// [`FilesystemExecutor`] keeps its own privately and the privileged path
    /// does not go through it. Two maps rather than one is the cost of the
    /// managed write not being a file write.
    rendered: BTreeMap<String, String>,
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
        let (step_id, content) = (step_id.into(), content.into());
        self.rendered.insert(step_id.clone(), content.clone());
        self.files = self.files.with_content(step_id, content);
        self
    }

    /// Give this executor the ability to perform the one privileged step.
    ///
    /// Never a default: an executor built without this refuses a managed-scope
    /// settings write, which is what keeps the endpoint-managed install opt-in
    /// at the layer that performs it and not only at the layer that asks for it.
    #[must_use]
    pub fn with_managed_installer(mut self, installer: Arc<ManagedSettingsInstaller>) -> Self {
        self.managed = Some(installer);
        self
    }

    /// The installer for a managed-scope step, or the refusal.
    fn managed_installer(&self, path: &std::path::Path) -> Result<&ManagedSettingsInstaller, ExecutionError> {
        let installer = self.managed.as_deref().ok_or_else(|| ExecutionError::Io {
            artifact: path.display().to_string(),
            detail: "writing the endpoint managed-settings file needs administrator authorization, and this \
                     execution was not given the authority to request it. Re-run \
                     `aasm integrations install claude-code --install-managed-settings`"
                .to_string(),
        })?;
        if installer.target() != path {
            return Err(ExecutionError::Io {
                artifact: path.display().to_string(),
                detail: format!(
                    "this step names {} and the authorized installer writes {}",
                    path.display(),
                    installer.target().display()
                ),
            });
        }
        Ok(installer)
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

impl ClaudeCodeStepExecutor {
    /// The path a managed-scope settings step names, when a step is one.
    ///
    /// Matching on the scope rather than on the step id: the id is an adapter
    /// convention and the scope is what the plan validated.
    fn managed_settings_target(action: &StepAction) -> Option<(&std::path::Path, &str)> {
        match action {
            StepAction::WriteManagedSettings {
                scope: SettingsScope::Managed,
                path,
                content_sha256,
                ..
            } => Some((path.as_path(), content_sha256.as_str())),
            _ => None,
        }
    }

    /// Perform the one privileged step: disclose, authorize, write, read back.
    fn apply_managed_settings(
        &self,
        step: &IntegrationStep,
        path: &std::path::Path,
        content_sha256: &str,
    ) -> Result<StepOutcome, ExecutionError> {
        let installer = self.managed_installer(path)?;
        let content = self
            .rendered
            .get(&step.id)
            .ok_or_else(|| ExecutionError::ContentMissing {
                step_id: step.id.clone(),
            })?;
        // The digest the user reviewed is what gets written; a mismatch fails
        // closed rather than elevating for bytes nobody approved.
        if sha256_hex(content) != content_sha256 {
            return Err(ExecutionError::ContentMismatch {
                step_id: step.id.clone(),
            });
        }

        let disclosure = installer.disclose(content).map_err(|e| managed_failure(path, &e))?;
        let outcome = installer.install(&disclosure).map_err(|e| managed_failure(path, &e))?;
        let fingerprint = format!("{FINGERPRINT_PREFIX}{}", outcome.attestation.sha256);
        Ok(StepOutcome {
            fingerprint: Some(fingerprint.clone()),
            document_fingerprint: Some(fingerprint),
            // The prior document is preserved as a backup file rather than as an
            // inline projection: the managed document is replaced wholesale, and
            // restoring it is the installer's job, not the merge helper's.
            prior_state: None,
            mutated: outcome.mutated,
        })
    }
}

/// Turn an installer refusal into an execution error the engine can roll back
/// on, keeping the `Permission Required` / `Unavailable` wording intact.
fn managed_failure(path: &std::path::Path, error: &ManagedSettingsError) -> ExecutionError {
    ExecutionError::Io {
        artifact: format!("{} ({})", path.display(), error.summary()),
        detail: error.to_string(),
    }
}

impl StepExecutor for ClaudeCodeStepExecutor {
    fn apply(&mut self, step: &IntegrationStep) -> Result<StepOutcome, ExecutionError> {
        if let Some((path, sha)) = Self::managed_settings_target(&step.action) {
            let (path, sha) = (path.to_path_buf(), sha.to_string());
            return self.apply_managed_settings(step, &path, &sha);
        }
        match Self::assignments(&step.action) {
            Some((scope, pairs)) => self.apply_assignments(scope, &pairs, step.action.kind()),
            None => self.files.apply(step),
        }
    }

    fn reverse(&mut self, step: &StepReceipt) -> Result<(), ExecutionError> {
        if let Some((path, _)) = Self::managed_settings_target(&step.action) {
            let path = path.to_path_buf();
            return self
                .managed_installer(&path)?
                .rollback()
                .map(|_| ())
                .map_err(|e| managed_failure(&path, &e));
        }
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
        if let Some((path, _)) = Self::managed_settings_target(&step.action) {
            // Reading the managed file needs no privilege, so drift is
            // observable on a host that could not authorize a write.
            return match std::fs::read_to_string(path) {
                Ok(raw) => ArtifactObservation::Present {
                    managed_fingerprint: raw_fingerprint(&raw),
                    document_fingerprint: Some(raw_fingerprint(&raw)),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => ArtifactObservation::Missing,
                Err(e) => ArtifactObservation::Unreadable { reason: e.to_string() },
            };
        }
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

    /// A managed-scope settings step over a **temporary** root. No test names
    /// the real `/Library/Application Support/ClaudeCode` path, and the real
    /// authority refuses any target that is not it.
    fn managed_step(path: &std::path::Path, content: &str) -> IntegrationStep {
        IntegrationStep::new(
            "endpoint-managed-settings",
            StepAction::WriteManagedSettings {
                scope: SettingsScope::Managed,
                path: path.to_path_buf(),
                managed_keys: crate::managed_settings::MANAGED_ONLY_KEYS
                    .iter()
                    .map(|k| (*k).to_string())
                    .collect(),
                content_sha256: sha256_hex(content),
                merge: aa_devtool_contract::SettingsMerge::Replace,
                format: aa_devtool_contract::DocumentFormat::Json,
            },
            "install the endpoint managed-settings file",
        )
        .privileged("Agent Assembly will ask for administrator authorization for one file write.")
        .with_reversal(StepAction::ManageArtifact {
            operation: ArtifactOperation::Remove,
            path: path.to_path_buf(),
        })
    }

    fn managed_document() -> String {
        crate::managed_settings::managed_settings_document(aa_devtool_contract::ProtectionProfile::Recommended)
            .expect("document")
    }

    fn installer(
        dir: &std::path::Path,
        authority: Arc<dyn crate::managed_settings::PrivilegedFileAuthority>,
    ) -> (std::path::PathBuf, Arc<ManagedSettingsInstaller>) {
        use std::os::unix::fs::MetadataExt as _;
        let target = dir.join("ClaudeCode").join("managed-settings.json");
        let uid = std::fs::metadata(dir).expect("uid probe").uid();
        (
            target.clone(),
            Arc::new(
                ManagedSettingsInstaller::new(target, dir.join("managed-state"), authority).expecting_owner_uid(uid),
            ),
        )
    }

    #[test]
    fn a_managed_settings_step_without_an_authorized_installer_refuses() {
        // The governing rule, at the layer that performs the mutation: an
        // ordinary execution cannot write the endpoint-managed file at all.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("ClaudeCode").join("managed-settings.json");
        let doc = managed_document();
        let mut exec = ClaudeCodeStepExecutor::new()
            .with_scope(SettingsScope::User, dir.path().join("launch-env"))
            .with_content("endpoint-managed-settings", doc.clone());

        let err = exec.apply(&managed_step(&target, &doc)).expect_err("must refuse");
        assert!(
            matches!(&err, ExecutionError::Io { detail, .. } if detail.contains("administrator authorization")),
            "{err}"
        );
        assert!(!target.exists(), "a refused step must write nothing");
    }

    #[test]
    fn an_authorized_managed_settings_step_is_applied_observed_and_rolled_back() {
        use crate::managed_settings::testing::FakeAuthority;
        let dir = tempfile::tempdir().unwrap();
        let (target, installer) = installer(dir.path(), FakeAuthority::granting());
        let doc = managed_document();
        let step = managed_step(&target, &doc);

        let mut exec = ClaudeCodeStepExecutor::new()
            .with_scope(SettingsScope::User, dir.path().join("launch-env"))
            .with_content(&step.id, doc.clone())
            .with_managed_installer(installer);

        let applied = exec.apply(&step).expect("apply");
        assert!(applied.mutated);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), doc);

        let receipt = StepReceipt::applied(&step, applied.fingerprint.clone());
        assert_eq!(
            exec.observe(&receipt),
            ArtifactObservation::Present {
                managed_fingerprint: applied.fingerprint.clone().unwrap(),
                document_fingerprint: applied.fingerprint,
            }
        );

        exec.reverse(&receipt).expect("rollback");
        assert!(!target.exists(), "removal must be symmetric");
        assert_eq!(exec.observe(&receipt), ArtifactObservation::Missing);
        exec.reverse(&receipt).expect("rollback twice");
    }

    #[test]
    fn a_denied_authorization_fails_the_step_rather_than_downgrading_it() {
        use crate::managed_settings::testing::FakeAuthority;
        let dir = tempfile::tempdir().unwrap();
        let (target, installer) = installer(dir.path(), FakeAuthority::denying());
        let doc = managed_document();
        let step = managed_step(&target, &doc);
        let mut exec = ClaudeCodeStepExecutor::new()
            .with_content(&step.id, doc)
            .with_managed_installer(installer);

        let err = exec.apply(&step).expect_err("denied");
        assert!(
            matches!(&err, ExecutionError::Io { artifact, .. } if artifact.contains("Permission Required")),
            "{err}"
        );
        assert!(!target.exists());
    }

    #[test]
    fn a_read_back_mismatch_fails_the_step() {
        use crate::managed_settings::testing::FakeAuthority;
        let dir = tempfile::tempdir().unwrap();
        let (target, installer) = installer(
            dir.path(),
            FakeAuthority::corrupting(r#"{"disableBypassPermissionsMode":false}"#),
        );
        let doc = managed_document();
        let step = managed_step(&target, &doc);
        let mut exec = ClaudeCodeStepExecutor::new()
            .with_content(&step.id, doc)
            .with_managed_installer(installer);

        let err = exec.apply(&step).expect_err("read-back must fail");
        assert!(
            matches!(&err, ExecutionError::Io { artifact, .. } if artifact.contains("Read-back verification failed")),
            "{err}"
        );
    }

    #[test]
    fn content_that_does_not_match_the_reviewed_digest_never_reaches_the_authority() {
        use crate::managed_settings::testing::FakeAuthority;
        let dir = tempfile::tempdir().unwrap();
        let authority = FakeAuthority::granting();
        let (target, installer) = installer(dir.path(), authority.clone());
        let doc = managed_document();
        let step = managed_step(&target, &doc);

        let mut exec = ClaudeCodeStepExecutor::new()
            .with_content(&step.id, r#"{"disableBypassPermissionsMode":true}"#)
            .with_managed_installer(installer);

        assert!(matches!(exec.apply(&step), Err(ExecutionError::ContentMismatch { .. })));
        assert!(authority.calls().is_empty(), "{:?}", authority.calls());
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
