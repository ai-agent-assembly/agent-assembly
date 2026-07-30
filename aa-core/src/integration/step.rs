//! The unit of work an [`IntegrationPlan`](super::IntegrationPlan) is made of.
//!
//! # Who executes these
//!
//! Nobody, here. ADR 0030 Decision 2 splits plan *authoring* (row 2, the
//! adapter) from plan *execution* (row 3, the service): a step is a **described**
//! mutation, not a performed one. Execution, receipt durability and rollback are
//! AAASM-5278's scope; this module only has to make every mutation the product
//! needs describable, reversible and reviewable before it happens.
//!
//! # Why trust material and launch environment are first-class step kinds
//!
//! The AAASM-5276 spike measured, against Claude Code 2.1.220, that
//! `NODE_EXTRA_CA_CERTS` pointing at the AASM proxy CA is what makes MitM
//! interception work at all — and that the product injects only `HTTPS_PROXY`
//! today. Without
//! [`MaterialiseTrustMaterial`](StepAction::MaterialiseTrustMaterial) and
//! [`InjectLaunchEnvironment`](StepAction::InjectLaunchEnvironment) the
//! highest-value fix available to the product would be unrepresentable in a plan,
//! unrecorded in a receipt, and therefore unremovable.
//!
//! # Why [`SettingsScope`] is explicit and mandatory
//!
//! Also measured in AAASM-5276: `aa-devtool-claude-code/src/apply.rs` silently
//! prefers `<cwd>/.claude/settings.json` whenever a `.claude/` directory happens
//! to exist in the caller's working directory. Which file gets written therefore
//! depends on where the process was started from. Every settings-touching step
//! names its scope, plans validate that every step agrees with the plan's scope,
//! and the receipt records it — so the destination is a decision, never a
//! side effect of `cwd`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::capability::IntegrationCapability;

/// Which configuration surface a settings-touching step writes to.
///
/// There is no "whichever one happens to exist" variant, deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SettingsScope {
    /// The user's own configuration, typically under the home directory.
    /// Applies to every project the user opens.
    User,
    /// Configuration checked in next to a project, applying only inside it.
    Project,
    /// An administrator-managed surface the tool treats as authoritative over
    /// the other two.
    Managed,
}

impl fmt::Display for SettingsScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::User => "user",
            Self::Project => "project",
            Self::Managed => "managed",
        };
        f.write_str(s)
    }
}

/// How a managed settings write combines with what is already in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SettingsMerge {
    /// Replace the file's entire contents. Only safe for files AASM owns
    /// outright.
    Replace,
    /// Merge only the keys the step claims, leaving everything else untouched.
    /// Required for any file the user also edits — drift detection is defined
    /// over AASM-owned keys, so a step that clobbers unowned keys makes drift
    /// undecidable.
    MergeManagedKeys,
}

/// What kind of trust material a step puts on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum TrustMaterialKind {
    /// The AASM proxy CA certificate, PEM-encoded, written where the tool can be
    /// pointed at it (e.g. via `NODE_EXTRA_CA_CERTS`). A user-scoped file, not a
    /// host change.
    ProxyCaCertificatePem,
    /// The same CA installed into the OS or user trust store. A **privileged
    /// host change** — always an individually consented step with a matching
    /// removal step (ADR 0030 §6.6).
    ProxyCaTrustStoreAnchor,
}

/// The value an injected environment variable takes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum EnvValue {
    /// A literal string.
    Literal(String),
    /// The path of an artifact an earlier step in the same plan materialises —
    /// how `NODE_EXTRA_CA_CERTS` is wired to the CA PEM without either step
    /// having to know the other's implementation.
    ArtifactPath(PathBuf),
}

impl fmt::Display for EnvValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(v) => f.write_str(v),
            Self::ArtifactPath(p) => write!(f, "{}", p.display()),
        }
    }
}

/// What a protection test should exercise.
///
/// The adapter supplies the descriptor; it does **not** judge the result (ADR
/// 0030 matrix row 9). `mechanism` is what makes the resulting
/// [`ProtectionEvidence`](super::ProtectionEvidence) attributable — an outcome
/// that cannot be attributed to an intercepting mechanism cannot raise the
/// ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProbeDescriptor {
    /// Stable identifier for this probe.
    pub id: String,
    /// The mechanism the probe traffic is meant to exercise.
    pub mechanism: IntegrationCapability,
    /// What the probe does, for the dry-run rendering.
    pub description: String,
}

/// Lifecycle operation on an artifact AASM owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ArtifactOperation {
    /// Create an artifact that did not exist.
    Create,
    /// Rewrite an artifact AASM already owns.
    Update,
    /// Delete an artifact AASM owns.
    Remove,
}

/// The concrete mutation a step describes.
///
/// `#[non_exhaustive]` because new tools bring new mechanisms; adding a variant
/// must not break an out-of-tree adapter that matches on this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum StepAction {
    /// Write or merge a managed settings block into the tool's native config.
    WriteManagedSettings {
        /// Which configuration surface to write.
        scope: SettingsScope,
        /// The exact file to write. Named, never inferred from `cwd`.
        path: PathBuf,
        /// The keys AASM claims ownership of — the only keys drift is defined
        /// over.
        managed_keys: Vec<String>,
        /// SHA-256 of the rendered content, hex-encoded, for the receipt's
        /// fingerprint.
        content_sha256: String,
        /// How to combine with existing content.
        merge: SettingsMerge,
    },
    /// Apply managed settings through a pre-lifecycle
    /// [`DevToolAdapter`](crate::DevToolAdapter).
    ///
    /// Produced only by
    /// [`LegacyAdapterShim`](super::LegacyAdapterShim): the legacy trait renders
    /// and writes in two calls and never discloses the destination path, so the
    /// honest description of that mutation cannot name a file. Migrated adapters
    /// use [`WriteManagedSettings`](Self::WriteManagedSettings).
    ApplyLegacyManagedSettings {
        /// The scope the caller requested. The legacy adapter may not honour it
        /// — that is precisely why this variant is distinguishable.
        scope: SettingsScope,
        /// SHA-256 of the rendered content, hex-encoded.
        content_sha256: String,
    },
    /// Install a hook into the tool's hook surface.
    InstallHook {
        /// Hook name as the tool knows it.
        name: String,
        /// Which configuration surface carries the hook.
        scope: SettingsScope,
        /// The hook script or configuration file.
        path: PathBuf,
    },
    /// Remove a hook AASM installed.
    RemoveHook {
        /// Hook name as the tool knows it.
        name: String,
        /// Which configuration surface carries the hook.
        scope: SettingsScope,
        /// The hook script or configuration file.
        path: PathBuf,
    },
    /// Point the tool at a model base URL.
    ///
    /// **Routing, not protection.** On its own this changes where traffic goes
    /// and nothing else; a plan whose only model-path step is this one cannot
    /// reach [`GatewayProtected`](super::ProtectionLevel::GatewayProtected).
    ConfigureModelGatewayBaseUrl {
        /// Which configuration surface carries the setting.
        scope: SettingsScope,
        /// The environment variable or settings key that holds the URL.
        variable: String,
        /// The URL to route to.
        base_url: String,
    },
    /// Set proxy variables (or the equivalent launcher wiring) so the tool's
    /// traffic traverses the AASM proxy.
    ConfigureProxy {
        /// Which configuration surface carries the variables.
        scope: SettingsScope,
        /// Variable name to value.
        variables: BTreeMap<String, String>,
    },
    /// Put trust material on disk so the tool will accept the intercepting
    /// proxy's certificates.
    MaterialiseTrustMaterial {
        /// What kind of material.
        kind: TrustMaterialKind,
        /// Where it goes.
        path: PathBuf,
        /// SHA-256 of the material, hex-encoded.
        content_sha256: String,
    },
    /// Inject an environment variable into the tool's launch environment.
    ///
    /// The lever `NODE_EXTRA_CA_CERTS` needs: a proxy address alone does not
    /// make an Electron/Node tool trust the proxy's CA.
    InjectLaunchEnvironment {
        /// Which configuration surface carries the injection.
        scope: SettingsScope,
        /// Variable name.
        variable: String,
        /// Variable value.
        value: EnvValue,
    },
    /// Apply an MCP allow/deny list to the tool's MCP configuration.
    ConfigureMcpServers {
        /// Servers explicitly permitted.
        allowed: Vec<String>,
        /// Servers explicitly denied. Denied wins on conflict, matching the
        /// policy engine's evaluation order.
        denied: Vec<String>,
    },
    /// Register an IDE extension or client with the integration.
    RegisterIdeClient {
        /// The IDE host (e.g. `vscode`, `jetbrains`).
        host: String,
        /// The extension or client identifier.
        client_id: String,
    },
    /// Connect the tool to the local runtime.
    ConnectLocalRuntime {
        /// Explicit socket path, when the plan pins one rather than relying on
        /// the documented convention.
        socket_path: Option<PathBuf>,
    },
    /// Run a protection test and let the core adjudicate the result.
    RunProtectionTest {
        /// What to exercise.
        probe: ProbeDescriptor,
    },
    /// Create, update or remove an artifact AASM owns.
    ManageArtifact {
        /// Which operation.
        operation: ArtifactOperation,
        /// The artifact.
        path: PathBuf,
    },
}

impl StepAction {
    /// The settings scope this action writes to, when it writes settings at all.
    ///
    /// Used by [`IntegrationPlan::validate`](super::IntegrationPlan::validate)
    /// to reject a plan whose steps disagree with the scope the request named.
    pub fn settings_scope(&self) -> Option<SettingsScope> {
        match self {
            Self::WriteManagedSettings { scope, .. }
            | Self::ApplyLegacyManagedSettings { scope, .. }
            | Self::InstallHook { scope, .. }
            | Self::RemoveHook { scope, .. }
            | Self::ConfigureModelGatewayBaseUrl { scope, .. }
            | Self::ConfigureProxy { scope, .. }
            | Self::InjectLaunchEnvironment { scope, .. } => Some(*scope),
            Self::MaterialiseTrustMaterial { .. }
            | Self::ConfigureMcpServers { .. }
            | Self::RegisterIdeClient { .. }
            | Self::ConnectLocalRuntime { .. }
            | Self::RunProtectionTest { .. }
            | Self::ManageArtifact { .. } => None,
        }
    }

    /// The filesystem artifacts this action touches, for the plan's
    /// affected-artifact list and the removal plan's coverage check.
    pub fn affected_paths(&self) -> Vec<PathBuf> {
        match self {
            Self::WriteManagedSettings { path, .. }
            | Self::InstallHook { path, .. }
            | Self::RemoveHook { path, .. }
            | Self::MaterialiseTrustMaterial { path, .. }
            | Self::ManageArtifact { path, .. } => vec![path.clone()],
            Self::InjectLaunchEnvironment {
                value: EnvValue::ArtifactPath(path),
                ..
            } => vec![path.clone()],
            _ => Vec::new(),
        }
    }

    /// Whether this action is a protection test — the only action whose result
    /// can produce exercised evidence.
    pub fn is_protection_test(&self) -> bool {
        matches!(self, Self::RunProtectionTest { .. })
    }

    /// Short, stable identifier for the action kind, used in dry-run rendering
    /// so the output does not change shape when a variant gains a field.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::WriteManagedSettings { .. } => "write-managed-settings",
            Self::ApplyLegacyManagedSettings { .. } => "apply-legacy-managed-settings",
            Self::InstallHook { .. } => "install-hook",
            Self::RemoveHook { .. } => "remove-hook",
            Self::ConfigureModelGatewayBaseUrl { .. } => "configure-model-base-url",
            Self::ConfigureProxy { .. } => "configure-proxy",
            Self::MaterialiseTrustMaterial { .. } => "materialise-trust-material",
            Self::InjectLaunchEnvironment { .. } => "inject-launch-environment",
            Self::ConfigureMcpServers { .. } => "configure-mcp-servers",
            Self::RegisterIdeClient { .. } => "register-ide-client",
            Self::ConnectLocalRuntime { .. } => "connect-local-runtime",
            Self::RunProtectionTest { .. } => "run-protection-test",
            Self::ManageArtifact { .. } => "manage-artifact",
        }
    }
}

/// Whether a step must succeed for the integration to be considered applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum StepRequirement {
    /// The integration is not applied unless this step verifies. Only required
    /// steps count towards
    /// [`Integrated`](super::ProtectionLevel::Integrated).
    Required,
    /// A best-effort improvement; its absence lowers the achieved level but does
    /// not make the integration partial.
    Optional,
}

/// Whether a step changes host state outside the developer's own tool
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum StepPrivilege {
    /// Touches only files the developer already owns.
    User,
    /// Changes host state — trust store, kernel probes, launch agents. Must be
    /// individually consented and individually reversible; never bundled into
    /// "install" and never implied by choosing a profile (ADR 0030 §6.6).
    PrivilegedHost {
        /// The exact sentence shown to the user before this step runs.
        consent_prompt: String,
    },
}

/// One reviewable, reversible unit of an integration plan.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IntegrationStep {
    /// Stable identifier, unique within its plan. Receipts key on it.
    pub id: String,
    /// The mutation this step describes.
    pub action: StepAction,
    /// Whether the integration depends on it.
    pub requirement: StepRequirement,
    /// Whether it changes host state.
    pub privilege: StepPrivilege,
    /// The action that undoes it. `None` means the step has no automated
    /// reversal — allowed for steps that mutate nothing (a protection test) but
    /// rejected by [`IntegrationPlan::validate`](super::IntegrationPlan::validate)
    /// for privileged ones.
    pub reversal: Option<StepAction>,
    /// One line describing the step to a human reviewing the dry run.
    pub summary: String,
}

impl IntegrationStep {
    /// A required, user-scoped step with no reversal.
    pub fn new(id: impl Into<String>, action: StepAction, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            action,
            requirement: StepRequirement::Required,
            privilege: StepPrivilege::User,
            reversal: None,
            summary: summary.into(),
        }
    }

    /// Mark the step optional.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.requirement = StepRequirement::Optional;
        self
    }

    /// Attach the action that undoes this step.
    #[must_use]
    pub fn with_reversal(mut self, reversal: StepAction) -> Self {
        self.reversal = Some(reversal);
        self
    }

    /// Mark the step as changing host state, with the sentence the user must
    /// agree to.
    #[must_use]
    pub fn privileged(mut self, consent_prompt: impl Into<String>) -> Self {
        self.privilege = StepPrivilege::PrivilegedHost {
            consent_prompt: consent_prompt.into(),
        };
        self
    }

    /// Whether the integration depends on this step.
    pub fn is_required(&self) -> bool {
        self.requirement == StepRequirement::Required
    }

    /// Whether this step changes host state.
    pub fn is_privileged(&self) -> bool {
        matches!(self.privilege, StepPrivilege::PrivilegedHost { .. })
    }

    /// Render one dry-run line. Stable shape: flags, id, kind, summary.
    pub fn render_dry_run(&self) -> String {
        let mut flags = vec![if self.is_required() { "required" } else { "optional" }];
        if self.is_privileged() {
            flags.push("privileged-host");
        }
        if self.reversal.is_none() {
            flags.push("no-automated-reversal");
        }
        format!(
            "[{}] {} ({}): {}",
            flags.join(","),
            self.id,
            self.action.kind(),
            self.summary
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca_step() -> IntegrationStep {
        IntegrationStep::new(
            "materialise-ca",
            StepAction::MaterialiseTrustMaterial {
                kind: TrustMaterialKind::ProxyCaCertificatePem,
                path: PathBuf::from("/home/dev/.aa/ca/aasm-ca.pem"),
                content_sha256: "abc123".to_string(),
            },
            "write the AASM proxy CA where the tool can read it",
        )
        .with_reversal(StepAction::ManageArtifact {
            operation: ArtifactOperation::Remove,
            path: PathBuf::from("/home/dev/.aa/ca/aasm-ca.pem"),
        })
    }

    #[test]
    fn trust_material_and_launch_env_are_expressible_and_linked() {
        // The AAASM-5276 fix in plan form: materialise the CA, then point
        // NODE_EXTRA_CA_CERTS at the artifact the previous step wrote.
        let ca = ca_step();
        let env = IntegrationStep::new(
            "inject-node-ca",
            StepAction::InjectLaunchEnvironment {
                scope: SettingsScope::User,
                variable: "NODE_EXTRA_CA_CERTS".to_string(),
                value: EnvValue::ArtifactPath(PathBuf::from("/home/dev/.aa/ca/aasm-ca.pem")),
            },
            "make the tool's Node runtime trust the AASM proxy CA",
        );

        assert_eq!(ca.action.affected_paths(), env.action.affected_paths());
        assert_eq!(env.action.settings_scope(), Some(SettingsScope::User));
    }

    #[test]
    fn every_settings_touching_action_names_its_scope() {
        let write = StepAction::WriteManagedSettings {
            scope: SettingsScope::Project,
            path: PathBuf::from("/repo/.claude/settings.json"),
            managed_keys: vec!["permissions".to_string()],
            content_sha256: "deadbeef".to_string(),
            merge: SettingsMerge::MergeManagedKeys,
        };
        assert_eq!(write.settings_scope(), Some(SettingsScope::Project));

        // Actions that touch no settings surface say so rather than defaulting.
        assert_eq!(
            StepAction::ConfigureMcpServers {
                allowed: vec![],
                denied: vec![]
            }
            .settings_scope(),
            None
        );
    }

    #[test]
    fn dry_run_lines_carry_the_flags_a_reviewer_needs() {
        let privileged = IntegrationStep::new(
            "trust-store",
            StepAction::MaterialiseTrustMaterial {
                kind: TrustMaterialKind::ProxyCaTrustStoreAnchor,
                path: PathBuf::from("/Library/Keychains/System.keychain"),
                content_sha256: "abc123".to_string(),
            },
            "install the AASM proxy CA into the system trust store",
        )
        .privileged("Agent Assembly will add its certificate authority to your system trust store.")
        .with_reversal(StepAction::ManageArtifact {
            operation: ArtifactOperation::Remove,
            path: PathBuf::from("/Library/Keychains/System.keychain"),
        });

        let line = privileged.render_dry_run();
        assert!(line.starts_with("[required,privileged-host]"), "{line}");
        assert!(line.contains("materialise-trust-material"), "{line}");

        let probe = IntegrationStep::new(
            "probe",
            StepAction::RunProtectionTest {
                probe: ProbeDescriptor {
                    id: "synthetic-secret".to_string(),
                    mechanism: IntegrationCapability::ModelPathInterception,
                    description: "send a synthetic secret down the model path".to_string(),
                },
            },
            "verify the model path is actually intercepted",
        )
        .optional();
        assert!(
            probe.render_dry_run().starts_with("[optional,no-automated-reversal]"),
            "{}",
            probe.render_dry_run()
        );
        assert!(probe.action.is_protection_test());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn steps_round_trip_through_json() {
        let step = ca_step();
        let json = serde_json::to_string(&step).unwrap();
        let restored: IntegrationStep = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, step);
    }
}
