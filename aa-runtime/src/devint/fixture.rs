//! A configurable [`DevToolIntegration`] for driving the DI-API end to end.
//!
//! # Why this is shipped rather than duplicated per test crate
//!
//! The DI-API's value is that one boundary serves every client, so the tests
//! that matter run a *real* [`DevIntServer`](super::server::DevIntServer) over
//! a real socket against a real [`EngineLifecycle`](super::service::EngineLifecycle)
//! — and that needs an adapter. `aa-cli` needs the same adapter to prove its
//! commands against the same boundary. A second copy in the CLI's test tree
//! would drift from this one, and the first thing to drift would be exactly the
//! properties the tests exist to pin: which evidence a verification produces,
//! and whether a plan writes anything.
//!
//! It is behind the `test-fixtures` feature so it never reaches a release
//! binary, and it is deliberately *configurable rather than clever*: a test says
//! which outcome it wants, and the fixture produces it honestly through the same
//! types a real adapter uses.
//!
//! # The poison
//!
//! [`FixtureIntegration::poisoned`] renders a settings body containing
//! [`LEAK_SENTINEL`]. Nothing in the DI-API's response types has a field that
//! body could land in, so a test that finds the sentinel in CLI output has found
//! a real leak rather than a formatting quirk.

use std::path::{Path, PathBuf};

use async_trait::async_trait;

use aa_core::dev_tool::{AdapterError, DevToolInfo, DevToolKind, GovernanceLevel};
use aa_core::integration::{
    now_unix_secs, sha256_hex, CapabilitySupport, DevToolCapabilities, DevToolIntegration, EvidenceKind,
    ExerciseOutcome, IntegrationCapability, IntegrationPlan, IntegrationReceipt, IntegrationRequest, IntegrationStatus,
    IntegrationStep, LifecyclePhase, NextLevel, ProtectionEvidence, ProtectionLevel, RemovalPlan, SettingsMerge,
    StateDerivation, StepAction, ToolVersion, VerificationOutcome, VerificationResult, VersionSupport,
    DEFAULT_FRESHNESS_WINDOW_SECS,
};

/// A string that must never appear in anything the DI-API or the CLI emits.
pub const LEAK_SENTINEL: &str = "sk-live-FIXTURE-MUST-NOT-LEAK";

/// What the fixture's protection test establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureVerification {
    /// Probe traffic was produced and the core redacted it — the only shape
    /// that can justify [`ProtectionLevel::GatewayProtected`].
    Exercised,
    /// Configuration was read back and matched, and nothing was exercised.
    /// The settings exist; no traffic was shown to be governed.
    ReadBackOnly,
    /// The adapter has no verification mechanism at all.
    Unverifiable,
    /// The adversarial case: the adapter reports `Passed` while having
    /// exercised nothing — a configuration check wearing a measurement's
    /// clothes. Exists so a client's "did the protected path actually run?"
    /// guard has something that can defeat it if the guard is removed.
    VacuousPass,
    /// The probe ran and reached the provider unprotected.
    Leaked,
}

/// A `DevToolIntegration` whose every observable behaviour a test chooses.
pub struct FixtureIntegration {
    tool: DevToolKind,
    settings_path: PathBuf,
    rendered: String,
    managed_keys: Vec<String>,
    detected_version: Option<ToolVersion>,
    verification: FixtureVerification,
    privileged: bool,
}

impl FixtureIntegration {
    /// A detected tool whose plan writes `settings_path`, and whose protection
    /// test exercises the path.
    pub fn new(tool: DevToolKind, settings_path: impl Into<PathBuf>) -> Self {
        Self {
            tool,
            settings_path: settings_path.into(),
            rendered: r#"{"aasmManaged":true,"aasmProfile":"recommended"}"#.to_string(),
            managed_keys: vec!["aasmManaged".to_string(), "aasmProfile".to_string()],
            detected_version: Some(ToolVersion::new(2, 1, 220)),
            verification: FixtureVerification::Exercised,
            privileged: false,
        }
    }

    /// Render a settings body carrying [`LEAK_SENTINEL`] in a managed value.
    #[must_use]
    pub fn poisoned(mut self) -> Self {
        self.rendered = format!(r#"{{"aasmManaged":true,"aasmToken":"{LEAK_SENTINEL}"}}"#);
        self.managed_keys = vec!["aasmManaged".to_string(), "aasmToken".to_string()];
        self
    }

    /// Choose what the protection test establishes.
    #[must_use]
    pub fn verifying(mut self, verification: FixtureVerification) -> Self {
        self.verification = verification;
        self
    }

    /// Report the tool as absent from this host.
    #[must_use]
    pub fn undetected(mut self) -> Self {
        self.detected_version = None;
        self
    }

    /// Report a version outside the adapter's supported range.
    #[must_use]
    pub fn at_version(mut self, version: ToolVersion) -> Self {
        self.detected_version = Some(version);
        self
    }

    /// Author a plan whose step changes host state, so consent is required.
    #[must_use]
    pub fn requiring_privilege(mut self) -> Self {
        self.privileged = true;
        self
    }

    /// The bytes this fixture's settings step writes.
    ///
    /// The lifecycle service asks the content source for these at apply time;
    /// a test wiring a [`super::service::RegisteredIntegration`] hands the same
    /// value to [`FixtureContent`].
    pub fn rendered(&self) -> &str {
        &self.rendered
    }

    /// Where the settings step writes.
    pub fn settings_path(&self) -> &Path {
        &self.settings_path
    }

    fn step(&self) -> IntegrationStep {
        let action = StepAction::WriteManagedSettings {
            scope: aa_core::integration::SettingsScope::User,
            path: self.settings_path.clone(),
            managed_keys: self.managed_keys.clone(),
            content_sha256: sha256_hex(&self.rendered),
            merge: SettingsMerge::MergeManagedKeys,
        };
        let step = IntegrationStep::new("settings", action, "write the managed settings block");
        if self.privileged {
            // `IntegrationPlan::validate` requires a privileged step to carry
            // its own reversal — a host change nobody can undo is not a step a
            // user can meaningfully consent to.
            step.privileged("Agent Assembly will change host state")
                .with_reversal(StepAction::ManageArtifact {
                    operation: aa_core::integration::ArtifactOperation::Remove,
                    path: self.settings_path.clone(),
                })
        } else {
            step
        }
    }

    fn evidence(&self, now: u64) -> Vec<ProtectionEvidence> {
        let kind = match self.verification {
            FixtureVerification::Exercised => EvidenceKind::Exercised {
                outcome: ExerciseOutcome::Redacted,
            },
            FixtureVerification::ReadBackOnly | FixtureVerification::VacuousPass => {
                EvidenceKind::ReadBack { matches_receipt: true }
            }
            FixtureVerification::Leaked => EvidenceKind::Exercised {
                outcome: ExerciseOutcome::Leaked,
            },
            FixtureVerification::Unverifiable => EvidenceKind::Absent {
                reason: "this adapter has no protection test".to_string(),
            },
        };
        vec![ProtectionEvidence {
            mechanism: IntegrationCapability::ManagedSettings,
            kind,
            observed_at_unix_secs: now,
            detail: match self.verification {
                FixtureVerification::Exercised => "the synthetic secret was redacted before egress".to_string(),
                FixtureVerification::ReadBackOnly | FixtureVerification::VacuousPass => {
                    "the managed keys read back equal to the receipt".to_string()
                }
                FixtureVerification::Leaked => "the synthetic secret reached the provider unprotected".to_string(),
                FixtureVerification::Unverifiable => "no protection test is available for this tool".to_string(),
            },
        }]
    }
}

#[async_trait]
impl DevToolIntegration for FixtureIntegration {
    fn capabilities(&self) -> DevToolCapabilities {
        DevToolCapabilities::new()
            .supported(IntegrationCapability::Discovery)
            .supported(IntegrationCapability::ManagedSettings)
            .declare(
                IntegrationCapability::HostEnforcement,
                CapabilitySupport::Unsupported {
                    reason: "host enforcement is not available on this platform".into(),
                },
            )
    }

    fn detect(&self) -> Option<DevToolInfo> {
        let version = self.detected_version.as_ref()?;
        Some(DevToolInfo {
            kind: self.tool.clone(),
            version: Some(version.to_string()),
            install_path: PathBuf::from("/usr/local/bin/fixture-tool"),
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: false,
            supports_managed_settings: true,
        })
    }

    fn version_support(&self) -> VersionSupport {
        VersionSupport {
            adapter_version: ToolVersion::new(0, 1, 0),
            lifecycle_schema_version: aa_core::integration::LIFECYCLE_SCHEMA_VERSION,
            supported_tool_versions: aa_core::integration::SupportedToolVersions::at_least(ToolVersion::new(2, 0, 0)),
        }
    }

    async fn plan_integration(&self, request: &IntegrationRequest) -> Result<IntegrationPlan, AdapterError> {
        Ok(IntegrationPlan::new(
            "plan-fixture-1",
            request,
            ProtectionLevel::Integrated,
            GovernanceLevel::L2Enforce,
        )
        .with_step(self.step())
        .declaring_unsupported(
            IntegrationCapability::HostEnforcement,
            "host enforcement is not available on this platform",
        ))
    }

    async fn integration_status(
        &self,
        receipt: Option<&IntegrationReceipt>,
    ) -> Result<IntegrationStatus, AdapterError> {
        let now = now_unix_secs();
        let compatibility = self
            .version_support()
            .supported_tool_versions
            .classify(self.detected_version.as_ref());
        let evidence = receipt.map(|r| r.achieved_evidence.clone()).unwrap_or_default();
        let planned_level = receipt.map(|r| r.planned_level).unwrap_or(ProtectionLevel::Integrated);

        let state = StateDerivation {
            detected: self.detected_version.is_some(),
            receipt_present: receipt.is_some(),
            required_steps: receipt.map(|r| r.required_steps()).unwrap_or(0),
            required_steps_verified: receipt.map(|r| r.verified_required_steps()).unwrap_or(0),
            mismatched_artifacts: &[],
            compatibility: &compatibility,
            schema_newer_than_core: false,
            evidence: &evidence,
            planned_level,
            now_unix_secs: now,
            freshness_window_secs: DEFAULT_FRESHNESS_WINDOW_SECS,
        }
        .derive();

        let achieved = state.achieved_level();
        Ok(IntegrationStatus {
            tool: self.tool.clone(),
            phase: if receipt.is_some() {
                LifecyclePhase::Installed
            } else {
                LifecyclePhase::DetectedNotIntegrated
            },
            state,
            evidence,
            planned_level,
            adapter_ceiling: GovernanceLevel::L2Enforce,
            compatibility,
            next_level: achieved.next_up().map(|level| NextLevel {
                level,
                blocked_because: match level {
                    ProtectionLevel::HostEnforced => "host enforcement is unavailable on this platform".to_string(),
                    _ => "no protection test has established it yet".to_string(),
                },
            }),
            observed_at_unix_secs: now,
            policy: aa_core::integration::policy_posture::PolicyPosture::Unknown {
                reason: "test fixture; no policy resolved".to_string(),
            },
        })
    }

    async fn verify_integration(&self, _receipt: &IntegrationReceipt) -> Result<VerificationResult, AdapterError> {
        let now = now_unix_secs();
        let outcome = match self.verification {
            // Both claim a pass; only the first has traffic behind it.
            FixtureVerification::Exercised | FixtureVerification::VacuousPass => VerificationOutcome::Passed,
            // Read-back alone is not a pass. The configuration is present and
            // nothing was shown to be protected, which is `PartiallyPassed`
            // with the protection test named as what is missing.
            FixtureVerification::ReadBackOnly => VerificationOutcome::PartiallyPassed {
                missing: vec!["the protected path was not exercised".to_string()],
            },
            FixtureVerification::Leaked => VerificationOutcome::Failed {
                reason: "the synthetic secret reached the provider unprotected".to_string(),
            },
            FixtureVerification::Unverifiable => VerificationOutcome::Unverifiable {
                reason: "this adapter has no protection test".to_string(),
            },
        };
        Ok(VerificationResult {
            verified_at_unix_secs: now,
            outcome,
            evidence: self.evidence(now),
        })
    }

    async fn plan_removal(&self, receipt: &IntegrationReceipt) -> Result<RemovalPlan, AdapterError> {
        Ok(RemovalPlan::new("removal-fixture-1", self.tool.clone())
            .with_step(IntegrationStep::new(
                "settings",
                StepAction::ManageArtifact {
                    operation: aa_core::integration::ArtifactOperation::Remove,
                    path: self.settings_path.clone(),
                },
                "restore the settings this integration changed",
            ))
            .warn(format!(
                "restores the {} keys recorded in receipt {}",
                receipt.steps.len(),
                receipt.receipt_id
            )))
    }
}

/// The [`super::service::StepContentSource`] that renders a
/// [`FixtureIntegration`]'s settings body.
pub struct FixtureContent {
    step_id: String,
    content: String,
}

impl FixtureContent {
    /// Render `content` for the fixture's `settings` step.
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            step_id: "settings".to_string(),
            content: content.into(),
        }
    }
}

#[async_trait]
impl super::service::StepContentSource for FixtureContent {
    async fn render(&self, _plan: &IntegrationPlan) -> Result<std::collections::BTreeMap<String, String>, String> {
        Ok([(self.step_id.clone(), self.content.clone())].into_iter().collect())
    }
}
