//! Drift: what a receipt claims versus what the host actually holds.
//!
//! # The distinction the whole model exists for
//!
//! Repair is only safe because drift can tell **"the user changed something of
//! their own"** from **"an AASM-managed value changed"**. Without that split,
//! repair is either useless (it never writes, because it cannot tell whether a
//! difference is its business) or dangerous (it writes over whatever it finds).
//! The split is made by comparing two fingerprints per settings step, not one:
//!
//! | Managed projection | Whole document | Classification |
//! | --- | --- | --- |
//! | matches receipt | matches receipt | no drift |
//! | matches receipt | differs | [`UserManagedUnrelatedChange`](DriftKind::UserManagedUnrelatedChange) — reported, never repaired |
//! | differs | (either) | [`AasmManagedValueChanged`](DriftKind::AasmManagedValueChanged) — repairable |
//!
//! Because the fingerprints are canonical (see
//! [`fingerprint`](super::fingerprint)), a reserialisation that changed only
//! formatting is *not* drift — which is the honest consequence of the
//! semantics-exact constraint rather than a hole in it.
//!
//! # Failing closed
//!
//! Two classifications exist purely so that "we could not tell" never renders as
//! "nothing is wrong": [`ReceiptCorrupt`](DriftKind::ReceiptCorrupt) and
//! [`Unobservable`](DriftKind::Unobservable). Neither is repairable. This is ADR
//! 0015's rule — a resolution failure is observable and never silently permitted
//! — applied to the one place in the lifecycle where a silent pass would
//! authorise a write.
//!
//! Drift detection is the service's job (ADR 0030 matrix row 10): the adapter
//! supplies the fingerprint recipe, never the comparison.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::receipt::{IntegrationReceipt, StepReceipt};
use super::step::{SettingsMerge, StepAction};
use super::version::VersionCompatibility;

/// The classes of divergence between a receipt and the host.
///
/// The ticket names seven; [`Unobservable`](Self::Unobservable) is the eighth,
/// added because the honest answer to "the artifact could not be read" is
/// neither "missing" nor "fine".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum DriftKind {
    /// The document changed outside every key the receipt claims. AASM-owned
    /// state is intact; the change is the user's and stays theirs.
    UserManagedUnrelatedChange,
    /// A value AASM owns no longer matches the receipt.
    AasmManagedValueChanged,
    /// An artifact AASM created is gone.
    AasmArtifactMissing,
    /// The detected tool version left the adapter's supported range since the
    /// receipt was written.
    ToolVersionIncompatible,
    /// The tool is still pointed at an endpoint the runtime no longer serves.
    RuntimeEndpointStale,
    /// No receipt exists for a tool that appears to be integrated.
    ReceiptMissing,
    /// A receipt exists but could not be read or failed its integrity check.
    ReceiptCorrupt,
    /// An AASM-owned artifact could not be inspected, so its state is unproven.
    Unobservable,
}

impl DriftKind {
    /// Whether this class says something about **AASM-owned** state.
    ///
    /// [`UserManagedUnrelatedChange`](Self::UserManagedUnrelatedChange) is the
    /// only one that does not, which is why it is the only one that must never
    /// reach [`ProtectionState::Drifted`](super::ProtectionState::Drifted) as a
    /// mismatched artifact.
    pub fn affects_aasm_state(self) -> bool {
        !matches!(self, Self::UserManagedUnrelatedChange)
    }

    /// Whether repair can fix this class by rewriting AASM-owned state.
    ///
    /// Everything else needs a human, a reinstall, or an upgrade — repair never
    /// papers over a condition it does not understand.
    pub fn is_repairable(self) -> bool {
        matches!(self, Self::AasmManagedValueChanged | Self::AasmArtifactMissing)
    }

    /// Stable identifier for rendering and for the DI-API's wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserManagedUnrelatedChange => "user-managed-unrelated-change",
            Self::AasmManagedValueChanged => "aasm-managed-value-changed",
            Self::AasmArtifactMissing => "aasm-artifact-missing",
            Self::ToolVersionIncompatible => "tool-version-incompatible",
            Self::RuntimeEndpointStale => "runtime-endpoint-stale",
            Self::ReceiptMissing => "receipt-missing",
            Self::ReceiptCorrupt => "receipt-corrupt",
            Self::Unobservable => "unobservable",
        }
    }
}

impl core::fmt::Display for DriftKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One divergence, attributed to the step and artifact it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DriftFinding {
    /// What class of divergence this is.
    pub kind: DriftKind,
    /// The step whose receipt this contradicts, when one is identifiable.
    pub step_id: Option<String>,
    /// Stable identifier of what diverged, for the user and for
    /// [`ProtectionState::Drifted`](super::ProtectionState::Drifted).
    pub artifact: String,
    /// What to tell the user, in words they can act on.
    pub detail: String,
}

impl DriftFinding {
    /// Construct one finding.
    pub fn new(kind: DriftKind, artifact: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind,
            step_id: None,
            artifact: artifact.into(),
            detail: detail.into(),
        }
    }

    /// Attribute the finding to a step.
    #[must_use]
    pub fn for_step(mut self, step_id: impl Into<String>) -> Self {
        self.step_id = Some(step_id.into());
        self
    }
}

/// Everything one drift check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DriftReport {
    /// The findings, in the order they were produced.
    pub findings: Vec<DriftFinding>,
}

impl DriftReport {
    /// A report with nothing in it.
    pub fn clean() -> Self {
        Self::default()
    }

    /// Whether nothing at all diverged — including nothing the user changed.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Whether AASM-owned state is intact.
    ///
    /// Deliberately distinct from [`is_clean`](Self::is_clean): a user who
    /// edited their own theme has drift in the report and an intact
    /// integration, and reporting those the same way is what would make the
    /// product cry wolf.
    pub fn aasm_state_is_intact(&self) -> bool {
        !self.findings.iter().any(|f| f.kind.affects_aasm_state())
    }

    /// The artifact identifiers that belong in
    /// [`ProtectionState::Drifted`](super::ProtectionState::Drifted) —
    /// AASM-owned divergences only.
    pub fn mismatched_artifacts(&self) -> Vec<String> {
        self.findings
            .iter()
            .filter(|f| f.kind.affects_aasm_state())
            .map(|f| f.artifact.clone())
            .collect()
    }

    /// The findings repair is allowed to act on.
    pub fn repairable(&self) -> impl Iterator<Item = &DriftFinding> {
        self.findings.iter().filter(|f| f.kind.is_repairable())
    }

    /// Whether every AASM-affecting finding can be repaired.
    ///
    /// `false` when anything needs a human — a corrupt receipt, an
    /// unreadable artifact, an incompatible tool version — so a caller can
    /// refuse to start a repair it cannot finish.
    pub fn is_fully_repairable(&self) -> bool {
        self.findings
            .iter()
            .filter(|f| f.kind.affects_aasm_state())
            .all(|f| f.kind.is_repairable())
    }

    /// The step ids repair would rewrite, deduplicated in first-seen order.
    pub fn repairable_step_ids(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for id in self.repairable().filter_map(|f| f.step_id.clone()) {
            if !seen.contains(&id) {
                seen.push(id);
            }
        }
        seen
    }

    /// Whether any finding is of `kind`.
    pub fn contains(&self, kind: DriftKind) -> bool {
        self.findings.iter().any(|f| f.kind == kind)
    }

    /// Record a finding.
    pub fn push(&mut self, finding: DriftFinding) {
        self.findings.push(finding);
    }
}

/// What was actually seen on the host for one receipted step.
///
/// Produced by the service's executor, never by the client (ADR 0030 forbidden
/// design 10).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum ArtifactObservation {
    /// The artifact is there and both fingerprints were taken.
    Present {
        /// Fingerprint of the AASM-owned projection as it stands now.
        managed_fingerprint: String,
        /// Fingerprint of the whole document as it stands now. `None` for
        /// artifacts that are not documents with unmanaged content — a CA PEM
        /// AASM owns outright has nothing unmanaged in it.
        document_fingerprint: Option<String>,
    },
    /// The artifact is not there.
    Missing,
    /// The artifact could not be inspected.
    Unreadable {
        /// Why, in words a user can act on.
        reason: String,
    },
}

/// One step's observation, paired with the step it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ObservedStep {
    /// The [`StepReceipt::step_id`] this observation is of.
    pub step_id: String,
    /// Stable identifier of the artifact, for the report.
    pub artifact: String,
    /// What was seen.
    pub observation: ArtifactObservation,
}

/// The inputs a drift check is a pure function of.
///
/// Holding them in one struct is what makes the classification exhaustively
/// testable rather than logic spread across the executor's call sites — the same
/// shape, and for the same reason, as
/// [`StateDerivation`](super::StateDerivation).
#[derive(Debug, Clone)]
pub struct DriftInputs<'a> {
    /// The receipt to compare against, when one could be loaded.
    pub receipt: Option<&'a IntegrationReceipt>,
    /// Set when a receipt file exists but could not be read or failed its
    /// integrity check. Takes precedence over everything else.
    pub receipt_unreadable: Option<String>,
    /// One entry per receipted step the service looked at.
    pub observed: &'a [ObservedStep],
    /// How the tool's version now compares to the adapter's supported range.
    pub compatibility: &'a VersionCompatibility,
    /// The endpoint the runtime currently serves, when the caller knows it.
    pub current_endpoint: Option<&'a str>,
}

impl DriftInputs<'_> {
    /// Classify every divergence between the receipt and the host.
    ///
    /// Rule order is part of the contract:
    ///
    /// 1. An unreadable receipt is terminal — with no trustworthy baseline,
    ///    every further comparison would be against a guess.
    /// 2. A missing receipt is likewise terminal: there is nothing to diverge
    ///    from, and the state model already reports that case as
    ///    [`DetectedNotIntegrated`](super::ProtectionLevel::DetectedNotIntegrated).
    /// 3. Version and endpoint conditions are recorded before per-step
    ///    comparisons, because they explain step-level mismatches that would
    ///    otherwise read as user tampering.
    /// 4. Each applied step is compared; a step with no observation is
    ///    [`Unobservable`](DriftKind::Unobservable), never "fine".
    pub fn classify(&self) -> DriftReport {
        let mut report = DriftReport::clean();

        if let Some(reason) = &self.receipt_unreadable {
            report.push(DriftFinding::new(
                DriftKind::ReceiptCorrupt,
                "integration receipt",
                format!("the stored receipt could not be trusted: {reason}"),
            ));
            return report;
        }

        let Some(receipt) = self.receipt else {
            report.push(DriftFinding::new(
                DriftKind::ReceiptMissing,
                "integration receipt",
                "no receipt records what Agent Assembly applied to this tool, so nothing about it can be verified",
            ));
            return report;
        };

        if let VersionCompatibility::Incompatible {
            detected, remediation, ..
        } = self.compatibility
        {
            let detected = detected
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown".to_string());
            report.push(DriftFinding::new(
                DriftKind::ToolVersionIncompatible,
                "tool version",
                format!(
                    "the tool is now at {detected}, outside the range this integration was applied for: {remediation}"
                ),
            ));
        }

        if let (Some(receipted), Some(current)) = (receipt.receipted_endpoint(), self.current_endpoint) {
            if receipted != current {
                report.push(DriftFinding::new(
                    DriftKind::RuntimeEndpointStale,
                    "runtime endpoint",
                    format!("the tool is still pointed at {receipted}, but the runtime now serves {current}"),
                ));
            }
        }

        for step in receipt.steps.iter().filter(|s| s.applied) {
            let observed = self.observed.iter().find(|o| o.step_id == step.step_id);
            match observed {
                None => report.push(
                    DriftFinding::new(
                        DriftKind::Unobservable,
                        artifact_label(step),
                        "this step was not inspected, so whether Agent Assembly's changes are still in place is unproven",
                    )
                    .for_step(&step.step_id),
                ),
                Some(observed) => classify_step(step, observed, &mut report),
            }
        }

        report
    }
}

/// A stable, user-legible name for what a step touched.
fn artifact_label(step: &StepReceipt) -> String {
    match step.action.affected_paths().first() {
        Some(path) => path.display().to_string(),
        None => format!("{} ({})", step.step_id, step.action.kind()),
    }
}

fn classify_step(step: &StepReceipt, observed: &ObservedStep, report: &mut DriftReport) {
    match &observed.observation {
        ArtifactObservation::Unreadable { reason } => report.push(
            DriftFinding::new(
                DriftKind::Unobservable,
                observed.artifact.clone(),
                format!("Agent Assembly could not inspect this artifact: {reason}"),
            )
            .for_step(&step.step_id),
        ),
        ArtifactObservation::Missing => report.push(
            DriftFinding::new(
                DriftKind::AasmArtifactMissing,
                observed.artifact.clone(),
                "an artifact Agent Assembly created is no longer there",
            )
            .for_step(&step.step_id),
        ),
        ArtifactObservation::Present {
            managed_fingerprint,
            document_fingerprint,
        } => {
            let Some(receipted) = step.fingerprint.as_deref() else {
                // A step applied without a fingerprint has no baseline. It is
                // already not counted as verified by the state model; here it is
                // additionally unprovable rather than assumed intact.
                report.push(
                    DriftFinding::new(
                        DriftKind::Unobservable,
                        observed.artifact.clone(),
                        "this step was applied without recording a fingerprint, so it has no baseline to compare against",
                    )
                    .for_step(&step.step_id),
                );
                return;
            };

            if receipted != managed_fingerprint {
                report.push(
                    DriftFinding::new(
                        DriftKind::AasmManagedValueChanged,
                        observed.artifact.clone(),
                        "a value Agent Assembly manages no longer matches what it applied",
                    )
                    .for_step(&step.step_id),
                );
                return;
            }

            // Only a merging write leaves unmanaged content in the file for a
            // user to change. A `Replace` step owns the file outright, so a
            // whole-document difference there is not "unrelated".
            let leaves_unmanaged_content = matches!(
                &step.action,
                StepAction::WriteManagedSettings {
                    merge: SettingsMerge::MergeManagedKeys,
                    ..
                }
            );
            if !leaves_unmanaged_content {
                return;
            }

            if let (Some(receipted_doc), Some(current_doc)) =
                (step.document_fingerprint.as_deref(), document_fingerprint.as_deref())
            {
                if receipted_doc != current_doc {
                    report.push(
                        DriftFinding::new(
                            DriftKind::UserManagedUnrelatedChange,
                            observed.artifact.clone(),
                            "this file changed outside the keys Agent Assembly manages; \
                             the change is yours and repair will not touch it",
                        )
                        .for_step(&step.step_id),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev_tool::DevToolKind;
    use crate::integration::plan::ProtectionProfile;
    use crate::integration::state::ProtectionLevel;
    use crate::integration::step::{ArtifactOperation, IntegrationStep, SettingsMerge, SettingsScope, StepAction};
    use crate::integration::version::{
        core_version, ComponentVersions, SupportedToolVersions, ToolVersion, LIFECYCLE_SCHEMA_VERSION,
    };
    use std::path::PathBuf;

    const SETTINGS: &str = "/home/dev/.claude/settings.json";

    fn settings_step() -> IntegrationStep {
        IntegrationStep::new(
            "settings",
            StepAction::WriteManagedSettings {
                scope: SettingsScope::User,
                path: PathBuf::from(SETTINGS),
                managed_keys: vec!["permissions".to_string()],
                content_sha256: "abc".to_string(),
                merge: SettingsMerge::MergeManagedKeys,
            },
            "write the managed settings block",
        )
        .with_reversal(StepAction::ManageArtifact {
            operation: ArtifactOperation::Remove,
            path: PathBuf::from(SETTINGS),
        })
    }

    fn receipt() -> IntegrationReceipt {
        IntegrationReceipt {
            schema_version: LIFECYCLE_SCHEMA_VERSION,
            receipt_id: "r1".to_string(),
            plan_id: "p1".to_string(),
            tool: DevToolKind::ClaudeCode,
            profile: ProtectionProfile::Recommended,
            settings_scope: SettingsScope::User,
            applied_at_unix_secs: 1_000_000,
            versions: ComponentVersions {
                core: core_version(),
                adapter: ToolVersion::new(0, 1, 0),
                lifecycle_schema: LIFECYCLE_SCHEMA_VERSION,
            },
            tool_version: Some(ToolVersion::new(2, 1, 220)),
            steps: vec![
                StepReceipt::applied(&settings_step(), Some("sha256:managed".to_string()))
                    .with_document_fingerprint("sha256:doc"),
            ],
            planned_level: ProtectionLevel::Integrated,
            achieved_level: ProtectionLevel::Integrated,
            achieved_evidence: vec![],
            verified_at_unix_secs: Some(1_000_000),
        }
    }

    fn compatible() -> VersionCompatibility {
        VersionCompatibility::Compatible {
            detected: ToolVersion::new(2, 1, 220),
        }
    }

    fn observed(managed: &str, document: &str) -> Vec<ObservedStep> {
        vec![ObservedStep {
            step_id: "settings".to_string(),
            artifact: SETTINGS.to_string(),
            observation: ArtifactObservation::Present {
                managed_fingerprint: managed.to_string(),
                document_fingerprint: Some(document.to_string()),
            },
        }]
    }

    fn inputs<'a>(
        receipt: &'a IntegrationReceipt,
        compat: &'a VersionCompatibility,
        observed: &'a [ObservedStep],
    ) -> DriftInputs<'a> {
        DriftInputs {
            receipt: Some(receipt),
            receipt_unreadable: None,
            observed,
            compatibility: compat,
            current_endpoint: None,
        }
    }

    #[test]
    fn matching_fingerprints_are_no_drift() {
        let r = receipt();
        let compat = compatible();
        let obs = observed("sha256:managed", "sha256:doc");
        let report = inputs(&r, &compat, &obs).classify();
        assert!(report.is_clean(), "{report:?}");
        assert!(report.aasm_state_is_intact());
        assert!(report.mismatched_artifacts().is_empty());
    }

    #[test]
    fn an_unrelated_user_change_is_reported_but_never_repaired() {
        let r = receipt();
        let compat = compatible();
        // Managed projection unchanged, whole document changed: the user edited
        // something of their own.
        let obs = observed("sha256:managed", "sha256:doc-after-user-edit");
        let report = inputs(&r, &compat, &obs).classify();

        assert!(report.contains(DriftKind::UserManagedUnrelatedChange));
        assert!(
            report.aasm_state_is_intact(),
            "a user's own edit must not be reported as AASM state having drifted"
        );
        assert!(
            report.mismatched_artifacts().is_empty(),
            "an unrelated user change must never reach ProtectionState::Drifted"
        );
        assert_eq!(
            report.repairable().count(),
            0,
            "repair must have nothing to do about a key it does not own"
        );
    }

    #[test]
    fn a_changed_aasm_value_is_drift_and_is_repairable() {
        let r = receipt();
        let compat = compatible();
        let obs = observed("sha256:tampered", "sha256:doc");
        let report = inputs(&r, &compat, &obs).classify();

        assert!(report.contains(DriftKind::AasmManagedValueChanged));
        assert!(!report.aasm_state_is_intact());
        assert_eq!(report.mismatched_artifacts(), vec![SETTINGS.to_string()]);
        assert_eq!(report.repairable_step_ids(), vec!["settings".to_string()]);
        assert!(report.is_fully_repairable());
    }

    #[test]
    fn a_managed_change_wins_over_a_document_change() {
        // Both hashes differ. The AASM-owned one is what repair acts on, and
        // reporting both would double-count one edit.
        let r = receipt();
        let compat = compatible();
        let obs = observed("sha256:tampered", "sha256:also-different");
        let report = inputs(&r, &compat, &obs).classify();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, DriftKind::AasmManagedValueChanged);
    }

    #[test]
    fn a_missing_artifact_is_drift() {
        let r = receipt();
        let compat = compatible();
        let obs = vec![ObservedStep {
            step_id: "settings".to_string(),
            artifact: SETTINGS.to_string(),
            observation: ArtifactObservation::Missing,
        }];
        let report = inputs(&r, &compat, &obs).classify();
        assert!(report.contains(DriftKind::AasmArtifactMissing));
        assert!(report.is_fully_repairable());
    }

    #[test]
    fn an_unreadable_or_uninspected_artifact_fails_closed() {
        let r = receipt();
        let compat = compatible();

        let unreadable = vec![ObservedStep {
            step_id: "settings".to_string(),
            artifact: SETTINGS.to_string(),
            observation: ArtifactObservation::Unreadable {
                reason: "permission denied".to_string(),
            },
        }];
        let report = inputs(&r, &compat, &unreadable).classify();
        assert!(report.contains(DriftKind::Unobservable));
        assert!(!report.aasm_state_is_intact(), "unproven must not read as intact");
        assert!(
            !report.is_fully_repairable(),
            "repair must not run over what it cannot read"
        );

        // No observation at all is the same answer, not a quiet pass.
        let report = inputs(&r, &compat, &[]).classify();
        assert!(report.contains(DriftKind::Unobservable));
        assert!(!report.aasm_state_is_intact());
    }

    #[test]
    fn a_corrupt_receipt_is_terminal_and_pre_empts_every_other_check() {
        let r = receipt();
        let compat = compatible();
        let obs = observed("sha256:tampered", "sha256:doc");
        let mut i = inputs(&r, &compat, &obs);
        i.receipt_unreadable = Some("integrity hash does not match".to_string());
        let report = i.classify();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, DriftKind::ReceiptCorrupt);
        assert!(
            !report.is_fully_repairable(),
            "a corrupt receipt must never authorise a repair write"
        );
    }

    #[test]
    fn a_missing_receipt_is_its_own_class() {
        let compat = compatible();
        let report = DriftInputs {
            receipt: None,
            receipt_unreadable: None,
            observed: &[],
            compatibility: &compat,
            current_endpoint: None,
        }
        .classify();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, DriftKind::ReceiptMissing);
    }

    #[test]
    fn a_tool_upgrade_out_of_range_is_drift_that_repair_cannot_fix() {
        let r = receipt();
        let incompatible = SupportedToolVersions::between(ToolVersion::new(2, 0, 0), ToolVersion::new(3, 0, 0))
            .classify(Some(&ToolVersion::new(3, 1, 0)));
        let obs = observed("sha256:managed", "sha256:doc");
        let report = inputs(&r, &incompatible, &obs).classify();

        assert!(report.contains(DriftKind::ToolVersionIncompatible));
        assert!(
            !report.is_fully_repairable(),
            "rewriting settings does not make an unsupported tool version supported"
        );
    }

    #[test]
    fn a_moved_runtime_endpoint_is_stale_drift() {
        let mut r = receipt();
        let endpoint_step = IntegrationStep::new(
            "base-url",
            StepAction::ConfigureModelGatewayBaseUrl {
                scope: SettingsScope::User,
                variable: "ANTHROPIC_BASE_URL".to_string(),
                base_url: "http://127.0.0.1:7391".to_string(),
            },
            "route at the local gateway",
        );
        r.steps.push(StepReceipt::applied(
            &endpoint_step,
            Some("sha256:endpoint".to_string()),
        ));

        let compat = compatible();
        let mut obs = observed("sha256:managed", "sha256:doc");
        obs.push(ObservedStep {
            step_id: "base-url".to_string(),
            artifact: "ANTHROPIC_BASE_URL".to_string(),
            observation: ArtifactObservation::Present {
                managed_fingerprint: "sha256:endpoint".to_string(),
                document_fingerprint: None,
            },
        });

        let mut i = inputs(&r, &compat, &obs);
        i.current_endpoint = Some("http://127.0.0.1:9999");
        let report = i.classify();
        assert!(report.contains(DriftKind::RuntimeEndpointStale));
        assert!(!report.aasm_state_is_intact());
    }

    #[test]
    fn a_replace_step_has_no_unrelated_content_to_drift() {
        // A file AASM owns outright has nothing unmanaged in it, so a
        // whole-document difference there is never "the user's own change".
        let mut r = receipt();
        r.steps[0].action = StepAction::WriteManagedSettings {
            scope: SettingsScope::User,
            path: PathBuf::from(SETTINGS),
            managed_keys: vec!["permissions".to_string()],
            content_sha256: "abc".to_string(),
            merge: SettingsMerge::Replace,
        };
        let compat = compatible();
        let obs = observed("sha256:managed", "sha256:different");
        let report = inputs(&r, &compat, &obs).classify();
        assert!(report.is_clean(), "{report:?}");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn drift_reports_round_trip_through_json() {
        let r = receipt();
        let compat = compatible();
        let obs = observed("sha256:tampered", "sha256:doc");
        let report = inputs(&r, &compat, &obs).classify();
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(serde_json::from_str::<DriftReport>(&json).unwrap(), report);
    }
}
