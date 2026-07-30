//! The durable record of what was applied, and the evidence that justified the
//! level it claims.
//!
//! # What lives here and what does not
//!
//! The receipt *type* is part of the lifecycle contract: an adapter reads one in
//! [`integration_status`](super::DevToolIntegration::integration_status),
//! [`verify_integration`](super::DevToolIntegration::verify_integration) and
//! [`plan_removal`](super::DevToolIntegration::plan_removal). Writing one,
//! storing one and rolling one back belong to the service (ADR 0030 matrix row
//! 3) and are AAASM-5278's scope — an adapter never writes a receipt.
//!
//! # Why the receipt records both the level and its evidence
//!
//! So a later status read can tell "verified once, long ago" from "verified
//! now". A receipt that recorded only `achieved_level: GatewayProtected` would
//! be indistinguishable from one where the claim had never been substantiated,
//! and [`IntegrationReceipt::validate`] would have nothing to check.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::plan::ProtectionProfile;
use super::state::{ProtectionEvidence, ProtectionLevel};
use super::step::{IntegrationStep, SettingsScope, StepAction, StepRequirement};
use super::version::{ComponentVersions, ToolVersion, LIFECYCLE_SCHEMA_VERSION};
use crate::dev_tool::DevToolKind;

/// What the step's target document held for the AASM-owned keys *before* the
/// step ran — the restoration evidence removal is derived from.
///
/// # Why a structured key snapshot and not a file backup
///
/// A full-file backup would put every unmanaged key — including anything the
/// user keeps in the same file — into a second copy AASM now owns and must
/// protect, and it would restore the file as it was at install time, silently
/// discarding everything the user changed afterwards. A structured snapshot of
/// only the claimed keys restores exactly what AASM displaced and carries
/// nothing else. That is also why AAASM-5278's non-goals rule out backing up a
/// developer's home directory: the smallest sufficient record is the one that
/// leaks least *and* preserves most.
///
/// # Fail closed when a prior value cannot be stored
///
/// A value that trips the credential screen is not stored, and its key is named
/// in [`withheld_keys`](Self::withheld_keys). Removal then cannot prove it
/// restored that key, so it declares a residual instead of writing a guess
/// (ADR 0015: a resolution failure is observable, never silently permitted).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PriorSettingsState {
    /// Canonical JSON object of the AASM-owned keys that existed before the
    /// step ran, minus anything withheld by the credential screen.
    pub managed_values_json: String,
    /// AASM-owned keys the document did not have before the step ran, and which
    /// removal must therefore delete rather than restore.
    pub absent_keys: Vec<String>,
    /// Keys whose prior value was withheld because it contained material the
    /// credential scanner recognised. Non-empty means removal is knowingly
    /// incomplete for those keys.
    pub withheld_keys: Vec<String>,
    /// Fingerprint of the whole document before the step ran, so a restore can
    /// be checked against the semantics it was aiming at.
    pub document_fingerprint: String,
}

impl PriorSettingsState {
    /// Whether every claimed key can be restored from this record.
    pub fn is_fully_restorable(&self) -> bool {
        self.withheld_keys.is_empty()
    }
}

/// What one applied step left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StepReceipt {
    /// The [`IntegrationStep::id`] this receipt records.
    pub step_id: String,
    /// The action that was applied.
    pub action: StepAction,
    /// Whether the integration depends on it.
    pub requirement: StepRequirement,
    /// Whether the step was actually applied. An interrupted apply leaves
    /// `false` here, which is what makes `PartiallyIntegrated` recoverable
    /// rather than guessed at.
    pub applied: bool,
    /// Fingerprint of what was written, for drift detection. `None` means no
    /// fingerprint could be taken, which counts as unverified — never as
    /// verified.
    ///
    /// For a settings step this is the fingerprint of the **AASM-owned
    /// projection**, not of the file: a mismatch here means an AASM-managed
    /// value changed, and that is the only mismatch repair may act on.
    pub fingerprint: Option<String>,
    /// Fingerprint of the whole target document immediately after the step ran.
    ///
    /// Its only job is to make "the user changed something of their own" a
    /// distinguishable observation rather than an unexplained hash mismatch. It
    /// never authorises a write — drift derived from it is reported and left
    /// alone.
    pub document_fingerprint: Option<String>,
    /// What the target document held for the claimed keys before the step ran.
    pub prior_state: Option<PriorSettingsState>,
    /// The action that undoes this one, copied from the plan so removal does not
    /// depend on the adapter still being able to re-derive it.
    pub reversal: Option<StepAction>,
}

impl StepReceipt {
    /// Record an applied step from the plan step it came from.
    pub fn applied(step: &IntegrationStep, fingerprint: Option<String>) -> Self {
        Self {
            step_id: step.id.clone(),
            action: step.action.clone(),
            requirement: step.requirement,
            applied: true,
            fingerprint,
            document_fingerprint: None,
            prior_state: None,
            reversal: step.reversal.clone(),
        }
    }

    /// Record a step that was planned but not applied.
    pub fn not_applied(step: &IntegrationStep) -> Self {
        Self {
            step_id: step.id.clone(),
            action: step.action.clone(),
            requirement: step.requirement,
            applied: false,
            fingerprint: None,
            document_fingerprint: None,
            prior_state: None,
            reversal: step.reversal.clone(),
        }
    }

    /// Attach the fingerprint of the whole target document after the step ran.
    #[must_use]
    pub fn with_document_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.document_fingerprint = Some(fingerprint.into());
        self
    }

    /// Attach the restoration evidence captured before the step ran.
    #[must_use]
    pub fn with_prior_state(mut self, prior_state: PriorSettingsState) -> Self {
        self.prior_state = Some(prior_state);
        self
    }

    /// Whether this step counts towards the "every required step verifies"
    /// criterion: applied **and** fingerprinted.
    pub fn is_verified(&self) -> bool {
        self.applied && self.fingerprint.is_some()
    }

    /// Whether removal can prove it restored everything this step displaced.
    ///
    /// A step that was applied without capturing prior state is *not* provably
    /// restorable — the absence of a record is not evidence there was nothing
    /// to record.
    pub fn is_provably_restorable(&self) -> bool {
        if !self.applied {
            return true;
        }
        match &self.prior_state {
            Some(prior) => prior.is_fully_restorable(),
            None => self.reversal.is_some(),
        }
    }
}

/// Why a receipt is not internally consistent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptError {
    /// The receipt claims a level its recorded evidence cannot justify.
    #[error("the receipt claims {claimed} but {detail}")]
    UnjustifiedAchievedLevel {
        /// The level claimed.
        claimed: ProtectionLevel,
        /// What is missing.
        detail: String,
    },
    /// The receipt claims a level above the plan it came from.
    #[error("the receipt claims {achieved} but its plan only intended {planned}")]
    AchievedAbovePlanned {
        /// The level claimed.
        achieved: ProtectionLevel,
        /// The level the plan intended.
        planned: ProtectionLevel,
    },
}

/// The durable record of one applied integration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IntegrationReceipt {
    /// The [`LIFECYCLE_SCHEMA_VERSION`] the writing core used. A receipt whose
    /// schema is newer than the reading core is reported as
    /// [`Incompatible`](super::ProtectionState::Incompatible), never guessed at.
    pub schema_version: u32,
    /// Stable identifier for this receipt.
    pub receipt_id: String,
    /// The plan this receipt records the application of.
    pub plan_id: String,
    /// The tool that was integrated.
    pub tool: DevToolKind,
    /// The profile the user chose.
    pub profile: ProtectionProfile,
    /// Which configuration surface was written. Recorded so a later status read
    /// looks at the file that was actually written, not the one the current
    /// working directory would suggest.
    pub settings_scope: SettingsScope,
    /// When the plan was applied, as seconds since the Unix epoch.
    pub applied_at_unix_secs: u64,
    /// The core, adapter and schema versions that produced it.
    pub versions: ComponentVersions,
    /// The tool version detected at apply time, when one was.
    pub tool_version: Option<ToolVersion>,
    /// One entry per planned step, applied or not.
    pub steps: Vec<StepReceipt>,
    /// The level the plan intended to reach.
    pub planned_level: ProtectionLevel,
    /// The level actually reached at apply time.
    pub achieved_level: ProtectionLevel,
    /// The evidence that justified [`achieved_level`](Self::achieved_level).
    pub achieved_evidence: Vec<ProtectionEvidence>,
    /// When the last successful verification ran, when one has.
    pub verified_at_unix_secs: Option<u64>,
}

impl IntegrationReceipt {
    /// How many steps the integration depends on.
    pub fn required_steps(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.requirement == StepRequirement::Required)
            .count()
    }

    /// How many required steps are applied and fingerprinted.
    pub fn verified_required_steps(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.requirement == StepRequirement::Required && s.is_verified())
            .count()
    }

    /// The reversal actions for every step that was actually applied, in reverse
    /// application order — the order removal must run in.
    pub fn reversal_actions(&self) -> Vec<StepAction> {
        self.steps
            .iter()
            .rev()
            .filter(|s| s.applied)
            .filter_map(|s| s.reversal.clone())
            .collect()
    }

    /// Applied steps whose reversal the receipt does not know, so a removal plan
    /// can say what it will leave behind instead of silently leaving it.
    pub fn irreversible_steps(&self) -> Vec<&StepReceipt> {
        self.steps
            .iter()
            .filter(|s| s.applied && s.reversal.is_none())
            .collect()
    }

    /// Applied steps whose restoration this receipt cannot prove — either no
    /// prior state was captured and no reversal is known, or the prior value was
    /// withheld by the credential screen.
    ///
    /// Removal reports every one of these as a residual rather than writing a
    /// value it cannot substantiate.
    pub fn unrestorable_steps(&self) -> Vec<&StepReceipt> {
        self.steps.iter().filter(|s| !s.is_provably_restorable()).collect()
    }

    /// The runtime or gateway endpoint the applied steps pointed the tool at,
    /// when one was.
    ///
    /// Drift compares this against the endpoint currently in effect; a receipt
    /// that names no endpoint simply cannot go stale in that direction, which is
    /// different from being fresh.
    pub fn receipted_endpoint(&self) -> Option<&str> {
        self.steps.iter().filter(|s| s.applied).find_map(|s| match &s.action {
            StepAction::ConfigureModelGatewayBaseUrl { base_url, .. } => Some(base_url.as_str()),
            _ => None,
        })
    }

    /// Whether this receipt was written by a core newer than the one reading it.
    pub fn is_schema_newer_than(&self, core_schema_version: u32) -> bool {
        self.schema_version > core_schema_version
    }

    /// Whether this receipt was written by a core newer than the one running.
    pub fn is_schema_newer_than_running_core(&self) -> bool {
        self.is_schema_newer_than(LIFECYCLE_SCHEMA_VERSION)
    }

    /// Check that the level the receipt claims is one its evidence can carry.
    ///
    /// The claim is checked without a freshness window: a receipt records what
    /// was true at apply time, and freshness is applied later, when the state is
    /// re-derived on read.
    pub fn validate(&self) -> Result<(), ReceiptError> {
        if self.achieved_level > self.planned_level {
            return Err(ReceiptError::AchievedAbovePlanned {
                achieved: self.achieved_level,
                planned: self.planned_level,
            });
        }

        if self.achieved_level >= ProtectionLevel::GatewayProtected
            && !self
                .achieved_evidence
                .iter()
                .any(ProtectionEvidence::is_gateway_protection_grade)
        {
            return Err(ReceiptError::UnjustifiedAchievedLevel {
                claimed: self.achieved_level,
                detail: "no recorded evidence exercises a mechanism that intercepts the model path".to_string(),
            });
        }

        if self.achieved_level >= ProtectionLevel::HostEnforced
            && !self
                .achieved_evidence
                .iter()
                .any(ProtectionEvidence::is_host_enforcement_grade)
        {
            return Err(ReceiptError::UnjustifiedAchievedLevel {
                claimed: self.achieved_level,
                detail: "no recorded evidence attests that a host-enforcement layer is healthy".to_string(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::capability::IntegrationCapability;
    use crate::integration::state::{EvidenceKind, ExerciseOutcome};
    use crate::integration::step::{ArtifactOperation, SettingsMerge};
    use crate::integration::version::core_version;
    use std::path::PathBuf;

    fn settings_step() -> IntegrationStep {
        IntegrationStep::new(
            "settings",
            StepAction::WriteManagedSettings {
                scope: SettingsScope::User,
                path: PathBuf::from("/home/dev/.claude/settings.json"),
                managed_keys: vec!["permissions".to_string()],
                content_sha256: "abc".to_string(),
                merge: SettingsMerge::MergeManagedKeys,
            },
            "write the managed settings block",
        )
        .with_reversal(StepAction::ManageArtifact {
            operation: ArtifactOperation::Remove,
            path: PathBuf::from("/home/dev/.claude/settings.json"),
        })
    }

    fn receipt(achieved: ProtectionLevel, evidence: Vec<ProtectionEvidence>) -> IntegrationReceipt {
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
            steps: vec![StepReceipt::applied(&settings_step(), Some("sha256:abc".to_string()))],
            planned_level: ProtectionLevel::GatewayProtected,
            achieved_level: achieved,
            achieved_evidence: evidence,
            verified_at_unix_secs: Some(1_000_000),
        }
    }

    fn exercised(mechanism: IntegrationCapability, outcome: ExerciseOutcome) -> ProtectionEvidence {
        ProtectionEvidence::new(
            mechanism,
            EvidenceKind::Exercised { outcome },
            1_000_000,
            "probe adjudicated by the core",
        )
    }

    #[test]
    fn a_gateway_protected_claim_needs_exercised_interception_evidence() {
        // Read-back only: rejected.
        let read_back = receipt(
            ProtectionLevel::GatewayProtected,
            vec![ProtectionEvidence::new(
                IntegrationCapability::ModelPathInterception,
                EvidenceKind::ReadBack { matches_receipt: true },
                1_000_000,
                "proxy address read back from settings",
            )],
        );
        assert!(matches!(
            read_back.validate(),
            Err(ReceiptError::UnjustifiedAchievedLevel { .. })
        ));

        // Exercised, but attributed to a routing lever: still rejected.
        let routing = receipt(
            ProtectionLevel::GatewayProtected,
            vec![exercised(
                IntegrationCapability::ModelGatewayBaseUrl,
                ExerciseOutcome::Redacted,
            )],
        );
        assert!(matches!(
            routing.validate(),
            Err(ReceiptError::UnjustifiedAchievedLevel { .. })
        ));

        // Exercised interception: accepted.
        let intercepted = receipt(
            ProtectionLevel::GatewayProtected,
            vec![exercised(
                IntegrationCapability::ModelPathInterception,
                ExerciseOutcome::Redacted,
            )],
        );
        assert_eq!(intercepted.validate(), Ok(()));
    }

    #[test]
    fn a_receipt_may_not_claim_more_than_its_plan_intended() {
        let mut r = receipt(
            ProtectionLevel::HostEnforced,
            vec![exercised(
                IntegrationCapability::ModelPathInterception,
                ExerciseOutcome::Redacted,
            )],
        );
        r.planned_level = ProtectionLevel::Integrated;
        assert!(matches!(r.validate(), Err(ReceiptError::AchievedAbovePlanned { .. })));
    }

    #[test]
    fn a_step_without_a_fingerprint_is_not_verified() {
        let mut r = receipt(ProtectionLevel::Integrated, vec![]);
        assert_eq!(r.required_steps(), 1);
        assert_eq!(r.verified_required_steps(), 1);

        r.steps[0].fingerprint = None;
        assert_eq!(
            r.verified_required_steps(),
            0,
            "a missing fingerprint must not count as verified"
        );
    }

    #[test]
    fn reversals_run_in_reverse_application_order() {
        let mut r = receipt(ProtectionLevel::Integrated, vec![]);
        let second = IntegrationStep::new(
            "ca",
            StepAction::ManageArtifact {
                operation: ArtifactOperation::Create,
                path: PathBuf::from("/home/dev/.aa/ca/aasm-ca.pem"),
            },
            "write the CA",
        )
        .with_reversal(StepAction::ManageArtifact {
            operation: ArtifactOperation::Remove,
            path: PathBuf::from("/home/dev/.aa/ca/aasm-ca.pem"),
        });
        r.steps
            .push(StepReceipt::applied(&second, Some("sha256:def".to_string())));

        let reversals = r.reversal_actions();
        assert_eq!(reversals.len(), 2);
        assert_eq!(
            reversals[0].affected_paths(),
            vec![PathBuf::from("/home/dev/.aa/ca/aasm-ca.pem")]
        );
    }

    #[test]
    fn a_withheld_prior_value_makes_a_step_unrestorable() {
        let mut r = receipt(ProtectionLevel::Integrated, vec![]);
        r.steps[0] = r.steps[0].clone().with_prior_state(PriorSettingsState {
            managed_values_json: "{}".to_string(),
            absent_keys: vec![],
            withheld_keys: vec!["permissions".to_string()],
            document_fingerprint: "sha256:before".to_string(),
        });
        assert_eq!(r.unrestorable_steps().len(), 1);

        r.steps[0] = r.steps[0].clone().with_prior_state(PriorSettingsState {
            managed_values_json: "{}".to_string(),
            absent_keys: vec!["permissions".to_string()],
            withheld_keys: vec![],
            document_fingerprint: "sha256:before".to_string(),
        });
        assert!(r.unrestorable_steps().is_empty());
    }

    #[test]
    fn an_applied_step_with_neither_prior_state_nor_a_reversal_is_unrestorable() {
        // The absence of a record is not evidence there was nothing to record.
        let mut r = receipt(ProtectionLevel::Integrated, vec![]);
        r.steps[0].reversal = None;
        assert_eq!(r.unrestorable_steps().len(), 1);
    }

    #[test]
    fn the_receipted_endpoint_comes_from_the_applied_steps() {
        let mut r = receipt(ProtectionLevel::Integrated, vec![]);
        assert_eq!(r.receipted_endpoint(), None);

        let endpoint = IntegrationStep::new(
            "base-url",
            StepAction::ConfigureModelGatewayBaseUrl {
                scope: SettingsScope::User,
                variable: "ANTHROPIC_BASE_URL".to_string(),
                base_url: "http://127.0.0.1:7391".to_string(),
            },
            "route the tool at the local gateway",
        );
        r.steps.push(StepReceipt::not_applied(&endpoint));
        assert_eq!(
            r.receipted_endpoint(),
            None,
            "a step that was never applied configured no endpoint"
        );

        r.steps.pop();
        r.steps
            .push(StepReceipt::applied(&endpoint, Some("sha256:e".to_string())));
        assert_eq!(r.receipted_endpoint(), Some("http://127.0.0.1:7391"));
    }

    #[test]
    fn an_unreversible_applied_step_is_reportable() {
        let mut r = receipt(ProtectionLevel::Integrated, vec![]);
        r.steps[0].reversal = None;
        assert_eq!(r.irreversible_steps().len(), 1);
    }

    #[test]
    fn a_newer_schema_is_detectable() {
        let mut r = receipt(ProtectionLevel::Integrated, vec![]);
        assert!(!r.is_schema_newer_than_running_core());
        r.schema_version = LIFECYCLE_SCHEMA_VERSION + 1;
        assert!(r.is_schema_newer_than_running_core());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn receipts_round_trip_through_json() {
        let r = receipt(
            ProtectionLevel::GatewayProtected,
            vec![exercised(
                IntegrationCapability::ModelPathInterception,
                ExerciseOutcome::Redacted,
            )],
        );
        let json = serde_json::to_string(&r).unwrap();
        let restored: IntegrationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, r);
    }
}
