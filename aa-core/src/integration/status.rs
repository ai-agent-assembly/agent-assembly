//! What `status` and `verify` return.
//!
//! # Two axes, because they answer different questions
//!
//! [`LifecyclePhase`] answers *"where is this integration in its lifecycle?"* —
//! planned, installed, being removed. [`ProtectionState`] answers *"what is
//! proven to be true right now, and by what evidence?"*. Collapsing them would
//! force a single enum to mean both "an apply is in progress" and "traffic is
//! governed", which is how a status ends up reporting installation progress as
//! though it were protection.
//!
//! Every state the ticket asks for maps onto exactly one of the two:
//!
//! | Asked for | Where it lives |
//! | --- | --- |
//! | detected but not installed | [`LifecyclePhase::DetectedNotIntegrated`] |
//! | planned | [`LifecyclePhase::Planned`] |
//! | installed | [`LifecyclePhase::Installed`] |
//! | partially installed | [`LifecyclePhase::PartiallyInstalled`] |
//! | removal pending | [`LifecyclePhase::RemovalPending`] |
//! | drifted | [`ProtectionState::Drifted`] |
//! | degraded | [`ProtectionState::Degraded`] |
//! | incompatible | [`ProtectionState::Incompatible`] |
//!
//! # Never a bare boolean
//!
//! [`IntegrationStatus`] carries the achieved level *and* the evidence that
//! produced it, split into what was exercised and what was merely read back, so
//! a user can reason about their own risk instead of reading one word.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::capability::IntegrationCapability;
use super::state::{ProtectionEvidence, ProtectionLevel, ProtectionState};
use super::version::VersionCompatibility;
use crate::dev_tool::{DevToolKind, GovernanceLevel};

/// Where an integration is in its lifecycle, independent of what it protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum LifecyclePhase {
    /// The tool is not on this host.
    NotInstalled,
    /// The tool is present and AASM has applied nothing to it.
    DetectedNotIntegrated,
    /// A plan exists and has been shown to the user; nothing has been applied.
    Planned,
    /// Every required step of a plan has been applied.
    Installed,
    /// Some but not all required steps have been applied — including the resting
    /// state of an interrupted apply.
    PartiallyInstalled,
    /// A removal plan has been accepted and not yet completed.
    RemovalPending,
}

/// The next rung up and why it is not active.
///
/// Present even when the answer is "not available on this platform": silence
/// reads as "there is nothing above what I have", which is the over-claim the
/// protection-level model exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NextLevel {
    /// The rung above the one currently achieved.
    pub level: ProtectionLevel,
    /// Why it is not active, in words a user can act on.
    pub blocked_because: String,
}

/// The machine-readable answer to "is this developer actually protected right
/// now, and how do you know?".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IntegrationStatus {
    /// The tool being reported on.
    pub tool: DevToolKind,
    /// Where the integration is in its lifecycle.
    pub phase: LifecyclePhase,
    /// What the evidence proves.
    pub state: ProtectionState,
    /// The evidence itself, so the claim carries its provenance.
    pub evidence: Vec<ProtectionEvidence>,
    /// The level the applied plan intended to reach.
    pub planned_level: ProtectionLevel,
    /// The adapter's static build-time ceiling. A ceiling is not a measurement.
    pub adapter_ceiling: GovernanceLevel,
    /// How the detected tool version compares to the adapter's supported range.
    pub compatibility: VersionCompatibility,
    /// The rung above the current one, and why it is not active.
    pub next_level: Option<NextLevel>,
    /// When this status was derived, as seconds since the Unix epoch. A status
    /// read without its timestamp over-reads the claim: it is "verified at T",
    /// not "true now".
    pub observed_at_unix_secs: u64,
}

impl IntegrationStatus {
    /// The ladder rung this status reports.
    pub fn achieved_level(&self) -> ProtectionLevel {
        self.state.achieved_level()
    }

    /// Evidence produced by exercising traffic.
    pub fn exercised_evidence(&self) -> impl Iterator<Item = &ProtectionEvidence> {
        self.evidence.iter().filter(|e| e.kind.is_exercised())
    }

    /// Evidence produced by reading configuration back and comparing it.
    pub fn read_back_evidence(&self) -> impl Iterator<Item = &ProtectionEvidence> {
        self.evidence.iter().filter(|e| e.kind.is_matching_read_back())
    }

    /// Whether anything at all has been exercised. A status with no exercised
    /// evidence is a statement about configuration, not about traffic.
    pub fn has_exercised_evidence(&self) -> bool {
        self.exercised_evidence().next().is_some()
    }
}

/// Whether a verification pass proved what it set out to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum VerificationOutcome {
    /// Every check the adapter set out to run passed.
    Passed,
    /// Some checks passed and some could not be completed.
    PartiallyPassed {
        /// What could not be established.
        missing: Vec<String>,
    },
    /// A check ran and failed.
    Failed {
        /// Why.
        reason: String,
    },
    /// No check could be run at all — the honest answer for an adapter that has
    /// no verification mechanism, and deliberately distinct from
    /// [`Failed`](Self::Failed) so "we did not look" is never read as "we looked
    /// and it was fine".
    Unverifiable {
        /// Why nothing could be checked.
        reason: String,
    },
}

impl VerificationOutcome {
    /// Whether the pass established anything positive.
    pub fn is_positive(&self) -> bool {
        matches!(self, Self::Passed | Self::PartiallyPassed { .. })
    }
}

/// The result of one verification pass.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VerificationResult {
    /// When the pass ran, as seconds since the Unix epoch.
    pub verified_at_unix_secs: u64,
    /// What it established.
    pub outcome: VerificationOutcome,
    /// Everything observed, exercised and read back alike.
    pub evidence: Vec<ProtectionEvidence>,
}

impl VerificationResult {
    /// A pass that established nothing, with the reason why.
    pub fn unverifiable(verified_at_unix_secs: u64, reason: impl Into<String>) -> Self {
        Self {
            verified_at_unix_secs,
            outcome: VerificationOutcome::Unverifiable { reason: reason.into() },
            evidence: Vec::new(),
        }
    }

    /// Attach an observation.
    #[must_use]
    pub fn with_evidence(mut self, evidence: ProtectionEvidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Whether any traffic was exercised during this pass.
    pub fn has_exercised_evidence(&self) -> bool {
        self.evidence.iter().any(|e| e.kind.is_exercised())
    }

    /// Every mechanism this pass observed.
    pub fn observed_mechanisms(&self) -> Vec<IntegrationCapability> {
        let mut seen: Vec<IntegrationCapability> = Vec::new();
        for mechanism in self.evidence.iter().map(|e| e.mechanism) {
            if !seen.contains(&mechanism) {
                seen.push(mechanism);
            }
        }
        seen
    }

    /// The highest rung this pass's evidence alone can justify.
    ///
    /// Caps at [`ProtectionLevel::Integrated`] for read-back-only evidence, no
    /// matter how much of it there is: a configuration can be fully applied and
    /// fully verified by read-back while no traffic has ever been protected.
    pub fn highest_justified_level(&self, now_unix_secs: u64, window_secs: u64) -> ProtectionLevel {
        let gateway = self
            .evidence
            .iter()
            .any(|e| e.justifies_gateway_protection(now_unix_secs, window_secs));
        let host = self
            .evidence
            .iter()
            .any(|e| e.justifies_host_enforcement(now_unix_secs, window_secs));

        if gateway && host {
            ProtectionLevel::HostEnforced
        } else if gateway {
            ProtectionLevel::GatewayProtected
        } else if self.outcome.is_positive()
            && self
                .evidence
                .iter()
                .any(|e| e.kind.is_matching_read_back() && e.is_fresh(now_unix_secs, window_secs))
        {
            ProtectionLevel::Integrated
        } else {
            ProtectionLevel::PartiallyIntegrated
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::state::{EvidenceKind, ExerciseOutcome};
    use crate::integration::version::ToolVersion;

    const NOW: u64 = 1_000_000;
    const WINDOW: u64 = 3600;

    fn read_back(mechanism: IntegrationCapability) -> ProtectionEvidence {
        ProtectionEvidence::new(
            mechanism,
            EvidenceKind::ReadBack { matches_receipt: true },
            NOW,
            "read back and matched",
        )
    }

    fn exercised(mechanism: IntegrationCapability, outcome: ExerciseOutcome) -> ProtectionEvidence {
        ProtectionEvidence::new(mechanism, EvidenceKind::Exercised { outcome }, NOW, "probe adjudicated")
    }

    fn status(state: ProtectionState, evidence: Vec<ProtectionEvidence>) -> IntegrationStatus {
        IntegrationStatus {
            tool: DevToolKind::ClaudeCode,
            phase: LifecyclePhase::Installed,
            state,
            evidence,
            planned_level: ProtectionLevel::GatewayProtected,
            adapter_ceiling: GovernanceLevel::L2Enforce,
            compatibility: VersionCompatibility::Compatible {
                detected: ToolVersion::new(2, 1, 220),
            },
            next_level: None,
            observed_at_unix_secs: NOW,
        }
    }

    #[test]
    fn status_splits_exercised_from_read_back_evidence() {
        let s = status(
            ProtectionState::Ladder(ProtectionLevel::GatewayProtected),
            vec![
                read_back(IntegrationCapability::ManagedSettings),
                exercised(IntegrationCapability::ModelPathInterception, ExerciseOutcome::Redacted),
            ],
        );
        assert_eq!(s.read_back_evidence().count(), 1);
        assert_eq!(s.exercised_evidence().count(), 1);
        assert!(s.has_exercised_evidence());
        assert_eq!(s.achieved_level(), ProtectionLevel::GatewayProtected);
    }

    #[test]
    fn a_configuration_only_status_admits_it_has_exercised_nothing() {
        let s = status(
            ProtectionState::Ladder(ProtectionLevel::Integrated),
            vec![read_back(IntegrationCapability::ManagedSettings)],
        );
        assert!(!s.has_exercised_evidence());
    }

    #[test]
    fn read_back_only_verification_caps_at_integrated() {
        let result = VerificationResult {
            verified_at_unix_secs: NOW,
            outcome: VerificationOutcome::Passed,
            evidence: vec![
                read_back(IntegrationCapability::ManagedSettings),
                read_back(IntegrationCapability::ModelPathInterception),
            ],
        };
        assert!(!result.has_exercised_evidence());
        assert_eq!(result.highest_justified_level(NOW, WINDOW), ProtectionLevel::Integrated);
    }

    #[test]
    fn exercised_routing_does_not_lift_the_cap() {
        let result = VerificationResult {
            verified_at_unix_secs: NOW,
            outcome: VerificationOutcome::Passed,
            evidence: vec![
                read_back(IntegrationCapability::ManagedSettings),
                exercised(IntegrationCapability::ModelGatewayBaseUrl, ExerciseOutcome::Redacted),
            ],
        };
        assert!(result.has_exercised_evidence());
        assert_eq!(
            result.highest_justified_level(NOW, WINDOW),
            ProtectionLevel::Integrated,
            "exercising a routing lever is not exercising interception"
        );
    }

    #[test]
    fn exercised_interception_lifts_to_gateway_protected() {
        let result = VerificationResult {
            verified_at_unix_secs: NOW,
            outcome: VerificationOutcome::Passed,
            evidence: vec![
                read_back(IntegrationCapability::ManagedSettings),
                exercised(IntegrationCapability::ModelPathInterception, ExerciseOutcome::Blocked),
            ],
        };
        assert_eq!(
            result.highest_justified_level(NOW, WINDOW),
            ProtectionLevel::GatewayProtected
        );
        assert_eq!(
            result.observed_mechanisms(),
            vec![
                IntegrationCapability::ManagedSettings,
                IntegrationCapability::ModelPathInterception
            ]
        );
    }

    #[test]
    fn stale_evidence_does_not_justify_anything() {
        let result = VerificationResult {
            verified_at_unix_secs: NOW - WINDOW - 1,
            outcome: VerificationOutcome::Passed,
            evidence: vec![ProtectionEvidence::new(
                IntegrationCapability::ModelPathInterception,
                EvidenceKind::Exercised {
                    outcome: ExerciseOutcome::Redacted,
                },
                NOW - WINDOW - 1,
                "verified a long time ago",
            )],
        };
        assert_eq!(
            result.highest_justified_level(NOW, WINDOW),
            ProtectionLevel::PartiallyIntegrated
        );
    }

    #[test]
    fn unverifiable_is_not_failure_and_justifies_nothing() {
        let result = VerificationResult::unverifiable(NOW, "this adapter has no verification mechanism");
        assert!(!result.outcome.is_positive());
        assert!(!result.has_exercised_evidence());
        assert_eq!(
            result.highest_justified_level(NOW, WINDOW),
            ProtectionLevel::PartiallyIntegrated
        );
        assert!(matches!(result.outcome, VerificationOutcome::Unverifiable { .. }));
    }
}
