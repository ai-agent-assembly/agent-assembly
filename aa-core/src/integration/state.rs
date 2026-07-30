//! Protection state, the evidence that justifies it, and the pure derivation
//! that turns one into the other — ADR 0030 Decision 4.
//!
//! # A state is a claim, and a claim needs evidence
//!
//! Protection state is **derived on every read, never cached**. The AAASM-5276
//! spike measured ~66 µs between stopping the core and connections being
//! refused: a stored level would keep displaying protection that had already
//! ceased to exist. Nothing in this module stores a state; [`StateDerivation`]
//! is a pure function of the inputs handed to it.
//!
//! # Exercised versus read back
//!
//! [`EvidenceKind`] separates configuration that was *read back and compared*
//! from traffic that was *exercised and adjudicated*. A configuration can be
//! fully applied and fully verified by read-back while no traffic has ever been
//! protected, so only exercised evidence can raise the ladder to
//! [`ProtectionLevel::GatewayProtected`].
//!
//! # Missing evidence lowers, never raises
//!
//! Every `Absent` reading, every `Unknown` version, every stale timestamp
//! resolves *downward*. This is ADR 0015's fail-closed discipline applied to
//! reporting: a claim you cannot substantiate is a claim you do not make.

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::capability::IntegrationCapability;
use super::version::VersionCompatibility;

/// The monotone protection ladder (ADR 0030 §4.1).
///
/// Ordering is meaningful and load-bearing: `NotInstalled < DetectedNotIntegrated
/// < PartiallyIntegrated < Integrated < GatewayProtected < HostEnforced`. The
/// overriding states (`Drifted`, `Degraded`, `Incompatible`) are **not** rungs —
/// they live in [`ProtectionState`] and carry the highest rung last held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ProtectionLevel {
    /// The tool is not present on this host.
    NotInstalled,
    /// The tool is present, but no receipt attributes any configuration to
    /// AASM. A settings file AASM did not write lands here, never higher.
    DetectedNotIntegrated,
    /// A receipt exists and at least one — but not all — required steps verify.
    /// Also the resting state of an interrupted apply, and of a verification
    /// that has fallen outside its freshness window.
    PartiallyIntegrated,
    /// Every required step verifies against the receipt and a verification is
    /// fresh. Says nothing at all about traffic.
    Integrated,
    /// `Integrated`, plus probe traffic was observed and adjudicated by the core
    /// on this integration's model path. The first rung that claims traffic is
    /// actually governed.
    GatewayProtected,
    /// `GatewayProtected`, plus a host-enforcement layer reports healthy and
    /// attributes coverage to the tool. The only rung that claims bypass
    /// resistance.
    HostEnforced,
}

impl ProtectionLevel {
    /// The next rung up, or `None` at the top of the ladder. Used to satisfy the
    /// product rule "always report the next level up and why it is not active".
    pub fn next_up(self) -> Option<Self> {
        match self {
            Self::NotInstalled => Some(Self::DetectedNotIntegrated),
            Self::DetectedNotIntegrated => Some(Self::PartiallyIntegrated),
            Self::PartiallyIntegrated => Some(Self::Integrated),
            Self::Integrated => Some(Self::GatewayProtected),
            Self::GatewayProtected => Some(Self::HostEnforced),
            Self::HostEnforced => None,
        }
    }
}

impl fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NotInstalled => "NotInstalled",
            Self::DetectedNotIntegrated => "DetectedNotIntegrated",
            Self::PartiallyIntegrated => "PartiallyIntegrated",
            Self::Integrated => "Integrated",
            Self::GatewayProtected => "GatewayProtected",
            Self::HostEnforced => "HostEnforced",
        };
        f.write_str(s)
    }
}

/// What is proven to be true for one integration right now — a ladder rung, or
/// one of the three overriding states that replace it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum ProtectionState {
    /// A rung of the monotone ladder.
    Ladder(ProtectionLevel),
    /// A receipt exists and at least one AASM-owned fingerprint mismatches, or
    /// an AASM-owned artifact is missing. Changes to keys the receipt does not
    /// claim never produce this state.
    Drifted {
        /// The highest rung held before drift was detected.
        last_held: ProtectionLevel,
        /// Identifiers of the AASM-owned artifacts that no longer match.
        mismatched: Vec<String>,
    },
    /// Integrated, but a runtime dependency of a planned capability is
    /// unavailable, so the achieved level is strictly below the planned one.
    /// Carries both so the gap is legible.
    Degraded {
        /// The level the plan intended to reach.
        planned: ProtectionLevel,
        /// The level the evidence currently supports.
        achieved: ProtectionLevel,
        /// What is missing, in words a user can act on.
        reason: String,
    },
    /// The detected tool version is outside the adapter's supported range, or a
    /// receipt's schema version is newer than the running core. Terminal until
    /// the user upgrades one side.
    Incompatible {
        /// What is incompatible.
        reason: String,
        /// Which side to upgrade.
        remediation: String,
    },
}

impl ProtectionState {
    /// The ladder rung this state reports, including the rung an overriding
    /// state last held.
    pub fn achieved_level(&self) -> ProtectionLevel {
        match self {
            Self::Ladder(level) => *level,
            Self::Drifted { last_held, .. } => *last_held,
            Self::Degraded { achieved, .. } => *achieved,
            Self::Incompatible { .. } => ProtectionLevel::DetectedNotIntegrated,
        }
    }

    /// Whether this state replaces a ladder rung rather than being one.
    pub fn is_overriding(&self) -> bool {
        !matches!(self, Self::Ladder(_))
    }
}

/// What was actually observed, and how.
///
/// The distinction between the variants is the whole point: `ReadBack` proves a
/// file says what the receipt claims; only `Exercised` proves anything about
/// traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum EvidenceKind {
    /// Configuration was read back from the tool's live config and compared to
    /// the receipt. Can justify at most [`ProtectionLevel::Integrated`].
    ReadBack {
        /// Whether the value read back equalled the value the receipt claims.
        matches_receipt: bool,
    },
    /// Probe traffic was produced and adjudicated **by the core**. The only kind
    /// that can justify [`ProtectionLevel::GatewayProtected`].
    Exercised {
        /// What the core did with the probe.
        outcome: ExerciseOutcome,
    },
    /// A host-enforcement layer reported on itself and attributed coverage to
    /// the tool's process.
    HostAttested {
        /// Whether the layer reported healthy.
        healthy: bool,
    },
    /// A check could not be made. Recorded so the gap is legible; never raises a
    /// state.
    Absent {
        /// Why the check could not be made.
        reason: String,
    },
}

impl EvidenceKind {
    /// Whether this is exercised (traffic-level) evidence.
    pub fn is_exercised(&self) -> bool {
        matches!(self, Self::Exercised { .. })
    }

    /// Whether this is read-back (configuration-level) evidence that matched.
    pub fn is_matching_read_back(&self) -> bool {
        matches!(self, Self::ReadBack { matches_receipt: true })
    }
}

/// What the core did with the probe traffic of a protection test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum ExerciseOutcome {
    /// The synthetic secret was redacted before egress.
    Redacted,
    /// The request was blocked.
    Blocked,
    /// The finding was audited and the payload forwarded unchanged — the
    /// `Observe only` profile. Deliberately **not** protective: observing is not
    /// protecting, and displaying it as protection is the single most likely way
    /// for the product to lie.
    ObservedOnly,
    /// The probe reached the provider unprotected — no AASM component was in the
    /// path. This is the outcome the AAASM-5276 spike measured for base-URL
    /// redirection.
    Leaked,
    /// The probe ran but could not be adjudicated.
    Inconclusive,
}

impl ExerciseOutcome {
    /// Whether this outcome demonstrates that something protective happened.
    pub fn is_protective(self) -> bool {
        matches!(self, Self::Redacted | Self::Blocked)
    }
}

/// One observation, attributed to the mechanism it is evidence *about*, with the
/// timestamp that makes it "verified at T" rather than "true now".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProtectionEvidence {
    /// The mechanism this observation is about.
    pub mechanism: IntegrationCapability,
    /// What was observed, and how.
    pub kind: EvidenceKind,
    /// When it was observed, as seconds since the Unix epoch.
    pub observed_at_unix_secs: u64,
    /// Human-readable detail for status output and audit.
    pub detail: String,
}

impl ProtectionEvidence {
    /// Construct one observation.
    pub fn new(
        mechanism: IntegrationCapability,
        kind: EvidenceKind,
        observed_at_unix_secs: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            mechanism,
            kind,
            observed_at_unix_secs,
            detail: detail.into(),
        }
    }

    /// Whether this observation is inside the freshness window ending at `now`.
    ///
    /// Evidence timestamped in the future is treated as fresh; clock skew is not
    /// something this type can adjudicate.
    pub fn is_fresh(&self, now_unix_secs: u64, window_secs: u64) -> bool {
        now_unix_secs.saturating_sub(self.observed_at_unix_secs) <= window_secs
    }

    /// Whether this observation is of the *kind and mechanism* that could
    /// justify [`ProtectionLevel::GatewayProtected`], ignoring freshness.
    ///
    /// Both halves are required and neither is sufficient:
    ///
    /// * the mechanism must actually intercept the model path — routing levers
    ///   ([`ModelGatewayBaseUrl`](IntegrationCapability::ModelGatewayBaseUrl),
    ///   [`HttpProxy`](IntegrationCapability::HttpProxy)) never qualify;
    /// * the observation must be [`Exercised`](EvidenceKind::Exercised) with a
    ///   protective outcome — read-back evidence never qualifies, however
    ///   complete.
    pub fn is_gateway_protection_grade(&self) -> bool {
        self.mechanism.justifies_gateway_protection()
            && matches!(&self.kind, EvidenceKind::Exercised { outcome } if outcome.is_protective())
    }

    /// [`is_gateway_protection_grade`](Self::is_gateway_protection_grade) **and**
    /// inside the freshness window.
    pub fn justifies_gateway_protection(&self, now_unix_secs: u64, window_secs: u64) -> bool {
        self.is_gateway_protection_grade() && self.is_fresh(now_unix_secs, window_secs)
    }

    /// Whether this observation is of the kind and mechanism that could justify
    /// [`ProtectionLevel::HostEnforced`], ignoring freshness.
    pub fn is_host_enforcement_grade(&self) -> bool {
        self.mechanism.justifies_host_enforcement() && matches!(self.kind, EvidenceKind::HostAttested { healthy: true })
    }

    /// [`is_host_enforcement_grade`](Self::is_host_enforcement_grade) **and**
    /// inside the freshness window.
    pub fn justifies_host_enforcement(&self, now_unix_secs: u64, window_secs: u64) -> bool {
        self.is_host_enforcement_grade() && self.is_fresh(now_unix_secs, window_secs)
    }
}

/// Default freshness window for verification evidence: 24 hours.
///
/// Callers may narrow it; the point of naming it is that "verified once, long
/// ago" and "verified now" must not read the same.
pub const DEFAULT_FRESHNESS_WINDOW_SECS: u64 = 24 * 60 * 60;

/// The inputs from which a [`ProtectionState`] is derived.
///
/// Everything here is supplied by the trusted service (ADR 0030 matrix row 14);
/// no field can be populated by a thin client. Holding the inputs in one struct
/// is what makes the derivation a pure, exhaustively testable function rather
/// than logic spread across call sites.
#[derive(Debug, Clone)]
pub struct StateDerivation<'a> {
    /// Whether `detect()` found the tool.
    pub detected: bool,
    /// Whether a receipt exists for this (tool, user) pair.
    pub receipt_present: bool,
    /// How many steps of the applied plan were required.
    pub required_steps: usize,
    /// How many of those verified present by fingerprint.
    pub required_steps_verified: usize,
    /// AASM-owned artifacts whose fingerprints no longer match.
    pub mismatched_artifacts: &'a [String],
    /// How the detected tool version compares to the adapter's supported range.
    pub compatibility: &'a VersionCompatibility,
    /// Whether a receipt's schema version is newer than this core can read.
    pub schema_newer_than_core: bool,
    /// Everything observed about this integration.
    pub evidence: &'a [ProtectionEvidence],
    /// The level the applied plan intended to reach.
    pub planned_level: ProtectionLevel,
    /// Now, as seconds since the Unix epoch.
    pub now_unix_secs: u64,
    /// How old verification evidence may be and still count.
    pub freshness_window_secs: u64,
}

impl StateDerivation<'_> {
    /// Derive the reported state from the evidence.
    ///
    /// The order of the rules is itself part of the contract:
    ///
    /// 1. An unreadable schema or an incompatible version is terminal —
    ///    reporting a rung for a tool the adapter does not understand would be a
    ///    guess.
    /// 2. The ladder is climbed only as far as the evidence reaches, and an
    ///    `Unknown` version caps it at
    ///    [`PartiallyIntegrated`](ProtectionLevel::PartiallyIntegrated) (rule 2:
    ///    an unresolvable version resolves downward).
    /// 3. Drift overrides the rung it replaces, carrying the rung last held.
    /// 4. A rung below the planned level, at or above `Integrated`, is reported
    ///    as `Degraded` so the gap is visible rather than silently smaller.
    pub fn derive(&self) -> ProtectionState {
        if self.schema_newer_than_core {
            return ProtectionState::Incompatible {
                reason: "this integration's receipt was written by a newer Agent Assembly release \
                         than the one running"
                    .to_string(),
                remediation: "upgrade Agent Assembly, or remove and reinstall the integration".to_string(),
            };
        }

        if let VersionCompatibility::Incompatible {
            detected, remediation, ..
        } = self.compatibility
        {
            let detected = detected
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown".to_string());
            return ProtectionState::Incompatible {
                reason: format!("the detected tool version ({detected}) is outside this adapter's supported range"),
                remediation: remediation.clone(),
            };
        }

        let ladder = self.ladder();

        if !self.mismatched_artifacts.is_empty() {
            return ProtectionState::Drifted {
                last_held: ladder,
                mismatched: self.mismatched_artifacts.to_vec(),
            };
        }

        if ladder >= ProtectionLevel::Integrated && ladder < self.planned_level {
            return ProtectionState::Degraded {
                planned: self.planned_level,
                achieved: ladder,
                reason: self.degradation_reason(),
            };
        }

        ProtectionState::Ladder(ladder)
    }

    /// Climb the ladder as far as the evidence reaches.
    fn ladder(&self) -> ProtectionLevel {
        if !self.detected {
            return ProtectionLevel::NotInstalled;
        }
        if !self.receipt_present {
            // A settings file AASM did not write is evidence of a file, nothing
            // more (ADR 0030 §4.2 rule 1).
            return ProtectionLevel::DetectedNotIntegrated;
        }

        let all_required_verified = self.required_steps > 0 && self.required_steps_verified >= self.required_steps;
        if !all_required_verified {
            return ProtectionLevel::PartiallyIntegrated;
        }

        let fresh = |e: &ProtectionEvidence| e.is_fresh(self.now_unix_secs, self.freshness_window_secs);

        let verification_is_fresh = self
            .evidence
            .iter()
            .any(|e| fresh(e) && (e.kind.is_matching_read_back() || e.kind.is_exercised()));
        if !verification_is_fresh {
            // Evidence decays rather than persisting on the strength of an old
            // result (ADR 0030 §4.2 rule 3).
            return ProtectionLevel::PartiallyIntegrated;
        }

        // An unresolvable version is a missing comparison; it resolves downward.
        if !self.compatibility.is_compatible() {
            return ProtectionLevel::PartiallyIntegrated;
        }

        let gateway_protected = self
            .evidence
            .iter()
            .any(|e| e.justifies_gateway_protection(self.now_unix_secs, self.freshness_window_secs));
        if !gateway_protected {
            return ProtectionLevel::Integrated;
        }

        let host_enforced = self
            .evidence
            .iter()
            .any(|e| e.justifies_host_enforcement(self.now_unix_secs, self.freshness_window_secs));
        if host_enforced {
            ProtectionLevel::HostEnforced
        } else {
            ProtectionLevel::GatewayProtected
        }
    }

    /// Assemble a user-actionable reason from whatever `Absent` evidence exists.
    fn degradation_reason(&self) -> String {
        let missing: Vec<&str> = self
            .evidence
            .iter()
            .filter_map(|e| match &e.kind {
                EvidenceKind::Absent { reason } => Some(reason.as_str()),
                _ => None,
            })
            .collect();

        if missing.is_empty() {
            "the achieved protection level is below the level this integration planned for".to_string()
        } else {
            missing.join("; ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::version::{SupportedToolVersions, ToolVersion};

    const NOW: u64 = 1_000_000;
    const WINDOW: u64 = DEFAULT_FRESHNESS_WINDOW_SECS;

    fn compatible() -> VersionCompatibility {
        VersionCompatibility::Compatible {
            detected: ToolVersion::new(2, 1, 220),
        }
    }

    fn read_back(mechanism: IntegrationCapability) -> ProtectionEvidence {
        ProtectionEvidence::new(
            mechanism,
            EvidenceKind::ReadBack { matches_receipt: true },
            NOW,
            "managed settings read back and matched the receipt",
        )
    }

    fn exercised(mechanism: IntegrationCapability, outcome: ExerciseOutcome) -> ProtectionEvidence {
        ProtectionEvidence::new(mechanism, EvidenceKind::Exercised { outcome }, NOW, "probe adjudicated")
    }

    fn derivation<'a>(
        compat: &'a VersionCompatibility,
        evidence: &'a [ProtectionEvidence],
        mismatched: &'a [String],
    ) -> StateDerivation<'a> {
        StateDerivation {
            detected: true,
            receipt_present: true,
            required_steps: 2,
            required_steps_verified: 2,
            mismatched_artifacts: mismatched,
            compatibility: compat,
            schema_newer_than_core: false,
            evidence,
            planned_level: ProtectionLevel::GatewayProtected,
            now_unix_secs: NOW,
            freshness_window_secs: WINDOW,
        }
    }

    #[test]
    fn the_ladder_is_ordered() {
        assert!(ProtectionLevel::NotInstalled < ProtectionLevel::DetectedNotIntegrated);
        assert!(ProtectionLevel::PartiallyIntegrated < ProtectionLevel::Integrated);
        assert!(ProtectionLevel::Integrated < ProtectionLevel::GatewayProtected);
        assert!(ProtectionLevel::GatewayProtected < ProtectionLevel::HostEnforced);
        assert_eq!(ProtectionLevel::HostEnforced.next_up(), None);
        assert_eq!(
            ProtectionLevel::Integrated.next_up(),
            Some(ProtectionLevel::GatewayProtected)
        );
    }

    #[test]
    fn gateway_protected_is_unreachable_from_read_back_only_evidence() {
        // Fully applied, fully verified by read-back — and still not protected,
        // because no traffic has ever been exercised.
        let compat = compatible();
        let evidence = [
            read_back(IntegrationCapability::ManagedSettings),
            read_back(IntegrationCapability::ModelPathInterception),
        ];
        let state = derivation(&compat, &evidence, &[]).derive();
        assert_eq!(
            state,
            ProtectionState::Degraded {
                planned: ProtectionLevel::GatewayProtected,
                achieved: ProtectionLevel::Integrated,
                reason: "the achieved protection level is below the level this integration planned for".to_string(),
            }
        );
        assert_eq!(state.achieved_level(), ProtectionLevel::Integrated);
    }

    #[test]
    fn base_url_redirection_cannot_reach_gateway_protected() {
        // Exercised evidence — but attributed to a routing lever, not to
        // interception. AAASM-5276 measured exactly this shape leaking a secret.
        let compat = compatible();
        let evidence = [
            read_back(IntegrationCapability::ManagedSettings),
            exercised(IntegrationCapability::ModelGatewayBaseUrl, ExerciseOutcome::Redacted),
        ];
        let state = derivation(&compat, &evidence, &[]).derive();
        assert_eq!(state.achieved_level(), ProtectionLevel::Integrated);
        assert!(
            state.achieved_level() < ProtectionLevel::GatewayProtected,
            "routing must never be reported as protection"
        );
    }

    #[test]
    fn exercised_interception_reaches_gateway_protected() {
        let compat = compatible();
        let evidence = [
            read_back(IntegrationCapability::ManagedSettings),
            exercised(IntegrationCapability::ModelPathInterception, ExerciseOutcome::Redacted),
        ];
        let state = derivation(&compat, &evidence, &[]).derive();
        assert_eq!(state, ProtectionState::Ladder(ProtectionLevel::GatewayProtected));
    }

    #[test]
    fn observe_only_traffic_is_not_protection() {
        let compat = compatible();
        let evidence = [
            read_back(IntegrationCapability::ManagedSettings),
            exercised(
                IntegrationCapability::ModelPathInterception,
                ExerciseOutcome::ObservedOnly,
            ),
        ];
        let state = derivation(&compat, &evidence, &[]).derive();
        assert_eq!(state.achieved_level(), ProtectionLevel::Integrated);
    }

    #[test]
    fn host_enforcement_requires_gateway_protection_first() {
        let compat = compatible();
        let attested = ProtectionEvidence::new(
            IntegrationCapability::HostEnforcement,
            EvidenceKind::HostAttested { healthy: true },
            NOW,
            "proxy CA present in the trust store",
        );

        // Attestation alone does not skip a rung.
        let without_traffic = [read_back(IntegrationCapability::ManagedSettings), attested.clone()];
        assert_eq!(
            derivation(&compat, &without_traffic, &[]).derive().achieved_level(),
            ProtectionLevel::Integrated
        );

        let with_traffic = [
            read_back(IntegrationCapability::ManagedSettings),
            exercised(IntegrationCapability::ModelPathInterception, ExerciseOutcome::Blocked),
            attested,
        ];
        assert_eq!(
            derivation(&compat, &with_traffic, &[]).derive(),
            ProtectionState::Ladder(ProtectionLevel::HostEnforced)
        );
    }

    #[test]
    fn a_settings_file_without_a_receipt_is_detected_not_integrated() {
        let compat = compatible();
        let evidence = [read_back(IntegrationCapability::ManagedSettings)];
        let mut d = derivation(&compat, &evidence, &[]);
        d.receipt_present = false;
        assert_eq!(
            d.derive(),
            ProtectionState::Ladder(ProtectionLevel::DetectedNotIntegrated)
        );
    }

    #[test]
    fn stale_verification_decays_to_partially_integrated() {
        let compat = compatible();
        let stale = [ProtectionEvidence::new(
            IntegrationCapability::ManagedSettings,
            EvidenceKind::ReadBack { matches_receipt: true },
            NOW - WINDOW - 1,
            "verified a long time ago",
        )];
        assert_eq!(
            derivation(&compat, &stale, &[]).derive().achieved_level(),
            ProtectionLevel::PartiallyIntegrated
        );
    }

    #[test]
    fn missing_evidence_only_ever_lowers_the_state() {
        let compat = compatible();
        let base = [
            read_back(IntegrationCapability::ManagedSettings),
            exercised(IntegrationCapability::ModelPathInterception, ExerciseOutcome::Redacted),
        ];
        let high = derivation(&compat, &base, &[]).derive().achieved_level();

        let with_absent = [
            read_back(IntegrationCapability::ManagedSettings),
            exercised(IntegrationCapability::ModelPathInterception, ExerciseOutcome::Redacted),
            ProtectionEvidence::new(
                IntegrationCapability::HostEnforcement,
                EvidenceKind::Absent {
                    reason: "host enforcement is unavailable on this platform".to_string(),
                },
                NOW,
                "no eBPF on macOS",
            ),
        ];
        let with_gap = derivation(&compat, &with_absent, &[]).derive().achieved_level();
        assert!(with_gap <= high, "an Absent reading must never raise the state");
    }

    #[test]
    fn an_unresolvable_version_resolves_downward() {
        let unknown = VersionCompatibility::Unknown {
            reason: "version probe failed".to_string(),
        };
        let evidence = [
            read_back(IntegrationCapability::ManagedSettings),
            exercised(IntegrationCapability::ModelPathInterception, ExerciseOutcome::Redacted),
        ];
        assert_eq!(
            derivation(&unknown, &evidence, &[]).derive().achieved_level(),
            ProtectionLevel::PartiallyIntegrated
        );
    }

    #[test]
    fn drift_overrides_the_rung_and_carries_it() {
        let compat = compatible();
        let evidence = [
            read_back(IntegrationCapability::ManagedSettings),
            exercised(IntegrationCapability::ModelPathInterception, ExerciseOutcome::Redacted),
        ];
        let mismatched = ["~/.claude/settings.json#permissions".to_string()];
        let state = derivation(&compat, &evidence, &mismatched).derive();
        assert_eq!(
            state,
            ProtectionState::Drifted {
                last_held: ProtectionLevel::GatewayProtected,
                mismatched: mismatched.to_vec(),
            }
        );
        assert!(state.is_overriding());
    }

    #[test]
    fn an_incompatible_version_is_terminal_and_actionable() {
        let supported = SupportedToolVersions::at_least(ToolVersion::new(3, 0, 0));
        let incompatible = supported.classify(Some(&ToolVersion::new(2, 1, 220)));
        let evidence = [read_back(IntegrationCapability::ManagedSettings)];
        match derivation(&incompatible, &evidence, &[]).derive() {
            ProtectionState::Incompatible { remediation, .. } => {
                assert!(remediation.contains("upgrade"), "{remediation}");
            }
            other => panic!("expected Incompatible, got {other:?}"),
        }
    }

    #[test]
    fn a_receipt_written_by_a_newer_core_is_incompatible() {
        let compat = compatible();
        let evidence = [read_back(IntegrationCapability::ManagedSettings)];
        let mut d = derivation(&compat, &evidence, &[]);
        d.schema_newer_than_core = true;
        assert!(matches!(d.derive(), ProtectionState::Incompatible { .. }));
    }

    #[test]
    fn an_uninstalled_tool_is_not_installed() {
        let compat = compatible();
        let mut d = derivation(&compat, &[], &[]);
        d.detected = false;
        assert_eq!(d.derive(), ProtectionState::Ladder(ProtectionLevel::NotInstalled));
    }

    #[test]
    fn an_interrupted_apply_rests_at_partially_integrated() {
        let compat = compatible();
        let evidence = [read_back(IntegrationCapability::ManagedSettings)];
        let mut d = derivation(&compat, &evidence, &[]);
        d.required_steps_verified = 1;
        assert_eq!(
            d.derive().achieved_level(),
            ProtectionLevel::PartiallyIntegrated,
            "an interrupted apply must not read as integrated"
        );
    }
}
