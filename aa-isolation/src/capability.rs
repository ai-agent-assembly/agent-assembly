//! What a backend can mechanically do, on this host, right now.
//!
//! ADR 0035's "Backend capability examples" section states the bar this module
//! has to clear: *"A single boolean `sandbox=true` or `supported=true` is
//! insufficient."* Each [`CapabilityReport`] therefore answers six independent
//! questions, none of which is derivable from the others:
//!
//! | Question | Type |
//! | --- | --- |
//! | Does it enforce, or only watch? | [`Mediation`] |
//! | Does the decision precede the effect? | [`DecisionTiming`] |
//! | Is the decision synchronous with the action? | [`Synchrony`] |
//! | What happens when the mechanism itself fails? | [`FailurePosture`] |
//! | Do child processes inherit it? | [`DescendantCoverage`] |
//! | Does it work fully, partly, or not at all here? | [`SupportLevel`] |
//!
//! The first four are the manifest vocabulary from
//! `schemas/capability-manifest/v1/capability-manifest.schema.json`; each type
//! carries an `as_manifest_str` that emits the exact token that schema accepts,
//! and the mapping is pinned by test.

use core::fmt;

use aa_core::attestation::ClaimTerm;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The axis of host behaviour a control acts on.
///
/// Deliberately split finer than "filesystem" or "network": ADR 0035 requires
/// read scope to be distinguishable from write scope, and egress from name
/// resolution, because a backend can genuinely enforce one and only observe the
/// other. Reporting them jointly would force a backend to describe the pair by
/// its weaker half or to overclaim by its stronger half.
///
/// `#[non_exhaustive]`: later tickets under Epic AAASM-5702 are expected to add
/// axes, and doing so must not be a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum CapabilityDomain {
    /// Reading file content or metadata.
    FilesystemRead,
    /// Creating, writing, renaming or deleting filesystem entries.
    FilesystemWrite,
    /// Outbound network connections, by destination, port and protocol.
    NetworkEgress,
    /// Hostname resolution, which can exfiltrate without an egress connection
    /// and so is not covered by [`NetworkEgress`](Self::NetworkEgress).
    NameResolution,
    /// Direct system-call access.
    Syscall,
    /// Creating child processes.
    ProcessCreation,
    /// Inter-process channels: sockets, shared memory, inherited descriptors.
    Ipc,
    /// The authority the child inherits: environment secrets, tokens, open
    /// descriptors and sockets that carry credentials (ADR 0035 §9).
    Credential,
    /// Numeric ceilings: memory, CPU, process count, wall clock, file size,
    /// open descriptors.
    Resource,
}

impl CapabilityDomain {
    /// Every domain, for exhaustive iteration in tests and reports.
    ///
    /// Kept in sync with the enum by [`Self::ALL`]'s own test; a variant added
    /// without updating this list fails that test rather than silently
    /// disappearing from any sweep that uses it.
    pub const ALL: &'static [Self] = &[
        Self::FilesystemRead,
        Self::FilesystemWrite,
        Self::NetworkEgress,
        Self::NameResolution,
        Self::Syscall,
        Self::ProcessCreation,
        Self::Ipc,
        Self::Credential,
        Self::Resource,
    ];

    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem_read",
            Self::FilesystemWrite => "filesystem_write",
            Self::NetworkEgress => "network_egress",
            Self::NameResolution => "name_resolution",
            Self::Syscall => "syscall",
            Self::ProcessCreation => "process_creation",
            Self::Ipc => "ipc",
            Self::Credential => "credential",
            Self::Resource => "resource",
        }
    }
}

impl fmt::Display for CapabilityDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a control acts on an action or merely records it.
///
/// Mirrors the capability manifest's `observe_or_enforce` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Mediation {
    /// The control can refuse the action.
    Enforce,
    /// The control produces evidence and cannot refuse.
    ///
    /// Never a substitute for [`Enforce`](Self::Enforce), however good the
    /// evidence is. This is the distinction ADR 0035 §4 forbids collapsing.
    Observe,
    /// No control on this axis.
    None,
}

impl Mediation {
    /// The capability-manifest token for this value.
    pub fn as_manifest_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Observe => "observe",
            Self::None => "none",
        }
    }
}

/// When the control's decision lands relative to the effect it governs.
///
/// Mirrors the capability manifest's `decision_timing` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DecisionTiming {
    /// The decision precedes the effect. The only timing that can prevent.
    Pre,
    /// The decision happens during the action, in its data path.
    ///
    /// Enough to modify or truncate; not enough to guarantee the action never
    /// took effect at all.
    InLine,
    /// The decision happens after the effect. A kill after the syscall
    /// completed is this, and reports as
    /// [`ClaimTerm::Detected`], never as prevention.
    Post,
    /// No decision is made.
    None,
}

impl DecisionTiming {
    /// The capability-manifest token for this value.
    pub fn as_manifest_str(self) -> &'static str {
        match self {
            Self::Pre => "pre",
            Self::InLine => "in_line",
            Self::Post => "post",
            Self::None => "none",
        }
    }
}

/// Whether the decision is synchronous with the action or merely attempted.
///
/// Mirrors the capability manifest's `sync_or_best_effort` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Synchrony {
    /// The action blocks on the decision.
    Sync,
    /// The decision is attempted but the action may proceed without it — a
    /// queue that can drop, a hook that can be raced.
    BestEffort,
    /// No decision is made.
    None,
}

impl Synchrony {
    /// The capability-manifest token for this value.
    pub fn as_manifest_str(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::BestEffort => "best_effort",
            Self::None => "none",
        }
    }
}

/// What the control does when the control itself fails.
///
/// Mirrors the capability manifest's `failure_posture` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FailurePosture {
    /// The action is denied when the control cannot decide.
    FailClosed,
    /// The action proceeds, and the gap is recorded.
    FailOpen,
    /// The action proceeds and nothing records that it was unexamined — the
    /// worst posture, because the resulting silence is indistinguishable from
    /// a clean run.
    FailOpenSilent,
    /// Input is truncated without the truncation being surfaced.
    SilentTruncation,
    /// The control has no failure mode of this kind.
    NotApplicable,
}

impl FailurePosture {
    /// The capability-manifest token for this value.
    pub fn as_manifest_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::FailOpen => "fail_open",
            Self::FailOpenSilent => "fail_open_silent",
            Self::SilentTruncation => "silent_truncation",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// How far down the process tree a control's semantics reach.
///
/// Per-capability, never per-backend: ADR 0035 §6 makes descendant coverage part
/// of *correctness*, and a backend commonly inherits filesystem restrictions
/// across `fork`/`exec` while losing a network restriction, or the reverse.
/// Reporting one tree-wide answer would have to pick a lie in one direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DescendantCoverage {
    /// The target process and every descendant created by ordinary
    /// `fork`/`exec` are covered, at the same or narrower scope.
    ProcessTree,
    /// Only the directly launched process is covered. A child escapes this
    /// control by existing — ADR 0035 §6's "no meaningful process boundary".
    /// Legal to report, and the reporting is what makes it legal.
    TargetProcessOnly,
    /// Coverage over descendants has not been measured on this host. Distinct
    /// from [`TargetProcessOnly`](Self::TargetProcessOnly): unknown, not known
    /// to be absent.
    Unmeasured,
}

impl DescendantCoverage {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessTree => "process_tree",
            Self::TargetProcessOnly => "target_process_only",
            Self::Unmeasured => "unmeasured",
        }
    }
}

/// How completely the backend implements a domain on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SupportLevel {
    /// The domain is implemented as reported, without caveat.
    Full,
    /// The domain is implemented with stated gaps.
    ///
    /// This is the "partial support" ADR 0035 requires be representable — a
    /// backend that enforces write restrictions on regular files but not on
    /// device nodes is neither `Full` nor `Unsupported`, and flattening it to
    /// either loses the operator's ability to judge the residual risk.
    Partial {
        /// What is not covered, in words an operator can act on. Must be
        /// non-empty; a `Partial` with no stated gap is indistinguishable from
        /// `Full` to a reader.
        limitations: Vec<String>,
    },
    /// No mechanism for this domain exists in this deployment.
    Unsupported {
        /// Why, in words an operator can act on.
        reason: String,
    },
}

impl SupportLevel {
    /// Whether any mechanism at all exists for this domain.
    pub fn is_available(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }
}

/// Whether a host precondition for a capability holds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PrerequisiteStatus {
    /// Checked on this host, and it holds.
    Satisfied,
    /// Checked on this host, and it does not hold.
    Unsatisfied {
        /// What was found instead, and what would fix it.
        detail: String,
    },
    /// Not checked.
    ///
    /// Treated as not satisfied by [`negotiate`](crate::plan::negotiate): an
    /// unverified precondition cannot support a prevention claim, because
    /// "we did not look" and "it is fine" are the same value otherwise.
    Unchecked,
}

/// A host precondition a capability depends on.
///
/// Deliberately a free-text requirement rather than an enum of known platform
/// features: naming the preconditions would mean naming the mechanisms, which
/// this crate must not do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Prerequisite {
    /// What must hold, phrased for an operator ("kernel supports per-process
    /// filesystem restriction", not a vendor feature name).
    pub requirement: String,
    /// Whether it holds.
    pub status: PrerequisiteStatus,
}

impl Prerequisite {
    /// A prerequisite that was checked and holds.
    pub fn satisfied(requirement: impl Into<String>) -> Self {
        Self {
            requirement: requirement.into(),
            status: PrerequisiteStatus::Satisfied,
        }
    }

    /// A prerequisite that was checked and does not hold.
    pub fn unsatisfied(requirement: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            requirement: requirement.into(),
            status: PrerequisiteStatus::Unsatisfied { detail: detail.into() },
        }
    }

    /// Whether this precondition is known to hold.
    ///
    /// [`PrerequisiteStatus::Unchecked`] is `false` — see that variant.
    pub fn is_satisfied(&self) -> bool {
        matches!(self.status, PrerequisiteStatus::Satisfied)
    }
}

/// The kind of kernel boundary the backend places between host and agent.
///
/// A property of the backend as a whole rather than of any one control, which
/// is why it sits on [`BackendCapabilities`] and not on [`CapabilityReport`]:
/// it has no mediation, timing or descendant semantics of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum PlatformBoundary {
    /// The agent runs on the host kernel, restricted in place.
    SharedHostKernel,
    /// System calls are serviced by a userspace kernel.
    UserspaceKernel,
    /// The agent runs under a separate guest kernel.
    GuestKernel,
}

/// One backend's statement about one [`CapabilityDomain`] on this host.
///
/// Constructed through [`CapabilityReport::unsupported`] or
/// [`CapabilityReport::new`] plus the `with_*` methods, rather than by literal,
/// so that the prevention-relevant fields cannot be left at a default that
/// happens to read as stronger than the backend meant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CapabilityReport {
    domain: CapabilityDomain,
    mediation: Mediation,
    timing: DecisionTiming,
    synchrony: Synchrony,
    failure_posture: FailurePosture,
    descendants: DescendantCoverage,
    support: SupportLevel,
    prerequisites: Vec<Prerequisite>,
}

impl CapabilityReport {
    /// A report for a domain the backend implements.
    ///
    /// Defaults are the *weakest* honest values — [`SupportLevel::Full`] with
    /// [`DescendantCoverage::Unmeasured`] and
    /// [`FailurePosture::NotApplicable`] — and are overridden by the `with_*`
    /// methods. Descendant coverage in particular defaults to `Unmeasured`
    /// rather than `ProcessTree` so that a backend author who forgets it
    /// under-claims instead of over-claiming.
    pub fn new(domain: CapabilityDomain, mediation: Mediation, timing: DecisionTiming, synchrony: Synchrony) -> Self {
        Self {
            domain,
            mediation,
            timing,
            synchrony,
            failure_posture: FailurePosture::NotApplicable,
            descendants: DescendantCoverage::Unmeasured,
            support: SupportLevel::Full,
            prerequisites: Vec::new(),
        }
    }

    /// A report for a domain the backend has no mechanism for.
    ///
    /// Fixes mediation, timing and synchrony at `None` so an unsupported domain
    /// cannot simultaneously advertise a decision it does not make.
    pub fn unsupported(domain: CapabilityDomain, reason: impl Into<String>) -> Self {
        Self {
            domain,
            mediation: Mediation::None,
            timing: DecisionTiming::None,
            synchrony: Synchrony::None,
            failure_posture: FailurePosture::NotApplicable,
            descendants: DescendantCoverage::Unmeasured,
            support: SupportLevel::Unsupported { reason: reason.into() },
            prerequisites: Vec::new(),
        }
    }

    /// Set what happens when the control itself fails.
    pub fn with_failure_posture(mut self, posture: FailurePosture) -> Self {
        self.failure_posture = posture;
        self
    }

    /// Set how far down the process tree this control reaches.
    pub fn with_descendants(mut self, coverage: DescendantCoverage) -> Self {
        self.descendants = coverage;
        self
    }

    /// Set how completely the domain is implemented.
    pub fn with_support(mut self, support: SupportLevel) -> Self {
        self.support = support;
        self
    }

    /// Add a host precondition this capability depends on.
    pub fn with_prerequisite(mut self, prerequisite: Prerequisite) -> Self {
        self.prerequisites.push(prerequisite);
        self
    }

    /// The domain reported on.
    pub fn domain(&self) -> CapabilityDomain {
        self.domain
    }

    /// Whether the control acts or only watches.
    pub fn mediation(&self) -> Mediation {
        self.mediation
    }

    /// When the decision lands relative to the effect.
    pub fn timing(&self) -> DecisionTiming {
        self.timing
    }

    /// Whether the action blocks on the decision.
    pub fn synchrony(&self) -> Synchrony {
        self.synchrony
    }

    /// What the control does when it cannot decide.
    pub fn failure_posture(&self) -> FailurePosture {
        self.failure_posture
    }

    /// How far down the process tree the control reaches.
    pub fn descendants(&self) -> DescendantCoverage {
        self.descendants
    }

    /// How completely the domain is implemented.
    pub fn support(&self) -> &SupportLevel {
        &self.support
    }

    /// Host preconditions this capability depends on.
    pub fn prerequisites(&self) -> &[Prerequisite] {
        &self.prerequisites
    }

    /// The first precondition that is not known to hold, if any.
    pub fn unsatisfied_prerequisite(&self) -> Option<&Prerequisite> {
        self.prerequisites.iter().find(|p| !p.is_satisfied())
    }

    /// Whether this capability can satisfy a requirement for synchronous
    /// pre-effect denial.
    ///
    /// All five conditions are required, and none implies another:
    ///
    /// 1. [`Mediation::Enforce`] — it can refuse at all;
    /// 2. [`DecisionTiming::Pre`] — the refusal precedes the effect;
    /// 3. [`Synchrony::Sync`] — the action waits for the refusal;
    /// 4. the domain is not [`SupportLevel::Unsupported`];
    /// 5. every stated prerequisite is known to hold.
    ///
    /// [`SupportLevel::Partial`] does *not* disqualify: a partially covered
    /// enforcing control genuinely prevents within its stated scope, and the
    /// gap travels to the operator through [`SupportLevel::Partial`]'s stated
    /// limitations and into evidence. Collapsing partial to "cannot prevent" would push
    /// backends to report `Full` to stay usable, which is the worse failure.
    pub fn can_prevent(&self) -> bool {
        self.mediation == Mediation::Enforce
            && self.timing == DecisionTiming::Pre
            && self.synchrony == Synchrony::Sync
            && self.support.is_available()
            && self.unsatisfied_prerequisite().is_none()
    }

    /// Whether this capability produces evidence about actions on its domain.
    ///
    /// True for enforcing controls as well: enforcing implies knowing.
    pub fn can_observe(&self) -> bool {
        self.support.is_available()
            && matches!(self.mediation, Mediation::Enforce | Mediation::Observe)
            && self.timing != DecisionTiming::None
    }

    /// The strongest [`ClaimTerm`] this capability could support *if exercised*.
    ///
    /// A ceiling, not a claim. It says what a decision from this control would
    /// be permitted to be called; it does not assert any decision happened.
    /// Only [`crate::evidence::EnforcementEvidence`] can assert that, and it
    /// requires an [`crate::evidence::EvidenceKind::Decision`] record to do so.
    pub fn claim_ceiling(&self) -> ClaimTerm {
        if !self.support.is_available() {
            return ClaimTerm::Unsupported;
        }
        if self.can_prevent() {
            return ClaimTerm::DeniedBeforeExecution;
        }
        match self.mediation {
            Mediation::Enforce | Mediation::Observe => ClaimTerm::Observed,
            Mediation::None => ClaimTerm::Unmeasured,
        }
    }
}

/// Whether a backend can be used on this host at all.
///
/// Kept out of [`crate::evidence::EnforcementEvidence`] on purpose. Availability
/// is a fact about the host discovered before any run; enforcement evidence is a
/// fact about one run. ADR 0035's validation bar — "E6 output never promotes
/// `available`/`configured`/`observed` into `enforced` without evidence" — is
/// easiest to hold when the two cannot be read out of the same object.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum BackendAvailability {
    /// The backend can be selected on this host.
    Available,
    /// The backend cannot be selected on this host.
    Unavailable {
        /// Why, in words an operator can act on.
        reason: String,
    },
}

impl BackendAvailability {
    /// Whether the backend can be selected.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Returned when a [`BackendCapabilities`] is built with two reports for the
/// same domain.
///
/// A hard error rather than a last-one-wins merge: two answers for one domain
/// means one of them is wrong, and silently choosing between them would decide
/// a prevention question by declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateDomain(pub CapabilityDomain);

impl fmt::Display for DuplicateDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "duplicate capability report for domain `{}`", self.0)
    }
}

impl std::error::Error for DuplicateDomain {}

/// A backend's complete machine-readable statement of what it can do here.
///
/// ADR 0035 §2 calls this object `CapabilitySet`; it is renamed here because
/// [`aa_core::capability::CapabilitySet`] already means the nine-capability
/// policy set. See the crate-level documentation.
///
/// A domain with no report is *unknown*, not *unsupported* — [`report_for`]
/// returns `None` and [`crate::plan::negotiate`] refuses a required prevention
/// requirement against it. A backend that means "no mechanism" must say so with
/// [`CapabilityReport::unsupported`].
///
/// [`report_for`]: Self::report_for
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BackendCapabilities {
    availability: BackendAvailability,
    platform_boundary: PlatformBoundary,
    reports: Vec<CapabilityReport>,
}

impl BackendCapabilities {
    /// Build a capability set, rejecting duplicate domains.
    ///
    /// # Errors
    ///
    /// [`DuplicateDomain`] if two reports name the same [`CapabilityDomain`].
    pub fn new(
        availability: BackendAvailability,
        platform_boundary: PlatformBoundary,
        reports: Vec<CapabilityReport>,
    ) -> Result<Self, DuplicateDomain> {
        for (index, report) in reports.iter().enumerate() {
            if reports[..index].iter().any(|r| r.domain == report.domain) {
                return Err(DuplicateDomain(report.domain));
            }
        }
        Ok(Self {
            availability,
            platform_boundary,
            reports,
        })
    }

    /// Whether the backend can be selected on this host.
    pub fn availability(&self) -> &BackendAvailability {
        &self.availability
    }

    /// The kind of kernel boundary this backend places around the agent.
    pub fn platform_boundary(&self) -> PlatformBoundary {
        self.platform_boundary
    }

    /// Every report, in declaration order.
    pub fn reports(&self) -> &[CapabilityReport] {
        &self.reports
    }

    /// The report for one domain, or `None` if the backend said nothing about
    /// it.
    pub fn report_for(&self, domain: CapabilityDomain) -> Option<&CapabilityReport> {
        self.reports.iter().find(|r| r.domain == domain)
    }

    /// Domains this backend said nothing about.
    ///
    /// Useful in `--dry-run` output: an unreported domain is a gap in the
    /// backend's self-description, and an operator should be able to see it
    /// without diffing against [`CapabilityDomain::ALL`] by hand.
    pub fn unreported_domains(&self) -> Vec<CapabilityDomain> {
        CapabilityDomain::ALL
            .iter()
            .copied()
            .filter(|d| self.report_for(*d).is_none())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CapabilityDomain::ALL` is hand-maintained, so a new variant could be
    /// added without it and silently vanish from every sweep that iterates it.
    ///
    /// This test has to live inside the crate: `CapabilityDomain` is
    /// `#[non_exhaustive]`, so an integration test in `tests/` would be forced
    /// to write a wildcard arm and the match below would stop being exhaustive
    /// — which is the entire mechanism being relied on here.
    #[test]
    fn all_lists_every_domain() {
        // Exhaustive by compiler enforcement: adding a variant fails to compile
        // here until it is handled, at which point the count assertion fails
        // until it is also added to `ALL`.
        let count = CapabilityDomain::ALL
            .iter()
            .map(|domain| match domain {
                CapabilityDomain::FilesystemRead
                | CapabilityDomain::FilesystemWrite
                | CapabilityDomain::NetworkEgress
                | CapabilityDomain::NameResolution
                | CapabilityDomain::Syscall
                | CapabilityDomain::ProcessCreation
                | CapabilityDomain::Ipc
                | CapabilityDomain::Credential
                | CapabilityDomain::Resource => 1,
            })
            .sum::<usize>();
        assert_eq!(count, 9, "CapabilityDomain::ALL is missing a variant");
        assert_eq!(CapabilityDomain::ALL.len(), count);

        // No duplicates, which would make `unreported_domains` over-count.
        let mut seen = CapabilityDomain::ALL.to_vec();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), CapabilityDomain::ALL.len());
    }
}
