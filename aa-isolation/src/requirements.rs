//! A versioned, backend-neutral statement of the runtime properties a launch
//! needs — what [`crate::planner`] evaluates candidates against.
//!
//! AAASM-6167 (Epic AAASM-6159, "Agent Execution Runtime 2.0"). Authority: ADR
//! 0035 §3 — *"isolation class is not backend identity"* — carried forward from
//! [`crate::spec::ExecutionSpec`] into a type a policy or operator can build
//! *before* any backend is known, so a caller can ask "give me a backend that
//! satisfies these properties" instead of naming one.
//!
//! # Why this is not a bigger [`ExecutionSpec`]
//!
//! [`ExecutionSpec`] is a real launch: a program, argv, a working directory and
//! an identity, alongside its requirements. [`RuntimeRequirements`] carries none
//! of that — it exists to be evaluated against a *candidate* backend before any
//! of those launch-specific facts are decided, the same way `aa-cli`'s existing
//! `probe_spec` (AAASM-5808) already builds a throwaway [`ExecutionSpec`] from
//! nothing but a lowered requirement set to probe eligibility. [`probe_spec`]
//! is that same throwaway construction, owned here instead of duplicated at
//! every call site.
//!
//! # What is versioned, and why
//!
//! [`RUNTIME_REQUIREMENTS_SCHEMA`] names this type's wire shape the same way
//! [`crate::report::REPORT_SCHEMA`] names [`crate::report::IsolationReport`]'s:
//! a policy or CLI flag that serializes a [`RuntimeRequirements`] needs a stable
//! token to bump when a field's *meaning* changes, not merely when a field is
//! added — [`crate::report`]'s own doc comment on this convention applies here
//! unchanged.
//!
//! # Deferred fields, and why they are still here
//!
//! The ticket's design section lists more properties than this pass wires into
//! [`crate::planner::select`]'s eligibility check. Two are present on this type
//! but not yet evaluated by anything:
//!
//! * [`transactional_workspace_required`](RuntimeRequirements::transactional_workspace_required) —
//!   AAASM-6162 ("transactional COW workspaces") had landed no commits past
//!   `main` at the time this ticket was implemented (`git branch -a` showed the
//!   branch created but empty), so there is no backend-reported capability this
//!   flag could be checked against yet. The field exists so a caller can start
//!   recording the requirement now; wiring it is AAASM-6162's or a follow-up's
//!   job, once a backend has something to report.
//! * Locality/latency constraints are **not** a field at all, deliberately.
//!   Unlike the workspace flag, there is no existing type anywhere in this
//!   crate a locality constraint could even be compared against — no backend
//!   capability reports network topology or launch latency — so adding a field
//!   nothing can ever read would be exactly the "documented more strongly than
//!   its property bundle" failure the ticket's own acceptance criteria forbid
//!   for runtime classes, applied here to a single field instead of a class.
//!   Deferred in full; a future ticket introducing a real locality-reporting
//!   backend capability is where this belongs.
//!
//! [`crate::planner::select`] never treats a deferred property as satisfied —
//! it simply does not read it, so nothing in this type can be misread as an
//! enforced guarantee.
//!
//! [`ExecutionSpec`]: crate::spec::ExecutionSpec
//! [`probe_spec`]: RuntimeRequirements::probe_spec

use std::collections::BTreeMap;

use crate::capability::{CapabilityDomain, FailurePosture, PlatformBoundary};
use crate::egress::EgressContract;
use crate::spec::{ControlRequirement, ExecutionSpec, IdentityRef, ResourceLimits};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The identifier a serialized [`RuntimeRequirements`] is versioned under.
///
/// Bumped when a field's meaning changes in a way that would misread an old
/// document under the new code — not when a field is merely added. Mirrors
/// [`crate::report::REPORT_SCHEMA`]'s own convention.
pub const RUNTIME_REQUIREMENTS_SCHEMA: &str = "aasm.isolation.runtime_requirements/1";

/// A floor on how much a candidate's capability report may fall short of
/// "unconditionally trustworthy" for one [`CapabilityDomain`], independent of
/// whether [`crate::plan::negotiate`] would already accept it.
///
/// # Why this axis is independent of `negotiate`
///
/// [`crate::plan::negotiate`]'s prevention check
/// ([`CapabilityReport::can_prevent`]) reads exactly three axes: mediation,
/// timing and synchrony. It does not read
/// [`FailurePosture`] or [`SupportLevel`] at all — a report can be
/// `Enforce`/`Pre`/`Sync` (and therefore satisfy every
/// [`RequirementIntent::PreventBeforeEffect`] requirement `negotiate` checks)
/// while its failure posture is [`FailurePosture::FailOpenSilent`] — "the worst
/// posture, because the resulting silence is indistinguishable from a clean
/// run", per that variant's own doc comment — or while its
/// [`SupportLevel`] is [`SupportLevel::Partial`] with stated gaps. Neither of
/// those is a `negotiate` refusal. This type is how a caller states a floor on
/// them anyway, which is what lets [`crate::planner::select`] disqualify a
/// candidate `negotiate` alone would accept — the ticket's "required
/// evidence/attestation quality can disqualify a backend" acceptance
/// criterion.
///
/// [`CapabilityReport::can_prevent`]: crate::capability::CapabilityReport::can_prevent
/// [`SupportLevel`]: crate::capability::SupportLevel
/// [`RequirementIntent::PreventBeforeEffect`]: crate::spec::RequirementIntent::PreventBeforeEffect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EvidenceMinimum {
    min_failure_posture: Option<FailurePosture>,
    require_full_support: bool,
}

impl EvidenceMinimum {
    /// No stated floor. The domain is not checked by this axis at all.
    pub fn none() -> Self {
        Self::default()
    }

    /// Require at least this [`FailurePosture`] on the domain.
    ///
    /// "At least" is defined by [`crate::planner`]'s own
    /// `meets_failure_posture_minimum`, not by an [`Ord`] on
    /// [`FailurePosture`] itself — see that function's doc comment for why a
    /// general ordering does not belong on the failure-posture type every
    /// backend's `capability.rs` already uses for other purposes.
    pub fn with_min_failure_posture(mut self, posture: FailurePosture) -> Self {
        self.min_failure_posture = Some(posture);
        self
    }

    /// Require [`SupportLevel::Full`](crate::capability::SupportLevel::Full) —
    /// no stated limitations — on the domain.
    pub fn with_full_support_required(mut self) -> Self {
        self.require_full_support = true;
        self
    }

    /// The stated failure-posture floor, if any.
    pub fn min_failure_posture(&self) -> Option<FailurePosture> {
        self.min_failure_posture
    }

    /// Whether full, unqualified support was required.
    pub fn requires_full_support(&self) -> bool {
        self.require_full_support
    }

    /// Whether this states no floor at all.
    pub fn is_none(&self) -> bool {
        *self == Self::default()
    }
}

/// A versioned, backend-neutral statement of what a launch needs from
/// whichever backend ends up running it.
///
/// Every field here is data a caller can build without knowing which backend,
/// if any, will satisfy it — the structural half of ADR 0035 §3 carried from
/// [`ExecutionSpec`] into a pre-selection type. See the module documentation
/// for which fields [`crate::planner::select`] actually evaluates today and
/// which are recorded but deferred.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RuntimeRequirements {
    confinement: Vec<ControlRequirement>,
    resource_limits: ResourceLimits,
    min_evidence: BTreeMap<CapabilityDomain, EvidenceMinimum>,
    allowed_platform_boundaries: Option<Vec<PlatformBoundary>>,
    transactional_workspace_required: bool,
    egress_contract: Option<EgressContract>,
}

impl RuntimeRequirements {
    /// A requirement set with nothing stated yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a required confinement domain.
    ///
    /// Reuses [`ControlRequirement`] rather than a new type: a confinement
    /// domain is exactly what that type already expresses, and evaluating it
    /// against a candidate is exactly [`crate::plan::negotiate`]'s job — a
    /// second requirement vocabulary here would only invite the two to drift.
    pub fn with_confinement(mut self, requirement: ControlRequirement) -> Self {
        self.confinement.push(requirement);
        self
    }

    /// Set the resource ceilings this launch needs.
    ///
    /// **Not yet evaluated.** The [`CapabilityDomain::Resource`] domain is not
    /// expressible through [`crate::lowering::lower_policy`] as of this ticket
    /// (see that module's own domain-coverage table), so there is nothing a
    /// candidate's capability report could be checked against —
    /// AAASM-6165 ("resource ceilings") owns closing that gap. This field
    /// exists so the value travels with the rest of the requirement set in
    /// the meantime, exactly as [`transactional_workspace_required`] does for
    /// the same reason.
    ///
    /// [`transactional_workspace_required`]: Self::transactional_workspace_required
    pub fn with_resource_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }

    /// State an [`EvidenceMinimum`] for one domain.
    pub fn with_evidence_minimum(mut self, domain: CapabilityDomain, minimum: EvidenceMinimum) -> Self {
        if minimum.is_none() {
            self.min_evidence.remove(&domain);
        } else {
            self.min_evidence.insert(domain, minimum);
        }
        self
    }

    /// Restrict the candidate's [`PlatformBoundary`] to one of these.
    ///
    /// The concrete stand-in for the ticket's "compatibility/runtime needs
    /// (POSIX/fork/toolchain/WASM)" axis: [`PlatformBoundary`] already
    /// distinguishes a shared-host-kernel process boundary from a
    /// userspace-kernel translation layer from a guest-kernel VM, which is
    /// precisely the axis the AAASM-6168/6169/6170 backend spikes (gVisor,
    /// Firecracker, Apple Containerization) differ on and the axis most
    /// likely to break a POSIX/fork-heavy toolchain. Reusing it avoids adding
    /// a second, redundant compatibility vocabulary next to a type that
    /// already exists on [`crate::capability::BackendCapabilities`].
    pub fn with_allowed_platform_boundaries(mut self, boundaries: Vec<PlatformBoundary>) -> Self {
        self.allowed_platform_boundaries = Some(boundaries);
        self
    }

    /// State whether this launch needs a transactional (copy-on-write)
    /// workspace.
    ///
    /// **Not yet evaluated** — see the module documentation.
    pub fn with_transactional_workspace_required(mut self, required: bool) -> Self {
        self.transactional_workspace_required = required;
        self
    }

    /// Every required confinement domain, in declaration order.
    pub fn confinement(&self) -> &[ControlRequirement] {
        &self.confinement
    }

    /// The resource ceilings stated, if any. See
    /// [`with_resource_limits`](Self::with_resource_limits) for why this is
    /// not yet checked against any candidate.
    pub fn resource_limits(&self) -> &ResourceLimits {
        &self.resource_limits
    }

    /// The stated [`EvidenceMinimum`] for `domain`, if any.
    pub fn evidence_minimum(&self, domain: CapabilityDomain) -> Option<&EvidenceMinimum> {
        self.min_evidence.get(&domain)
    }

    /// Every stated evidence minimum, in [`CapabilityDomain`] order —
    /// deterministic, so [`crate::planner::select`]'s rejection order for one
    /// candidate does not depend on hash-map iteration.
    pub fn evidence_minimums(&self) -> impl Iterator<Item = (&CapabilityDomain, &EvidenceMinimum)> {
        self.min_evidence.iter()
    }

    /// The allowed [`PlatformBoundary`] set, when this requirement set
    /// restricts it.
    pub fn allowed_platform_boundaries(&self) -> Option<&[PlatformBoundary]> {
        self.allowed_platform_boundaries.as_deref()
    }

    /// Whether a transactional workspace was requested. See
    /// [`with_transactional_workspace_required`](Self::with_transactional_workspace_required)
    /// for why this is not yet checked against any candidate.
    pub fn transactional_workspace_required(&self) -> bool {
        self.transactional_workspace_required
    }

    /// State this launch's egress contract (AAASM-6163).
    pub fn with_egress_contract(mut self, contract: EgressContract) -> Self {
        self.egress_contract = Some(contract);
        self
    }

    /// This launch's egress contract, when one was stated.
    ///
    /// **Not yet evaluated by [`crate::planner::select`].** No
    /// [`crate::capability::BackendCapabilities`] reports an egress-broker
    /// property, so there is no per-candidate eligibility check this could
    /// feed — it is evaluated once, at `resolve_boundary`, alongside
    /// `authority_gate` via [`crate::egress::egress_gate`], not in candidate
    /// selection. `None` for every launch today, matching
    /// [`crate::egress::EgressContract::not_required`]'s own rc.7-compatible
    /// default.
    pub fn egress_contract(&self) -> Option<&EgressContract> {
        self.egress_contract.as_ref()
    }

    /// A throwaway [`ExecutionSpec`] carrying nothing but this requirement
    /// set's confinement domains, for probing a candidate's eligibility.
    ///
    /// Mirrors `aa-cli`'s own `probe_spec` (AAASM-5808): [`crate::plan::negotiate`]
    /// reads only [`ExecutionSpec::requirements`], never the program, args,
    /// identity, working directory or credentials, so a probe built from
    /// nothing else reaches the identical verdict a real launch's own spec
    /// would against the same candidate.
    pub fn probe_spec(&self) -> ExecutionSpec {
        self.confinement.iter().cloned().fold(
            ExecutionSpec::new("probe", IdentityRef::root("probe")),
            |spec, requirement| spec.with_requirement(requirement),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::FailurePosture;

    #[test]
    fn evidence_minimum_none_is_the_default_and_is_removed_on_write() {
        let requirements = RuntimeRequirements::new()
            .with_evidence_minimum(CapabilityDomain::FilesystemWrite, EvidenceMinimum::none());
        assert!(requirements
            .evidence_minimum(CapabilityDomain::FilesystemWrite)
            .is_none());
    }

    #[test]
    fn evidence_minimums_iterate_in_domain_order() {
        let requirements = RuntimeRequirements::new()
            .with_evidence_minimum(
                CapabilityDomain::NetworkEgress,
                EvidenceMinimum::none().with_min_failure_posture(FailurePosture::FailClosed),
            )
            .with_evidence_minimum(
                CapabilityDomain::FilesystemRead,
                EvidenceMinimum::none().with_min_failure_posture(FailurePosture::FailClosed),
            );
        let domains: Vec<CapabilityDomain> = requirements.evidence_minimums().map(|(d, _)| *d).collect();
        assert_eq!(
            domains,
            vec![CapabilityDomain::FilesystemRead, CapabilityDomain::NetworkEgress]
        );
    }

    #[test]
    fn probe_spec_carries_only_the_confinement_requirements() {
        let requirements =
            RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        let probe = requirements.probe_spec();
        assert_eq!(probe.requirements().len(), 1);
        assert_eq!(probe.requirements()[0].domain(), CapabilityDomain::FilesystemWrite);
    }
}
