//! Process-tree inheritance: what a nested launch may hold, relative to the
//! launch it descends from.
//!
//! # The rule, and where it comes from
//!
//! ADR 0035's threat model, item 4: *"A descendant cannot gain broader authority
//! by ordinary fork/exec. Child and sub-agent processes remain at the same or
//! narrower effective capability scope unless an explicit delegated-capability
//! mechanism is introduced and evidenced."* ADR 0035 §6 states the governance
//! half of the same rule: *"Sub-agent identity may become narrower or more
//! specific at the governance layer, but ordinary process creation must not
//! widen OS capabilities."*
//!
//! Two mechanisms hold that rule, at two different layers, and neither
//! substitutes for the other:
//!
//! | Layer | Who holds it | What it covers |
//! | --- | --- | --- |
//! | Operating system | the backend, measured | An ordinary `fork`/`exec` descendant that makes no request of AASM at all |
//! | Governance | this module | A sub-agent launched *through* AASM, which does get to state requirements |
//!
//! The OS half is a property of the mechanism and is reported per capability as
//! [`DescendantCoverage`]. It is never assumed: [`DescendantCoverage::Unmeasured`]
//! exists precisely so that "nobody looked" cannot read as coverage, and
//! [`negotiate`](crate::plan::negotiate) refuses a
//! [`DescendantRequirement::ProcessTree`] requirement against anything but
//! [`DescendantCoverage::ProcessTree`].
//!
//! The governance half is what this module adds. An agent that cannot escape by
//! calling `fork` can still try to escape by asking AASM to launch a sub-agent
//! on *better terms* — dropping a requirement, downgrading a required control to
//! optional, delegating a credential its parent had removed. Every one of those
//! is a widening that the OS layer has no reason to notice, because from the
//! kernel's point of view it is a fresh, well-formed launch.
//!
//! # What this module does not claim
//!
//! [`authority_widening`] compares two [`ExecutionSpec`]s. It is a check on
//! *what was asked for*, so it can prove a nested launch requested more than its
//! ancestor and it cannot prove a nested launch *received* less. What a launch
//! received is a backend fact and travels through
//! [`EnforcementEvidence`](crate::evidence::EnforcementEvidence). A caller that
//! ran this check and skipped the evidence has verified an intention.

use crate::capability::{CapabilityDomain, DescendantCoverage};
use crate::spec::{ControlRequirement, DescendantRequirement, ExecutionSpec, RequirementIntent, RequirementPosture};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// One way a nested launch asked for more authority than the launch it descends
/// from.
///
/// Fine-grained rather than a single "widened" flag, for the same reason
/// [`RefusalReason`](crate::plan::RefusalReason) is: the operator's next action
/// differs completely between "the sub-agent dropped the filesystem requirement"
/// and "the sub-agent delegated a credential its parent removed".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum AuthorityWidening {
    /// The nested launch does not name its ancestor in its lineage.
    ///
    /// Reported first and separately because it invalidates every other
    /// comparison: without the ancestry, the two specs are unrelated launches
    /// and there is no inheritance relation to check.
    LineageBroken {
        /// The ancestor's agent id, which the descendant's lineage omits.
        ancestor: String,
        /// The descendant's own agent id.
        descendant: String,
    },
    /// The ancestor carried a requirement for this domain and the descendant
    /// carries none.
    RequirementDropped {
        /// The domain left uncovered.
        domain: CapabilityDomain,
    },
    /// The descendant asks a control only to watch what its ancestor's control
    /// had to stop.
    IntentWeakened {
        /// The domain.
        domain: CapabilityDomain,
        /// What the ancestor required.
        ancestor: RequirementIntent,
        /// What the descendant requires.
        descendant: RequirementIntent,
    },
    /// The descendant will proceed where its ancestor would have refused.
    PostureWeakened {
        /// The domain.
        domain: CapabilityDomain,
        /// What the ancestor required.
        ancestor: RequirementPosture,
        /// What the descendant requires.
        descendant: RequirementPosture,
    },
    /// The descendant asks for coverage of itself where its ancestor asked for
    /// coverage of a whole tree.
    ///
    /// A sub-agent that need not confine *its* children re-opens the escape the
    /// tree requirement closed, one level further down.
    DescendantScopeReduced {
        /// The domain.
        domain: CapabilityDomain,
        /// What the ancestor required.
        ancestor: DescendantRequirement,
        /// What the descendant requires.
        descendant: DescendantRequirement,
    },
    /// The descendant hands the child a name that does not reach its ancestor's
    /// child.
    ///
    /// Covers both directions of the credential posture: a name the descendant
    /// *delegates* and a name it merely fails to remove are the same widening
    /// from the child's point of view, because the child can use it either way.
    CredentialWidened {
        /// The environment variable name. Never a value.
        name: String,
    },
}

impl AuthorityWidening {
    /// The domain this widening concerns, if it concerns one.
    pub fn domain(&self) -> Option<CapabilityDomain> {
        match self {
            Self::LineageBroken { .. } => None,
            Self::CredentialWidened { .. } => Some(CapabilityDomain::Credential),
            Self::RequirementDropped { domain }
            | Self::IntentWeakened { domain, .. }
            | Self::PostureWeakened { domain, .. }
            | Self::DescendantScopeReduced { domain, .. } => Some(*domain),
        }
    }
}

/// How strong a requirement is, on the three axes that can be weakened.
///
/// Higher is stricter on every axis, so a descendant is same-or-narrower exactly
/// when each of its components is greater than or equal to its ancestor's.
/// Scope is deliberately absent: [`RequirementScope`] is opaque to this crate,
/// and a comparison over path globs or destination selectors would be the
/// matching semantics the type documentation forbids putting here. That is a
/// real gap and it is stated in [`authority_widening`]'s documentation rather
/// than approximated.
///
/// [`RequirementScope`]: crate::spec::RequirementScope
fn strength(requirement: &ControlRequirement) -> (u8, u8, u8) {
    let intent = match requirement.intent() {
        RequirementIntent::PreventBeforeEffect => 1,
        RequirementIntent::Observe => 0,
    };
    let posture = match requirement.posture() {
        RequirementPosture::Required => 2,
        RequirementPosture::DegradeIfUnavailable => 1,
        RequirementPosture::Optional => 0,
    };
    let descendants = match requirement.descendants() {
        DescendantRequirement::ProcessTree => 1,
        DescendantRequirement::TargetProcessOnly => 0,
    };
    (intent, posture, descendants)
}

/// The strictest requirement a spec states for one domain, if any.
///
/// A spec may state several requirements for one domain, and the effective
/// demand is the strictest of them: a launch that carries both a required
/// prevention and an optional observation of the same domain will refuse if the
/// prevention cannot be met. Comparing anything else — the first, the last, all
/// of them pairwise — would let a descendant widen by adding a weak duplicate.
fn strictest(spec: &ExecutionSpec, domain: CapabilityDomain) -> Option<&ControlRequirement> {
    spec.requirements()
        .iter()
        .filter(|r| r.domain() == domain)
        .max_by_key(|r| strength(r))
}

/// Every name that reaches a spec's child: delegated on purpose, or ambient and
/// unremoved. Both are authority the child holds.
fn reaching_child(spec: &ExecutionSpec) -> Vec<&str> {
    spec.credentials()
        .delegated
        .iter()
        .chain(spec.credentials().ambient_unremoved.iter())
        .map(String::as_str)
        .collect()
}

/// Every way `descendant` asks for more authority than `ancestor`.
///
/// Empty means the nested launch is same-or-narrower **on the axes this crate
/// can compare**, which is the whole of the requirement vocabulary except
/// [`RequirementScope`](crate::spec::RequirementScope). Selector scope is opaque
/// here by design (see [`strength`]), so a descendant that keeps every
/// requirement at full strength while permitting a wider set of paths or
/// destinations passes this check and must still be compared by the backend
/// that understands those selectors. A caller reporting "not widened" on the
/// strength of this function alone is over-reading it.
///
/// Ordering is stable: the lineage check first, then domains in
/// [`CapabilityDomain::ALL`] order, then credentials. Two runs over the same
/// pair produce identical output.
pub fn authority_widening(ancestor: &ExecutionSpec, descendant: &ExecutionSpec) -> Vec<AuthorityWidening> {
    let mut widenings = Vec::new();

    let ancestor_id = &ancestor.identity().agent_id;
    if !descendant.identity().lineage.iter().any(|a| a == ancestor_id) {
        widenings.push(AuthorityWidening::LineageBroken {
            ancestor: ancestor_id.clone(),
            descendant: descendant.identity().agent_id.clone(),
        });
    }

    for domain in CapabilityDomain::ALL.iter().copied() {
        let Some(before) = strictest(ancestor, domain) else {
            // The ancestor demanded nothing here, so nothing the descendant does
            // is a *reduction*. Whether the domain should have been covered at
            // all is a policy-lowering question, answered by
            // `DomainCoverage::PolicyCannotExpress`, not by this comparison.
            continue;
        };
        let Some(after) = strictest(descendant, domain) else {
            widenings.push(AuthorityWidening::RequirementDropped { domain });
            continue;
        };
        if strength(after).0 < strength(before).0 {
            widenings.push(AuthorityWidening::IntentWeakened {
                domain,
                ancestor: before.intent(),
                descendant: after.intent(),
            });
        }
        if strength(after).1 < strength(before).1 {
            widenings.push(AuthorityWidening::PostureWeakened {
                domain,
                ancestor: before.posture(),
                descendant: after.posture(),
            });
        }
        if strength(after).2 < strength(before).2 {
            widenings.push(AuthorityWidening::DescendantScopeReduced {
                domain,
                ancestor: before.descendants(),
                descendant: after.descendants(),
            });
        }
    }

    let inherited = reaching_child(ancestor);
    for name in reaching_child(descendant) {
        if !inherited.contains(&name) {
            widenings.push(AuthorityWidening::CredentialWidened { name: name.to_string() });
        }
    }

    widenings
}

/// Whether a nested launch stays within its ancestor's authority.
///
/// Convenience over [`authority_widening`], with the same stated limitation: it
/// answers for the requirement vocabulary and not for selector scope.
pub fn is_same_or_narrower(ancestor: &ExecutionSpec, descendant: &ExecutionSpec) -> bool {
    authority_widening(ancestor, descendant).is_empty()
}

/// Whether a capability's coverage extends to the descendants ADR 0035 §6 makes
/// part of correctness.
///
/// True only for [`DescendantCoverage::ProcessTree`].
/// [`DescendantCoverage::Unmeasured`] is false alongside
/// [`DescendantCoverage::TargetProcessOnly`], for the reason stated on that
/// variant: an unmeasured boundary is not one anybody can rely on, and treating
/// it as coverage would let a backend meet the requirement by declining to look.
pub fn covers_ordinary_descendants(coverage: DescendantCoverage) -> bool {
    matches!(coverage, DescendantCoverage::ProcessTree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{CredentialPosture, IdentityRef};

    fn parent() -> ExecutionSpec {
        ExecutionSpec::new("/bin/agent", IdentityRef::root("parent"))
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
    }

    fn child_of(parent_id: &str) -> ExecutionSpec {
        ExecutionSpec::new(
            "/bin/sub-agent",
            IdentityRef::root("sub-agent").with_ancestor(parent_id),
        )
    }

    #[test]
    fn an_identical_nested_launch_widens_nothing() {
        let descendant =
            child_of("parent").with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        assert!(is_same_or_narrower(&parent(), &descendant));
    }

    /// The governance direction ADR 0035 §6 permits: identity narrows, authority
    /// does not widen.
    #[test]
    fn a_stricter_nested_launch_widens_nothing() {
        let descendant = child_of("parent")
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress));
        assert_eq!(authority_widening(&parent(), &descendant), []);
    }

    #[test]
    fn dropping_a_requirement_is_a_widening() {
        let descendant = child_of("parent");
        assert_eq!(
            authority_widening(&parent(), &descendant),
            [AuthorityWidening::RequirementDropped {
                domain: CapabilityDomain::FilesystemWrite
            }]
        );
    }

    #[test]
    fn downgrading_a_required_control_to_optional_is_a_widening() {
        let descendant = child_of("parent").with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite).with_posture(RequirementPosture::Optional),
        );
        let widenings = authority_widening(&parent(), &descendant);
        assert_eq!(
            widenings,
            [AuthorityWidening::PostureWeakened {
                domain: CapabilityDomain::FilesystemWrite,
                ancestor: RequirementPosture::Required,
                descendant: RequirementPosture::Optional,
            }]
        );
        assert_eq!(widenings[0].domain(), Some(CapabilityDomain::FilesystemWrite));
    }

    #[test]
    fn downgrading_prevention_to_observation_is_a_widening() {
        let descendant =
            child_of("parent").with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemWrite));
        assert_eq!(
            authority_widening(&parent(), &descendant),
            [AuthorityWidening::IntentWeakened {
                domain: CapabilityDomain::FilesystemWrite,
                ancestor: RequirementIntent::PreventBeforeEffect,
                descendant: RequirementIntent::Observe,
            }]
        );
    }

    /// The escape one level down: a sub-agent that need not confine its own
    /// children.
    #[test]
    fn narrowing_tree_coverage_to_the_target_process_is_a_widening() {
        let descendant = child_of("parent").with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
                .with_descendants(DescendantRequirement::TargetProcessOnly),
        );
        assert_eq!(
            authority_widening(&parent(), &descendant),
            [AuthorityWidening::DescendantScopeReduced {
                domain: CapabilityDomain::FilesystemWrite,
                ancestor: DescendantRequirement::ProcessTree,
                descendant: DescendantRequirement::TargetProcessOnly,
            }]
        );
    }

    /// A weak duplicate must not be able to lower the effective demand, or every
    /// other check here is bypassed by adding one requirement rather than
    /// editing one.
    #[test]
    fn a_weak_duplicate_requirement_does_not_lower_the_effective_demand() {
        let descendant = child_of("parent")
            .with_requirement(
                ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
                    .with_posture(RequirementPosture::Optional),
            )
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        assert_eq!(authority_widening(&parent(), &descendant), []);
    }

    /// A launch that does not name its ancestor is not a descendant, and every
    /// other comparison rests on the claim that it is.
    #[test]
    fn a_missing_lineage_is_reported_before_anything_else() {
        let orphan = ExecutionSpec::new("/bin/sub-agent", IdentityRef::root("sub-agent"))
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        let widenings = authority_widening(&parent(), &orphan);
        assert_eq!(
            widenings[0],
            AuthorityWidening::LineageBroken {
                ancestor: "parent".to_string(),
                descendant: "sub-agent".to_string(),
            }
        );
        assert_eq!(widenings[0].domain(), None);
        // The control: the identical spec *with* the ancestry passes, so the
        // report above is about the lineage and not about the requirements.
        let acknowledged =
            child_of("parent").with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        assert!(is_same_or_narrower(&parent(), &acknowledged));
    }

    /// A credential the parent's child never held must not appear in the
    /// sub-agent's child, whichever list it arrives in.
    #[test]
    fn a_credential_the_ancestor_removed_cannot_be_delegated_by_a_descendant() {
        let ancestor = parent().with_credentials(CredentialPosture {
            removed: vec!["GITHUB_TOKEN".to_string()],
            ..CredentialPosture::default()
        });
        let descendant = child_of("parent")
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
            .with_credentials(CredentialPosture {
                delegated: vec!["GITHUB_TOKEN".to_string()],
                ..CredentialPosture::default()
            });
        assert_eq!(
            authority_widening(&ancestor, &descendant),
            [AuthorityWidening::CredentialWidened {
                name: "GITHUB_TOKEN".to_string()
            }]
        );

        // The control: the same name, delegated by both, is not a widening —
        // otherwise the assertion above would fire for any credential at all.
        let inheriting = ancestor.clone().with_credentials(CredentialPosture {
            delegated: vec!["GITHUB_TOKEN".to_string()],
            ..CredentialPosture::default()
        });
        assert!(is_same_or_narrower(&inheriting, &descendant));
    }

    /// Ambient authority the descendant could not remove is a widening too when
    /// the ancestor's child never had it. "We failed to remove it" is not a
    /// weaker fact than "we chose to pass it" from the child's side.
    #[test]
    fn unremoved_ambient_authority_counts_as_widening() {
        let descendant = child_of("parent")
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
            .with_credentials(CredentialPosture {
                ambient_unremoved: vec!["SSH_AUTH_SOCK".to_string()],
                ..CredentialPosture::default()
            });
        assert_eq!(
            authority_widening(&parent(), &descendant),
            [AuthorityWidening::CredentialWidened {
                name: "SSH_AUTH_SOCK".to_string()
            }]
        );
    }

    /// An unmeasured boundary is not a boundary. Asserted alongside the two
    /// values it must be distinguished from, so a change that collapsed the
    /// three-valued enum would fail here rather than silently widen every
    /// process-tree claim.
    #[test]
    fn only_measured_process_tree_coverage_counts_as_covering_descendants() {
        assert!(covers_ordinary_descendants(DescendantCoverage::ProcessTree));
        assert!(!covers_ordinary_descendants(DescendantCoverage::TargetProcessOnly));
        assert!(!covers_ordinary_descendants(DescendantCoverage::Unmeasured));
    }
}
