//! Turning policy-derived [`ControlRequirement`]s into this backend's permitted
//! path scope.
//!
//! # There is no parallel policy representation here
//!
//! Every path this backend grants comes from a
//! [`RequirementScope::Selectors`] entry carrying the contract's
//! permitted-set prefix, which `aa_isolation::lower_policy` produced from the
//! canonical `aa_security::policy::filesystem::PathScope` node. Nothing in this
//! module invents a path, reads a configuration file, or consults an environment
//! variable, and [`tests::no_requirement_can_grant_a_path_policy_did_not_name`]
//! sweeps every domain and every scope shape to keep that true against a future
//! branch rather than against today's.
//!
//! # Lowering is total, with an explicit failure arm
//!
//! Most domains cannot be expressed by a filesystem primitive at all. Those
//! return [`LoweringGap`] rather than silently emitting nothing, because a
//! requirement that produced no rule and no complaint is a requirement that
//! reads as satisfied. [`crate::capability::narrow_for`] turns each gap into an
//! unsupported capability report, and `aa_isolation::negotiate` turns that into
//! a refusal before anything starts.
//!
//! # A whole-domain requirement grants nothing, and that is the strictest answer
//!
//! The kernel primitive is default-deny within every access right it is asked to
//! handle, so an empty permitted set denies the entire filesystem for that verb.
//! [`RequirementScope::Whole`] therefore emits no path and says so, rather than
//! being treated as unexpressible.

use std::str::FromStr;

use aa_isolation::{permitted_selector, CapabilityDomain, ControlRequirement, ExecutionSpec, RequirementScope};
use aa_security::policy::syscall::Syscall;

use crate::launch::{Grants, SyscallFilter};

/// A requirement this backend cannot express, and why.
///
/// Carried out of lowering rather than thrown away, so the reason reaches the
/// operator through a capability report and a refusal instead of vanishing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweringGap {
    /// The domain that could not be lowered.
    pub domain: CapabilityDomain,
    /// What this backend can do instead, phrased for someone deciding whether to
    /// change the policy or change the backend.
    pub reason: String,
}

/// Everything one requirement contributed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainLowering {
    /// The paths this requirement permits, by verb.
    pub grants: Grants,
    /// The syscall filter this requirement contributes.
    pub syscalls: SyscallFilter,
    /// A description of what was done, in this backend's own words, for
    /// [`aa_isolation::Lowering`].
    pub steps: Vec<String>,
}

/// Lower one requirement, or report why it cannot be.
///
/// # Errors
///
/// [`LoweringGap`] when this backend cannot express the requirement. This is not
/// "the requirement failed" — nothing has been attempted yet.
pub fn lower_requirement(requirement: &ControlRequirement) -> Result<DomainLowering, LoweringGap> {
    match requirement.domain() {
        CapabilityDomain::FilesystemRead => Ok(filesystem(requirement, Verb::Read)),
        CapabilityDomain::FilesystemWrite => Ok(filesystem(requirement, Verb::Write)),
        CapabilityDomain::Syscall => syscall(requirement),
        CapabilityDomain::NetworkEgress => Err(LoweringGap {
            domain: CapabilityDomain::NetworkEgress,
            reason: "the kernel primitive this backend configures restricts network access by TCP PORT \
                     only, and the contract scopes egress by destination. A port allowlist cannot express \
                     an address or host allowlist, so no rule is emitted; network mediation for this \
                     product is the proxy layer (ADR 0035, `Alternatives considered and rejected`)"
                .to_string(),
        }),
        CapabilityDomain::NameResolution => Err(LoweringGap {
            domain: CapabilityDomain::NameResolution,
            reason: "a filesystem boundary can withhold the resolver's configuration files but cannot \
                     decide a resolution; withholding a file is not a decision about a name, and treating \
                     it as one would report a read denial as a resolution denial"
                .to_string(),
        }),
        CapabilityDomain::ProcessCreation => Err(LoweringGap {
            domain: CapabilityDomain::ProcessCreation,
            reason: "this backend has no process-count ceiling and no rule about which programs may be \
                     executed beyond the paths its filesystem scope makes executable. Denying execute on \
                     every path would stop the launched program itself, so it is not the same control and \
                     is not offered as one"
                .to_string(),
        }),
        CapabilityDomain::Ipc => Err(LoweringGap {
            domain: CapabilityDomain::Ipc,
            reason: "abstract-namespace unix sockets, shared memory and inherited descriptors are outside \
                     the filesystem scope this version installs. The kernel primitive gained an \
                     abstract-socket scope at a later ABI than this backend's floor, and adopting it \
                     would raise the floor for a domain this ticket does not claim"
                .to_string(),
        }),
        CapabilityDomain::Credential => Err(LoweringGap {
            domain: CapabilityDomain::Credential,
            reason: "the child's environment is replaced by the supervisor rather than enforced by the \
                     kernel, so nothing here decides a credential access; what the launch did with the \
                     environment is reported in evidence as a configured fact, which is a weaker and \
                     truthful statement"
                .to_string(),
        }),
        CapabilityDomain::Resource => Err(LoweringGap {
            domain: CapabilityDomain::Resource,
            reason: "this backend imposes no numeric ceiling of any kind — no memory, CPU, process, \
                     wall-clock, file-size or descriptor limit. A filesystem boundary caps nothing \
                     countable, and approximating one would be a control the kernel is not applying"
                .to_string(),
        }),
        // `CapabilityDomain` is `#[non_exhaustive]`: a domain added by a later
        // ticket must refuse here, not fall through to "nothing to do".
        other => Err(LoweringGap {
            domain: other,
            reason: "this backend has no lowering for the domain; it was added to the contract after the \
                     backend was written"
                .to_string(),
        }),
    }
}

/// Which half of the filesystem scope a requirement contributes to.
#[derive(Debug, Clone, Copy)]
enum Verb {
    Read,
    Write,
}

impl Verb {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "readable",
            Self::Write => "writable, creatable, renameable and deletable",
        }
    }
}

/// Filesystem domains: a permitted set of path subtrees, or nothing at all.
fn filesystem(requirement: &ControlRequirement, verb: Verb) -> DomainLowering {
    let domain = requirement.domain();
    let mut grants = Grants::default();
    match requirement.scope() {
        RequirementScope::Selectors(selectors) => {
            let permitted: Vec<&str> = selectors.iter().filter_map(|s| permitted_selector(s)).collect();
            let bare = selectors.len() - permitted.len();
            let target = match verb {
                Verb::Read => &mut grants.read,
                Verb::Write => &mut grants.write,
            };
            for path in &permitted {
                target.insert((*path).to_string());
            }
            let mut steps = vec![format!(
                "{domain}: default-deny; {} path subtree(s) made {} by a kernel rule tied to each path",
                permitted.len(),
                verb.as_str()
            )];
            if bare > 0 {
                // A selector with no permitted-set prefix is not a path this
                // backend may grant — the contract gives selectors no polarity
                // field, and reading a bare string as a grant would invert the
                // requirement's meaning on exactly the inputs where it matters.
                steps.push(format!(
                    "{domain}: {bare} selector(s) carried no permitted-set prefix and were NOT granted; \
                     they remain denied by the default-deny posture"
                ));
            }
            DomainLowering {
                grants,
                syscalls: SyscallFilter::NotRequested,
                steps,
            }
        }
        RequirementScope::Whole => DomainLowering {
            grants,
            syscalls: SyscallFilter::NotRequested,
            steps: vec![format!(
                "{domain}: whole-domain requirement; no path is made {}, so the kernel's default-deny \
                 posture covers the domain entirely",
                verb.as_str()
            )],
        },
        RequirementScope::Limits(_) => DomainLowering {
            grants,
            syscalls: SyscallFilter::NotRequested,
            steps: vec![format!(
                "{domain}: numeric ceilings do not apply to a filesystem domain; no grant emitted, so the \
                 default-deny posture stands"
            )],
        },
    }
}

/// Syscall domain: a permitted syscall set, or an explicit refusal.
///
/// # Why `Whole` and `Limits` refuse rather than expressing "permit nothing"
///
/// A filesystem `Whole` requirement grants no path, which the kernel's own
/// default-deny posture already realizes — nothing further is needed to make
/// that true. A syscall filter has no such free default: the launcher's own
/// `execve` of the confined program needs `crate::seccomp::STARTUP_BASELINE`
/// permitted regardless, and a filter that permitted only the baseline would
/// let the confined program execute nothing else at all, including its own
/// first instruction beyond the loader. That is not "the strictest posture
/// available" the way an empty filesystem grant is — it is a launch that
/// cannot do anything, and refusing names that honestly rather than silently
/// producing an unusable filter.
fn syscall(requirement: &ControlRequirement) -> Result<DomainLowering, LoweringGap> {
    let domain = requirement.domain();
    match requirement.scope() {
        RequirementScope::Selectors(selectors) => {
            let mut permitted = std::collections::BTreeSet::new();
            for selector in selectors {
                let Some(name) = permitted_selector(selector) else {
                    continue;
                };
                let syscall = Syscall::from_str(name).map_err(|_| LoweringGap {
                    domain,
                    reason: format!(
                        "`{name}` is not in `aa_security::policy::syscall::Syscall`'s closed 15-name \
                         vocabulary; a syscall filter can only permit a name the vocabulary recognises"
                    ),
                })?;
                permitted.insert(syscall);
            }
            if permitted.is_empty() {
                return Err(LoweringGap {
                    domain,
                    reason: "every selector this requirement named carried no permitted-set prefix, or \
                             none were named at all; a syscall filter that permits nothing beyond the \
                             startup baseline cannot run the confined program's own code, so this backend \
                             refuses rather than installing one"
                        .to_string(),
                });
            }
            let names: Vec<&str> = permitted.iter().map(|s| s.name()).collect();
            Ok(DomainLowering {
                grants: Grants::default(),
                syscalls: SyscallFilter::Allow(permitted),
                steps: vec![format!(
                    "{domain}: default-deny beyond the startup baseline; {} syscall(s) permitted by policy: {}",
                    names.len(),
                    names.join(", ")
                )],
            })
        }
        RequirementScope::Whole => Err(LoweringGap {
            domain,
            reason: "a whole-domain syscall requirement names no permitted syscall, and this backend's \
                     launcher needs its own startup baseline permitted to reach the confined program at \
                     all; permitting only the baseline is not the strictest expressible posture the way \
                     an empty filesystem grant is, it is a launch that cannot execute anything, so this is \
                     refused rather than silently installed"
                .to_string(),
        }),
        RequirementScope::Limits(_) => Err(LoweringGap {
            domain,
            reason: "numeric ceilings do not name a syscall; a syscall filter is enumerated or nothing".to_string(),
        }),
    }
}

/// Names that policy asked to keep out of the child and that this launch cannot
/// keep out.
///
/// Two sources, and both are real:
///
/// * the spec's own `ambient_unremoved` list — a compatibility exception the
///   caller recorded, which this backend honours by passing the name through;
/// * every name in `removed`, but **only** when `environment_replaced` is false.
///   With no replacement the child inherits the supervisor's environment whole,
///   so a name policy asked to remove is still there, and reporting it as removed
///   would be exactly the failure this Epic exists to prevent.
///
/// `environment_replaced` is a parameter rather than something derived from the
/// posture, because the caller — not the posture — is what decides whether an
/// explicit child environment was installed.
pub fn unremoved_ambient(spec: &ExecutionSpec, environment_replaced: bool) -> Vec<String> {
    let credentials = spec.credentials();
    let mut residue = credentials.ambient_unremoved.clone();
    if !environment_replaced {
        residue.extend(credentials.removed.iter().cloned());
    }
    residue.sort();
    residue.dedup();
    residue
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_isolation::{permit_only_selector, IdentityRef, RequirementIntent, ResourceLimits};

    #[test]
    fn permitted_paths_become_grants_and_bare_selectors_do_not() {
        let requirement = ControlRequirement::prevent(CapabilityDomain::FilesystemRead).with_scope(
            RequirementScope::Selectors(vec![permit_only_selector("/usr"), "/etc/shadow".to_string()]),
        );
        let lowered = lower_requirement(&requirement).expect("expressible");
        assert_eq!(lowered.grants.read.iter().collect::<Vec<_>>(), ["/usr"]);
        assert!(lowered.grants.write.is_empty());
        assert!(
            lowered
                .steps
                .iter()
                .any(|s| s.contains("carried no permitted-set prefix")),
            "the un-prefixed selector must be reported, not silently dropped: {:?}",
            lowered.steps
        );
    }

    /// Read and write are separate verbs, and a read grant must never arrive as
    /// a write grant. The pair is the control.
    #[test]
    fn the_verb_a_requirement_names_is_the_verb_that_is_granted() {
        let scope = RequirementScope::Selectors(vec![permit_only_selector("/workspace")]);
        let read =
            lower_requirement(&ControlRequirement::prevent(CapabilityDomain::FilesystemRead).with_scope(scope.clone()))
                .expect("expressible");
        assert_eq!(read.grants.read.len(), 1);
        assert!(read.grants.write.is_empty(), "a read requirement granted write");

        let write =
            lower_requirement(&ControlRequirement::prevent(CapabilityDomain::FilesystemWrite).with_scope(scope))
                .expect("expressible");
        assert_eq!(write.grants.write.len(), 1);
        assert!(write.grants.read.is_empty(), "a write requirement granted read");
    }

    /// A whole-domain requirement is expressible and grants nothing — the
    /// strictest posture — rather than being a gap.
    #[test]
    fn a_whole_domain_filesystem_requirement_grants_nothing() {
        let lowered = lower_requirement(&ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
            .expect("a whole-domain filesystem requirement is expressible");
        assert!(lowered.grants.is_empty());
        assert!(lowered.steps[0].contains("default-deny"), "{:?}", lowered.steps);
    }

    /// Every domain this version does not implement must be a gap, so a required
    /// requirement for it refuses instead of planning successfully against a
    /// control that is not installed.
    #[test]
    fn every_unimplemented_domain_is_a_gap_rather_than_an_empty_lowering() {
        for domain in CapabilityDomain::ALL {
            let expressible = matches!(
                domain,
                CapabilityDomain::FilesystemRead | CapabilityDomain::FilesystemWrite
            );
            let lowered = lower_requirement(&ControlRequirement::prevent(*domain));
            assert_eq!(
                lowered.is_ok(),
                expressible,
                "{domain} lowered as {:?}, which does not match what this version implements",
                lowered.map(|l| l.steps)
            );
        }
    }

    /// **The property this module exists for.** Swept across every domain and
    /// every scope shape rather than asserted on one example: the risk is a
    /// future lowering branch, and a test that only checks today's branches
    /// would not see it.
    #[test]
    fn no_requirement_can_grant_a_path_policy_did_not_name() {
        let named = ["/workspace", "/usr"];
        let scopes = [
            RequirementScope::Whole,
            RequirementScope::Selectors(vec![
                permit_only_selector("/workspace"),
                permit_only_selector("/usr"),
                // Bare, so it must NOT be granted.
                "/etc/shadow".to_string(),
            ]),
            RequirementScope::Limits(ResourceLimits {
                max_memory_bytes: Some(1),
                ..ResourceLimits::default()
            }),
        ];
        let mut granted: Vec<String> = Vec::new();
        for domain in CapabilityDomain::ALL {
            for scope in &scopes {
                let requirement = ControlRequirement::prevent(*domain).with_scope(scope.clone());
                if let Ok(lowered) = lower_requirement(&requirement) {
                    granted.extend(lowered.grants.read);
                    granted.extend(lowered.grants.write);
                }
            }
        }
        for path in &granted {
            assert!(
                named.contains(&path.as_str()),
                "lowering granted `{path}`, which no permitted-set selector named"
            );
        }
        // The control: the sweep DID produce grants, so the assertion above is
        // not passing over an empty list.
        assert!(!granted.is_empty(), "the sweep granted nothing, so it proved nothing");
        assert!(
            !granted.contains(&"/etc/shadow".to_string()),
            "a bare selector became a grant"
        );
    }

    #[test]
    fn the_intent_of_a_requirement_does_not_change_the_grants_emitted() {
        // Lowering answers "what would this backend do", not "may it". Whether
        // an observe-only requirement is acceptable is `negotiate`'s decision,
        // and duplicating it here is how the two would diverge.
        let prevent = lower_requirement(&ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)).unwrap();
        let observe = lower_requirement(&ControlRequirement::observe(CapabilityDomain::FilesystemWrite)).unwrap();
        assert_eq!(prevent.grants, observe.grants);
        assert_eq!(
            ControlRequirement::observe(CapabilityDomain::FilesystemWrite).intent(),
            RequirementIntent::Observe
        );
    }

    /// A name the posture says could not be removed must come out of
    /// `unremoved_ambient`, and must not be silently absent because the
    /// environment was replaced.
    #[test]
    fn a_compatibility_exception_is_reported_as_residue() {
        let kept =
            ExecutionSpec::new("/bin/true", IdentityRef::root("a")).with_credentials(aa_isolation::CredentialPosture {
                removed: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
                delegated: Vec::new(),
                ambient_unremoved: vec!["PATH".to_string()],
            });
        assert_eq!(unremoved_ambient(&kept, true), ["PATH"]);

        // Negative control: the same variable moved into `removed`, on a launch
        // that replaced the environment, leaves the residue entirely.
        let removed =
            ExecutionSpec::new("/bin/true", IdentityRef::root("a")).with_credentials(aa_isolation::CredentialPosture {
                removed: vec!["AWS_SECRET_ACCESS_KEY".to_string(), "PATH".to_string()],
                delegated: Vec::new(),
                ambient_unremoved: Vec::new(),
            });
        assert!(unremoved_ambient(&removed, true).is_empty());
        // And with no replacement, every removed name is residue again.
        assert_eq!(unremoved_ambient(&removed, false), ["AWS_SECRET_ACCESS_KEY", "PATH"]);
    }
}
