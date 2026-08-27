//! What this backend reports it can do, and what each value is standing on.
//!
//! # The rule every report here follows
//!
//! A domain is reported as able to prevent **only when a denial was observed on
//! this host**. Not when the mechanism documents the feature, not when the
//! kernel release is new enough, not when the security module is listed in
//! `/sys`. Those are inputs to the *message*; the only input to the *verdict*
//! is [`crate::probe`], which runs a controlled pair of confined commands and
//! reports whether the boundary stopped one of them.
//!
//! The mechanism is that every preventable domain carries a
//! [`Prerequisite`] whose status comes from its probe, and
//! [`CapabilityReport::can_prevent`] requires every prerequisite to be
//! satisfied. So an unmeasured domain cannot satisfy a
//! [`RequirementIntent::PreventBeforeEffect`](aa_isolation::RequirementIntent)
//! requirement, and `aa_isolation::negotiate` refuses the launch before the
//! child starts. Under-claiming is the failure direction this is arranged to
//! have.
//!
//! # Two domains are reported as unsupported on purpose
//!
//! [`CapabilityDomain::Syscall`] and [`CapabilityDomain::NameResolution`] are
//! not gaps in the measurement — they are gaps in what the mechanism can be
//! *asked*. The contract scopes a syscall requirement as a permitted set, and
//! the mechanism takes a denied list; the complement of a permitted set is
//! unbounded, so no denied list expresses it. Name resolution is redirected to
//! a pinned hosts file rather than decided. Reporting either as `Partial` would
//! leave `can_prevent` true and let a requirement neither of them can meet plan
//! successfully.
//!
//! # Narrowing, and why it is not the backend deciding
//!
//! [`narrow_for`] replaces a domain's report with an unsupported one when the
//! *specific* requirement in front of it cannot be lowered — a CPU-time
//! ceiling, say, on a mechanism that only caps memory and process count. It
//! changes what the backend *reports*, never what `negotiate` does with the
//! report. The refusal rules stay in one place, which is the whole point of
//! `negotiate` being a free function.

use aa_isolation::{
    BackendAvailability, BackendCapabilities, CapabilityDomain, CapabilityReport, DecisionTiming, DescendantCoverage,
    ExecutionSpec, FailurePosture, Mediation, PlatformBoundary, Prerequisite, PrerequisiteStatus, SupportLevel,
    Synchrony,
};

use crate::host::HostFacts;
use crate::lower::lower_requirement;
use crate::probe::{ConfinementProbe, Observation};

/// The mechanism's own name for the protection that covers
/// [`CapabilityDomain::Ipc`].
///
/// Named here so the one place that decides what a waiver costs is the same
/// place that reports the domain.
pub const ABSTRACT_UNIX_SOCKET_SCOPE: &str = "abstract-unix-socket-scope";

/// The mechanism's own name for the signal-scoping protection.
///
/// Waiving it costs no [`CapabilityDomain`] this backend reports: the contract
/// has no signal axis, so there is no report to weaken. It is named anyway so a
/// caller authorising a waiver on an old host has the vocabulary, and so the
/// omission from the domain table is a decision on the record rather than an
/// oversight.
pub const SIGNAL_SCOPE: &str = "signal-scope";

/// Build the capability set for a host the backend cannot be used on.
pub fn unavailable(reason: impl Into<String>) -> BackendCapabilities {
    let reason = reason.into();
    let reports = CapabilityDomain::ALL
        .iter()
        .map(|domain| CapabilityReport::unsupported(*domain, reason.clone()))
        .collect();
    BackendCapabilities::new(
        BackendAvailability::Unavailable { reason },
        PlatformBoundary::SharedHostKernel,
        reports,
    )
    .expect("CapabilityDomain::ALL contains no duplicates")
}

/// Build the capability set from measured host facts and a measured probe.
///
/// `facts` supplies the words an operator reads; `probe` supplies every verdict.
pub fn discover(facts: &HostFacts, probe: &ConfinementProbe, degraded: &[String]) -> BackendCapabilities {
    let reports = vec![
        filesystem_read(probe),
        filesystem_write(probe),
        network_egress(probe),
        process_creation(probe),
        resource(probe),
        ipc(facts, degraded),
        credential(),
        name_resolution(),
        syscall(),
    ];
    BackendCapabilities::new(
        BackendAvailability::Available,
        // The confined process runs on this kernel, restricted in place — there
        // is no guest kernel and no userspace syscall implementation. Stating
        // it is what stops a reader inferring a stronger boundary from the word
        // "sandbox".
        PlatformBoundary::SharedHostKernel,
        reports,
    )
    .expect("each domain is reported exactly once")
}

/// A prerequisite whose status is the probe's verdict.
///
/// The single place a measurement becomes a permission to claim prevention.
fn measured(requirement: &str, observation: &Observation) -> Prerequisite {
    Prerequisite {
        requirement: requirement.to_string(),
        status: match observation {
            Observation::Denied => PrerequisiteStatus::Satisfied,
            Observation::Permitted => PrerequisiteStatus::Unsatisfied {
                detail: observation.describe(),
            },
            // `Unchecked` rather than `Unsatisfied`: the contract treats both as
            // not satisfied, and keeping them apart preserves the difference
            // between "this host does not enforce it" and "nobody looked",
            // which need different fixes.
            Observation::Inconclusive { .. } => PrerequisiteStatus::Unchecked,
        },
    }
}

/// Descendant coverage, reported only when a grandchild was the process that
/// got denied.
fn descendants(observation: &Observation) -> DescendantCoverage {
    if observation.is_denied() {
        DescendantCoverage::ProcessTree
    } else {
        DescendantCoverage::Unmeasured
    }
}

/// The failure posture of a domain whose denial was observed.
///
/// `FailClosed` is justified by this backend's own structure rather than by the
/// mechanism's documentation: there is exactly one code path that starts the
/// caller's program, it always runs it through the confinement, and a
/// preparation or spawn failure returns an error instead of a process. A
/// boundary that could not be established therefore yields no run at all, which
/// is what fail-closed means here. `crate::backend`'s negative-control test is
/// what keeps that true.
fn posture(observation: &Observation) -> FailurePosture {
    if observation.is_denied() {
        FailurePosture::FailClosed
    } else {
        FailurePosture::NotApplicable
    }
}

/// Support level for a measured domain: available when observed, and explicitly
/// unsupported when the probe found the action went through.
fn support(observation: &Observation, limitations: Vec<String>) -> SupportLevel {
    match observation {
        Observation::Permitted => SupportLevel::Unsupported {
            reason: format!(
                "the probe watched this action succeed under confinement on this host — {}",
                observation.describe()
            ),
        },
        _ if limitations.is_empty() => SupportLevel::Full,
        _ => SupportLevel::Partial { limitations },
    }
}

fn filesystem_read(probe: &ConfinementProbe) -> CapabilityReport {
    CapabilityReport::new(
        CapabilityDomain::FilesystemRead,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_failure_posture(posture(&probe.filesystem_read))
    .with_descendants(descendants(&probe.filesystem_read))
    .with_support(support(
        &probe.filesystem_read,
        vec![
            "the permitted set is a list of path prefixes; a requirement that names no path at all is \
             lowered as a total denial, which is stricter than it is precise"
                .to_string(),
        ],
    ))
    .with_prerequisite(measured(
        "the kernel denies a read of a path the launch did not permit, to a descendant of the launched \
         process, before the read takes effect",
        &probe.filesystem_read,
    ))
}

fn filesystem_write(probe: &ConfinementProbe) -> CapabilityReport {
    CapabilityReport::new(
        CapabilityDomain::FilesystemWrite,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_failure_posture(posture(&probe.filesystem_write))
    .with_descendants(descendants(&probe.filesystem_write))
    .with_support(support(
        &probe.filesystem_write,
        vec![
            "creation, rename and removal are all governed by the same path grant; the contract's \
             filesystem-write domain cannot ask for one and not the others, and neither can this backend"
                .to_string(),
        ],
    ))
    .with_prerequisite(measured(
        "the kernel denies a write to a path the launch did not permit, to a descendant of the launched \
         process, before the write takes effect",
        &probe.filesystem_write,
    ))
}

fn network_egress(probe: &ConfinementProbe) -> CapabilityReport {
    CapabilityReport::new(
        CapabilityDomain::NetworkEgress,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_failure_posture(posture(&probe.network_egress))
    .with_descendants(descendants(&probe.network_egress))
    .with_support(support(
        &probe.network_egress,
        vec![
            "a hostname destination is resolved once when the launch starts and pinned; the permitted \
             set is the addresses observed then, so a name that later resolves elsewhere is denied and \
             a permitted address that later serves someone else is allowed"
                .to_string(),
            "the probe measured one TCP destination on loopback. Nothing here was measured about UDP, \
             ICMP or raw sockets on this host"
                .to_string(),
        ],
    ))
    .with_prerequisite(measured(
        "an outbound connection to a destination the launch did not permit is denied to a descendant of \
         the launched process, before the connection is established",
        &probe.network_egress,
    ))
}

fn process_creation(probe: &ConfinementProbe) -> CapabilityReport {
    CapabilityReport::new(
        CapabilityDomain::ProcessCreation,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_failure_posture(posture(&probe.process_ceiling))
    .with_descendants(descendants(&probe.process_ceiling))
    .with_support(support(
        &probe.process_ceiling,
        vec![
            "the control is a ceiling on how many processes may exist in the confined tree, not a rule \
             about which programs may be executed; a launch that permits two processes cannot say which \
             the second one may be"
                .to_string(),
        ],
    ))
    .with_prerequisite(measured(
        "a process the ceiling did not leave room for never comes into existence",
        &probe.process_ceiling,
    ))
}

fn resource(probe: &ConfinementProbe) -> CapabilityReport {
    CapabilityReport::new(
        CapabilityDomain::Resource,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_failure_posture(posture(&probe.process_ceiling))
    .with_descendants(descendants(&probe.process_ceiling))
    .with_support(support(
        &probe.process_ceiling,
        vec![
            "only two ceilings are expressible: resident memory and process count. CPU time, single-file \
             size and open-descriptor count have no control here and are refused rather than approximated"
                .to_string(),
            "a wall-clock ceiling is a termination after the process has already run, which is detection \
             and not prevention, so it is refused by this domain rather than lowered"
                .to_string(),
            "the ceiling measured on this host is the process count; the memory ceiling is emitted but \
             its enforcement was not observed here"
                .to_string(),
        ],
    ))
    .with_prerequisite(measured(
        "a numeric ceiling stops an action before it takes effect on this host",
        &probe.process_ceiling,
    ))
}

fn ipc(facts: &HostFacts, degraded: &[String]) -> CapabilityReport {
    // A waived protection is a removed control, not a weaker one. Reporting the
    // domain as partially supported would leave `can_prevent` reachable for a
    // control that is not installed at all.
    if degraded.iter().any(|p| p == ABSTRACT_UNIX_SOCKET_SCOPE) {
        return CapabilityReport::unsupported(
            CapabilityDomain::Ipc,
            format!(
                "abstract-namespace unix socket scoping was waived for this launch by explicit \
                 authorisation, because the host cannot provide it (access-control interface {}); the \
                 control is not installed, so nothing on this axis is covered",
                facts
                    .landlock_abi()
                    .map(|abi| format!("version {abi}"))
                    .unwrap_or_else(|| "version unreadable".to_string()),
            ),
        );
    }
    let kernel = facts
        .kernel_release()
        .map(|r| format!("kernel {r}"))
        .unwrap_or_else(|| "an unreadable kernel release".to_string());
    CapabilityReport::new(
        CapabilityDomain::Ipc,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_support(SupportLevel::Partial {
        limitations: vec![
            "only abstract-namespace unix sockets are scoped. Shared memory, pipes, filesystem-backed \
             unix sockets and descriptors passed at launch are not covered by this domain"
                .to_string(),
        ],
    })
    // Deliberately unmeasured. The scoping is applied by the confinement itself
    // with no flag to vary, so the controlled pair this crate uses everywhere
    // else — same command, one flag different — cannot be constructed for it.
    // Rather than report a value from the mechanism's documentation, the domain
    // says nobody looked, and `can_prevent` is false as a result.
    .with_prerequisite(Prerequisite {
        requirement: "abstract-namespace unix socket scoping denies a connection the launch did not \
                      permit"
            .to_string(),
        status: PrerequisiteStatus::Unchecked,
    })
    .with_prerequisite(Prerequisite {
        requirement: format!(
            "no controlled measurement of this domain is possible, because the scoping cannot be turned \
             off for a control run ({kernel})"
        ),
        status: PrerequisiteStatus::Unchecked,
    })
}

/// The authority the child inherits.
///
/// Reported as unmeasured for the same reason as [`ipc`]: the control this
/// backend applies — start from an empty environment and add back only what was
/// named — is a property of the command line, and what reaches the child *in
/// spite of it* (the three standard descriptors, and whatever the supervisor
/// process itself holds outside the boundary) is residue this crate records in
/// evidence rather than something it prevents.
fn credential() -> CapabilityReport {
    CapabilityReport::new(
        CapabilityDomain::Credential,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_support(SupportLevel::Partial {
        limitations: vec![
            "the environment is replaced rather than filtered: the child starts empty and receives only \
             the names the launch delegated. A name policy asked to remove but that nothing delegated is \
             absent because nothing was inherited, not because it was removed"
                .to_string(),
            "standard input, output and error are inherited by design and are not removable without \
             changing what a governed launch means; they are recorded as delegated authority"
                .to_string(),
            "the supervisor process that establishes the boundary runs outside it and keeps the \
             launching process's own authority; this domain says nothing about that process"
                .to_string(),
            // AAASM-5940: this is a permanent limitation of the mechanism's own
            // vocabulary (`--env=NAME=VALUE` on the confinement executable's
            // own argv), not a gap this crate has a plan to close — see
            // `crate::lower::CredentialArgvRefusal`'s documentation. State it
            // here for as long as it remains true rather than only in the
            // refusal a caller may never trigger.
            "when a caller has not resolved an exact child environment itself (via \
             `SandlockBackend::set_child_environment`), a delegated or ambient-unremoved credential's \
             value cannot be delivered at all: the only channel this mechanism exposes for a name-value \
             pair is an argument of the confinement executable's own command line, visible to anything \
             that can read that process's argv, and this crate refuses such a launch rather than exposing \
             the value there"
                .to_string(),
        ],
    })
    .with_prerequisite(Prerequisite {
        requirement: "the child's environment contains only the names the launch delegated".to_string(),
        status: PrerequisiteStatus::Unchecked,
    })
}

fn name_resolution() -> CapabilityReport {
    CapabilityReport::unsupported(
        CapabilityDomain::NameResolution,
        "the mechanism redirects resolution to a hosts file pinned when the launch starts; a redirection \
         is not a decision about a resolution, and there is no control that could refuse one",
    )
}

fn syscall() -> CapabilityReport {
    CapabilityReport::unsupported(
        CapabilityDomain::Syscall,
        "the mechanism applies a fixed denied list of system calls that no launch can widen, plus an \
         optional additional denied list. The contract scopes this domain as a permitted set, whose \
         complement is unbounded, so no denied list expresses one — the domain is reported unsupported \
         rather than partially supported so that a permitted-set requirement is refused instead of \
         being met by a control that does not implement it",
    )
}

/// Replace a domain's report with an unsupported one when *this* requirement
/// cannot be lowered.
///
/// The general capability report answers "what can this backend do here"; a
/// requirement can still ask for something inside a supported domain that the
/// mechanism has no way to express. Narrowing is how that becomes a refusal
/// with an actionable reason rather than a flag that approximately means the
/// requirement.
pub fn narrow_for(base: &BackendCapabilities, spec: &ExecutionSpec) -> BackendCapabilities {
    let mut reports: Vec<CapabilityReport> = base.reports().to_vec();
    for requirement in spec.requirements() {
        let Err(gap) = lower_requirement(requirement) else {
            continue;
        };
        let replacement = CapabilityReport::unsupported(gap.domain, gap.reason);
        match reports.iter().position(|r| r.domain() == gap.domain) {
            Some(index) => reports[index] = replacement,
            None => reports.push(replacement),
        }
    }
    BackendCapabilities::new(base.availability().clone(), base.platform_boundary(), reports)
        .expect("narrowing replaces reports in place and never adds a second one for a domain")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_isolation::{ControlRequirement, IdentityRef, RequirementScope, ResourceLimits};

    fn denied_everything() -> ConfinementProbe {
        ConfinementProbe {
            filesystem_read: Observation::Denied,
            filesystem_write: Observation::Denied,
            process_ceiling: Observation::Denied,
            network_egress: Observation::Denied,
        }
    }

    fn facts() -> HostFacts {
        HostFacts::for_test("/usr/bin/sandlock", "sandlock 0.8.6", None)
    }

    /// The load-bearing property of the module. A domain whose probe was
    /// inconclusive must not be able to prevent anything, however complete the
    /// rest of its report looks.
    #[test]
    fn an_unmeasured_domain_cannot_prevent() {
        let probe = ConfinementProbe::unmeasured("no measurement was taken");
        let capabilities = discover(&facts(), &probe, &[]);
        for domain in [
            CapabilityDomain::FilesystemRead,
            CapabilityDomain::FilesystemWrite,
            CapabilityDomain::NetworkEgress,
            CapabilityDomain::ProcessCreation,
            CapabilityDomain::Resource,
        ] {
            let report = capabilities.report_for(domain).expect("every domain is reported");
            assert!(
                !report.can_prevent(),
                "{domain} claimed prevention with no measurement behind it"
            );
        }
    }

    /// The control for the test above: with the *same* code and a probe that
    /// observed denials, the same domains do claim prevention. Without this
    /// pair, the assertion above could pass because the reports are broken
    /// rather than because the measurement gates them.
    #[test]
    fn a_measured_domain_can_prevent() {
        let capabilities = discover(&facts(), &denied_everything(), &[]);
        for domain in [
            CapabilityDomain::FilesystemRead,
            CapabilityDomain::FilesystemWrite,
            CapabilityDomain::NetworkEgress,
            CapabilityDomain::ProcessCreation,
            CapabilityDomain::Resource,
        ] {
            let report = capabilities.report_for(domain).expect("every domain is reported");
            assert!(report.can_prevent(), "{domain} was measured and still cannot prevent");
            assert_eq!(report.descendants(), DescendantCoverage::ProcessTree);
        }
    }

    /// A probe that watched the action succeed is not the same as one that did
    /// not look, and the report must not collapse them.
    #[test]
    fn an_action_observed_to_succeed_is_reported_unsupported_not_unmeasured() {
        let mut probe = denied_everything();
        probe.filesystem_write = Observation::Permitted;
        let capabilities = discover(&facts(), &probe, &[]);
        let report = capabilities
            .report_for(CapabilityDomain::FilesystemWrite)
            .expect("reported");
        assert!(
            matches!(report.support(), SupportLevel::Unsupported { .. }),
            "{report:?}"
        );
    }

    #[test]
    fn every_domain_is_reported_so_none_reads_as_merely_unknown() {
        let capabilities = discover(&facts(), &denied_everything(), &[]);
        assert!(
            capabilities.unreported_domains().is_empty(),
            "unreported: {:?}",
            capabilities.unreported_domains()
        );
    }

    #[test]
    fn syscall_and_name_resolution_are_unsupported_by_construction() {
        let capabilities = discover(&facts(), &denied_everything(), &[]);
        for domain in [CapabilityDomain::Syscall, CapabilityDomain::NameResolution] {
            let report = capabilities.report_for(domain).expect("reported");
            assert!(matches!(report.support(), SupportLevel::Unsupported { .. }));
            assert!(!report.can_prevent());
        }
    }

    #[test]
    fn an_unavailable_host_reports_no_preventable_domain() {
        let capabilities = unavailable("this host is not Linux");
        assert!(!capabilities.availability().is_available());
        for report in capabilities.reports() {
            assert!(!report.can_prevent());
        }
    }

    /// Narrowing must turn an unlowerable requirement into an unsupported
    /// domain, so `negotiate` refuses it. The same domain with a lowerable
    /// requirement must be left alone — that pair is what shows the narrowing
    /// keys on the requirement and not on the domain.
    #[test]
    fn narrowing_marks_only_the_requirement_that_cannot_be_lowered() {
        let base = discover(&facts(), &denied_everything(), &[]);
        let cpu_ceiling = ExecutionSpec::new("/bin/true", IdentityRef::root("a")).with_requirement(
            ControlRequirement::prevent(CapabilityDomain::Resource).with_scope(RequirementScope::Limits(
                ResourceLimits {
                    max_cpu_seconds: Some(5),
                    ..ResourceLimits::default()
                },
            )),
        );
        let narrowed = narrow_for(&base, &cpu_ceiling);
        assert!(matches!(
            narrowed.report_for(CapabilityDomain::Resource).unwrap().support(),
            SupportLevel::Unsupported { .. }
        ));

        let memory_ceiling = ExecutionSpec::new("/bin/true", IdentityRef::root("a")).with_requirement(
            ControlRequirement::prevent(CapabilityDomain::Resource).with_scope(RequirementScope::Limits(
                ResourceLimits {
                    max_memory_bytes: Some(1 << 20),
                    ..ResourceLimits::default()
                },
            )),
        );
        let untouched = narrow_for(&base, &memory_ceiling);
        assert!(untouched.report_for(CapabilityDomain::Resource).unwrap().can_prevent());
    }

    #[test]
    fn narrowing_preserves_availability_and_boundary() {
        let base = discover(&facts(), &denied_everything(), &[]);
        let spec = ExecutionSpec::new("/bin/true", IdentityRef::root("a"));
        let narrowed = narrow_for(&base, &spec);
        assert_eq!(narrowed.availability(), base.availability());
        assert_eq!(narrowed.platform_boundary(), base.platform_boundary());
    }
}
