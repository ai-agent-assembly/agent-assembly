//! What this backend reports it can do, and what each value is standing on.
//!
//! # The rule every report here follows
//!
//! A domain is reported as able to prevent **only when a denial was observed on
//! this host**. Not when the kernel answers a version query, not when the release
//! string is new enough, not when the security module is listed in `/sys`. Those
//! are inputs to the *message*; the only input to the *verdict* is
//! [`crate::probe`], which runs a controlled pair of confined commands and reports
//! whether the boundary stopped one of them.
//!
//! The mechanism is that every preventable domain carries a [`Prerequisite`]
//! whose status comes from its probe, and [`CapabilityReport::can_prevent`]
//! requires every prerequisite to be satisfied. So an unmeasured domain cannot
//! satisfy a prevention requirement, and `aa_isolation::negotiate` refuses the
//! launch before the child starts.
//!
//! # Seven domains are unsupported on purpose
//!
//! This version installs a filesystem boundary and nothing else. Every other
//! domain is [`SupportLevel::Unsupported`] with the reason
//! [`crate::lower::lower_requirement`] gives for the same domain, and that is a
//! deliberate choice rather than a gap in the measurement: reporting one of them
//! as `Partial` would leave `can_prevent` true and let a requirement nothing here
//! implements plan successfully. AAASM-5803 adds the syscall domain by extending
//! the same launcher; until it does, a required syscall requirement refuses.
//!
//! # Why the write domain carries one prerequisite and not two
//!
//! `truncate(2)` takes a path and needs no writable descriptor, so a host that
//! denies `open(O_WRONLY)` outside the grant and still permits truncation would
//! not support this backend's write claim. That host cannot reach this code: the
//! kernel handles the truncate right only from the ABI this backend's rules are
//! built against, [`crate::rules::REQUIRED_ABI_VERSION`], `crate::host` refuses
//! below it, and `crate::rules::install` asks for the whole right set as a *hard*
//! requirement so it cannot quietly install a boundary missing one.
//!
//! An earlier draft attached a second, probe-backed prerequisite for it. The pair
//! behind that prerequisite used the shell's `> file` redirection, which is
//! `open(O_TRUNC)` — governed by the write right the first prerequisite already
//! measures — so it was the same measurement wearing a second name. It was
//! removed rather than re-worded: the standalone syscall is measured where it can
//! honestly be, in `tests/adversarial_boundary_native_linux.rs`, against a
//! control.

use aa_isolation::{
    BackendAvailability, BackendCapabilities, CapabilityDomain, CapabilityReport, DecisionTiming, DescendantCoverage,
    ExecutionSpec, FailurePosture, Mediation, PlatformBoundary, Prerequisite, PrerequisiteStatus, SupportLevel,
    Synchrony,
};

use crate::host::HostFacts;
use crate::lower::lower_requirement;
use crate::probe::{ConfinementProbe, Observation};

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
pub fn discover(facts: &HostFacts, probe: &ConfinementProbe) -> BackendCapabilities {
    let mut reports = vec![filesystem_read(probe), filesystem_write(facts, probe)];
    for domain in CapabilityDomain::ALL {
        if matches!(
            domain,
            CapabilityDomain::FilesystemRead | CapabilityDomain::FilesystemWrite
        ) {
            continue;
        }
        // The reason a domain is unsupported is the reason lowering gives for
        // refusing it, read from `crate::lower` rather than restated here. Two
        // copies of that sentence would drift, and the one an operator reads
        // would eventually stop being the one that decides.
        let reason = match lower_requirement(&aa_isolation::ControlRequirement::prevent(*domain)) {
            Err(gap) => gap.reason,
            // Unreachable while `lower_requirement` expresses exactly the two
            // filesystem domains skipped above. Stated rather than
            // `unreachable!` so a future lowering branch that starts answering
            // a domain surfaces as an honest report instead of a panic.
            Ok(_) => format!(
                "this backend can lower a `{domain}` requirement but reports no measured capability for \
                 the domain; nothing was measured, so nothing is claimed"
            ),
        };
        reports.push(CapabilityReport::unsupported(*domain, reason));
    }
    BackendCapabilities::new(
        BackendAvailability::Available,
        // The confined process runs on this kernel, restricted in place — there
        // is no guest kernel and no userspace syscall implementation. Stating it
        // is what stops a reader inferring a stronger boundary from the word
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
            // between "this host does not enforce it" and "nobody looked", which
            // need different fixes.
            Observation::Inconclusive { .. } => PrerequisiteStatus::Unchecked,
        },
    }
}

/// Descendant coverage, reported only when a grandchild was the process that got
/// denied.
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
/// kernel's documentation: there is exactly one code path that starts the
/// caller's program, it always starts it as an argument of the launcher, and the
/// launcher installs the boundary before it `execve`s anything and refuses
/// without executing if it cannot. A boundary that could not be established
/// therefore yields no run at all, which is what fail-closed means here.
/// `crate::backend`'s negative-control test is what keeps that true.
fn posture(observation: &Observation) -> FailurePosture {
    if observation.is_denied() {
        FailurePosture::FailClosed
    } else {
        FailurePosture::NotApplicable
    }
}

/// Support level for a measured domain: available when observed, and explicitly
/// unsupported when the probe found the action went through.
fn support(observations: &[&Observation], limitations: Vec<String>) -> SupportLevel {
    if let Some(permitted) = observations.iter().find(|o| matches!(o, Observation::Permitted)) {
        return SupportLevel::Unsupported {
            reason: format!(
                "the probe watched this action succeed under confinement on this host — {}",
                permitted.describe()
            ),
        };
    }
    if limitations.is_empty() {
        SupportLevel::Full
    } else {
        SupportLevel::Partial { limitations }
    }
}

/// Limitations every filesystem domain carries here, whichever verb it is.
fn shared_limitations() -> Vec<String> {
    vec![
        "the permitted set is a list of path subtrees; a requirement that names no path at all is lowered \
         as a total denial, which is stricter than it is precise"
            .to_string(),
        "a descriptor opened before the boundary was installed carries its access with it and is never \
         re-resolved against a rule. `crate::inherit` marks every inherited descriptor close-on-exec and \
         reports any it could not, so what this domain does not cover is stated per run rather than left \
         to be inferred"
            .to_string(),
        "a filesystem mounted over a permitted subtree after the boundary was installed is a different \
         hierarchy from the one the rule was tied to; this domain says nothing about a host where an \
         unprivileged process can mount"
            .to_string(),
    ]
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
    .with_support(support(&[&probe.filesystem_read], shared_limitations()))
    .with_prerequisite(measured(
        "the kernel denies a read of a path the launch did not permit, to a descendant of the launched \
         process, before the read takes effect",
        &probe.filesystem_read,
    ))
}

fn filesystem_write(facts: &HostFacts, probe: &ConfinementProbe) -> CapabilityReport {
    let mut limitations = shared_limitations();
    limitations.push(
        "creation, rename, write and deletion are all governed by the same path grant; the contract's \
         filesystem-write domain cannot ask for one and not the others, and neither can this backend"
            .to_string(),
    );
    limitations.push(format!(
        "the boundary is built against Landlock ABI v{}, so the device-ioctl right added at a later ABI \
         is NOT handled: `ioctl(2)` on a device file the read grant makes reachable is unrestricted here. \
         This host reported {}",
        crate::rules::REQUIRED_ABI_VERSION,
        facts
            .abi_floor()
            .measured()
            .map(|v| format!("ABI v{v}"))
            .unwrap_or_else(|| "no Landlock at all".to_string()),
    ));
    CapabilityReport::new(
        CapabilityDomain::FilesystemWrite,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_failure_posture(posture(&probe.filesystem_write))
    .with_descendants(descendants(&probe.filesystem_write))
    .with_support(support(&[&probe.filesystem_write], limitations))
    .with_prerequisite(measured(
        "the kernel denies a write to a path the launch did not permit, to a descendant of the launched \
         process, before the write takes effect",
        &probe.filesystem_write,
    ))
}

/// Replace a domain's report with an unsupported one when *this* requirement
/// cannot be lowered.
///
/// The general capability report answers "what can this backend do here"; a
/// requirement can still ask for something inside a supported domain that this
/// backend has no way to express. Narrowing is how that becomes a refusal with an
/// actionable reason rather than a rule that approximately means the requirement.
///
/// It changes what the backend *reports*, never what `negotiate` does with the
/// report. The refusal rules stay in one place.
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
    use crate::host::AbiFloor;
    use aa_isolation::{permit_only_selector, ControlRequirement, IdentityRef, RequirementScope};

    fn denied_everything() -> ConfinementProbe {
        ConfinementProbe {
            filesystem_read: Observation::Denied,
            filesystem_write: Observation::Denied,
        }
    }

    fn facts() -> HostFacts {
        HostFacts::for_test("/nonexistent/aa-isolation-launch", AbiFloor::Met { measured: 5 })
    }

    /// The load-bearing property of the module. A domain whose probe was
    /// inconclusive must not be able to prevent anything, however complete the
    /// rest of its report looks.
    #[test]
    fn an_unmeasured_domain_cannot_prevent() {
        let probe = ConfinementProbe::unmeasured("no measurement was taken");
        let capabilities = discover(&facts(), &probe);
        for report in capabilities.reports() {
            assert!(
                !report.can_prevent(),
                "{} claimed prevention with no measurement behind it",
                report.domain()
            );
        }
    }

    /// The control for the test above: with the *same* code and a probe that
    /// observed denials, the filesystem domains do claim prevention. Without this
    /// pair, the assertion above could pass because the reports are broken rather
    /// than because the measurement gates them.
    #[test]
    fn a_measured_filesystem_domain_can_prevent() {
        let capabilities = discover(&facts(), &denied_everything());
        for domain in [CapabilityDomain::FilesystemRead, CapabilityDomain::FilesystemWrite] {
            let report = capabilities.report_for(domain).expect("every domain is reported");
            assert!(report.can_prevent(), "{domain} was measured and still cannot prevent");
            assert_eq!(report.descendants(), DescendantCoverage::ProcessTree);
            assert_eq!(report.failure_posture(), FailurePosture::FailClosed);
        }
    }

    /// The two filesystem domains are measured independently: a probe that
    /// watched the write succeed must withdraw the write claim and leave the read
    /// claim alone. Without the pair, a report that collapsed both on either
    /// observation would pass a single-domain assertion.
    #[test]
    fn a_permitted_write_withdraws_only_the_write_claim() {
        let mut probe = denied_everything();
        probe.filesystem_write = Observation::Permitted;
        let capabilities = discover(&facts(), &probe);

        let write = capabilities
            .report_for(CapabilityDomain::FilesystemWrite)
            .expect("reported");
        assert!(matches!(write.support(), SupportLevel::Unsupported { .. }), "{write:?}");
        assert!(!write.can_prevent());

        let read = capabilities
            .report_for(CapabilityDomain::FilesystemRead)
            .expect("reported");
        assert!(read.can_prevent(), "the read domain lost a claim it does not depend on");
    }

    /// A probe that watched the action succeed is not the same as one that did
    /// not look, and the report must not collapse them.
    #[test]
    fn an_action_observed_to_succeed_is_reported_unsupported_not_unmeasured() {
        let mut probe = denied_everything();
        probe.filesystem_write = Observation::Permitted;
        let capabilities = discover(&facts(), &probe);
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
        let capabilities = discover(&facts(), &denied_everything());
        assert!(
            capabilities.unreported_domains().is_empty(),
            "unreported: {:?}",
            capabilities.unreported_domains()
        );
    }

    /// Everything but the two filesystem domains is unsupported by construction
    /// in this version, and must be, or a requirement nothing implements would
    /// plan successfully.
    #[test]
    fn every_domain_this_version_does_not_implement_is_unsupported() {
        let capabilities = discover(&facts(), &denied_everything());
        for domain in CapabilityDomain::ALL {
            let report = capabilities.report_for(*domain).expect("reported");
            let implemented = matches!(
                domain,
                CapabilityDomain::FilesystemRead | CapabilityDomain::FilesystemWrite
            );
            assert_eq!(
                report.support().is_available(),
                implemented,
                "{domain} reports support that does not match what this version implements"
            );
            if !implemented {
                assert!(!report.can_prevent(), "{domain}");
            }
        }
    }

    /// The syscall domain in particular: it is the next ticket's work, and until
    /// then it must refuse rather than read as partially covered.
    #[test]
    fn the_syscall_domain_is_unsupported_and_says_why() {
        let capabilities = discover(&facts(), &denied_everything());
        let report = capabilities.report_for(CapabilityDomain::Syscall).expect("reported");
        let SupportLevel::Unsupported { reason } = report.support() else {
            panic!("{report:?}");
        };
        assert!(reason.contains("no system-call filter"), "{reason}");
        assert!(!report.can_prevent());
    }

    #[test]
    fn an_unavailable_host_reports_no_preventable_domain() {
        let capabilities = unavailable("this host is not Linux");
        assert!(!capabilities.availability().is_available());
        for report in capabilities.reports() {
            assert!(!report.can_prevent());
        }
    }

    /// Narrowing must turn an unlowerable requirement into an unsupported domain,
    /// so `negotiate` refuses it. The same domain with a lowerable requirement
    /// must be left alone — that pair is what shows the narrowing keys on the
    /// requirement and not on the domain.
    #[test]
    fn narrowing_marks_only_the_requirement_that_cannot_be_lowered() {
        let base = discover(&facts(), &denied_everything());

        let scoped = ExecutionSpec::new("/bin/true", IdentityRef::root("a")).with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
                .with_scope(RequirementScope::Selectors(vec![permit_only_selector("/workspace")])),
        );
        assert!(narrow_for(&base, &scoped)
            .report_for(CapabilityDomain::FilesystemWrite)
            .unwrap()
            .can_prevent());

        let unlowerable = ExecutionSpec::new("/bin/true", IdentityRef::root("a"))
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::Resource));
        assert!(matches!(
            narrow_for(&base, &unlowerable)
                .report_for(CapabilityDomain::Resource)
                .unwrap()
                .support(),
            SupportLevel::Unsupported { .. }
        ));
    }

    #[test]
    fn narrowing_preserves_availability_and_boundary() {
        let base = discover(&facts(), &denied_everything());
        let spec = ExecutionSpec::new("/bin/true", IdentityRef::root("a"));
        let narrowed = narrow_for(&base, &spec);
        assert_eq!(narrowed.availability(), base.availability());
        assert_eq!(narrowed.platform_boundary(), base.platform_boundary());
    }

    /// The unhandled-ioctl gap is a real hole in the write domain and has to be
    /// stated on the report an operator reads, not only in a comment.
    #[test]
    fn the_unhandled_device_ioctl_right_is_a_stated_limitation() {
        let capabilities = discover(&facts(), &denied_everything());
        let report = capabilities
            .report_for(CapabilityDomain::FilesystemWrite)
            .expect("reported");
        let SupportLevel::Partial { limitations } = report.support() else {
            panic!("{report:?}");
        };
        assert!(limitations.iter().any(|l| l.contains("ioctl(2)")), "{limitations:?}");
    }
}
