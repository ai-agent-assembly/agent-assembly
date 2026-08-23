//! What this backend reports it can do, and what each value is standing on.
//!
//! # The rule every report here follows
//!
//! Mirrors `aa_isolation_native::capability`'s own rule exactly, because this
//! backend delegates its actual confinement to that crate's launcher running
//! inside the guest: a domain is reported as able to prevent **only when a
//! denial was observed on this host** — not when an artifact exists on disk,
//! not when a helper is codesigned, not when a wire message calls itself
//! `GuestReady`. The only input to the verdict is [`crate::probe`], which
//! runs a controlled pair of confined launches through a real guest and
//! reports whether the boundary stopped one of them.
//!
//! Every preventable domain carries a [`Prerequisite`] whose status comes
//! from its probe, and `CapabilityReport::can_prevent` requires it
//! satisfied. So an unmeasured domain cannot satisfy a prevention
//! requirement, and `aa_isolation::negotiate` refuses the launch before the
//! guest boots.
//!
//! # Why only two domains are measured, and the rest borrow their reason
//!
//! This backend's [`crate::MacosVmBackend::spawn`] delegates grant
//! computation to `aa_isolation_native::permitted_scope`, which in turn
//! calls that crate's own `lower_requirement` — the same lowering the native
//! backend uses on Linux. A domain that lowering cannot express here is
//! unsupported for the identical reason it is unsupported there, so this
//! module reads that reason rather than restating an independent one that
//! could drift from the code actually deciding it.
//!
//! # Why the syscall domain is unsupported without a probe attempt
//!
//! `spawn` always sends `syscall_filter: None` on the wire
//! (`aa_isolation_native`'s syscall filter is built for x86_64 syscall
//! numbers only, and this guest is aarch64) — there is nothing installed to
//! measure. Reporting it unsupported without spending a launch on it mirrors
//! the native backend's own report for a host whose kernel cannot support
//! the filter at all: `SupportLevel::Unsupported` needs no measurement,
//! only a true statement about what is not installed.

use aa_isolation::{
    BackendAvailability, BackendCapabilities, CapabilityDomain, CapabilityReport, ControlRequirement, DecisionTiming,
    DescendantCoverage, FailurePosture, Mediation, PlatformBoundary, Prerequisite, PrerequisiteStatus, SupportLevel,
    Synchrony,
};
use aa_isolation_native::lower::lower_requirement;

use crate::probe::{GuestProbe, Observation};

/// Build the capability set for a host this backend cannot be used on at
/// all (see [`crate::MacosVmBackend::discover`]'s own prerequisite checks).
pub fn unavailable(reason: impl Into<String>) -> BackendCapabilities {
    let reason = reason.into();
    let reports = CapabilityDomain::ALL
        .iter()
        .map(|domain| CapabilityReport::unsupported(*domain, reason.clone()))
        .collect();
    BackendCapabilities::new(
        BackendAvailability::Unavailable { reason },
        PlatformBoundary::GuestKernel,
        reports,
    )
    .expect("CapabilityDomain::ALL contains no duplicates")
}

/// Build the capability set from a measured [`GuestProbe`].
pub fn discover(probe: &GuestProbe) -> BackendCapabilities {
    let mut reports = vec![filesystem_read(probe), filesystem_write(probe), syscall_unsupported()];
    for domain in CapabilityDomain::ALL {
        if matches!(
            domain,
            CapabilityDomain::FilesystemRead | CapabilityDomain::FilesystemWrite | CapabilityDomain::Syscall
        ) {
            continue;
        }
        let reason = match lower_requirement(&ControlRequirement::prevent(*domain)) {
            Err(gap) => format!(
                "the guest-side launcher this backend delegates to reports: {}",
                gap.reason
            ),
            // Unreachable while `lower_requirement` expresses exactly the two
            // filesystem domains skipped above. Stated rather than
            // `unreachable!` so a future lowering branch that starts
            // answering a domain surfaces as an honest report instead of a
            // panic.
            Ok(_) => format!(
                "this backend can lower a `{domain}` requirement but reports no measured capability for \
                 the domain; nothing was measured, so nothing is claimed"
            ),
        };
        reports.push(CapabilityReport::unsupported(*domain, reason));
    }
    BackendCapabilities::new(BackendAvailability::Available, PlatformBoundary::GuestKernel, reports)
        .expect("each domain is reported exactly once")
}

/// A prerequisite whose status is the probe's verdict — the single place a
/// measurement becomes a permission to claim prevention.
fn measured(requirement: &str, observation: &Observation) -> Prerequisite {
    Prerequisite {
        requirement: requirement.to_string(),
        status: match observation {
            Observation::Denied => PrerequisiteStatus::Satisfied,
            Observation::Permitted => PrerequisiteStatus::Unsatisfied {
                detail: observation.describe(),
            },
            // `Unchecked`, not `Unsatisfied`: the contract treats both as not
            // satisfied, and keeping them apart preserves the difference
            // between "this guest does not enforce it" and "nobody looked",
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
/// `FailClosed` is justified by this backend's own structure, mirroring
/// `aa_isolation_native::capability::posture`'s own rationale: there is
/// exactly one code path that starts the caller's program inside the guest,
/// it always starts it through the guest's own launcher, and that launcher
/// installs the boundary before it `execve`s anything and refuses without
/// executing if it cannot.
fn posture(observation: &Observation) -> FailurePosture {
    if observation.is_denied() {
        FailurePosture::FailClosed
    } else {
        FailurePosture::NotApplicable
    }
}

/// Support level for a measured domain: available when observed, and
/// explicitly unsupported when the probe found the action went through.
fn support(observation: &Observation, limitations: Vec<String>) -> SupportLevel {
    if matches!(observation, Observation::Permitted) {
        return SupportLevel::Unsupported {
            reason: format!(
                "the probe watched this action succeed under confinement in this guest — {}",
                observation.describe()
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
        "the permitted set is a list of path subtrees, mapped through `crate::paths::to_guest_path` \
         from the launch's own working directory; anything outside the shared directory and outside \
         `crate::paths::GUEST_RESIDENT_PROGRAMS` is refused before the guest boots, never silently \
         dropped (AAASM-5849 tracks the guest image having no general toolchain to reach beyond that)"
            .to_string(),
        "what was measured is the virtiofs share this launch's working directory is mounted at — a \
         grant on a guest-resident program's own path (the implicit exec grant every launch carries) is \
         not what this probe measured"
            .to_string(),
        "descendant coverage was observed to one nesting level (a grandchild of the launched process); \
         deeper process trees are not separately measured"
            .to_string(),
        "the guest's Landlock ABI version is not reported to the host by this backend's wire protocol \
         (AAASM-5837, protocol v1), so the device-ioctl-right ABI gap `aa_isolation_native`'s own write \
         domain states for its host is not independently measured here either — it is inherited, not \
         re-verified"
            .to_string(),
    ]
}

fn filesystem_read(probe: &GuestProbe) -> CapabilityReport {
    CapabilityReport::new(
        CapabilityDomain::FilesystemRead,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_failure_posture(posture(&probe.filesystem_read))
    .with_descendants(descendants(&probe.filesystem_read))
    .with_support(support(&probe.filesystem_read, shared_limitations()))
    .with_prerequisite(measured(
        "the guest's kernel denies a read of a path the launch did not grant, to a descendant of the \
         launched process, before the read takes effect",
        &probe.filesystem_read,
    ))
}

fn filesystem_write(probe: &GuestProbe) -> CapabilityReport {
    let mut limitations = shared_limitations();
    limitations.push(
        "creation, rename, write and deletion are all governed by the same path grant; the contract's \
         filesystem-write domain cannot ask for one and not the others, and neither can this backend"
            .to_string(),
    );
    CapabilityReport::new(
        CapabilityDomain::FilesystemWrite,
        Mediation::Enforce,
        DecisionTiming::Pre,
        Synchrony::Sync,
    )
    .with_failure_posture(posture(&probe.filesystem_write))
    .with_descendants(descendants(&probe.filesystem_write))
    .with_support(support(&probe.filesystem_write, limitations))
    .with_prerequisite(measured(
        "the guest's kernel denies a write to a path the launch did not grant, to a descendant of the \
         launched process, before the write takes effect",
        &probe.filesystem_write,
    ))
}

/// The syscall domain is unsupported without spending a probe launch on it —
/// see this module's own documentation on why.
fn syscall_unsupported() -> CapabilityReport {
    CapabilityReport::unsupported(
        CapabilityDomain::Syscall,
        "this backend's spawn always sends `syscall_filter: None` on the wire — \
         `aa_isolation_native`'s syscall filter is built for x86_64 syscall numbers only, and the guest \
         this backend boots is aarch64"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_isolation::{permit_only_selector, ExecutionSpec, IdentityRef, RequirementScope};

    fn denied_everything() -> GuestProbe {
        GuestProbe {
            filesystem_read: Observation::Denied,
            filesystem_write: Observation::Denied,
        }
    }

    /// The load-bearing property of the module. A domain whose probe was
    /// inconclusive must not be able to prevent anything, however complete
    /// the rest of its report looks.
    #[test]
    fn an_unmeasured_domain_cannot_prevent() {
        let probe = GuestProbe::unmeasured("no measurement was taken");
        let capabilities = discover(&probe);
        for report in capabilities.reports() {
            assert!(
                !report.can_prevent(),
                "{} claimed prevention with no measurement behind it",
                report.domain()
            );
        }
    }

    /// The control for the test above: with the same code and a probe that
    /// observed denials, the filesystem domains do claim prevention.
    #[test]
    fn a_measured_filesystem_domain_can_prevent() {
        let capabilities = discover(&denied_everything());
        for domain in [CapabilityDomain::FilesystemRead, CapabilityDomain::FilesystemWrite] {
            let report = capabilities.report_for(domain).expect("every domain is reported");
            assert!(report.can_prevent(), "{domain} was measured and still cannot prevent");
            assert_eq!(report.descendants(), DescendantCoverage::ProcessTree);
            assert_eq!(report.failure_posture(), FailurePosture::FailClosed);
        }
    }

    /// The two filesystem domains are measured independently: a probe that
    /// watched the write succeed must withdraw the write claim and leave the
    /// read claim alone.
    #[test]
    fn a_permitted_write_withdraws_only_the_write_claim() {
        let mut probe = denied_everything();
        probe.filesystem_write = Observation::Permitted;
        let capabilities = discover(&probe);

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

    #[test]
    fn every_domain_is_reported_so_none_reads_as_merely_unknown() {
        let capabilities = discover(&denied_everything());
        assert!(
            capabilities.unreported_domains().is_empty(),
            "unreported: {:?}",
            capabilities.unreported_domains()
        );
    }

    /// Everything but the two filesystem domains is unsupported by
    /// construction, and must be, or a requirement nothing here implements
    /// would plan successfully.
    #[test]
    fn every_domain_this_version_does_not_implement_is_unsupported() {
        let capabilities = discover(&denied_everything());
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

    #[test]
    fn the_syscall_domain_is_unsupported_and_names_the_architecture_mismatch() {
        let capabilities = discover(&denied_everything());
        let report = capabilities.report_for(CapabilityDomain::Syscall).expect("reported");
        let SupportLevel::Unsupported { reason } = report.support() else {
            panic!("{report:?}");
        };
        assert!(reason.contains("aarch64"), "{reason}");
        assert!(!report.can_prevent());
    }

    #[test]
    fn an_unavailable_host_reports_no_preventable_domain() {
        let capabilities = unavailable("this host is not configured");
        assert!(!capabilities.availability().is_available());
        for report in capabilities.reports() {
            assert!(!report.can_prevent());
        }
    }

    #[test]
    fn narrowing_marks_only_the_requirement_that_cannot_be_lowered() {
        let base = discover(&denied_everything());
        let scoped = ExecutionSpec::new("/bin/true", IdentityRef::root("a")).with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
                .with_scope(RequirementScope::Selectors(vec![permit_only_selector("/workspace")])),
        );
        assert!(aa_isolation_native::capability::narrow_for(&base, &scoped)
            .report_for(CapabilityDomain::FilesystemWrite)
            .unwrap()
            .can_prevent());

        let unlowerable = ExecutionSpec::new("/bin/true", IdentityRef::root("a"))
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::Resource));
        assert!(matches!(
            aa_isolation_native::capability::narrow_for(&base, &unlowerable)
                .report_for(CapabilityDomain::Resource)
                .unwrap()
                .support(),
            SupportLevel::Unsupported { .. }
        ));
    }
}
