//! Measured-versus-asserted host facts (AAASM-6166).
//!
//! The whole point of this module is refusing to let a compile-time constant
//! and a probed value share one name. `build_target_arch` is what this binary
//! was compiled for; it is a fact about the artifact, not about the machine it
//! is currently running on, and calling it `host_arch` would be exactly the
//! overclaim campaign AAASM-6159 exists to prevent (see the parent Epic's own
//! framing, and the AAASM-5528 incident report this repo already carries).
use aa_isolation::{CapabilityReport, IsolationBackend, PlatformBoundary, PrerequisiteStatus, UnmeasuredReason};

use super::text::ReceiptText;

/// A named host or build fact a receipt records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FactName {
    /// What this binary was compiled for. Never the host's own architecture.
    BuildTargetArch,
    /// What OS this binary was compiled for.
    BuildTargetOs,
    /// The architecture the process is actually running on.
    HostArch,
    /// The host kernel's release string.
    KernelRelease,
    /// A guest kernel's release string, for a backend that runs one.
    GuestKernelRelease,
    /// A guest's architecture, for a backend that runs one.
    GuestArch,
    /// The backend's [`PlatformBoundary`].
    PlatformBoundary,
    /// One of the backend's [`CapabilityReport::prerequisites`] entries.
    AbiFloor,
}

/// Where a [`MeasuredFact`]'s value or non-value basis came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FactSource {
    /// Read directly from `/proc/sys/kernel/osrelease`.
    ProcKernelOsrelease,
    /// `std::env::consts::*` — describes the binary, not the running machine.
    BuildTargetConstants,
    /// [`aa_isolation::BackendCapabilities::platform_boundary`].
    BackendCapabilities,
    /// One [`CapabilityReport::prerequisites`] entry.
    BackendPrerequisite,
    /// A hardcoded statement in a backend's own source — nothing was probed.
    BackendSourceAssertion,
}

/// How a fact's value, or absence of one, was established.
///
/// Deliberately **not** [`aa_core::attestation::AttestationBasis`]: that type
/// grades a *protection component's* state for `claim_ceiling`, and a
/// descriptive host fact (a kernel release string) carries no protection claim
/// at all — forcing it into that enum would misfit a safety-critical
/// vocabulary onto a fact that has nothing to do with enforcement. The
/// unmeasured arm reuses [`UnmeasuredReason`] rather than duplicating that
/// vocabulary a third time.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[non_exhaustive]
pub enum FactBasis {
    /// Read from a live probe of this specific run.
    Measured {
        /// What was probed.
        source: FactSource,
    },
    /// Stated without probing — a build-time constant or a backend's own
    /// documented claim about itself.
    Asserted {
        /// What asserted it.
        by: FactSource,
    },
    /// Nothing established a value.
    Unmeasured {
        /// A stable token for the [`UnmeasuredReason`] variant
        /// (`no_backend_selected`/`no_control_requested`/`inconclusive`).
        ///
        /// Stored as a token rather than the enum itself: `aa-isolation` is
        /// depended on with no `serde` feature (see `project.rs`'s module
        /// doc for why), so nothing in this crate can derive
        /// `Serialize`/`Deserialize` over a type it does not implement.
        reason: ReceiptText,
        /// The `Inconclusive` detail sentence, screened, when present.
        detail: Option<ReceiptText>,
    },
}

/// One host or build fact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MeasuredFact {
    /// Which fact this is.
    pub name: FactName,
    /// The value, when [`basis`](Self::basis) is not
    /// [`FactBasis::Unmeasured`].
    pub value: Option<ReceiptText>,
    /// How the value (or its absence) was established.
    pub basis: FactBasis,
}

impl MeasuredFact {
    fn measured(name: FactName, source: FactSource, value: impl Into<String>) -> Self {
        Self {
            name,
            value: Some(ReceiptText::screened(&value.into())),
            basis: FactBasis::Measured { source },
        }
    }

    fn asserted(name: FactName, by: FactSource, value: &'static str) -> Self {
        Self {
            name,
            value: Some(ReceiptText::token(value)),
            basis: FactBasis::Asserted { by },
        }
    }

    fn unmeasured(name: FactName, reason: UnmeasuredReason) -> Self {
        let detail = match &reason {
            UnmeasuredReason::Inconclusive { detail } => Some(ReceiptText::screened(detail)),
            _ => None,
        };
        Self {
            name,
            value: None,
            basis: FactBasis::Unmeasured {
                reason: ReceiptText::token(reason.as_str()),
                detail,
            },
        }
    }
}

/// The stable token for a [`PlatformBoundary`].
///
/// `#[non_exhaustive]` upstream, so this has a wildcard arm — an unrecognized
/// future boundary is reported as `unknown_platform_boundary` rather than
/// failing to build, matching `validate.rs`'s own fail-closed-on-unrecognized
/// discipline for a receipt *reading* an unknown token (this is the writing
/// side of the same fact: a build newer than the vocabulary it links against).
pub(super) fn platform_boundary_token(boundary: PlatformBoundary) -> &'static str {
    match boundary {
        PlatformBoundary::SharedHostKernel => "shared_host_kernel",
        PlatformBoundary::UserspaceKernel => "userspace_kernel",
        PlatformBoundary::GuestKernel => "guest_kernel",
        _ => "unknown_platform_boundary",
    }
}

/// Read `/proc/sys/kernel/osrelease` directly.
///
/// Re-reads the same file `aa-isolation-native` and `aa-isolation-sandlock`
/// already read privately for their own purposes, rather than plumbing a new
/// public accessor out of either crate for one string this module can read
/// itself just as cheaply.
#[cfg(target_os = "linux")]
fn kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(not(target_os = "linux"))]
fn kernel_release() -> Option<String> {
    None
}

/// This run's host and build facts, for `backend`'s [`PlatformBoundary`] and
/// prerequisites.
///
/// Facts that are the same regardless of backend (the two `build_target_*`
/// entries, `host_arch`) are unconditionally unmeasured/asserted per the
/// per-platform table in the AAASM-6166 design — this function does not probe
/// the running host's own architecture, deliberately: nothing in this crate
/// establishes that today, and asserting it from a build constant would be
/// exactly the `host_arch`-from-`build_target_arch` overclaim this module
/// exists to prevent.
pub fn facts(backend: &dyn IsolationBackend) -> Vec<MeasuredFact> {
    let mut facts = vec![
        MeasuredFact::asserted(
            FactName::BuildTargetArch,
            FactSource::BuildTargetConstants,
            std::env::consts::ARCH,
        ),
        MeasuredFact::asserted(
            FactName::BuildTargetOs,
            FactSource::BuildTargetConstants,
            std::env::consts::OS,
        ),
        MeasuredFact::unmeasured(
            FactName::HostArch,
            UnmeasuredReason::Inconclusive {
                detail: "no probe of the running host's own architecture exists in this crate today".to_string(),
            },
        ),
    ];

    let capabilities = backend.capabilities();
    let boundary = capabilities.platform_boundary();
    facts.push(MeasuredFact {
        name: FactName::PlatformBoundary,
        value: Some(ReceiptText::token(platform_boundary_token(boundary))),
        basis: FactBasis::Measured {
            source: FactSource::BackendCapabilities,
        },
    });

    match boundary {
        PlatformBoundary::GuestKernel => {
            facts.push(MeasuredFact::unmeasured(
                FactName::KernelRelease,
                UnmeasuredReason::Inconclusive {
                    detail: "this backend runs a separate guest kernel; the host kernel release is not what \
                             executed the launch"
                        .to_string(),
                },
            ));
            facts.push(MeasuredFact::unmeasured(
                FactName::GuestKernelRelease,
                UnmeasuredReason::Inconclusive {
                    detail: "the backend's guest configuration names a kernel image but nothing reads its version"
                        .to_string(),
                },
            ));
            // aa-isolation-macos-vm's guest is documented in its own source as
            // aarch64 — an assertion, never a probe of the running guest.
            facts.push(MeasuredFact::asserted(
                FactName::GuestArch,
                FactSource::BackendSourceAssertion,
                "aarch64",
            ));
        }
        // `PlatformBoundary` is `#[non_exhaustive]` upstream; an unrecognized
        // future boundary is treated like the two known non-guest boundaries
        // — the conservative reading, since a guest-kernel boundary is the
        // only one that makes the host's own kernel release irrelevant.
        PlatformBoundary::SharedHostKernel | PlatformBoundary::UserspaceKernel | _ => {
            match kernel_release() {
                Some(release) => facts.push(MeasuredFact::measured(
                    FactName::KernelRelease,
                    FactSource::ProcKernelOsrelease,
                    release,
                )),
                None => facts.push(MeasuredFact::unmeasured(
                    FactName::KernelRelease,
                    UnmeasuredReason::Inconclusive {
                        detail: "/proc/sys/kernel/osrelease could not be read on this host".to_string(),
                    },
                )),
            }
            facts.push(MeasuredFact::unmeasured(
                FactName::GuestKernelRelease,
                UnmeasuredReason::NoControlRequested,
            ));
            facts.push(MeasuredFact::unmeasured(
                FactName::GuestArch,
                UnmeasuredReason::NoControlRequested,
            ));
        }
    }

    for report in capabilities.reports() {
        push_abi_floor_facts(&mut facts, report);
    }

    facts
}

fn push_abi_floor_facts(facts: &mut Vec<MeasuredFact>, report: &CapabilityReport) {
    for prerequisite in report.prerequisites() {
        let fact = match &prerequisite.status {
            PrerequisiteStatus::Satisfied => MeasuredFact::measured(
                FactName::AbiFloor,
                FactSource::BackendPrerequisite,
                format!("{}: satisfied", prerequisite.requirement),
            ),
            PrerequisiteStatus::Unsatisfied { detail } => MeasuredFact::measured(
                FactName::AbiFloor,
                FactSource::BackendPrerequisite,
                format!("{}: unsatisfied ({detail})", prerequisite.requirement),
            ),
            PrerequisiteStatus::Unchecked => MeasuredFact::unmeasured(
                FactName::AbiFloor,
                UnmeasuredReason::Inconclusive {
                    detail: format!("{}: not checked", prerequisite.requirement),
                },
            ),
        };
        facts.push(fact);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_isolation::mock::MockBackend;

    #[test]
    fn a_shared_host_kernel_backend_reports_measured_platform_boundary() {
        let backend = MockBackend::inert();
        let facts = facts(&backend);
        let platform = facts.iter().find(|f| f.name == FactName::PlatformBoundary).unwrap();
        assert!(matches!(platform.basis, FactBasis::Measured { .. }));
    }

    #[test]
    fn build_target_arch_is_never_named_host_arch() {
        let backend = MockBackend::inert();
        let facts = facts(&backend);
        let host_arch = facts.iter().find(|f| f.name == FactName::HostArch).unwrap();
        assert!(matches!(host_arch.basis, FactBasis::Unmeasured { .. }));
        assert!(host_arch.value.is_none());
    }

    /// AAASM-6295: the real `aasm-macos-vm` backend's `kernel_release` fact
    /// must be `Unmeasured`, never a fabricated host or guest kernel version
    /// — the guest kernel ran the confined process, not the host's, and this
    /// build never probes the guest's version (see this module's `facts`
    /// doc comment on the `GuestKernel` arm). `MacosVmBackend::discover()`
    /// only inspects env-var configuration and never starts a VM, so this
    /// exercises the real backend crate's `capabilities()`/`platform_boundary()`
    /// logic — not `MockBackend` — without requiring the VM substrate to be
    /// present on this host. Degraded-state truthfulness check for golden
    /// journey J87/J92 (AAASM-6295): confirms this build never claims a
    /// measured kernel release for a guest-kernel boundary, independent of
    /// whether the VM assets (`AA_ISOLATION_MACOS_VM_HELPER`/`_KERNEL`/`_ROOTFS`)
    /// are configured on this host.
    #[test]
    fn a_real_macos_vm_backend_reports_kernel_release_unmeasured_not_fabricated() {
        let backend = aa_isolation_macos_vm::MacosVmBackend::discover();
        let facts = facts(&backend);

        let boundary = facts.iter().find(|f| f.name == FactName::PlatformBoundary).unwrap();
        assert_eq!(
            boundary.value.as_ref().and_then(ReceiptText::as_str),
            Some("guest_kernel"),
            "aasm-macos-vm must report a GuestKernel platform boundary: {boundary:?}"
        );

        let kernel_release = facts.iter().find(|f| f.name == FactName::KernelRelease).unwrap();
        assert!(
            matches!(kernel_release.basis, FactBasis::Unmeasured { .. }),
            "a guest-kernel backend must never report kernel_release as measured or asserted — the \
             host's own kernel never ran the confined process: {kernel_release:?}"
        );
        assert!(
            kernel_release.value.is_none(),
            "an unmeasured kernel_release must carry no value: {kernel_release:?}"
        );
    }
}
