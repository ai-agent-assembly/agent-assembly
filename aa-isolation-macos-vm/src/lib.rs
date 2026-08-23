//! A macOS process-isolation backend for Agent Assembly (AAASM-5813).
//!
//! Implements [`aa_isolation::IsolationBackend`] by delegating confinement to
//! `aa-isolation-native` running inside a Virtualization.framework Linux
//! guest (the substrate AAASM-5812 built and proved: a Landlock-capable
//! kernel, `guest-init`, and a vsock channel — see
//! `aa-isolation-macos-vm-poc/README.md`).
//!
//! # This backend reports `Unavailable` on every host today, and that is correct
//!
//! Two things AC1 needs do not exist yet, and this crate does not pretend
//! otherwise:
//!
//! 1. **No launch protocol.** AAASM-5812's vsock channel exchanges a fixed
//!    hello/reply greeting; nothing on either end accepts "launch this
//!    program with these grants" and returns a disposition. `guest-init` runs
//!    a hardcoded scenario list, not an arbitrary confined launch. Building
//!    that protocol — both ends — is tracked separately; see the crate-level
//!    tracking note in the Jira ticket, not restated here since a comment
//!    cannot stay in sync with a ticket's status.
//! 2. **No entitlement on any binary this repo ships.** `.github/workflows/release.yml`
//!    signs `aasm` with `codesign --sign "$APPLE_DEVELOPER_ID"` and no
//!    `--entitlements` flag, so a released `aasm` cannot be granted
//!    `com.apple.security.virtualization` and therefore cannot create a
//!    `VZVirtualMachine` — confirmed by the `VZErrorDomain Code=2` failure the
//!    PoC hit on every unsigned build, fixed there only by hand-running
//!    `codesign --entitlements ... --force` after each build.
//!
//! Reporting [`aa_isolation::BackendAvailability::Available`] with neither of
//! those in place would be exactly the false claim ADR 0035 §4 exists to
//! prevent — the trait's own [`aa_isolation::IsolationBackend::capabilities`]
//! doc calls this "discovery, not a claim about any run", and the honest
//! discovery on every host reachable today is that this backend cannot run
//! one. [`MacosVmBackend::discover`] measures exactly that and nothing more:
//! it does not probe Virtualization.framework, the guest image, or codesigning
//! status per-host, because the answer is already `Unavailable` for a
//! host-independent reason (the protocol) that no host-specific probe can
//! change. Per-host prerequisite probing (guest image presence, entitlement
//! on *this* binary) is worth adding once the protocol exists to make
//! `Available` a reachable outcome at all — probing prerequisites for a
//! capability this crate can never grant would only decorate the same
//! `Unavailable`.
//!
//! # What this pass does close
//!
//! Registration into `aa-cli`'s capability-aware `--isolation auto` selection
//! (AAASM-5808) and explicit `--isolation-backend` pinning, both exercised
//! against a real, honestly-`Unavailable` backend rather than a stub outside
//! the selection path — see `aa-cli/tests/run_isolation.rs`. `auto_select`
//! already rejects an `Unavailable` candidate with `RejectedUnavailable` and
//! continues the walk, so this registration cannot change any existing
//! selection outcome; that is asserted by test, not just reasoned about.

use std::collections::BTreeMap;

use aa_isolation::{
    negotiate, BackendAvailability, BackendCapabilities, BackendIdentity, EnforcementEvidence, EnforcementPlan,
    ExecutionHandle, ExecutionSpec, ExitDisposition, IsolationBackend, Lowering, PlanRefusal, PlatformBoundary,
    PreparedExecution, Provenance, SpawnError, TerminationRequest,
};

/// Stable machine identifier for this backend, named in `--isolation-backend`
/// and in every refusal that lists the candidates a build has.
pub const BACKEND_ID: &str = "aasm-macos-vm";

/// A macOS backend that delegates confinement to `aa-isolation-native` inside
/// a Virtualization.framework guest — currently always `Unavailable`; see the
/// crate documentation for why.
#[derive(Debug, Default)]
pub struct MacosVmBackend {
    /// The exact environment the confined program is to receive, when the
    /// caller computed one. Held for parity with the other two backends'
    /// `set_child_environment`, though nothing reads it yet: `prepare` cannot
    /// be reached while [`Self::capabilities`] reports `Unavailable`, since
    /// `negotiate` refuses every plan before a launch gets that far.
    child_environment: Option<BTreeMap<String, String>>,
}

impl MacosVmBackend {
    /// Discover this backend's availability.
    ///
    /// Never fails, matching [`aa_isolation_sandlock::SandlockBackend::discover`]
    /// and [`aa_isolation_native::NativeBackend::discover`]: a backend that
    /// cannot run here is a fact `plan()` reports through a refusal, not a
    /// `Result` a caller has to unwrap before it can even ask.
    pub fn discover() -> Self {
        Self::default()
    }

    /// Set the exact environment the confined program is to receive.
    pub fn set_child_environment(&mut self, env: BTreeMap<String, String>) {
        self.child_environment = Some(env);
    }

    fn identity_value() -> BackendIdentity {
        BackendIdentity {
            id: BACKEND_ID.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            provenance: Provenance {
                source: "aa-isolation-macos-vm (AAASM-5813)".to_string(),
                license: "Apache-2.0".to_string(),
                modified: false,
            },
        }
    }

    fn capabilities_value() -> BackendCapabilities {
        BackendCapabilities::new(
            BackendAvailability::Unavailable {
                reason: "no host↔guest launch protocol exists yet over AAASM-5812's vsock channel (it exchanges \
                         a fixed hello/reply only), and no binary this repo signs carries the \
                         com.apple.security.virtualization entitlement — see this crate's documentation for the \
                         evidence"
                    .to_string(),
            },
            PlatformBoundary::GuestKernel,
            Vec::new(),
        )
        .expect("no two reports name the same domain: this backend reports none yet")
    }
}

impl IsolationBackend for MacosVmBackend {
    fn identity(&self) -> BackendIdentity {
        Self::identity_value()
    }

    fn capabilities(&self) -> BackendCapabilities {
        Self::capabilities_value()
    }

    fn plan(&self, spec: &ExecutionSpec) -> Result<EnforcementPlan, PlanRefusal> {
        // `negotiate` reads `capabilities.availability()` first and refuses
        // every requirement with `RefusalReason::BackendUnavailable` before
        // it ever calls this closure — see `aa_isolation::plan::negotiate`.
        // It is unreachable today and stays written out, rather than
        // `unreachable!()`, because it is the one place this backend will
        // gain real lowering logic once the launch protocol exists.
        negotiate(
            spec,
            &self.identity(),
            &self.capabilities(),
            &|_requirement, _outcome| Lowering::new(Vec::<String>::new()),
        )
    }

    fn prepare(&self, _plan: EnforcementPlan) -> Result<PreparedExecution, SpawnError> {
        // Unreachable while `capabilities()` reports `Unavailable`: `plan()`
        // never returns `Ok`, so no caller can hold an `EnforcementPlan` from
        // this backend to prepare. Kept as a real error rather than a panic
        // so a future bug in that invariant fails a launch instead of the
        // process.
        Err(SpawnError::Prepare {
            detail: "aasm-macos-vm cannot prepare an execution: this backend is unavailable, see \
                     MacosVmBackend::discover"
                .to_string(),
        })
    }

    fn spawn(&self, _prepared: PreparedExecution) -> Result<ExecutionHandle, SpawnError> {
        Err(SpawnError::Spawn {
            detail: "aasm-macos-vm cannot spawn: this backend is unavailable, see MacosVmBackend::discover".to_string(),
        })
    }

    fn wait_for_exit(&self, _handle: &ExecutionHandle) -> Result<ExitDisposition, SpawnError> {
        Err(SpawnError::Supervision {
            detail: "aasm-macos-vm holds no running execution: this backend is unavailable".to_string(),
        })
    }

    fn terminate(&self, _handle: &ExecutionHandle, _request: TerminationRequest) -> Result<(), SpawnError> {
        Err(SpawnError::Supervision {
            detail: "aasm-macos-vm holds no running execution: this backend is unavailable".to_string(),
        })
    }

    fn evidence(&self, handle: &ExecutionHandle) -> EnforcementEvidence {
        EnforcementEvidence::new(self.identity(), handle.posture())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_always_yields_a_backend() {
        let backend = MacosVmBackend::discover();
        assert_eq!(backend.identity().id, BACKEND_ID);
    }

    /// Pinned so a future change cannot flip this to `Available` without also
    /// touching the documentation that explains why it is not — see the
    /// crate-level docs for the two missing prerequisites this asserts.
    #[test]
    fn is_unavailable_until_the_launch_protocol_and_entitlement_exist() {
        let backend = MacosVmBackend::discover();
        assert!(matches!(
            backend.capabilities().availability(),
            BackendAvailability::Unavailable { .. }
        ));
    }

    #[test]
    fn an_unavailable_backend_refuses_every_plan() {
        let backend = MacosVmBackend::discover();
        let spec = ExecutionSpec::new("probe", aa_isolation::IdentityRef::root("probe"));
        assert!(backend.plan(&spec).is_err());
    }
}
