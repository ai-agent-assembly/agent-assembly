//! The Sandlock-specific half of the adversarial harness (AAASM-5712).
//!
//! The backend-neutral vocabulary — [`AttackFamily`], [`ControlledPair`],
//! [`AdversarialTarget`], the shared fixtures and the adjudicator's own tests —
//! moved to `aa-integration-tests/tests/adversarial/mod.rs` (AAASM-5805) so the
//! AASM-native lane could drive the same scenarios without duplicating them.
//! This file keeps only what is specific to the Sandlock backend: the
//! [`SandlockTarget`] adapter and the preconditions a Sandlock-confined run
//! needs before it can measure anything.

#![allow(dead_code)]

#[path = "../../../aa-integration-tests/tests/adversarial/mod.rs"]
mod core;

pub use core::*;

// `pub use core::*` does not re-export `core`'s own `pub mod evidence` under a
// name the scenario files import by — `adversarial::evidence::record` is called
// directly, so the module itself has to be named here too, not just its
// contents. The glob above already carries it in practice; named explicitly so
// that fact does not depend on nothing else in `core`'s public surface changing
// shape, and `#[allow(unused_imports)]` because this binary crate cannot see
// that `adversarial_boundary_linux.rs`/`adversarial_negotiation.rs` are the
// consumers.
#[allow(unused_imports)]
pub use core::evidence;

use aa_isolation::{EnforcementEvidence, ExecutionHandle, ExecutionSpec, IsolationBackend, PlanRefusal};
use aa_isolation_sandlock::{host::DEFAULT_PROTECTION_FLOOR_ABI, CompletedRun, SandlockBackend};

/// A backend that measured a working boundary on this host, or a recorded skip.
///
/// The same four preconditions `linux_confinement.rs` folds into its own guard,
/// for the same reason: a scenario that checked three of them and forgot the
/// fourth would report a missing measurement as a product failure.
pub fn require_confining_backend(scenario: &str) -> Option<SandlockBackend> {
    if !cfg!(target_os = "linux") {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the sandlock backend confines Linux processes; this host is {}",
                std::env::consts::OS
            ),
        );
    }
    let backend = SandlockBackend::discover().with_captured_output(true);

    let Some(host) = backend.host() else {
        return decline(
            scenario,
            Measurement::ToolAbsent,
            "no sandlock executable was found; a lane that installs it and still reports this is broken",
        );
    };

    if host.below_default_protection_floor() {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the kernel's access-control interface is {} and the mechanism enforces every protection \
                 it knows about, requiring at least version {DEFAULT_PROTECTION_FLOOR_ABI}",
                host.landlock_abi()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unreadable".to_string()),
            ),
        );
    }

    let probe = backend.probe_result();
    if !probe.filesystem_write.is_denied() || !probe.filesystem_read.is_denied() {
        return decline(
            scenario,
            Measurement::NotMeasured,
            &format!(
                "the discovery probe established no filesystem denial on a host that meets every \
                 precondition. read: {} | write: {}",
                probe.filesystem_read.describe(),
                probe.filesystem_write.describe()
            ),
        );
    }
    Some(backend)
}

/// The Sandlock backend, which starts a real confined process.
pub struct SandlockTarget(pub SandlockBackend);

impl AdversarialTarget for SandlockTarget {
    fn label(&self) -> &'static str {
        "sandlock"
    }

    fn backend(&self) -> &dyn IsolationBackend {
        &self.0
    }

    fn launch(&self, spec: &ExecutionSpec) -> Result<RunOutcome, PlanRefusal> {
        let plan = self.0.plan(spec)?;
        let posture = plan.posture();
        let prepared = self.0.prepare(plan).expect("the boundary could not be prepared");
        let handle = self
            .0
            .spawn(prepared)
            .expect("the confined program could not be launched");
        let completed = self.0.wait(&handle).expect("waiting for the confined program failed");
        Ok(RunOutcome {
            posture,
            stdout: completed.stdout,
            stderr: completed.stderr,
            evidence: self.0.evidence(&handle),
        })
    }
}

/// Plan, prepare, launch and wait on the Sandlock backend.
pub fn launch_confined(backend: &SandlockBackend, spec: &ExecutionSpec) -> (CompletedRun, EnforcementEvidence) {
    let plan = backend
        .plan(spec)
        .unwrap_or_else(|refusal| panic!("the backend refused a spec this scenario needs: {refusal:?}"));
    let prepared = backend.prepare(plan).expect("the boundary could not be prepared");
    let handle: ExecutionHandle = backend
        .spawn(prepared)
        .expect("the confined program could not be launched");
    let completed = backend.wait(&handle).expect("waiting for the confined program failed");
    let evidence = backend.evidence(&handle);
    (completed, evidence)
}
