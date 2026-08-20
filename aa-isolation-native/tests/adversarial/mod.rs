//! The AASM-native-specific half of the adversarial harness (AAASM-5805).
//!
//! The backend-neutral vocabulary lives in
//! `aa-integration-tests/tests/adversarial/mod.rs` — see
//! `aa-isolation-sandlock/tests/adversarial/mod.rs` for why it is reached
//! through `#[path] mod core; pub use core::*;` rather than `include!`. This
//! file keeps only what is specific to the AASM-native backend: the
//! [`NativeTarget`] adapter and the precondition a native-confined run needs
//! before it can measure anything.

#![allow(dead_code)]

#[path = "../../../aa-integration-tests/tests/adversarial/mod.rs"]
mod core;

pub use core::*;

// `pub use core::*` does not re-export `core`'s own `pub mod evidence` under a
// name the scenario files import by — `adversarial::evidence::record` is
// called directly, so the module itself has to be named here too, not just
// its contents.
#[allow(unused_imports)]
pub use core::evidence;

use aa_isolation::{ExecutionSpec, IsolationBackend, PlanRefusal};
use aa_isolation_native::{NativeBackend, REQUIRED_ABI_VERSION};

/// A backend that measured a working boundary on this host, or a recorded
/// skip.
///
/// The same preconditions `linux_confinement_native.rs` and
/// `adversarial_boundary_native_linux.rs` fold into their own guards, for the
/// same reason: a scenario that checked some of them and forgot the rest would
/// report a missing measurement as a product failure.
pub fn require_confining_backend(scenario: &str) -> Option<NativeBackend> {
    if !cfg!(target_os = "linux") {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "this backend confines Linux processes; this host is {}",
                std::env::consts::OS
            ),
        );
    }
    let launcher = std::path::PathBuf::from(env!("CARGO_BIN_EXE_aa-isolation-launch"));
    if !launcher.is_file() {
        return decline(
            scenario,
            Measurement::ToolAbsent,
            &format!("the launcher `{}` was not built", launcher.display()),
        );
    }
    let backend = NativeBackend::discover_with_launcher(launcher).with_captured_output(true);
    let Some(host) = backend.host() else {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the host could not provide the boundary this backend requires (at least Landlock ABI \
                 v{REQUIRED_ABI_VERSION}): {:?}",
                backend.capabilities().availability()
            ),
        );
    };
    if !backend.probe_result().covers_descendants() {
        return decline(
            scenario,
            Measurement::NotMeasured,
            &format!(
                "the discovery probe established no filesystem denial on a host that meets every \
                 precondition: {}",
                host.describe()
            ),
        );
    }
    Some(backend)
}

/// The AASM-native backend, which starts a real confined process.
pub struct NativeTarget(pub NativeBackend);

impl AdversarialTarget for NativeTarget {
    fn label(&self) -> &'static str {
        "native"
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
