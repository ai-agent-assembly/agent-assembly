//! The macOS VM backend's half of the adversarial harness (AAASM-5814).
//!
//! The backend-neutral vocabulary lives in
//! `aa-integration-tests/tests/adversarial/mod.rs` — see
//! `aa-isolation-sandlock/tests/adversarial/mod.rs` for why it is reached
//! through `#[path] mod core; pub use core::*;` rather than `include!`. This
//! file keeps only what is specific to this backend: the [`MacosVmTarget`]
//! adapter and the precondition a real guest-confined run needs before it
//! can measure anything.

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

use aa_isolation::{CapabilityDomain, ExecutionSpec, IsolationBackend, PlanRefusal};
use aa_isolation_macos_vm::MacosVmBackend;

/// A backend that measured a working guest boundary on this host, or a
/// recorded skip.
///
/// Mirrors `aa-isolation-native/tests/adversarial/mod.rs`'s
/// `require_confining_backend`: check every precondition here, once, so a
/// scenario that checked some of them and forgot the rest cannot report a
/// missing measurement as a product failure.
pub fn require_confining_backend(scenario: &str) -> Option<MacosVmBackend> {
    if !(cfg!(target_os = "macos") && cfg!(target_arch = "aarch64")) {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "this backend confines a Linux guest via Virtualization.framework on Apple Silicon macOS; this \
                 host is {}/{}",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        );
    }
    let backend = MacosVmBackend::discover();
    if !backend.capabilities().availability().is_available() {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the substrate is not configured or the guest probe could not run on this host: {:?}",
                backend.capabilities().availability()
            ),
        );
    }
    let capabilities = backend.capabilities();
    for domain in [CapabilityDomain::FilesystemRead, CapabilityDomain::FilesystemWrite] {
        let measured = capabilities.report_for(domain).is_some_and(|r| r.can_prevent());
        if !measured {
            return decline(
                scenario,
                Measurement::NotMeasured,
                &format!("discover()'s probe established no {domain} denial on a host that meets every precondition"),
            );
        }
    }
    Some(backend)
}

/// The macOS VM backend, which starts a real guest-confined process.
pub struct MacosVmTarget(pub MacosVmBackend);

impl AdversarialTarget for MacosVmTarget {
    fn label(&self) -> &'static str {
        "macos-vm"
    }

    fn backend(&self) -> &dyn IsolationBackend {
        &self.0
    }

    fn launch(&self, spec: &ExecutionSpec) -> Result<RunOutcome, PlanRefusal> {
        let plan = self.0.plan(spec)?;
        let posture = plan.posture();
        let prepared = self.0.prepare(plan).expect("the guest boundary could not be prepared");
        let handle = self
            .0
            .spawn(prepared)
            .expect("the confined program could not be launched");
        let disposition = self
            .0
            .wait_for_exit(&handle)
            .expect("waiting for the confined program failed");
        let (stdout, stderr) = self.0.captured_output(&handle);
        let evidence = self.0.evidence(&handle);
        // `wait_for_exit`'s own return value is not part of `RunOutcome` —
        // scenarios read stdout content, matching every other backend's
        // adapter — but a disposition this launcher itself could not
        // interpret is worth surfacing loudly rather than silently dropping.
        let _ = &disposition;
        Ok(RunOutcome {
            posture,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            evidence,
        })
    }
}
