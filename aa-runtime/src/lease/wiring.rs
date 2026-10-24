//! Startup wiring for governed lease mode (AAASM-6259, ADR 0038).
//!
//! This file is deliberately *outside* the `devtool` strip region: the
//! crates.io build deletes the gate (`aa-isolation` is `publish = false`), and
//! a published runtime that was asked to govern must refuse to start, not run
//! ungoverned. [`prepare`] is that single decision point; only the call into
//! the real implementation is stripped, so the refusal is what remains.

use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::RuntimeConfig;
use crate::pipeline::LeaseGate;
use crate::runtime::StartupRefusal;

/// What `GET /health` publishes about governed lease mode.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LeaseGovernanceReport {
    /// The run this runtime is bound to. A revoker must see its own run here,
    /// or it is talking to a different (older or newer) run's runtime.
    pub run_id: String,
    /// Generation of the revocation set the gate is deciding against.
    pub generation: u64,
    /// `governed`, or `denied_all` once the state record was found anomalous
    /// (the gate then denies every request until the runtime restarts).
    pub state: &'static str,
}

/// Shared, cheap-to-read mirror of the installed gate snapshot.
///
/// Written only *after* the gate accepted a snapshot, so `/health` never claims
/// a generation the gate is not yet deciding with. `aasm lease revoke --wait`
/// relies on that ordering.
#[derive(Debug)]
pub struct LeaseStatus {
    inner: Mutex<LeaseGovernanceReport>,
}

impl LeaseStatus {
    /// A status reporting `governed` at `generation`.
    pub fn new(run_id: &str, generation: u64) -> Self {
        Self {
            inner: Mutex::new(LeaseGovernanceReport {
                run_id: run_id.to_string(),
                generation,
                state: "governed",
            }),
        }
    }

    /// Record that the gate now decides against `generation`.
    pub fn set_governed(&self, generation: u64) {
        self.set(|r| {
            r.generation = generation;
            r.state = "governed";
        });
    }

    /// Record that the gate is denying every request.
    pub fn set_denied_all(&self, generation: u64) {
        self.set(|r| {
            r.generation = generation;
            r.state = "denied_all";
        });
    }

    fn set(&self, f: impl FnOnce(&mut LeaseGovernanceReport)) {
        // A poisoned mutex only means a panic elsewhere; the report is plain data.
        f(&mut self.inner.lock().unwrap_or_else(|e| e.into_inner()));
    }

    /// The current report.
    pub fn report(&self) -> LeaseGovernanceReport {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Hook that spawns the revocation reload task into the runtime's tracker.
pub type ReloadSpawner = Box<dyn FnOnce(&TaskTracker, CancellationToken) + Send>;

/// A runtime that was asked to govern and could.
pub struct GovernedLease {
    /// Passed to `pipeline::run_with_lease_gate`.
    pub gate: Arc<dyn LeaseGate>,
    /// Published on `/health`.
    pub status: Arc<LeaseStatus>,
    /// Spawns the reload task; call once, after the tracker exists.
    pub reload: ReloadSpawner,
}

/// Decide whether this runtime is governed and, if so, build the gate.
///
/// `Ok(None)` means *not requested*: `AA_LEASE_POLICY` is unset and the runtime
/// behaves exactly as it did before governed mode existed. A set variable is
/// never silently downgraded to `Ok(None)`.
///
/// # Errors
///
/// [`StartupRefusal`] for every reason a requested governed mode cannot be
/// honoured, including a build that does not contain the gate.
// The tail `Err` is unreachable in a unix build that has the gate; it is the
// live path in the crates.io build (gate stripped) and on non-unix hosts.
#[allow(unreachable_code)]
pub fn prepare(config: &RuntimeConfig) -> Result<Option<GovernedLease>, StartupRefusal> {
    if config.lease_policy_path.is_none() {
        return Ok(None);
    }
    // strip-for-publish:begin devtool
    #[cfg(unix)]
    {
        return super::governed::prepare(config).map(Some);
    }
    // strip-for-publish:end devtool
    Err(StartupRefusal::new(
        "AA_LEASE_POLICY is set but this build of aa-runtime cannot enforce capability leases \
         (the lease gate is not part of this build, or the host is not unix); refusing to run \
         ungoverned",
    ))
}
