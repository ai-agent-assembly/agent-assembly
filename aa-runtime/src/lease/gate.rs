//! The production [`LeaseGate`]: a hot-swappable snapshot answered by
//! [`decide`] (AAASM-6259, ADR 0038 §31-34).
//!
//! Nothing here is wired into the runtime yet. A later change builds the
//! governance at startup, passes the gate to `run_with_lease_gate` and feeds
//! [`PolicyLeaseGate::install`] from a revocation reload task.
//!
//! # Locking
//!
//! `check` runs inline in the single pipeline loop, so it holds the lock only
//! long enough to clone an `Arc` and decides on the clone. No I/O happens under
//! the lock, in `check` or in `install`. A poisoned lock denies every call:
//! fail-closed, and persistent until the process restarts, because healing a
//! lock a panic poisoned would hide that the state behind it may be wrong.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use aa_proto::assembly::policy::v1::CheckActionRequest;

use super::decide::{decide, LeaseGovernance};
use crate::pipeline::{LeaseGate, LeaseVerdict};

/// What the gate decides against: governance (or a refusal to govern), the
/// revoked lease ids, and a generation for log correlation.
#[derive(Debug, Clone)]
pub struct Snapshot {
    mode: Mode,
    revoked: BTreeSet<String>,
    generation: u64,
}

#[derive(Debug, Clone)]
enum Mode {
    Governed(Box<LeaseGovernance>),
    DenyAll(String),
}

impl Snapshot {
    /// A snapshot that decides with `governance` and refuses every lease in
    /// `revoked` (ids as reported by [`LeaseGovernance::lease_ids`]).
    pub fn governed(governance: LeaseGovernance, revoked: BTreeSet<String>, generation: u64) -> Self {
        Self {
            mode: Mode::Governed(Box::new(governance)),
            revoked,
            generation,
        }
    }

    /// A snapshot that denies every request, for a runtime that must stay
    /// governed but cannot currently trust its lease state. `reason` is
    /// operator log text only.
    pub fn deny_all(reason: impl Into<String>, generation: u64) -> Self {
        Self {
            mode: Mode::DenyAll(reason.into()),
            revoked: BTreeSet::new(),
            generation,
        }
    }

    /// The generation this snapshot was built at.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn verdict(&self, subject: &str, req: &CheckActionRequest, now: SystemTime) -> LeaseVerdict {
        match &self.mode {
            Mode::DenyAll(reason) => LeaseVerdict::Deny {
                reason: format!("lease gate is denying all requests: {reason}"),
            },
            Mode::Governed(governance) => {
                // The seam's subject is the runtime's server-side id; the
                // governance was built for one subject. A mismatch means the
                // two were wired inconsistently, which must not admit.
                if governance.subject() != subject {
                    return LeaseVerdict::Deny {
                        reason: "lease governance was built for a different agent id".to_string(),
                    };
                }
                decide(governance, &self.revoked, req, now)
            }
        }
    }
}

/// `install` could not replace the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallError;

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lease gate state lock is poisoned; the gate keeps denying")
    }
}

impl std::error::Error for InstallError {}

/// [`LeaseGate`] backed by a replaceable [`Snapshot`].
#[derive(Debug)]
pub struct PolicyLeaseGate {
    state: RwLock<Arc<Snapshot>>,
}

impl PolicyLeaseGate {
    /// A gate that starts from `initial`.
    pub fn new(initial: Snapshot) -> Self {
        Self {
            state: RwLock::new(Arc::new(initial)),
        }
    }

    /// Replace the snapshot; the next `check` sees it.
    ///
    /// # Errors
    ///
    /// [`InstallError`] when the lock is poisoned. The gate then keeps denying.
    pub fn install(&self, snapshot: Snapshot) -> Result<(), InstallError> {
        let next = Arc::new(snapshot);
        let mut guard = self.state.write().map_err(|_| InstallError)?;
        *guard = next;
        Ok(())
    }

    /// Generation of the installed snapshot, or `None` if the lock is poisoned.
    pub fn generation(&self) -> Option<u64> {
        self.state.read().ok().map(|s| s.generation)
    }
}

impl LeaseGate for PolicyLeaseGate {
    fn check(&self, subject: &str, req: &CheckActionRequest, now: SystemTime) -> LeaseVerdict {
        let snapshot = match self.state.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(_) => {
                return LeaseVerdict::Deny {
                    reason: "lease gate state is unavailable".to_string(),
                }
            }
        };
        snapshot.verdict(subject, req, now)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use aa_proto::assembly::common::v1::ActionType;
    use aa_proto::assembly::policy::v1::action_context::Action;
    use aa_proto::assembly::policy::v1::{ActionContext, ToolCallContext};

    use super::*;
    use crate::lease::decide::GovernedIssuance;
    use crate::pipeline::lease_gate::enforce;

    const SUBJECT: &str = "server-agent";

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000)
    }

    fn governance(subject: &str) -> LeaseGovernance {
        let resolution = aa_policy::resolve::classify(
            Path::new("p.yaml"),
            "tools:\n  calc: { allow: true, capabilities: [none] }\n  reader: { allow: true, capabilities: [filesystem_read] }\n\
             authority:\n  leases:\n    - domain: filesystem_read\n      scope: whole\n      reason: test\n",
        );
        LeaseGovernance::from_resolution(
            &resolution,
            subject,
            &GovernedIssuance {
                issued_at: now(),
                default_ttl_seconds: 600,
                default_issuer: "test".to_string(),
                id_prefix: "gov".to_string(),
            },
        )
        .expect("governance builds")
    }

    fn call(tool: &str) -> CheckActionRequest {
        CheckActionRequest {
            action_type: ActionType::ToolCall as i32,
            context: Some(ActionContext {
                action: Some(Action::ToolCall(ToolCallContext {
                    tool_name: tool.to_string(),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        }
    }

    fn governed_gate() -> PolicyLeaseGate {
        PolicyLeaseGate::new(Snapshot::governed(governance(SUBJECT), BTreeSet::new(), 1))
    }

    #[test]
    fn a_governed_snapshot_answers_with_the_decision() {
        let gate = governed_gate();
        assert_eq!(gate.check(SUBJECT, &call("reader"), now()), LeaseVerdict::Permit);
        assert!(matches!(
            gate.check(SUBJECT, &call("nope"), now()),
            LeaseVerdict::Deny { .. }
        ));
    }

    #[test]
    fn a_revoked_id_in_the_snapshot_denies() {
        let revoked: BTreeSet<String> = ["gov-0".to_string()].into();
        let gate = PolicyLeaseGate::new(Snapshot::governed(governance(SUBJECT), revoked, 2));
        assert!(matches!(
            gate.check(SUBJECT, &call("reader"), now()),
            LeaseVerdict::Deny { .. }
        ));
        // A tool needing no lease is unaffected by revocation.
        assert_eq!(gate.check(SUBJECT, &call("calc"), now()), LeaseVerdict::Permit);
    }

    #[test]
    fn installing_deny_all_flips_the_very_next_check_and_installing_back_restores_it() {
        let gate = governed_gate();
        assert_eq!(gate.check(SUBJECT, &call("calc"), now()), LeaseVerdict::Permit);

        gate.install(Snapshot::deny_all("revocation state unreadable", 2))
            .unwrap();
        // Even a tool needing no lease and a never-leased action type deny.
        for req in [call("calc"), call("reader"), CheckActionRequest::default()] {
            let LeaseVerdict::Deny { reason } = gate.check(SUBJECT, &req, now()) else {
                panic!("deny_all must deny");
            };
            assert!(reason.contains("revocation state unreadable"), "{reason}");
        }
        assert_eq!(gate.generation(), Some(2));

        gate.install(Snapshot::governed(governance(SUBJECT), BTreeSet::new(), 3))
            .unwrap();
        assert_eq!(gate.check(SUBJECT, &call("calc"), now()), LeaseVerdict::Permit);
        assert_eq!(gate.generation(), Some(3));
    }

    #[test]
    fn a_subject_other_than_the_governed_one_is_denied() {
        let gate = governed_gate();
        let LeaseVerdict::Deny { reason } = gate.check("someone-else", &call("calc"), now()) else {
            panic!("a subject mismatch must deny, even for a tool needing no lease");
        };
        assert!(reason.contains("different agent id"), "{reason}");
    }

    fn poisoned() -> PolicyLeaseGate {
        let gate = governed_gate();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = gate.state.write().unwrap();
            panic!("poison the lock");
        }));
        assert!(gate.state.is_poisoned(), "precondition: the lock is poisoned");
        gate
    }

    #[test]
    fn a_poisoned_lock_denies_everything_and_refuses_installs() {
        let gate = poisoned();
        assert!(matches!(
            gate.check(SUBJECT, &call("calc"), now()),
            LeaseVerdict::Deny { .. }
        ));
        assert!(matches!(
            gate.check(SUBJECT, &CheckActionRequest::default(), now()),
            LeaseVerdict::Deny { .. }
        ));
        assert_eq!(gate.generation(), None);
        // A refused install must not heal the gate into permitting.
        assert_eq!(
            gate.install(Snapshot::governed(governance(SUBJECT), BTreeSet::new(), 9)),
            Err(InstallError)
        );
        assert!(matches!(
            gate.check(SUBJECT, &call("calc"), now()),
            LeaseVerdict::Deny { .. }
        ));
    }

    #[test]
    fn the_seam_turns_a_poisoned_gate_into_a_denied_request() {
        let gate = poisoned();
        assert!(enforce(&gate, SUBJECT, &call("calc"), now()).is_err());
        assert!(enforce(&governed_gate(), SUBJECT, &call("calc"), now()).is_ok());
    }
}
