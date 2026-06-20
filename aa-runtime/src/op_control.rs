//! Runtime-side consumer of the gateway's op-control kill switch
//! (`PolicyService.OpControlStream`, AAASM-3491).
//!
//! # Why this exists
//!
//! The gateway can already *publish* pause/resume/terminate signals for an
//! in-flight op (`aa-gateway/src/ops`), but before this module **no client on
//! the agent's execution path subscribed to them** — an operator terminate
//! flipped the gateway registry to `Terminated` and broadcast into a channel
//! with no listener, so the running agent kept executing (a silent no-op /
//! allow-through of the documented kill switch; QA `qa3464-ops-registry-control`).
//!
//! [`OpControlClient`] is the missing consumer. It opens the
//! `OpControlStream` for this agent's composite id, and records each signal in
//! a shared [`OpControlStore`] keyed by `op_id` (`"{trace_id}:{span_id}"`, the
//! same form the gateway and dashboard use). The runtime's per-tool policy
//! check (`pipeline::handle_policy_query`) consults the store before allowing
//! an action, so a terminate **fast-fails** the in-flight action and a pause
//! **blocks** it until resume.
//!
//! # Fail-closed
//!
//! An op the operator has terminated is denied; a paused op is held. The store
//! is the authoritative runtime-side record — once a terminate is observed it
//! is sticky (`Terminated` is never cleared by a later pause/resume), so the
//! kill switch cannot be undone by a racing signal.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::Notify;

use aa_proto::assembly::policy::v1::OpControlSignal;

/// The runtime-observed lifecycle state of a single op.
///
/// Derived from the most recent [`OpControlSignal`] the gateway pushed for the
/// op's `op_id`. Absence from the [`OpControlStore`] means "no control signal
/// seen" — the op runs normally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpState {
    /// Operator paused the op: the next per-tool check must block until a
    /// `Resume` (or `Terminate`) arrives.
    Paused,
    /// Operator (or a policy deny) terminated the op: every further per-tool
    /// check must fast-fail. Terminal and sticky — never downgraded.
    Terminated,
}

/// Shared, lock-light record of op-control state keyed by `op_id`.
///
/// Written by the [`OpControlClient`] background subscriber; read by the
/// runtime pipeline on every per-tool policy check. Cheap to clone (`Arc`).
#[derive(Clone, Default)]
pub struct OpControlStore {
    /// `op_id` → latest non-`Resume` state. A `Resume` removes the entry so a
    /// resumed op reads as "runnable" again.
    states: Arc<DashMap<String, OpState>>,
    /// Woken whenever a signal is applied, so a check parked on a paused op
    /// re-evaluates promptly instead of polling.
    changed: Arc<Notify>,
}

impl OpControlStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one `OpControlSignal` for `op_id`, returning the resulting state
    /// (`None` once the op is runnable again, i.e. after a `Resume`).
    ///
    /// `Terminate` is sticky: once recorded it overrides a later `Pause` or
    /// `Resume` so the kill switch cannot be lifted by a racing signal.
    /// `Unspecified` is a malformed message and is ignored.
    pub fn apply(&self, op_id: &str, signal: OpControlSignal) -> Option<OpState> {
        let result = match signal {
            OpControlSignal::Terminate => {
                self.states.insert(op_id.to_owned(), OpState::Terminated);
                Some(OpState::Terminated)
            }
            OpControlSignal::Pause => {
                // Never undo a terminate.
                if matches!(self.states.get(op_id).as_deref(), Some(OpState::Terminated)) {
                    Some(OpState::Terminated)
                } else {
                    self.states.insert(op_id.to_owned(), OpState::Paused);
                    Some(OpState::Paused)
                }
            }
            OpControlSignal::Resume => {
                // A terminated op stays terminated; otherwise resume clears it.
                if matches!(self.states.get(op_id).as_deref(), Some(OpState::Terminated)) {
                    Some(OpState::Terminated)
                } else {
                    self.states.remove(op_id);
                    None
                }
            }
            OpControlSignal::Unspecified => self.states.get(op_id).as_deref().copied(),
        };
        self.changed.notify_waiters();
        result
    }

    /// Current state of `op_id`, or `None` if no control signal is in effect.
    pub fn state(&self, op_id: &str) -> Option<OpState> {
        self.states.get(op_id).as_deref().copied()
    }

    /// Await the next signal application. Used by a check parked on a paused op
    /// to wake the moment a resume/terminate lands rather than busy-polling.
    pub async fn changed(&self) {
        self.changed.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminate_records_terminated_state() {
        let store = OpControlStore::new();
        assert_eq!(store.apply("t:s", OpControlSignal::Terminate), Some(OpState::Terminated));
        assert_eq!(store.state("t:s"), Some(OpState::Terminated));
    }

    #[test]
    fn pause_then_resume_clears_state() {
        let store = OpControlStore::new();
        assert_eq!(store.apply("t:s", OpControlSignal::Pause), Some(OpState::Paused));
        assert_eq!(store.apply("t:s", OpControlSignal::Resume), None);
        assert_eq!(store.state("t:s"), None);
    }

    #[test]
    fn terminate_is_sticky_against_later_pause_and_resume() {
        let store = OpControlStore::new();
        store.apply("t:s", OpControlSignal::Terminate);
        // A racing pause or resume must not lift the kill switch.
        assert_eq!(store.apply("t:s", OpControlSignal::Pause), Some(OpState::Terminated));
        assert_eq!(store.apply("t:s", OpControlSignal::Resume), Some(OpState::Terminated));
        assert_eq!(store.state("t:s"), Some(OpState::Terminated));
    }

    #[test]
    fn unspecified_signal_is_ignored() {
        let store = OpControlStore::new();
        assert_eq!(store.apply("t:s", OpControlSignal::Unspecified), None);
        assert_eq!(store.state("t:s"), None);
    }

    #[test]
    fn distinct_ops_are_independent() {
        let store = OpControlStore::new();
        store.apply("a:1", OpControlSignal::Terminate);
        store.apply("b:2", OpControlSignal::Pause);
        assert_eq!(store.state("a:1"), Some(OpState::Terminated));
        assert_eq!(store.state("b:2"), Some(OpState::Paused));
        assert_eq!(store.state("c:3"), None);
    }
}
