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
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use aa_proto::assembly::common::v1::AgentId;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::{OpControlSignal, OpControlSubscribeRequest};

/// First reconnect delay; doubles on each consecutive failure.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Upper bound on the reconnect delay (1s → 2 → 4 → … → 32s cap).
const MAX_BACKOFF: Duration = Duration::from_secs(32);

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

    /// A future that resolves on the next signal application.
    ///
    /// Returned (not awaited) so a caller parked on a paused op can register
    /// interest **before** re-reading [`state`](Self::state) — closing the race
    /// where a resume/terminate lands between the state read and the await.
    /// `notify_waiters` only wakes already-registered waiters, so registering
    /// first is required for correctness.
    pub fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.changed.notified()
    }
}

/// Next reconnect delay: double the current one, capped at [`MAX_BACKOFF`].
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(MAX_BACKOFF)
}

/// Background subscriber that keeps an [`OpControlStore`] fresh from the
/// gateway's `PolicyService.OpControlStream`.
///
/// Mirrors [`crate::invalidation_client::InvalidationClient`]: it opens the
/// stream keyed by this agent's composite id, applies each pushed signal to the
/// store, and reconnects forever with exponential backoff. The gateway filters
/// the broadcast so only this agent's ops arrive.
pub struct OpControlClient;

impl OpControlClient {
    /// Spawn the subscribe loop on the Tokio runtime and return its handle.
    ///
    /// `gateway_url` is the same endpoint the policy-check path forwards to;
    /// `agent_id` must match the `agent_id` on this agent's `CheckActionRequest`s
    /// so the gateway routes the right signals. Abort the returned
    /// [`JoinHandle`] to stop the subscriber.
    pub fn start(gateway_url: String, agent_id: AgentId, store: OpControlStore) -> JoinHandle<()> {
        tokio::spawn(async move { run(gateway_url, agent_id, store).await })
    }
}

/// Reconnect loop: subscribe, apply signals, and on disconnect back off
/// exponentially before resubscribing.
async fn run(gateway_url: String, agent_id: AgentId, store: OpControlStore) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match subscribe_once(&gateway_url, &agent_id, &store).await {
            // The gateway closed the stream cleanly — reconnect promptly.
            Ok(()) => backoff = INITIAL_BACKOFF,
            Err(err) => {
                metrics::counter!("aa_op_control_reconnects_total").increment(1);
                tracing::warn!(
                    error = %err,
                    backoff_secs = backoff.as_secs(),
                    "op-control stream dropped; reconnecting after backoff"
                );
                tokio::time::sleep(backoff).await;
                backoff = next_backoff(backoff);
            }
        }
    }
}

/// Open one `OpControlStream` and apply messages to the store until it ends or
/// errors.
async fn subscribe_once(
    gateway_url: &str,
    agent_id: &AgentId,
    store: &OpControlStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = PolicyServiceClient::connect(gateway_url.to_owned()).await?;
    let request = OpControlSubscribeRequest {
        agent_id: Some(agent_id.clone()),
    };
    let response = client.op_control_stream(request).await?;
    let mut inbound = response.into_inner();

    while let Some(message) = inbound.message().await? {
        let signal = message.signal();
        tracing::debug!(op_id = %message.op_id, ?signal, "op-control signal received");
        store.apply(&message.op_id, signal);
        metrics::counter!("aa_op_control_signals_total").increment(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps_at_32s() {
        let schedule: Vec<u64> = std::iter::successors(Some(INITIAL_BACKOFF), |&d| Some(next_backoff(d)))
            .take(7)
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(schedule, vec![1, 2, 4, 8, 16, 32, 32]);
    }

    #[test]
    fn terminate_records_terminated_state() {
        let store = OpControlStore::new();
        assert_eq!(
            store.apply("t:s", OpControlSignal::Terminate),
            Some(OpState::Terminated)
        );
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
