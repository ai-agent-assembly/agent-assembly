//! Assembly-side waiter registry for `ApprovalResolved` push events
//! (Story AAASM-2378).
//!
//! An agent blocked on a human approval calls [`ApprovalSink::wait_for_approval`]
//! and awaits the returned future instead of polling the gateway. The
//! [`ApprovalSink`] is registered as an
//! [`InvalidationSink`](crate::invalidation_client::InvalidationSink) on the
//! [`InvalidationClient`](crate::invalidation_client::InvalidationClient); when
//! the gateway pushes an `ApprovalResolved` event for a request the agent is
//! waiting on, the matching future resolves with the reviewer's [`Decision`].
//!
//! This reuses the existing L1 push-invalidation channel for a second event
//! type — one stream, two consumers (spec line 7699).

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::oneshot;

use aa_proto::assembly::gateway::v1::Decision;

use crate::invalidation_client::InvalidationSink;

/// Registry of in-flight approval waiters keyed by `request_id`.
///
/// Holds one [`oneshot::Sender`] per outstanding
/// [`wait_for_approval`](ApprovalSink::wait_for_approval) call. An incoming
/// `ApprovalResolved` event removes the matching sender and delivers the
/// [`Decision`], waking the awaiting future. Cheap to clone behind an `Arc`;
/// the waiter map is shared so the [`InvalidationClient`](crate::invalidation_client::InvalidationClient)
/// task and the awaiting agent see the same registrations.
#[derive(Default)]
pub struct ApprovalSink {
    waiters: Arc<DashMap<String, oneshot::Sender<Decision>>>,
}

impl ApprovalSink {
    /// Create an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of approval requests currently being awaited. Primarily for
    /// tests and metrics.
    pub fn waiter_count(&self) -> usize {
        self.waiters.len()
    }

    /// Subscribe to the verdict for `request_id`, returning a future that
    /// resolves when the gateway pushes the matching `ApprovalResolved` event
    /// or `deadline` elapses — whichever happens first.
    ///
    /// The waiter is registered **synchronously** on call (before the returned
    /// future is first polled), so a verdict that races in immediately after
    /// this returns is not lost.
    ///
    /// # Timeout
    ///
    /// On `deadline` expiry the future resolves to [`Decision::Pending`] —
    /// **not** [`Decision::Denied`]. Callers MUST treat `Pending` as "no human
    /// response arrived, decide locally" (e.g. apply the policy's configured
    /// timeout fallback); it is never an implicit denial. AAASM-2378.
    pub fn wait_for_approval(
        &self,
        request_id: impl Into<String>,
        deadline: Duration,
    ) -> impl Future<Output = Decision> {
        let request_id = request_id.into();
        let (tx, rx) = oneshot::channel();
        self.waiters.insert(request_id.clone(), tx);
        let waiters = Arc::clone(&self.waiters);
        async move {
            match tokio::time::timeout(deadline, rx).await {
                // Verdict pushed before the deadline.
                Ok(Ok(decision)) => decision,
                // Sender dropped without a verdict (e.g. the sink was dropped) —
                // treat as "no human response".
                Ok(Err(_)) => Decision::Pending,
                // Deadline elapsed: drop our registration and report Pending so
                // the caller falls back to a local decision.
                Err(_) => {
                    waiters.remove(&request_id);
                    Decision::Pending
                }
            }
        }
    }
}

impl InvalidationSink for ApprovalSink {
    /// Approval waiters do not care about policy invalidations.
    fn on_policy_invalidated(&self, _agent_id: &str) {}

    /// Deliver `decision` to the waiter registered for `request_id`, if any.
    /// An event with no matching waiter (already resolved, timed out, or never
    /// registered) is dropped.
    fn on_approval_resolved(&self, request_id: &str, decision: Decision) {
        if let Some((_id, tx)) = self.waiters.remove(request_id) {
            let _ = tx.send(decision);
        }
    }
}
