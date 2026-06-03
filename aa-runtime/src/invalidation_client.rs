//! Assembly-side subscriber for the gateway's L1 push-invalidation channel
//! (Story AAASM-2377).
//!
//! [`InvalidationClient`] opens the `assembly.gateway.v1.InvalidationService`
//! Subscribe stream, applies each `PolicyInvalidated` event to the registered
//! [`InvalidationSink`]s (e.g. the [`crate::l1_cache::PolicyL1Cache`]), and
//! reconnects with exponential backoff — resuming from `last_seq_seen` so the
//! gateway replays anything missed while disconnected.

/// A consumer of policy-invalidation events delivered over the push channel.
///
/// The canonical implementor is an in-process L1 cache, which drops the cached
/// decision for the named agent. An empty `agent_id` is the "invalidate all
/// cached agents" convention the gateway uses for a global policy swap.
pub trait InvalidationSink: Send + Sync {
    /// Apply a policy invalidation for `agent_id` (empty = invalidate all).
    fn on_policy_invalidated(&self, agent_id: &str);
}
