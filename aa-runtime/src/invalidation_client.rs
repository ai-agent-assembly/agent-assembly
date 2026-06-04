//! Assembly-side subscriber for the gateway's L1 push-invalidation channel
//! (Story AAASM-2377).
//!
//! [`InvalidationClient`] opens the `assembly.gateway.v1.InvalidationService`
//! Subscribe stream, applies each `PolicyInvalidated` event to the registered
//! [`InvalidationSink`]s (e.g. the [`crate::l1_cache::PolicyL1Cache`]), and
//! reconnects with exponential backoff — resuming from `last_seq_seen` so the
//! gateway replays anything missed while disconnected.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

use aa_proto::assembly::gateway::v1::invalidation_event::Payload;
use aa_proto::assembly::gateway::v1::invalidation_service_client::InvalidationServiceClient;
use aa_proto::assembly::gateway::v1::{subscribe_request::Kind, Decision, SubscribeInitial, SubscribeRequest};

/// First reconnect delay; doubles on each consecutive failure.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Upper bound on the reconnect delay (1s → 2 → 4 → … → 32s cap).
const MAX_BACKOFF: Duration = Duration::from_secs(32);

/// A consumer of policy-invalidation events delivered over the push channel.
///
/// The canonical implementor is an in-process L1 cache, which drops the cached
/// decision for the named agent. An empty `agent_id` is the "invalidate all
/// cached agents" convention the gateway uses for a global policy swap.
pub trait InvalidationSink: Send + Sync {
    /// Apply a policy invalidation for `agent_id` (empty = invalidate all).
    fn on_policy_invalidated(&self, agent_id: &str);

    /// Deliver a human reviewer's verdict for the approval request
    /// `request_id` to a blocked waiter. The default is a no-op so that
    /// policy-only sinks (e.g. the L1 cache) need not care about the
    /// approval-reuse half of the channel; the [`crate::approval_sink::ApprovalSink`]
    /// overrides it to wake the matching `wait_for_approval` future. AAASM-2378.
    fn on_approval_resolved(&self, request_id: &str, decision: Decision) {
        let _ = (request_id, decision);
    }
}

/// Next reconnect delay: double the current one, capped at [`MAX_BACKOFF`].
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(MAX_BACKOFF)
}

/// Background subscriber that keeps the registered [`InvalidationSink`]s fresh
/// from the gateway's push-invalidation stream.
pub struct InvalidationClient;

impl InvalidationClient {
    /// Spawn the subscribe loop on the Tokio runtime and return its handle.
    ///
    /// The task reconnects forever with exponential backoff; abort the returned
    /// [`JoinHandle`] to stop it. `assembly_id` keys the gateway's per-subscriber
    /// replay buffer so reconnects resume from the last applied sequence.
    pub fn start(gateway_url: String, assembly_id: String, sinks: Vec<Arc<dyn InvalidationSink>>) -> JoinHandle<()> {
        tokio::spawn(async move { run(gateway_url, assembly_id, sinks).await })
    }
}

/// Reconnect loop: subscribe, apply events, and on disconnect back off
/// exponentially before resubscribing from `last_seq_seen`.
async fn run(gateway_url: String, assembly_id: String, sinks: Vec<Arc<dyn InvalidationSink>>) {
    let mut backoff = INITIAL_BACKOFF;
    let mut last_seq_seen: u64 = 0;
    loop {
        match subscribe_once(&gateway_url, &assembly_id, &mut last_seq_seen, &sinks).await {
            // The gateway closed the stream cleanly — reconnect promptly.
            Ok(()) => backoff = INITIAL_BACKOFF,
            Err(err) => {
                metrics::counter!("aa_invalidation_reconnects_total").increment(1);
                tracing::warn!(
                    error = %err,
                    backoff_secs = backoff.as_secs(),
                    last_seq_seen,
                    "invalidation stream dropped; reconnecting after backoff"
                );
                tokio::time::sleep(backoff).await;
                backoff = next_backoff(backoff);
            }
        }
    }
}

/// Open one Subscribe stream and apply events until it ends or errors.
///
/// `last_seq_seen` is advanced as events arrive (even if the stream later
/// errors), so the next reconnect replays only what was genuinely missed.
async fn subscribe_once(
    gateway_url: &str,
    assembly_id: &str,
    last_seq_seen: &mut u64,
    sinks: &[Arc<dyn InvalidationSink>],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = InvalidationServiceClient::connect(gateway_url.to_owned()).await?;
    let initial = SubscribeRequest {
        assembly_id: assembly_id.to_owned(),
        kind: Some(Kind::Initial(SubscribeInitial {
            last_seq_seen: *last_seq_seen,
        })),
    };
    let response = client.subscribe(tokio_stream::once(initial)).await?;
    let mut inbound = response.into_inner();

    while let Some(event) = inbound.message().await? {
        let applied_at = Instant::now();
        match &event.payload {
            Some(Payload::PolicyInvalidated(policy)) => {
                for sink in sinks {
                    sink.on_policy_invalidated(&policy.agent_id);
                }
            }
            Some(Payload::ApprovalResolved(approval)) => {
                let decision = approval.decision();
                for sink in sinks {
                    sink.on_approval_resolved(&approval.request_id, decision);
                }
            }
            None => {}
        }
        if event.seq > *last_seq_seen {
            *last_seq_seen = event.seq;
        }
        metrics::histogram!("aa_invalidation_latency_seconds").record(applied_at.elapsed().as_secs_f64());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps_at_32s() {
        // 1s → 2 → 4 → 8 → 16 → 32 → 32 (capped).
        let schedule: Vec<u64> = std::iter::successors(Some(INITIAL_BACKOFF), |&d| Some(next_backoff(d)))
            .take(7)
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(schedule, vec![1, 2, 4, 8, 16, 32, 32]);
    }
}
