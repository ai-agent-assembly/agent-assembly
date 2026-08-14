//! The standalone binary's subscriber for the `PipelineEvent` broadcast
//! (AAASM-5449).
//!
//! # Why this exists
//!
//! `aa-proxy`'s `main` created the broadcast channel and dropped the receiver
//! on the next line. Every `emit_policy_decision` / `emit_mcp_decision` /
//! `intercept` call publishes onto it and discards the send error, so in the
//! standalone binary the entire governance event stream went nowhere — a
//! publisher with no subscriber, which reads at the call site exactly like a
//! working one.
//!
//! The channel is not removable: it is how an *embedder* (`aa-runtime` calling
//! [`crate::run`]) receives the proxy's events, and that is its real purpose.
//! What was missing was a subscriber for the case where there is no embedder.
//!
//! # Why this logs a shape and not the event
//!
//! An [`EnrichedEvent`](aa_runtime::pipeline::EnrichedEvent) carries the audit
//! payload, which for LLM traffic includes prompt-derived fields. Writing that
//! to the process log would move request content into a destination with none
//! of the sink's protections — no `0600`, no redaction projection, no ADR 0032
//! §9 offset rule. So this records the *shape* of the stream (kind, agent id,
//! sequence number) and never its payload.
//!
//! `Lagged` is logged at `warn` and counted, because a broadcast receiver that
//! falls behind loses events silently — the same class of defect as the audit
//! channel's full-buffer drop, on the one channel that had nobody watching it
//! at all.

use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::Receiver;

use aa_runtime::pipeline::PipelineEvent;

/// What the drain saw before the channel closed.
///
/// Returned rather than only logged so the behaviour is assertable: a drain
/// that silently consumed nothing and one that consumed everything produce the
/// same empty log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineDrainSummary {
    /// Events received and logged.
    pub observed: u64,
    /// Events the broadcast buffer overwrote before this receiver reached
    /// them. Lost, not delayed.
    pub lagged: u64,
}

/// Consume the pipeline event stream until every sender is dropped.
///
/// Returns once the channel closes; the standalone binary spawns this and
/// never awaits it, since the proxy's accept loop outlives it either way.
pub async fn drain_pipeline_events(mut rx: Receiver<PipelineEvent>) -> PipelineDrainSummary {
    let mut summary = PipelineDrainSummary::default();
    loop {
        match rx.recv().await {
            Ok(event) => {
                summary.observed += 1;
                log_event(&event);
            }
            Err(RecvError::Lagged(skipped)) => {
                summary.lagged += skipped;
                tracing::warn!(
                    skipped,
                    lagged_total = summary.lagged,
                    "proxy pipeline event subscriber lagged; those events are lost, not delayed",
                );
            }
            Err(RecvError::Closed) => break,
        }
    }
    tracing::info!(
        observed = summary.observed,
        lagged = summary.lagged,
        "proxy pipeline event stream closed",
    );
    summary
}

/// Record that an event happened, and nothing about what it contained.
fn log_event(event: &PipelineEvent) {
    match event {
        PipelineEvent::Audit(enriched) => tracing::debug!(
            kind = "audit",
            agent_id = %enriched.agent_id,
            sequence_number = enriched.sequence_number,
            "proxy pipeline event",
        ),
        PipelineEvent::LayerDegradation(info) => tracing::warn!(
            kind = "layer_degradation",
            layer = %info.layer,
            reason = %info.reason,
            "proxy interception layer degraded",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aa_runtime::pipeline::{EnrichedEvent, EventSource, LayerDegradationInfo};
    use tokio::sync::broadcast;

    fn audit(sequence_number: u64) -> PipelineEvent {
        PipelineEvent::Audit(Box::new(EnrichedEvent {
            inner: Default::default(),
            received_at_ms: 1_700_000_000_000,
            source: EventSource::Proxy,
            agent_id: "agent-1".into(),
            connection_id: 1,
            sequence_number,
            observed_sdk_identity: aa_security::sdk_identity::ObservedSdkIdentity::missing(),
            tamper: None,
        }))
    }

    /// The defect: `main` dropped the receiver, so everything published on this
    /// channel was discarded. A drain that reports what it consumed is what
    /// makes the difference between "subscribed" and "not" observable at all.
    #[tokio::test]
    async fn a_subscribed_channel_delivers_every_event() {
        let (tx, rx) = broadcast::channel(16);
        let handle = tokio::spawn(drain_pipeline_events(rx));

        for n in 0..3 {
            tx.send(audit(n)).expect("a live subscriber means send succeeds");
        }
        tx.send(PipelineEvent::LayerDegradation(LayerDegradationInfo {
            layer: "ebpf".into(),
            reason: "not attached".into(),
            remaining_layers: vec!["proxy".into()],
        }))
        .unwrap();
        drop(tx);

        let summary = handle.await.unwrap();
        assert_eq!(summary.observed, 4);
        assert_eq!(summary.lagged, 0);
    }

    /// With no receiver, `send` fails — which is exactly what the binary did to
    /// every governance event it produced, while every call site wrote
    /// `let _ = tx.send(..)`.
    #[test]
    fn an_unsubscribed_channel_refuses_the_send() {
        let (tx, rx) = broadcast::channel(16);
        drop(rx);
        assert!(
            tx.send(audit(0)).is_err(),
            "a publisher with no subscriber must be observable as one"
        );
    }

    /// A broadcast receiver that falls behind loses events rather than
    /// delaying them. Counting that is the point: an uncounted lag is the same
    /// silent under-count as an uncounted channel drop.
    #[tokio::test]
    async fn a_lagging_subscriber_counts_what_it_lost() {
        let (tx, rx) = broadcast::channel(2);
        // Overrun the ring before the drain is ever polled.
        for n in 0..6 {
            tx.send(audit(n)).unwrap();
        }
        drop(tx);

        let summary = drain_pipeline_events(rx).await;
        assert_eq!(summary.lagged, 4, "six events through a two-slot ring loses four");
        assert_eq!(summary.observed, 2, "and delivers the two that survived");
    }
}
