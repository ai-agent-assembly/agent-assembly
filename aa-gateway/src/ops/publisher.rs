//! Fan-out channel for [`crate::ops::OpsRegistry`] lifecycle transitions.
//!
//! `OpControlPublisher` is the gateway-side broadcast point that subscribed
//! SDK clients (via `PolicyService::OpControlStream`, AAASM-1653) receive
//! pause / resume / terminate signals on. PR-D ships the channel + handler;
//! PR-H wires the `OpsRegistry` transitions to call `publish` with the
//! matching signal.
//!
//! Implementation: a single `tokio::sync::broadcast` channel. Subscribers
//! filter by `agent_id` themselves, which is cheaper than maintaining a
//! per-agent registry of senders for low-volume signalling (pause / resume
//! / terminate are operator-triggered, not per-action). The trade-off is
//! that every subscriber wakes on every message — acceptable for the
//! expected steady-state of < 100 active agents per gateway.
//!
//! Sequence numbers are assigned by the publisher on `publish()`, starting
//! at 0 on construction. They reset across gateway restarts; SDK consumers
//! treat the value as advisory dedup help, not a cross-publisher ordering
//! guarantee.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::broadcast;

use aa_proto::assembly::common::v1::AgentId;
use aa_proto::assembly::policy::v1::{OpControlMessage, OpControlSignal};

/// Broadcast capacity. Sized so a momentarily-slow subscriber doesn't lag
/// out under normal pause/resume churn. Subscribers that fall behind by
/// more than this many messages will get `RecvError::Lagged` and skip
/// the missed entries; the SDK reconciles via the next steady-state
/// transition rather than replaying history.
const CHANNEL_CAPACITY: usize = 256;

/// One pre-serialised lifecycle signal addressed to a specific agent.
///
/// Wraps the wire-format [`OpControlMessage`] with the routing key
/// (`agent_id`) so subscribers can filter cheaply without parsing the
/// message body.
#[derive(Debug, Clone)]
pub struct OpControlEnvelope {
    /// The agent the message is destined for. Subscribers compare this
    /// against their own `subscribe(agent_id)` filter and drop mismatches.
    ///
    /// Ignored when [`global`](Self::global) is set — a global halt reaches
    /// every subscriber regardless of this field.
    pub agent_id: AgentId,
    /// The wire-format message that will be forwarded to the subscriber.
    pub message: OpControlMessage,
    /// Fleet-wide halt marker (AAASM-3881). When `true`, every subscriber
    /// receives the envelope regardless of [`agent_id`](Self::agent_id), so a
    /// global kill switch reaches all runtimes under the reserved op-id `"*"`.
    /// Set only by `OpControlPublisher`; every
    /// per-agent publish leaves it `false`.
    pub global: bool,
}

/// Broadcast publisher for op-control signals.
///
/// Wrap in `Arc` and clone-share between the policy service handler (which
/// calls `subscribe`) and the OpsRegistry call sites (which call
/// `publish` — wiring lands in PR-H).
pub struct OpControlPublisher {
    tx: broadcast::Sender<OpControlEnvelope>,
    sequence: AtomicU64,
}

impl OpControlPublisher {
    /// Create a fresh publisher with no subscribers.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            tx,
            sequence: AtomicU64::new(0),
        }
    }

    /// Subscribe to the broadcast. Returns a receiver that yields every
    /// envelope published from now on. Subscribers must filter by
    /// `agent_id` themselves — see [`PolicyServiceImpl::op_control_stream`].
    ///
    /// [`PolicyServiceImpl::op_control_stream`]: crate::service::PolicyServiceImpl
    pub fn subscribe(&self) -> broadcast::Receiver<OpControlEnvelope> {
        self.tx.subscribe()
    }

    /// Publish a signal addressed to an agent. Returns the assigned
    /// sequence number. Silently succeeds when there are zero subscribers
    /// (the message is dropped) so registry transitions don't fail just
    /// because no SDK happens to be connected.
    pub fn publish(&self, agent_id: AgentId, op_id: String, signal: OpControlSignal) -> u64 {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let envelope = OpControlEnvelope {
            agent_id,
            message: OpControlMessage {
                op_id,
                signal: signal as i32,
                sequence,
            },
            global: false,
        };
        let _ = self.tx.send(envelope);
        sequence
    }

    /// Publish an agent-wide halt under the reserved `agent:{agent_id}` op-id
    /// (AAASM-3881).
    ///
    /// Routed to the subscriber whose composite id matches `agent_id`, exactly
    /// like `publish`(Self::publish), but under the server-side reserved key
    /// the runtime always consults (AAASM-3873). Because the op-id is derived
    /// from the agent identity the gateway knows — not from the agent-supplied
    /// `trace_id` — the resulting halt cannot be evaded by an absent or forged
    /// `trace_id`. The op-id is produced by [`aa_runtime::op_control::agent_halt_op_id`]
    /// so producer and consumer can never drift.
    pub fn publish_agent_halt(&self, agent_id: AgentId, signal: OpControlSignal) -> u64 {
        let op_id = aa_runtime::op_control::agent_halt_op_id(&agent_id.agent_id);
        self.publish(agent_id, op_id, signal)
    }

    /// Publish a fleet-wide halt under the reserved global op-id `"*"`
    /// (AAASM-3881), delivered to **every** connected subscriber.
    ///
    /// Unlike the per-agent publishes, the envelope is marked
    /// [`global`](OpControlEnvelope::global) so `op_control_stream` forwards it
    /// regardless of the subscriber's `agent_id` filter. Each runtime records it
    /// under [`aa_runtime::op_control::GLOBAL_HALT_OP_ID`], which AAASM-3873 has
    /// the runtime consult on every request — a true global kill switch.
    pub fn publish_global_halt(&self, signal: OpControlSignal) -> u64 {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let envelope = OpControlEnvelope {
            // Ignored for global delivery; left default for clarity.
            agent_id: AgentId::default(),
            message: OpControlMessage {
                op_id: aa_runtime::op_control::GLOBAL_HALT_OP_ID.to_string(),
                signal: signal as i32,
                sequence,
            },
            global: true,
        };
        let _ = self.tx.send(envelope);
        sequence
    }

    /// Current number of active subscribers. Useful for shedding work
    /// when no one is listening (and for tests).
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for OpControlPublisher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience alias for the shared-ownership shape used everywhere the
/// publisher is threaded through (`PolicyServiceImpl`, `OpsRegistry`).
pub type SharedOpControlPublisher = Arc<OpControlPublisher>;

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: &str) -> AgentId {
        AgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: id.into(),
        }
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_succeeds_and_drops_message() {
        let pub_ = OpControlPublisher::new();
        let seq = pub_.publish(agent("a1"), "trace:span".into(), OpControlSignal::Pause);
        assert_eq!(seq, 0);
        assert_eq!(pub_.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn sequence_numbers_are_monotonically_increasing() {
        let pub_ = OpControlPublisher::new();
        let s0 = pub_.publish(agent("a1"), "o:0".into(), OpControlSignal::Pause);
        let s1 = pub_.publish(agent("a1"), "o:1".into(), OpControlSignal::Resume);
        let s2 = pub_.publish(agent("a1"), "o:2".into(), OpControlSignal::Terminate);
        assert_eq!((s0, s1, s2), (0, 1, 2));
    }

    #[tokio::test]
    async fn subscriber_receives_published_envelope() {
        let pub_ = OpControlPublisher::new();
        let mut rx = pub_.subscribe();
        let seq = pub_.publish(agent("a1"), "trace:span".into(), OpControlSignal::Pause);

        let envelope = rx.recv().await.unwrap();
        assert_eq!(envelope.agent_id.agent_id, "a1");
        assert_eq!(envelope.message.op_id, "trace:span");
        assert_eq!(envelope.message.signal, OpControlSignal::Pause as i32);
        assert_eq!(envelope.message.sequence, seq);
    }

    #[tokio::test]
    async fn each_subscriber_receives_every_envelope_independently() {
        let pub_ = OpControlPublisher::new();
        let mut a = pub_.subscribe();
        let mut b = pub_.subscribe();
        pub_.publish(agent("a1"), "o:0".into(), OpControlSignal::Pause);

        assert_eq!(a.recv().await.unwrap().message.op_id, "o:0");
        assert_eq!(b.recv().await.unwrap().message.op_id, "o:0");
    }

    #[tokio::test]
    async fn publish_agent_halt_uses_reserved_agent_op_id() {
        // AAASM-3881: an agent-wide halt must land under the same reserved
        // op-id the runtime consults (AAASM-3873), keyed off the server-side
        // agent identity rather than any agent-supplied trace_id.
        let pub_ = OpControlPublisher::new();
        let mut rx = pub_.subscribe();
        pub_.publish_agent_halt(agent("a1"), OpControlSignal::Terminate);

        let envelope = rx.recv().await.unwrap();
        assert!(!envelope.global);
        assert_eq!(envelope.agent_id.agent_id, "a1");
        assert_eq!(envelope.message.op_id, aa_runtime::op_control::agent_halt_op_id("a1"));
        assert_eq!(envelope.message.op_id, "agent:a1");
        assert_eq!(envelope.message.signal, OpControlSignal::Terminate as i32);
    }

    #[tokio::test]
    async fn publish_global_halt_uses_global_op_id_and_is_marked_global() {
        // AAASM-3881: a fleet-wide halt rides under the reserved "*" op-id and
        // is flagged global so the stream handler forwards it to everyone.
        let pub_ = OpControlPublisher::new();
        let mut rx = pub_.subscribe();
        pub_.publish_global_halt(OpControlSignal::Terminate);

        let envelope = rx.recv().await.unwrap();
        assert!(envelope.global);
        assert_eq!(envelope.message.op_id, aa_runtime::op_control::GLOBAL_HALT_OP_ID);
        assert_eq!(envelope.message.op_id, "*");
        assert_eq!(envelope.message.signal, OpControlSignal::Terminate as i32);
    }

    #[tokio::test]
    async fn subscriber_count_tracks_active_receivers() {
        let pub_ = OpControlPublisher::new();
        assert_eq!(pub_.subscriber_count(), 0);
        let r1 = pub_.subscribe();
        assert_eq!(pub_.subscriber_count(), 1);
        let r2 = pub_.subscribe();
        assert_eq!(pub_.subscriber_count(), 2);
        drop(r1);
        assert_eq!(pub_.subscriber_count(), 1);
        drop(r2);
        assert_eq!(pub_.subscriber_count(), 0);
    }
}
