//! [`InvalidationHub`] — the gateway-side fan-out for L1 push-invalidation.
//!
//! One [`Subscriber`] is tracked per connected Assembly (keyed by `assembly_id`).
//! Each subscriber owns a monotonic sequence counter and a bounded replay ring
//! so a reconnecting Assembly can request everything it missed via
//! `SubscribeInitial.last_seq_seen`. A policy mutation calls
//! [`InvalidationHub::broadcast_policy_invalidated`], which fans the event out to
//! every subscriber's live channel and records it in their replay ring.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::broadcast;

use aa_proto::assembly::gateway::v1::invalidation_event::Payload;
use aa_proto::assembly::gateway::v1::{InvalidationEvent, PolicyInvalidated};

/// Stable identifier of a subscribing Assembly instance.
pub type AssemblyId = String;

/// Number of recent events retained per subscriber for replay-on-reconnect.
const REPLAY_RING_CAPACITY: usize = 1024;

/// Bound on the per-subscriber live broadcast channel. A subscriber that falls
/// this far behind is marked lagged and recovers via the replay ring on its
/// next reconnect.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 1024;

/// Per-Assembly delivery state: a live channel, a monotonic seq counter, and a
/// bounded replay ring.
struct Subscriber {
    /// Live fan-out channel; the Subscribe RPC holds the receiving end.
    tx: broadcast::Sender<InvalidationEvent>,
    /// Next sequence number to assign. Starts at 1 so `last_seq_seen == 0`
    /// (cold start) replays the full ring.
    next_seq: AtomicU64,
    /// Most recent events (≤ [`REPLAY_RING_CAPACITY`]) for replay-on-reconnect.
    ring: Mutex<VecDeque<InvalidationEvent>>,
}

/// The result of [`InvalidationHub::subscribe`]: events the Assembly missed
/// (to flush first) plus the live receiver for everything thereafter.
pub struct SubscriptionHandle {
    /// Events with `seq > last_seq_seen` that were buffered while the Assembly
    /// was disconnected. The Subscribe RPC yields these before live events.
    pub replay: Vec<InvalidationEvent>,
    /// Live event stream for everything published after this subscription.
    pub receiver: broadcast::Receiver<InvalidationEvent>,
}

/// Gateway-side hub that fans policy invalidations out to every connected
/// Assembly and buffers them for replay across reconnects.
#[derive(Default)]
pub struct InvalidationHub {
    subscribers: RwLock<HashMap<AssemblyId, Arc<Subscriber>>>,
}

impl InvalidationHub {
    /// Create an empty hub.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register (or look up) the subscriber for `assembly_id` and return a
    /// [`SubscriptionHandle`] carrying the replay backlog plus a live receiver.
    ///
    /// Reconnecting with the same `assembly_id` reuses the existing sequence
    /// counter and replay ring, so `last_seq_seen` resumes exactly where the
    /// previous connection left off.
    pub fn subscribe(&self, assembly_id: impl Into<AssemblyId>, last_seq_seen: u64) -> SubscriptionHandle {
        let assembly_id = assembly_id.into();
        let mut subscribers = self
            .subscribers
            .write()
            .expect("invalidation subscribers lock poisoned");
        let subscriber = subscribers
            .entry(assembly_id)
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(SUBSCRIBER_CHANNEL_CAPACITY);
                Arc::new(Subscriber {
                    tx,
                    next_seq: AtomicU64::new(1),
                    ring: Mutex::new(VecDeque::new()),
                })
            })
            .clone();

        // Subscribe the receiver and snapshot the ring while still holding the
        // write lock so a concurrent broadcast cannot interleave and be lost.
        let receiver = subscriber.tx.subscribe();
        let replay: Vec<InvalidationEvent> = {
            let ring = subscriber.ring.lock().expect("replay ring lock poisoned");
            ring.iter().filter(|event| event.seq > last_seq_seen).cloned().collect()
        };
        let subscriber_count = subscribers.len();
        drop(subscribers);

        if !replay.is_empty() {
            metrics::counter!("aa_invalidation_replay_count").increment(replay.len() as u64);
        }
        metrics::gauge!("aa_invalidation_subscribers").set(subscriber_count as f64);

        SubscriptionHandle { replay, receiver }
    }

    /// Fan a `PolicyInvalidated` event out to every connected Assembly.
    ///
    /// Each subscriber receives the event under its own monotonic sequence
    /// number and a copy is appended to its replay ring (oldest trimmed past
    /// [`REPLAY_RING_CAPACITY`]). An empty `agent_id` is the "invalidate all
    /// cached agents" convention used for a global policy swap.
    pub fn broadcast_policy_invalidated(&self, agent_id: impl Into<String>, policy_version: u64) {
        let agent_id = agent_id.into();
        let subscribers = self.subscribers.read().expect("invalidation subscribers lock poisoned");
        for subscriber in subscribers.values() {
            let seq = subscriber.next_seq.fetch_add(1, Ordering::Relaxed);
            let event = InvalidationEvent {
                seq,
                payload: Some(Payload::PolicyInvalidated(PolicyInvalidated {
                    agent_id: agent_id.clone(),
                    policy_version,
                })),
            };
            {
                let mut ring = subscriber.ring.lock().expect("replay ring lock poisoned");
                ring.push_back(event.clone());
                while ring.len() > REPLAY_RING_CAPACITY {
                    ring.pop_front();
                }
            }
            // Best-effort: a subscriber with no live receiver still has the
            // event recorded in its ring for replay on reconnect.
            let _ = subscriber.tx.send(event);
            metrics::counter!("aa_invalidation_events_broadcast").increment(1);
        }
    }

    /// Trim a subscriber's replay ring up to and including `seq`, in response to
    /// a `SubscribeAck`. Advances the low-water mark so acknowledged events are
    /// not replayed again. Unknown `assembly_id`s are ignored.
    pub fn ack(&self, assembly_id: &str, seq: u64) {
        let subscribers = self.subscribers.read().expect("invalidation subscribers lock poisoned");
        if let Some(subscriber) = subscribers.get(assembly_id) {
            let mut ring = subscriber.ring.lock().expect("replay ring lock poisoned");
            while ring.front().is_some_and(|event| event.seq <= seq) {
                ring.pop_front();
            }
        }
    }

    /// Number of registered subscribers. Primarily for tests and metrics.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers
            .read()
            .expect("invalidation subscribers lock poisoned")
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn policy_agent(event: &InvalidationEvent) -> &str {
        match event.payload.as_ref().expect("payload set") {
            Payload::PolicyInvalidated(p) => &p.agent_id,
            Payload::ApprovalResolved(_) => panic!("expected PolicyInvalidated"),
        }
    }

    #[tokio::test]
    async fn broadcast_reaches_live_subscriber_within_100ms() {
        let hub = InvalidationHub::new();
        let mut handle = hub.subscribe("asm-1", 0);
        assert!(handle.replay.is_empty());

        let start = std::time::Instant::now();
        hub.broadcast_policy_invalidated("agent-x", 7);

        let event = tokio::time::timeout(Duration::from_millis(100), handle.receiver.recv())
            .await
            .expect("event delivered within 100 ms")
            .expect("channel open");
        assert!(start.elapsed() < Duration::from_millis(100));
        assert_eq!(event.seq, 1);
        assert_eq!(policy_agent(&event), "agent-x");
    }

    #[tokio::test]
    async fn reconnect_replays_only_events_after_last_seq() {
        let hub = InvalidationHub::new();
        // First connection registers the subscriber, then disconnects.
        let handle = hub.subscribe("asm-1", 0);
        drop(handle);

        hub.broadcast_policy_invalidated("agent-a", 1);
        hub.broadcast_policy_invalidated("agent-b", 2);

        // Cold reconnect replays the full backlog.
        let full = hub.subscribe("asm-1", 0);
        assert_eq!(full.replay.len(), 2);
        assert_eq!(full.replay[0].seq, 1);
        assert_eq!(full.replay[1].seq, 2);

        // Reconnect having already applied seq 1 replays only seq 2.
        let partial = hub.subscribe("asm-1", 1);
        assert_eq!(partial.replay.len(), 1);
        assert_eq!(partial.replay[0].seq, 2);
        assert_eq!(policy_agent(&partial.replay[0]), "agent-b");
    }

    #[tokio::test]
    async fn ack_trims_replay_ring() {
        let hub = InvalidationHub::new();
        let _handle = hub.subscribe("asm-1", 0);
        hub.broadcast_policy_invalidated("agent-a", 1);
        hub.broadcast_policy_invalidated("agent-b", 2);

        hub.ack("asm-1", 1);

        // After acking seq 1, a cold reconnect only replays seq 2.
        let reconnect = hub.subscribe("asm-1", 0);
        assert_eq!(reconnect.replay.len(), 1);
        assert_eq!(reconnect.replay[0].seq, 2);
    }

    #[test]
    fn each_subscriber_gets_independent_sequence() {
        let hub = InvalidationHub::new();
        let _a = hub.subscribe("asm-1", 0);
        let _b = hub.subscribe("asm-2", 0);
        assert_eq!(hub.subscriber_count(), 2);

        hub.broadcast_policy_invalidated("agent-a", 1);

        // Each subscriber independently records the event at its own seq 1.
        let reconnect_a = hub.subscribe("asm-1", 0);
        let reconnect_b = hub.subscribe("asm-2", 0);
        assert_eq!(reconnect_a.replay.len(), 1);
        assert_eq!(reconnect_b.replay.len(), 1);
        assert_eq!(reconnect_a.replay[0].seq, 1);
        assert_eq!(reconnect_b.replay[0].seq, 1);
    }
}
