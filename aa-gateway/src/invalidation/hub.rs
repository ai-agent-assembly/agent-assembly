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
use aa_proto::assembly::gateway::v1::{ApprovalResolved, Decision, InvalidationEvent, PolicyInvalidated};
use aa_runtime::approval::{ApprovalDecision, ApprovalResolvedNotifier};

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
    /// Tenant (team) this subscriber belongs to, captured from the verified
    /// caller at subscribe time. `None` means the caller had no resolvable
    /// tenant; such a subscriber receives only global (untenanted) events so a
    /// missing tenant can never leak another tenant's events (fail-closed).
    /// AAASM-3890.
    tenant: Option<String>,
}

/// Why [`InvalidationHub::subscribe`] refused to register a subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscribeError {
    /// The `assembly_id` is already registered under a different tenant than the
    /// authenticated caller. Reusing the slot would attach this caller's
    /// receiver to the existing tenant's broadcast channel (leaking its events)
    /// and let this caller's acks trim that tenant's replay ring. Fail-closed:
    /// the subscription is refused (AAASM-3914).
    TenantMismatch,
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

/// Decide whether a subscriber is entitled to an event, given the subscriber's
/// captured tenant and the event's owning tenant (AAASM-3890).
///
/// A `None` `event_tenant` is global and reaches everyone. A `Some` event
/// reaches only subscribers whose tenant equals it; a subscriber with no
/// resolved tenant (`None`) never receives a tenant-scoped event. This is
/// fail-closed: any ambiguity resolves to *not* delivering, so a cross-tenant
/// leak cannot occur.
fn event_entitled(subscriber_tenant: Option<&str>, event_tenant: Option<&str>) -> bool {
    match event_tenant {
        None => true,
        Some(event_tenant) => subscriber_tenant == Some(event_tenant),
    }
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
    ///
    /// `tenant` is the verified caller's team, captured so [`Self::fan_out`] can
    /// scope tenant-bound events to their owning tenant. On reconnect the
    /// originally-registered tenant is retained.
    ///
    /// Returns [`SubscribeError::TenantMismatch`] when `assembly_id` is already
    /// registered under a tenant other than `tenant` (AAASM-3914). The match is
    /// exact: an untenanted slot (`None`) may not be claimed by a tenant, nor a
    /// tenanted slot by an untenanted caller — any mismatch is fail-closed, so a
    /// caller can never attach to another tenant's channel or trim its ring. A
    /// reconnect by the same tenant (the common `None == None` cold-start case
    /// included) is permitted and resumes from `last_seq_seen`.
    pub fn subscribe(
        &self,
        assembly_id: impl Into<AssemblyId>,
        tenant: Option<String>,
        last_seq_seen: u64,
    ) -> Result<SubscriptionHandle, SubscribeError> {
        let assembly_id = assembly_id.into();
        let mut subscribers = self
            .subscribers
            .write()
            .expect("invalidation subscribers lock poisoned");
        // Fail-closed: an existing subscriber bound to a different tenant must
        // not be re-bound to this caller, or its events would leak to — and its
        // replay ring be trimmed by — the wrong tenant (AAASM-3914).
        if let Some(existing) = subscribers.get(&assembly_id) {
            if existing.tenant != tenant {
                return Err(SubscribeError::TenantMismatch);
            }
        }
        let subscriber = subscribers
            .entry(assembly_id)
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(SUBSCRIBER_CHANNEL_CAPACITY);
                Arc::new(Subscriber {
                    tx,
                    next_seq: AtomicU64::new(1),
                    ring: Mutex::new(VecDeque::new()),
                    tenant,
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

        Ok(SubscriptionHandle { replay, receiver })
    }

    /// Fan a `PolicyInvalidated` event out to every connected Assembly.
    ///
    /// Each subscriber receives the event under its own monotonic sequence
    /// number and a copy is appended to its replay ring (oldest trimmed past
    /// [`REPLAY_RING_CAPACITY`]). An empty `agent_id` is the "invalidate all
    /// cached agents" convention used for a global policy swap.
    ///
    /// A policy swap mutates the single global policy epoch, so it is fanned out
    /// to every subscriber regardless of tenant (`event_tenant = None`).
    pub fn broadcast_policy_invalidated(&self, agent_id: impl Into<String>, policy_version: u64) {
        self.fan_out(
            Payload::PolicyInvalidated(PolicyInvalidated {
                agent_id: agent_id.into(),
                policy_version,
            }),
            None,
        );
    }

    /// Fan an `ApprovalResolved` event out to every connected Assembly.
    ///
    /// Reuses the same push channel as [`broadcast_policy_invalidated`]: a
    /// blocked agent that subscribed (via an `ApprovalSink`) is woken the
    /// instant a human reviewer's verdict is recorded, instead of polling.
    /// `request_id` identifies the resolved approval request; `decision` is
    /// the reviewer's verdict. AAASM-2378.
    ///
    /// `tenant` is the resolved request's owning team; the event is delivered
    /// only to subscribers of that tenant so one tenant's approval resolutions
    /// never reach another tenant's Assemblies (AAASM-3890). `None` falls back
    /// to a global fan-out.
    pub fn broadcast_approval_resolved(&self, request_id: impl Into<String>, decision: Decision, tenant: Option<&str>) {
        self.fan_out(
            Payload::ApprovalResolved(ApprovalResolved {
                request_id: request_id.into(),
                decision: decision as i32,
            }),
            tenant,
        );
    }

    /// Fan a single payload out to the connected Assemblies entitled to it,
    /// under each subscriber's own monotonic sequence number, recording a copy
    /// in its replay ring (oldest trimmed past [`REPLAY_RING_CAPACITY`]) so a
    /// reconnecting Assembly can recover anything missed.
    ///
    /// `event_tenant` scopes delivery (AAASM-3890): `None` is a global event
    /// delivered to every subscriber; `Some(tenant)` is delivered only to
    /// subscribers whose captured tenant matches. A subscriber with no resolved
    /// tenant therefore receives only global events — a tenant mismatch (or a
    /// missing tenant on either side) can never leak a tenant-scoped event
    /// (fail-closed). The filter gates both the live send and the replay ring
    /// append so a reconnect cannot replay an event the subscriber was never
    /// entitled to.
    fn fan_out(&self, payload: Payload, event_tenant: Option<&str>) {
        let subscribers = self.subscribers.read().expect("invalidation subscribers lock poisoned");
        for subscriber in subscribers.values() {
            if !event_entitled(subscriber.tenant.as_deref(), event_tenant) {
                continue;
            }
            let seq = subscriber.next_seq.fetch_add(1, Ordering::Relaxed);
            let event = InvalidationEvent {
                seq,
                payload: Some(payload.clone()),
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

/// Bridges [`ApprovalQueue`](aa_runtime::approval::ApprovalQueue) resolutions to
/// the push channel: a human verdict becomes an `ApprovalResolved` event fanned
/// out to subscribed Assemblies. Timeouts are *not* broadcast — they are not a
/// human response, and a blocked agent handles its own deadline locally via
/// `ApprovalSink::wait_for_approval`. AAASM-2378.
impl ApprovalResolvedNotifier for InvalidationHub {
    fn notify_resolved(&self, request_id: &str, decision: &ApprovalDecision, tenant: Option<&str>) {
        let wire = match decision {
            ApprovalDecision::Approved { .. } => Decision::Approved,
            ApprovalDecision::Rejected { .. } => Decision::Denied,
            ApprovalDecision::TimedOut { .. } => return,
        };
        self.broadcast_approval_resolved(request_id, wire, tenant);
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
        let mut handle = hub.subscribe("asm-1", None, 0).expect("subscribe succeeds");
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
        let handle = hub.subscribe("asm-1", None, 0).expect("subscribe succeeds");
        drop(handle);

        hub.broadcast_policy_invalidated("agent-a", 1);
        hub.broadcast_policy_invalidated("agent-b", 2);

        // Cold reconnect replays the full backlog.
        let full = hub.subscribe("asm-1", None, 0).expect("subscribe succeeds");
        assert_eq!(full.replay.len(), 2);
        assert_eq!(full.replay[0].seq, 1);
        assert_eq!(full.replay[1].seq, 2);

        // Reconnect having already applied seq 1 replays only seq 2.
        let partial = hub.subscribe("asm-1", None, 1).expect("subscribe succeeds");
        assert_eq!(partial.replay.len(), 1);
        assert_eq!(partial.replay[0].seq, 2);
        assert_eq!(policy_agent(&partial.replay[0]), "agent-b");
    }

    #[tokio::test]
    async fn ack_trims_replay_ring() {
        let hub = InvalidationHub::new();
        let _handle = hub.subscribe("asm-1", None, 0).expect("subscribe succeeds");
        hub.broadcast_policy_invalidated("agent-a", 1);
        hub.broadcast_policy_invalidated("agent-b", 2);

        hub.ack("asm-1", 1);

        // After acking seq 1, a cold reconnect only replays seq 2.
        let reconnect = hub.subscribe("asm-1", None, 0).expect("subscribe succeeds");
        assert_eq!(reconnect.replay.len(), 1);
        assert_eq!(reconnect.replay[0].seq, 2);
    }

    #[test]
    fn each_subscriber_gets_independent_sequence() {
        let hub = InvalidationHub::new();
        let _a = hub.subscribe("asm-1", None, 0).expect("subscribe succeeds");
        let _b = hub.subscribe("asm-2", None, 0).expect("subscribe succeeds");
        assert_eq!(hub.subscriber_count(), 2);

        hub.broadcast_policy_invalidated("agent-a", 1);

        // Each subscriber independently records the event at its own seq 1.
        let reconnect_a = hub.subscribe("asm-1", None, 0).expect("subscribe succeeds");
        let reconnect_b = hub.subscribe("asm-2", None, 0).expect("subscribe succeeds");
        assert_eq!(reconnect_a.replay.len(), 1);
        assert_eq!(reconnect_b.replay.len(), 1);
        assert_eq!(reconnect_a.replay[0].seq, 1);
        assert_eq!(reconnect_b.replay[0].seq, 1);
    }

    #[tokio::test]
    async fn broadcast_approval_resolved_reaches_subscriber() {
        let hub = InvalidationHub::new();
        let mut handle = hub.subscribe("asm-1", None, 0).expect("subscribe succeeds");

        hub.broadcast_approval_resolved("req-42", Decision::Approved, None);

        let event = tokio::time::timeout(Duration::from_millis(100), handle.receiver.recv())
            .await
            .expect("event delivered within 100 ms")
            .expect("channel open");
        assert_eq!(event.seq, 1);
        match event.payload.expect("payload set") {
            Payload::ApprovalResolved(ar) => {
                assert_eq!(ar.request_id, "req-42");
                assert_eq!(ar.decision(), Decision::Approved);
            }
            other => panic!("expected ApprovalResolved, got {other:?}"),
        }
    }

    /// AAASM-3890 regression: a tenant-scoped approval resolution reaches only
    /// its owning tenant's subscriber, never another tenant's — neither on the
    /// live channel nor via the replay ring on reconnect.
    #[tokio::test]
    async fn approval_fan_out_is_scoped_to_owning_tenant() {
        let hub = InvalidationHub::new();
        let mut team_a = hub
            .subscribe("asm-a", Some("team-a".to_string()), 0)
            .expect("subscribe succeeds");
        let mut team_b = hub
            .subscribe("asm-b", Some("team-b".to_string()), 0)
            .expect("subscribe succeeds");

        // Resolve an approval owned by team-a.
        hub.broadcast_approval_resolved("req-a", Decision::Approved, Some("team-a"));

        // team-a receives its own event.
        let event = tokio::time::timeout(Duration::from_millis(100), team_a.receiver.recv())
            .await
            .expect("team-a event delivered within 100 ms")
            .expect("channel open");
        match event.payload.expect("payload set") {
            Payload::ApprovalResolved(ar) => assert_eq!(ar.request_id, "req-a"),
            other => panic!("expected ApprovalResolved, got {other:?}"),
        }

        // team-b must NOT receive team-a's event on its live channel.
        let leaked = tokio::time::timeout(Duration::from_millis(50), team_b.receiver.recv()).await;
        assert!(leaked.is_err(), "team-b must not receive team-a's approval event");

        // Nor may it surface via replay: team-b's ring never recorded the event.
        let reconnect_b = hub
            .subscribe("asm-b", Some("team-b".to_string()), 0)
            .expect("subscribe succeeds");
        assert!(
            reconnect_b.replay.is_empty(),
            "team-b replay ring must not contain team-a's event"
        );
    }

    /// AAASM-3914 regression: a Subscribe whose `assembly_id` already belongs to
    /// another tenant is refused, so the caller can neither attach to the
    /// victim's broadcast channel nor trim its replay ring.
    #[tokio::test]
    async fn subscribe_rejects_cross_tenant_assembly_id_reuse() {
        let hub = InvalidationHub::new();
        let mut victim = hub
            .subscribe("asm-shared", Some("team-a".to_string()), 0)
            .expect("victim subscribe succeeds");

        // Attacker in team-b knows team-a's assembly_id; binding is refused.
        let attacker = hub.subscribe("asm-shared", Some("team-b".to_string()), 0);
        assert!(matches!(attacker, Err(SubscribeError::TenantMismatch)));

        // An untenanted caller likewise may not claim a tenanted slot.
        let untenanted = hub.subscribe("asm-shared", None, 0);
        assert!(matches!(untenanted, Err(SubscribeError::TenantMismatch)));

        // The victim's own event still flows to the victim only; the rejected
        // attacker never received a handle, so nothing leaked.
        hub.broadcast_approval_resolved("req-a", Decision::Approved, Some("team-a"));
        let event = tokio::time::timeout(Duration::from_millis(100), victim.receiver.recv())
            .await
            .expect("victim event delivered within 100 ms")
            .expect("channel open");
        assert_eq!(event.seq, 1);

        // The attacker's rejection left no extra subscriber registered.
        assert_eq!(hub.subscriber_count(), 1);
    }

    /// AAASM-3914 regression: the legitimate reconnect path — same tenant, same
    /// assembly_id — is still permitted, resumes from `last_seq_seen`, and keeps
    /// receiving its tenant's live events.
    #[tokio::test]
    async fn subscribe_allows_same_tenant_reconnect() {
        let hub = InvalidationHub::new();
        let first = hub
            .subscribe("asm-a", Some("team-a".to_string()), 0)
            .expect("first subscribe succeeds");
        drop(first);

        hub.broadcast_approval_resolved("req-1", Decision::Approved, Some("team-a"));
        hub.broadcast_approval_resolved("req-2", Decision::Approved, Some("team-a"));

        // Reconnect by the same tenant resumes after seq 1: only seq 2 replays.
        let mut reconnect = hub
            .subscribe("asm-a", Some("team-a".to_string()), 1)
            .expect("same-tenant reconnect succeeds");
        assert_eq!(reconnect.replay.len(), 1);
        assert_eq!(reconnect.replay[0].seq, 2);

        // It still receives this tenant's subsequent live events.
        hub.broadcast_approval_resolved("req-3", Decision::Approved, Some("team-a"));
        let event = tokio::time::timeout(Duration::from_millis(100), reconnect.receiver.recv())
            .await
            .expect("live event delivered within 100 ms")
            .expect("channel open");
        assert_eq!(event.seq, 3);
    }
}
