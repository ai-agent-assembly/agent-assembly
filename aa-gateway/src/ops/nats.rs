//! Cross-process op-control delivery over a NATS subject (AAASM-3883).
//!
//! [`OpControlPublisher`](super::OpControlPublisher) is an **in-process**
//! `tokio::sync::broadcast`. In the shipped product the operator halt endpoints
//! (`AppState.ops_registry`, aa-api-server process) and the gRPC
//! `PolicyService.op_control_stream` that runtimes subscribe to (aa-gateway
//! process) run in **separate processes**, so an in-process publish reaches no
//! subscriber. This module bridges the gap with a shared NATS subject, mirroring
//! the existing audit subsystem (`assembly.audit.>`) rather than inventing a
//! parallel NATS stack. See ADR 0011.
//!
//! Two halves, both running over **NATS JetStream** (AAASM-3885) so a halt is
//! durably persisted and redelivered to a gateway that (re)subscribes — not merely
//! "accepted onto the bus" (the at-most-once CORE-NATS behavior AAASM-3883 shipped):
//!
//! * **Publish** ([`OpControlNatsPublisher`]) — used by the aa-api halt handlers
//!   to publish an [`OpControlWireEnvelope`] to `assembly.opcontrol.<tenant>.<agent>`
//!   (or `assembly.opcontrol.global`) **and await the JetStream publish ACK**, so a
//!   successful return means the halt is persisted in the durable stream. A missing
//!   stream / NATS outage / un-acked publish surfaces as a real error, never a
//!   silent-drop `200`.
//! * **Consume** ([`spawn_bridge`]) — a gateway boot task that ensures the durable
//!   [`STREAM_NAME`] stream, creates a JetStream consumer over `assembly.opcontrol.>`
//!   (replaying everything still within retention, so a halt published while this
//!   gateway had no consumer attached is still delivered), and forwards each received
//!   envelope into the gateway's in-process
//!   [`OpControlPublisher`](super::OpControlPublisher) — acking it — so the existing
//!   `op_control_stream` filtering / reserved-key matching delivers it to runtimes
//!   unchanged.
//!
//! `async-nats` is already a non-optional dependency (via `aa-runtime`'s audit
//! publisher), so this module is always compiled and activated purely by the
//! `AA_OPCONTROL_NATS_URL` environment variable — matching the always-on runtime
//! audit publisher rather than the feature-gated audit consumer. The configured NATS
//! server **must have JetStream enabled** (a deployment requirement; see ADR 0011).

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

use aa_proto::assembly::common::v1::AgentId;
use aa_proto::assembly::policy::v1::OpControlSignal;
use aa_runtime::op_control::{agent_halt_op_id, GLOBAL_HALT_OP_ID};

use super::SharedOpControlPublisher;

/// Subject prefix shared by every op-control message (mirrors `assembly.audit`).
pub const SUBJECT_PREFIX: &str = "assembly.opcontrol";
/// Subject a fleet-wide halt is published under.
pub const GLOBAL_SUBJECT: &str = "assembly.opcontrol.global";
/// Wildcard the gateway bridge subscribes to, capturing every op-control subject.
pub const SUBJECT_WILDCARD: &str = "assembly.opcontrol.>";
/// Token used when a tenant identifier is unavailable on the envelope.
const UNKNOWN_TENANT: &str = "default";
/// Token used when an agent identifier is empty.
const UNKNOWN_AGENT: &str = "unknown";

/// First reconnect delay for the bridge; doubles on each consecutive failure.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Upper bound on the bridge reconnect delay (1s → 2 → 4 → … → 32s cap).
const MAX_BACKOFF: Duration = Duration::from_secs(32);

/// Name of the durable JetStream stream that persists every op-control subject
/// (AAASM-3885). All processes ensure this stream idempotently at boot.
pub const STREAM_NAME: &str = "AA_OPCONTROL";
/// Retention window for persisted op-control halts. Halts are tiny and
/// time-sensitive, so a bounded max-age is the right retention: it covers a
/// gateway restart / rollout window (a halt published in that gap is redelivered
/// to the gateway that resubscribes within it) while keeping the stream small and
/// preventing an indefinitely-replayed stale kill switch. See ADR 0011.
pub const STREAM_MAX_AGE: Duration = Duration::from_secs(600);
/// Upper bound on how long a publish waits for the JetStream server ACK before the
/// halt endpoint reports an honest failure (`503`) rather than hanging. Keeps a
/// missing-stream / JetStream-disabled server from blocking the operator surface.
const PUBLISH_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Wire form of an op-control signal carried over NATS.
///
/// Reuses the reserved-key semantics of the in-process path: `op_id` is the same
/// reserved key the gateway and runtime already agree on (`agent:{id}` for an
/// agent-wide halt, `"*"` for a fleet-wide halt, or `"{trace}:{span}"` for a
/// per-op signal), and `signal` is the [`OpControlSignal`] discriminant. `global`
/// marks a fleet-wide halt so the gateway forwards it to every subscriber.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpControlWireEnvelope {
    /// Owning org of the targeted agent (empty for a global halt).
    pub org_id: String,
    /// Owning team of the targeted agent (empty for a global halt).
    pub team_id: String,
    /// Targeted agent id (empty for a global halt).
    pub agent_id: String,
    /// Reserved op-id the runtime consults (`agent:{id}` / `"*"` / `"{trace}:{span}"`).
    pub op_id: String,
    /// Wire [`OpControlSignal`] discriminant.
    pub signal: i32,
    /// Fleet-wide halt marker: when `true` the gateway forwards to every subscriber.
    pub global: bool,
}

/// Build the NATS subject for `envelope`.
///
/// Fleet-wide halts use [`GLOBAL_SUBJECT`]; per-agent envelopes use
/// `assembly.opcontrol.<tenant>.<agent>` where `<tenant>` is the org id, falling
/// back to the team id, then `default`, and `<agent>` is the agent id. Both tokens
/// are sanitized so the subject contains only subject-safe characters.
pub fn subject_for(envelope: &OpControlWireEnvelope) -> String {
    if envelope.global {
        return GLOBAL_SUBJECT.to_string();
    }
    let tenant = [&envelope.org_id, &envelope.team_id]
        .into_iter()
        .map(|raw| sanitize_token(raw))
        .find(|token| !token.is_empty())
        .unwrap_or_else(|| UNKNOWN_TENANT.to_string());
    let agent = {
        let token = sanitize_token(&envelope.agent_id);
        if token.is_empty() {
            UNKNOWN_AGENT.to_string()
        } else {
            token
        }
    };
    format!("{SUBJECT_PREFIX}.{tenant}.{agent}")
}

/// Replace every character outside `[A-Za-z0-9_-]` with `_` so the result is a
/// single valid NATS subject token (NATS reserves `.`, `*`, `>` and whitespace).
fn sanitize_token(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Errors raised by the op-control NATS publisher and bridge.
#[derive(Debug, thiserror::Error)]
pub enum OpControlNatsError {
    /// Connecting to the NATS server failed.
    #[error("op-control NATS connect failed: {0}")]
    Connect(String),
    /// Publishing or flushing a message failed.
    #[error("op-control NATS publish failed: {0}")]
    Publish(String),
    /// Subscribing to the op-control subject failed.
    #[error("op-control NATS subscribe failed: {0}")]
    Subscribe(String),
    /// Serializing the envelope to JSON failed.
    #[error("op-control envelope serialization failed: {0}")]
    Serialize(String),
    /// Ensuring / fetching the durable JetStream stream failed (AAASM-3885).
    #[error("op-control JetStream stream setup failed: {0}")]
    Stream(String),
    /// Creating or reading the JetStream consumer failed (AAASM-3885).
    #[error("op-control JetStream consumer failed: {0}")]
    Consumer(String),
}

impl OpControlNatsError {
    /// `true` when this error means the durable stream / consumer could not be
    /// established **after a successful connection** — a non-transient
    /// misconfiguration that retrying alone cannot fix (AAASM-3886).
    ///
    /// The canonical trigger is an operator who pre-provisioned an
    /// [`STREAM_NAME`] stream with an **incompatible immutable config**
    /// (different storage type / retention policy / non-overlapping subjects):
    /// `create_or_update_stream` can never reconcile it, so the bridge would
    /// otherwise loop forever setting up the stream **without ever consuming**,
    /// while op-control publishes keep ACKing against the existing stream — a
    /// silent non-delivery of a kill switch. JetStream being disabled or the
    /// stream being otherwise unconsumable lands here too.
    ///
    /// [`Connect`](Self::Connect) (server unreachable) is genuinely transient and
    /// returns `false` — that is the ordinary reconnect path, not a fail-loud one.
    pub fn is_stream_setup_failure(&self) -> bool {
        matches!(self, Self::Stream(_) | Self::Consumer(_))
    }
}

/// Runtime configuration for the op-control NATS bridge / publisher.
#[derive(Debug, Clone)]
pub struct OpControlNatsConfig {
    /// NATS server URL (e.g. `nats://127.0.0.1:4222`).
    pub url: String,
}

impl OpControlNatsConfig {
    /// Build a config for the given NATS URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Build a config from the environment, returning `None` (op-control NATS
    /// disabled) when `AA_OPCONTROL_NATS_URL` is unset — mirrors the audit
    /// consumer's `AA_AUDIT_NATS_URL` activation so both processes keep their
    /// existing in-process behavior unless explicitly configured.
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("AA_OPCONTROL_NATS_URL").ok().filter(|u| !u.is_empty())?;
        Some(Self::new(url))
    }
}

/// Liveness of the gateway-side op-control bridge (AAASM-3886).
///
/// Reported by [`OpControlBridgeHealth`] so the bridge's structural ability to
/// deliver halts is observable rather than buried in a silent retry loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeHealthState {
    /// Initial state, before the first connect + consumer attempt completes.
    Connecting,
    /// A JetStream consumer is established; halts are being delivered. Healthy.
    Subscribed,
    /// A transient connection drop; reconnecting with backoff. Not fail-loud —
    /// op-control delivery resumes automatically once NATS is reachable again.
    Reconnecting,
    /// **Fail-loud.** The durable stream / consumer could not be established
    /// after connecting — op-control delivery is **DOWN** and will not recover by
    /// retrying (e.g. a pre-provisioned [`STREAM_NAME`] stream with an
    /// incompatible immutable config, or JetStream disabled). A halt may still be
    /// ACKed by the publisher against the existing stream yet never reach a
    /// runtime, so this state must be surfaced, not silently looped on.
    StreamUnavailable,
}

impl BridgeHealthState {
    const CONNECTING: u8 = 0;
    const SUBSCRIBED: u8 = 1;
    const RECONNECTING: u8 = 2;
    const STREAM_UNAVAILABLE: u8 = 3;

    const fn to_u8(self) -> u8 {
        match self {
            Self::Connecting => Self::CONNECTING,
            Self::Subscribed => Self::SUBSCRIBED,
            Self::Reconnecting => Self::RECONNECTING,
            Self::StreamUnavailable => Self::STREAM_UNAVAILABLE,
        }
    }

    const fn from_u8(raw: u8) -> Self {
        match raw {
            Self::SUBSCRIBED => Self::Subscribed,
            Self::RECONNECTING => Self::Reconnecting,
            Self::STREAM_UNAVAILABLE => Self::StreamUnavailable,
            _ => Self::Connecting,
        }
    }
}

/// Cheap, cloneable, thread-safe handle to the op-control bridge's current
/// [`BridgeHealthState`] (AAASM-3886).
///
/// The bridge task owns one clone and updates it as it (re)connects; callers
/// (the gateway boot, tests, a future readiness probe) hold other clones to read
/// it. Reading is lock-free. This is the **observable** half of the fail-loud
/// behaviour — the loud `tracing::error!` is the operator-facing half.
#[derive(Clone)]
pub struct OpControlBridgeHealth {
    state: Arc<AtomicU8>,
}

impl Default for OpControlBridgeHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl OpControlBridgeHealth {
    /// A fresh handle in the [`BridgeHealthState::Connecting`] state.
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(BridgeHealthState::Connecting.to_u8())),
        }
    }

    /// Record the bridge's current state, mirroring it onto the
    /// `aa_op_control_bridge_up` gauge (`1.0` only when delivering).
    pub fn set(&self, state: BridgeHealthState) {
        self.state.store(state.to_u8(), Ordering::Relaxed);
        let up = if state == BridgeHealthState::Subscribed {
            1.0
        } else {
            0.0
        };
        metrics::gauge!("aa_op_control_bridge_up").set(up);
    }

    /// Read the bridge's current state.
    pub fn get(&self) -> BridgeHealthState {
        BridgeHealthState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// `true` only when a consumer is established and halts are being delivered.
    pub fn is_healthy(&self) -> bool {
        self.get() == BridgeHealthState::Subscribed
    }

    /// `true` when op-control delivery is structurally **down** (the fail-loud
    /// [`BridgeHealthState::StreamUnavailable`] state) — a misconfiguration that
    /// will not recover by retrying.
    pub fn is_delivery_down(&self) -> bool {
        self.get() == BridgeHealthState::StreamUnavailable
    }
}

/// Idempotently create (or update) the durable JetStream stream that persists
/// every op-control subject (AAASM-3885).
///
/// Bounded by [`STREAM_MAX_AGE`] with `Limits` retention and `File` storage so a
/// halt published while no gateway consumer is attached is durably persisted and
/// **redelivered** to a gateway that (re)subscribes within the retention window —
/// the core durability guarantee of this ticket. Safe to call from every process
/// at boot (create-or-update is idempotent). The NATS server must have JetStream
/// enabled; if it does not, this call fails with [`OpControlNatsError::Stream`].
pub async fn ensure_op_control_stream(
    jetstream: &jetstream::Context,
) -> Result<jetstream::stream::Stream, OpControlNatsError> {
    jetstream
        .create_or_update_stream(jetstream::stream::Config {
            name: STREAM_NAME.to_string(),
            subjects: vec![SUBJECT_WILDCARD.to_string()],
            retention: jetstream::stream::RetentionPolicy::Limits,
            max_age: STREAM_MAX_AGE,
            storage: jetstream::stream::StorageType::File,
            ..Default::default()
        })
        .await
        .map_err(|e| OpControlNatsError::Stream(e.to_string()))?;
    jetstream
        .get_stream(STREAM_NAME)
        .await
        .map_err(|e| OpControlNatsError::Stream(e.to_string()))
}

/// Publishes op-control signals onto the durable JetStream stream (aa-api side).
#[derive(Clone)]
pub struct OpControlNatsPublisher {
    jetstream: jetstream::Context,
    ack_timeout: Duration,
}

impl OpControlNatsPublisher {
    /// Wrap an already-connected NATS client in a JetStream context.
    pub fn new(client: async_nats::Client) -> Self {
        Self {
            jetstream: jetstream::new(client),
            ack_timeout: PUBLISH_ACK_TIMEOUT,
        }
    }

    /// Override the publish-ACK timeout (tests use a short bound so the
    /// honest-failure path returns quickly).
    pub fn with_ack_timeout(mut self, ack_timeout: Duration) -> Self {
        self.ack_timeout = ack_timeout;
        self
    }

    /// Connect to the server described by `config` and wrap the client.
    pub async fn connect(config: &OpControlNatsConfig) -> Result<Self, OpControlNatsError> {
        let client = async_nats::connect(&config.url)
            .await
            .map_err(|e| OpControlNatsError::Connect(e.to_string()))?;
        Ok(Self::new(client))
    }

    /// Publish `envelope` to JetStream and **await the publish ACK**.
    ///
    /// The first `await` sends the publish; the second resolves the JetStream
    /// server ACK, which only arrives once the message is persisted in the durable
    /// stream. A successful return therefore means the halt is durably stored and
    /// will reach any gateway that (re)subscribes within retention — not merely
    /// that bytes reached the bus. A missing stream / JetStream-disabled server /
    /// outage surfaces as an honest [`OpControlNatsError::Publish`] (the endpoint
    /// maps it to `503`), never a silent-drop `200`. The ACK wait is bounded by
    /// `ack_timeout` so the operator surface never hangs.
    pub async fn publish(&self, envelope: &OpControlWireEnvelope) -> Result<(), OpControlNatsError> {
        let subject = subject_for(envelope);
        let payload = serde_json::to_vec(envelope).map_err(|e| OpControlNatsError::Serialize(e.to_string()))?;
        let ack = self
            .jetstream
            .publish(subject, payload.into())
            .await
            .map_err(|e| OpControlNatsError::Publish(e.to_string()))?;
        match tokio::time::timeout(self.ack_timeout, ack).await {
            Ok(Ok(_ack)) => Ok(()),
            Ok(Err(e)) => Err(OpControlNatsError::Publish(e.to_string())),
            Err(_) => Err(OpControlNatsError::Publish(format!(
                "JetStream publish ACK timed out after {:?} (stream not ready or JetStream disabled?)",
                self.ack_timeout
            ))),
        }
    }

    /// Publish an agent-wide halt under the reserved `agent:{agent_id}` op-id.
    pub async fn publish_agent_halt(
        &self,
        agent_id: AgentId,
        signal: OpControlSignal,
    ) -> Result<(), OpControlNatsError> {
        let envelope = OpControlWireEnvelope {
            op_id: agent_halt_op_id(&agent_id.agent_id),
            org_id: agent_id.org_id,
            team_id: agent_id.team_id,
            agent_id: agent_id.agent_id,
            signal: signal as i32,
            global: false,
        };
        self.publish(&envelope).await
    }

    /// Publish a fleet-wide halt under the reserved global op-id `"*"`.
    pub async fn publish_global_halt(&self, signal: OpControlSignal) -> Result<(), OpControlNatsError> {
        let envelope = OpControlWireEnvelope {
            org_id: String::new(),
            team_id: String::new(),
            agent_id: String::new(),
            op_id: GLOBAL_HALT_OP_ID.to_string(),
            signal: signal as i32,
            global: true,
        };
        self.publish(&envelope).await
    }
}

/// Forward one received wire envelope into the gateway's in-process broadcast.
///
/// Reconstructs the exact envelope the in-process path would have produced: a
/// global halt goes through `publish_global_halt` (so it is marked global and
/// reaches every subscriber); a per-agent envelope goes through `publish`, which
/// preserves the reserved `op_id`. An `Unspecified` / unknown signal is dropped.
fn forward_to_broadcast(publisher: &SharedOpControlPublisher, envelope: OpControlWireEnvelope) {
    let signal = match OpControlSignal::try_from(envelope.signal) {
        Ok(OpControlSignal::Unspecified) | Err(_) => {
            tracing::warn!(
                signal = envelope.signal,
                "op-control bridge: dropping unspecified/unknown signal"
            );
            return;
        }
        Ok(signal) => signal,
    };
    if envelope.global {
        publisher.publish_global_halt(signal);
    } else {
        let agent = AgentId {
            org_id: envelope.org_id,
            team_id: envelope.team_id,
            agent_id: envelope.agent_id,
        };
        publisher.publish(agent, envelope.op_id, signal);
    }
}

/// Spawn the gateway-side bridge task: ensure the durable JetStream stream,
/// consume `assembly.opcontrol.>` (replaying everything still within retention),
/// and forward every received halt into `publisher` (the in-process broadcast
/// `op_control_stream` serves), acking each message. Reconnects forever with
/// exponential backoff so a transient NATS outage never permanently silences the
/// cross-process kill switch.
pub fn spawn_bridge(config: OpControlNatsConfig, publisher: SharedOpControlPublisher) -> JoinHandle<()> {
    spawn_bridge_with_health(config, publisher).0
}

/// Like [`spawn_bridge`] but also returns an [`OpControlBridgeHealth`] handle so
/// the caller can observe whether the bridge is actually delivering halts
/// (AAASM-3886) — in particular to detect the fail-loud
/// [`BridgeHealthState::StreamUnavailable`] state. The handle is independent of
/// the [`JoinHandle`]; dropping either does not stop the bridge task.
pub fn spawn_bridge_with_health(
    config: OpControlNatsConfig,
    publisher: SharedOpControlPublisher,
) -> (JoinHandle<()>, OpControlBridgeHealth) {
    let health = OpControlBridgeHealth::new();
    let handle = tokio::spawn(run_bridge(config, publisher, health.clone()));
    (handle, health)
}

/// Reconnect loop for the bridge.
async fn run_bridge(config: OpControlNatsConfig, publisher: SharedOpControlPublisher, health: OpControlBridgeHealth) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match bridge_once(&config, &publisher, &health).await {
            // The subscription ended cleanly — reconnect promptly.
            Ok(()) => backoff = INITIAL_BACKOFF,
            Err(err) if err.is_stream_setup_failure() => {
                // FAIL LOUD (AAASM-3886): the durable stream / consumer could not
                // be established after connecting. This does not recover by
                // retrying — the dominant cause is a pre-provisioned AA_OPCONTROL
                // stream with an incompatible immutable config — so op-control
                // delivery is structurally DOWN. Publishes may still ACK against
                // the existing stream and return 200 while NO halt reaches a
                // runtime. Surface it loudly and as unhealthy rather than burying
                // it in a quiet reconnect warning. We keep retrying (an operator
                // may repair the stream), but every attempt screams.
                metrics::counter!("aa_op_control_bridge_reconnects_total").increment(1);
                health.set(BridgeHealthState::StreamUnavailable);
                tracing::error!(
                    error = %err,
                    stream = STREAM_NAME,
                    subject = SUBJECT_WILDCARD,
                    backoff_secs = backoff.as_secs(),
                    "op-control JetStream bridge cannot establish its stream/consumer — \
                     OP-CONTROL DELIVERY IS DOWN: operator halts may be ACKed (200) yet \
                     never reach any runtime. The AA_OPCONTROL stream likely exists with an \
                     INCOMPATIBLE immutable config (storage/retention/subjects) or JetStream \
                     is disabled. Reconcile the stream (delete/recreate, or align its config) \
                     to restore the kill switch."
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            Err(err) => {
                // Transient (e.g. NATS unreachable) — reconnect quietly with backoff.
                metrics::counter!("aa_op_control_bridge_reconnects_total").increment(1);
                health.set(BridgeHealthState::Reconnecting);
                tracing::warn!(
                    error = %err,
                    backoff_secs = backoff.as_secs(),
                    "op-control NATS bridge dropped; reconnecting after backoff"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Open one JetStream consumer and forward messages until the stream ends or errors.
///
/// Ensures the durable stream, then creates an **ephemeral** JetStream consumer
/// with `DeliverPolicy::All` and explicit ack. Ephemeral + `All` is deliberate:
///
/// * each gateway replica gets its **own** consumer and therefore its own copy of
///   every halt — preserving the AAASM-3883 multi-replica fan-out (a named durable
///   consumer shared across replicas would queue-group halts to a single replica,
///   so a runtime streamed from a different replica would miss its kill switch);
/// * `DeliverPolicy::All` replays everything still in the stream when this consumer
///   is (re)created, so a halt published while this gateway had **no** consumer
///   attached is delivered once the bridge comes up — the AAASM-3885 durability
///   property. Re-reading an already-applied halt after a restart is safe because
///   `Terminate` is sticky/idempotent in the runtime `OpControlStore`.
async fn bridge_once(
    config: &OpControlNatsConfig,
    publisher: &SharedOpControlPublisher,
    health: &OpControlBridgeHealth,
) -> Result<(), OpControlNatsError> {
    let client = async_nats::connect(&config.url)
        .await
        .map_err(|e| OpControlNatsError::Connect(e.to_string()))?;
    let context = jetstream::new(client);
    let stream = ensure_op_control_stream(&context).await?;
    let consumer = stream
        .create_consumer(jetstream::consumer::pull::Config {
            deliver_policy: jetstream::consumer::DeliverPolicy::All,
            ack_policy: jetstream::consumer::AckPolicy::Explicit,
            filter_subject: SUBJECT_WILDCARD.to_string(),
            ..Default::default()
        })
        .await
        .map_err(|e| OpControlNatsError::Consumer(e.to_string()))?;
    let mut messages = consumer
        .messages()
        .await
        .map_err(|e| OpControlNatsError::Consumer(e.to_string()))?;
    // The stream and consumer are established and we are about to deliver —
    // healthy (AAASM-3886).
    health.set(BridgeHealthState::Subscribed);
    tracing::info!(
        stream = STREAM_NAME,
        subject = SUBJECT_WILDCARD,
        "op-control JetStream bridge subscribed"
    );

    while let Some(message) = messages.next().await {
        let message = message.map_err(|e| OpControlNatsError::Consumer(e.to_string()))?;
        match serde_json::from_slice::<OpControlWireEnvelope>(&message.payload) {
            Ok(envelope) => {
                metrics::counter!("aa_op_control_bridge_forwarded_total").increment(1);
                forward_to_broadcast(publisher, envelope);
            }
            Err(err) => {
                tracing::warn!(%err, "op-control bridge: dropping undecodable message");
            }
        }
        // Ack so the halt is removed from this consumer's pending set. A failed ack
        // only risks a redelivery, which is safe (sticky/idempotent halts).
        if let Err(err) = message.ack().await {
            tracing::warn!(%err, "op-control bridge: failed to ack message");
        }
    }
    Ok(())
}

/// Convenience alias for the shared-ownership shape used when threading the
/// publisher into `OpsRegistry`.
pub type SharedOpControlNatsPublisher = Arc<OpControlNatsPublisher>;

#[cfg(test)]
mod tests {
    use super::*;

    fn env(
        global: bool,
        org: &str,
        team: &str,
        agent: &str,
        op_id: &str,
        signal: OpControlSignal,
    ) -> OpControlWireEnvelope {
        OpControlWireEnvelope {
            org_id: org.into(),
            team_id: team.into(),
            agent_id: agent.into(),
            op_id: op_id.into(),
            signal: signal as i32,
            global,
        }
    }

    #[test]
    fn subject_prefers_org_then_team_then_default() {
        let with_org = env(
            false,
            "acme",
            "payments",
            "bot-7",
            "agent:bot-7",
            OpControlSignal::Terminate,
        );
        assert_eq!(subject_for(&with_org), "assembly.opcontrol.acme.bot-7");

        let team_only = env(false, "", "payments", "bot-7", "agent:bot-7", OpControlSignal::Pause);
        assert_eq!(subject_for(&team_only), "assembly.opcontrol.payments.bot-7");

        let neither = env(false, "", "", "bot-7", "agent:bot-7", OpControlSignal::Pause);
        assert_eq!(subject_for(&neither), "assembly.opcontrol.default.bot-7");
    }

    #[test]
    fn subject_sanitizes_unsafe_tokens_and_falls_back_for_empty_agent() {
        let dotted = env(
            false,
            "acme corp.eu",
            "",
            "bot.7",
            "agent:bot.7",
            OpControlSignal::Terminate,
        );
        assert_eq!(subject_for(&dotted), "assembly.opcontrol.acme_corp_eu.bot_7");

        let no_agent = env(false, "acme", "", "", "*", OpControlSignal::Terminate);
        assert_eq!(subject_for(&no_agent), "assembly.opcontrol.acme.unknown");
    }

    #[test]
    fn global_envelope_uses_the_global_subject() {
        let g = env(true, "", "", "", GLOBAL_HALT_OP_ID, OpControlSignal::Terminate);
        assert_eq!(subject_for(&g), GLOBAL_SUBJECT);
    }

    #[test]
    fn wire_envelope_round_trips_through_json() {
        let original = env(
            false,
            "acme",
            "payments",
            "bot-7",
            "agent:bot-7",
            OpControlSignal::Terminate,
        );
        let bytes = serde_json::to_vec(&original).unwrap();
        let decoded: OpControlWireEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.signal, OpControlSignal::Terminate as i32);
    }

    #[tokio::test]
    async fn forward_reconstructs_per_agent_envelope_into_broadcast() {
        let publisher = Arc::new(super::super::OpControlPublisher::new());
        let mut rx = publisher.subscribe();

        forward_to_broadcast(
            &publisher,
            env(
                false,
                "org",
                "team",
                "a1",
                &agent_halt_op_id("a1"),
                OpControlSignal::Terminate,
            ),
        );

        let envelope = rx.recv().await.unwrap();
        assert!(!envelope.global);
        assert_eq!(envelope.agent_id.agent_id, "a1");
        assert_eq!(envelope.message.op_id, "agent:a1");
        assert_eq!(envelope.message.signal, OpControlSignal::Terminate as i32);
    }

    #[tokio::test]
    async fn forward_reconstructs_global_envelope_into_broadcast() {
        let publisher = Arc::new(super::super::OpControlPublisher::new());
        let mut rx = publisher.subscribe();

        forward_to_broadcast(
            &publisher,
            env(true, "", "", "", GLOBAL_HALT_OP_ID, OpControlSignal::Pause),
        );

        let envelope = rx.recv().await.unwrap();
        assert!(envelope.global);
        assert_eq!(envelope.message.op_id, "*");
        assert_eq!(envelope.message.signal, OpControlSignal::Pause as i32);
    }

    // ── AAASM-3886: fail-loud classification + bridge health handle ─────────

    #[test]
    fn stream_and_consumer_setup_failures_are_fail_loud() {
        // A stream/consumer setup failure (after a successful connect) is the
        // non-transient fail-loud condition — the canonical trigger is a
        // pre-provisioned stream with an incompatible immutable config.
        assert!(OpControlNatsError::Stream("immutable field".into()).is_stream_setup_failure());
        assert!(OpControlNatsError::Consumer("cannot create".into()).is_stream_setup_failure());
    }

    #[test]
    fn connect_and_other_errors_are_transient_not_fail_loud() {
        // Server-unreachable / publish / serialize / subscribe are NOT fail-loud
        // — they are the ordinary transient reconnect path.
        assert!(!OpControlNatsError::Connect("refused".into()).is_stream_setup_failure());
        assert!(!OpControlNatsError::Publish("no ack".into()).is_stream_setup_failure());
        assert!(!OpControlNatsError::Subscribe("nope".into()).is_stream_setup_failure());
        assert!(!OpControlNatsError::Serialize("bad json".into()).is_stream_setup_failure());
    }

    #[test]
    fn bridge_health_starts_connecting_and_tracks_transitions() {
        let health = OpControlBridgeHealth::new();
        assert_eq!(health.get(), BridgeHealthState::Connecting);
        assert!(!health.is_healthy());
        assert!(!health.is_delivery_down());

        health.set(BridgeHealthState::Subscribed);
        assert_eq!(health.get(), BridgeHealthState::Subscribed);
        assert!(health.is_healthy());
        assert!(!health.is_delivery_down());

        health.set(BridgeHealthState::Reconnecting);
        assert!(!health.is_healthy());
        assert!(!health.is_delivery_down());

        health.set(BridgeHealthState::StreamUnavailable);
        assert!(!health.is_healthy());
        assert!(
            health.is_delivery_down(),
            "the fail-loud state must report op-control delivery as down",
        );
    }

    #[test]
    fn bridge_health_handle_clones_share_one_state() {
        // The bridge task owns one clone and updates it; callers read another.
        let writer = OpControlBridgeHealth::new();
        let reader = writer.clone();
        writer.set(BridgeHealthState::StreamUnavailable);
        assert!(
            reader.is_delivery_down(),
            "a clone must observe the writer's StreamUnavailable transition",
        );
    }

    #[tokio::test]
    async fn forward_drops_unspecified_signal() {
        let publisher = Arc::new(super::super::OpControlPublisher::new());
        let mut rx = publisher.subscribe();

        forward_to_broadcast(
            &publisher,
            env(false, "org", "team", "a1", "agent:a1", OpControlSignal::Unspecified),
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx.recv())
                .await
                .is_err(),
            "an unspecified signal must not be forwarded",
        );
    }
}
