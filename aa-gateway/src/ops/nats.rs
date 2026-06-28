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
//! Two halves:
//!
//! * **Publish** ([`OpControlNatsPublisher`]) — used by the aa-api halt handlers
//!   to publish an [`OpControlWireEnvelope`] to `assembly.opcontrol.<tenant>.<agent>`
//!   (or `assembly.opcontrol.global`). It `flush()`es after every publish so a
//!   NATS outage surfaces as a real error, never a silent-drop `200`.
//! * **Consume** ([`spawn_bridge`]) — a gateway boot task that subscribes to
//!   `assembly.opcontrol.>` and forwards each received envelope into the gateway's
//!   in-process [`OpControlPublisher`](super::OpControlPublisher), so the existing
//!   `op_control_stream` filtering / reserved-key matching delivers it to runtimes
//!   unchanged.
//!
//! `async-nats` is already a non-optional dependency (via `aa-runtime`'s audit
//! publisher), so this module is always compiled and activated purely by the
//! `AA_OPCONTROL_NATS_URL` environment variable — matching the always-on runtime
//! audit publisher rather than the feature-gated audit consumer.

use std::sync::Arc;
use std::time::Duration;

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

/// Publishes op-control signals onto the shared NATS subject (aa-api side).
#[derive(Clone)]
pub struct OpControlNatsPublisher {
    client: async_nats::Client,
}

impl OpControlNatsPublisher {
    /// Wrap an already-connected NATS client.
    pub fn new(client: async_nats::Client) -> Self {
        Self { client }
    }

    /// Connect to the server described by `config` and wrap the client.
    pub async fn connect(config: &OpControlNatsConfig) -> Result<Self, OpControlNatsError> {
        let client = async_nats::connect(&config.url)
            .await
            .map_err(|e| OpControlNatsError::Connect(e.to_string()))?;
        Ok(Self::new(client))
    }

    /// Publish `envelope` and flush so the write reaches the server before
    /// returning. The flush is what makes a NATS outage an honest error rather
    /// than a buffered success the operator would misread as a delivered halt.
    pub async fn publish(&self, envelope: &OpControlWireEnvelope) -> Result<(), OpControlNatsError> {
        let subject = subject_for(envelope);
        let payload = serde_json::to_vec(envelope).map_err(|e| OpControlNatsError::Serialize(e.to_string()))?;
        self.client
            .publish(subject, payload.into())
            .await
            .map_err(|e| OpControlNatsError::Publish(e.to_string()))?;
        self.client
            .flush()
            .await
            .map_err(|e| OpControlNatsError::Publish(e.to_string()))?;
        Ok(())
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

/// Spawn the gateway-side bridge task: subscribe to `assembly.opcontrol.>` and
/// forward every received halt into `publisher` (the in-process broadcast
/// `op_control_stream` serves). Reconnects forever with exponential backoff so a
/// transient NATS outage never permanently silences the cross-process kill switch.
pub fn spawn_bridge(config: OpControlNatsConfig, publisher: SharedOpControlPublisher) -> JoinHandle<()> {
    tokio::spawn(run_bridge(config, publisher))
}

/// Reconnect loop for the bridge.
async fn run_bridge(config: OpControlNatsConfig, publisher: SharedOpControlPublisher) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match bridge_once(&config, &publisher).await {
            // The subscription ended cleanly — reconnect promptly.
            Ok(()) => backoff = INITIAL_BACKOFF,
            Err(err) => {
                metrics::counter!("aa_op_control_bridge_reconnects_total").increment(1);
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

/// Open one subscription and forward messages until the stream ends or errors.
async fn bridge_once(
    config: &OpControlNatsConfig,
    publisher: &SharedOpControlPublisher,
) -> Result<(), OpControlNatsError> {
    let client = async_nats::connect(&config.url)
        .await
        .map_err(|e| OpControlNatsError::Connect(e.to_string()))?;
    let mut subscription = client
        .subscribe(SUBJECT_WILDCARD)
        .await
        .map_err(|e| OpControlNatsError::Subscribe(e.to_string()))?;
    // Flush so the SUB is registered server-side before we report readiness.
    client
        .flush()
        .await
        .map_err(|e| OpControlNatsError::Subscribe(e.to_string()))?;
    tracing::info!(subject = SUBJECT_WILDCARD, "op-control NATS bridge subscribed");

    while let Some(message) = subscription.next().await {
        match serde_json::from_slice::<OpControlWireEnvelope>(&message.payload) {
            Ok(envelope) => {
                metrics::counter!("aa_op_control_bridge_forwarded_total").increment(1);
                forward_to_broadcast(publisher, envelope);
            }
            Err(err) => {
                tracing::warn!(%err, "op-control bridge: dropping undecodable message");
            }
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
