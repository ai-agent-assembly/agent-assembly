//! Enriched event type produced by the pipeline ingestion stage.

use aa_proto::assembly::audit::v1::AuditEvent;
use aa_security::sdk_identity::ObservedSdkIdentity;

/// Reserved `AuditEvent.labels` key carrying the SDK version an agent *claims*.
///
/// The SDK controls the `labels` map, so this is an **untrusted claim**: it is
/// transported to the server-side classifier (AAASM-3621) to be recomputed
/// against the verified identity, never honoured at face value. Unlike the
/// trust-marker keys stripped in enforcement (AAASM-3630), this key is
/// preserved — it is a claim to be verified, not a trust grant.
pub const SDK_VERSION_LABEL: &str = "aa.sdk_version";

/// The input source that delivered the raw event to the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventSource {
    /// Delivered via the Unix domain socket IPC server (SDK process).
    Sdk,
    /// Delivered via eBPF kernel-level instrumentation.
    EBpf,
    /// Delivered via the aa-proxy sidecar.
    Proxy,
}

/// A governance event enriched with runtime-side metadata.
///
/// Produced by the pipeline enrichment stage from a raw [`AuditEvent`].
/// Cloneable so it can be broadcast to multiple subscribers via
/// `tokio::sync::broadcast`.
#[derive(Debug, Clone)]
pub struct EnrichedEvent {
    /// The original audit event from the SDK or other source.
    pub inner: AuditEvent,
    /// Unix milliseconds when this event was received by the pipeline
    /// (wall-clock time on the runtime host, not the SDK's timestamp).
    pub received_at_ms: i64,
    /// The input source that delivered this event.
    pub source: EventSource,
    /// Agent identity string — copied from `RuntimeConfig::agent_id`.
    pub agent_id: String,
    /// ID of the IPC connection that submitted this event.
    /// Used to route `IpcResponse::ViolationAlert` back to the originating SDK client.
    pub connection_id: u64,
    /// Monotonically increasing sequence number assigned by the pipeline at event
    /// arrival time (not flush time). Starts at 0 when the pipeline task starts.
    /// Downstream subscribers can use this to detect gaps caused by broadcast ring
    /// buffer overflow (`RecvError::Lagged(n)` tells how many were dropped but not
    /// which ones — sequence numbers identify the missing range).
    pub sequence_number: u64,
    /// The SDK identity the agent *claimed* on the wire, read from the
    /// (attacker-controlled) `inner.labels` map at ingest (AAASM-3625).
    ///
    /// This is the **observed** signal only: it is recomputed server-side
    /// against the verified handshake identity (AAASM-3640) by the classifier
    /// before any tamper verdict is drawn. Never granted trust at face value.
    pub observed_sdk_identity: ObservedSdkIdentity,
}

/// Top-level event type carried by the pipeline broadcast channel.
///
/// Wraps both audit events (the primary flow) and operational events such as
/// layer degradation notifications. Downstream subscribers pattern-match on
/// the variant to decide which events they care about.
#[derive(Debug, Clone)]
pub enum PipelineEvent {
    /// A governance audit event enriched with runtime metadata.
    Audit(Box<EnrichedEvent>),
    /// An interception layer became unavailable.
    LayerDegradation(LayerDegradationInfo),
}

/// Runtime-side representation of a layer degradation event.
///
/// Created when an interception layer is unavailable at startup or degrades
/// at runtime. Emitted via `tracing::warn!` and exposed through the `/health`
/// endpoint. The corresponding proto message (`LayerDegradationEvent`) is used
/// for gateway forwarding.
#[derive(Debug, Clone)]
pub struct LayerDegradationInfo {
    /// Name of the degraded layer (e.g. `"ebpf"`, `"proxy"`).
    pub layer: String,
    /// Human-readable reason for the degradation.
    pub reason: String,
    /// Remaining active layers after degradation (e.g. `["proxy", "sdk"]`).
    pub remaining_layers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enriched_event_fields_are_accessible() {
        let audit_event = AuditEvent::default();
        let received_at_ms: i64 = 1234567890;
        let source = EventSource::Sdk;
        let agent_id = "test-agent".to_string();
        let connection_id: u64 = 42;

        let enriched_event = EnrichedEvent {
            inner: audit_event.clone(),
            received_at_ms,
            source: source.clone(),
            agent_id: agent_id.clone(),
            connection_id,
            sequence_number: 0,
            observed_sdk_identity: ObservedSdkIdentity::present("1.2.3"),
        };

        assert_eq!(enriched_event.inner, audit_event);
        assert_eq!(enriched_event.received_at_ms, received_at_ms);
        assert_eq!(enriched_event.source, source);
        assert_eq!(enriched_event.agent_id, agent_id);
        assert_eq!(enriched_event.connection_id, connection_id);
        assert_eq!(enriched_event.sequence_number, 0);
        assert!(enriched_event.observed_sdk_identity.present);
        assert_eq!(enriched_event.observed_sdk_identity.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn event_source_variants_are_distinct() {
        assert_ne!(EventSource::Sdk, EventSource::EBpf);
        assert_ne!(EventSource::EBpf, EventSource::Proxy);
        assert_ne!(EventSource::Sdk, EventSource::Proxy);
    }

    #[test]
    fn enriched_event_is_clone() {
        let audit_event = AuditEvent::default();
        let original = EnrichedEvent {
            inner: audit_event,
            received_at_ms: 1234567890,
            source: EventSource::EBpf,
            agent_id: "original-agent".to_string(),
            connection_id: 7,
            sequence_number: 3,
            observed_sdk_identity: ObservedSdkIdentity::missing(),
        };

        let cloned = original.clone();
        assert_eq!(cloned.agent_id, original.agent_id);
        assert_eq!(cloned.connection_id, original.connection_id);
    }

    #[test]
    fn layer_degradation_info_fields_are_accessible() {
        let info = LayerDegradationInfo {
            layer: "ebpf".to_string(),
            reason: "kernel version 4.18 < 5.8".to_string(),
            remaining_layers: vec!["proxy".to_string(), "sdk".to_string()],
        };
        assert_eq!(info.layer, "ebpf");
        assert_eq!(info.reason, "kernel version 4.18 < 5.8");
        assert_eq!(info.remaining_layers, vec!["proxy", "sdk"]);
    }

    #[test]
    fn pipeline_event_audit_variant() {
        let event = PipelineEvent::Audit(Box::new(EnrichedEvent {
            inner: AuditEvent::default(),
            received_at_ms: 0,
            source: EventSource::Sdk,
            agent_id: "a".to_string(),
            connection_id: 0,
            sequence_number: 0,
            observed_sdk_identity: ObservedSdkIdentity::default(),
        }));
        assert!(matches!(event, PipelineEvent::Audit(_)));
    }

    #[test]
    fn pipeline_event_layer_degradation_variant() {
        let event = PipelineEvent::LayerDegradation(LayerDegradationInfo {
            layer: "ebpf".to_string(),
            reason: "missing".to_string(),
            remaining_layers: vec!["sdk".to_string()],
        });
        assert!(matches!(event, PipelineEvent::LayerDegradation(_)));
    }

    #[test]
    fn pipeline_event_is_clone() {
        let event = PipelineEvent::Audit(Box::new(EnrichedEvent {
            inner: AuditEvent::default(),
            received_at_ms: 0,
            source: EventSource::Sdk,
            agent_id: "a".to_string(),
            connection_id: 0,
            sequence_number: 0,
            observed_sdk_identity: ObservedSdkIdentity::default(),
        }));
        let cloned = event.clone();
        assert!(matches!(cloned, PipelineEvent::Audit(_)));
    }

    #[test]
    fn layer_degradation_info_is_clone() {
        let original = LayerDegradationInfo {
            layer: "proxy".to_string(),
            reason: "aa-proxy not in PATH".to_string(),
            remaining_layers: vec!["sdk".to_string()],
        };
        let cloned = original.clone();
        assert_eq!(cloned.layer, original.layer);
        assert_eq!(cloned.reason, original.reason);
        assert_eq!(cloned.remaining_layers, original.remaining_layers);
    }
}
