//! Fail-loud-on-stream-config-mismatch test (AAASM-3886, ADR 0011).
//!
//! Reproduces the operational edge found in the AAASM-3885 review: an operator
//! pre-provisions the `AA_OPCONTROL` JetStream stream with an **incompatible
//! immutable config** (here: `Memory` storage instead of the gateway's `File`).
//! `create_or_update_stream` can never reconcile that, so the gateway bridge
//! cannot establish its consumer.
//!
//! Before AAASM-3886 the bridge looped on stream/consumer setup **without ever
//! consuming**, logging only a quiet reconnect warning, while op-control
//! publishes kept ACKing (200) against the existing stream — a silent
//! non-delivery of a kill switch. This test proves the bridge now **fails loud**:
//! it surfaces [`BridgeHealthState::StreamUnavailable`] instead of silently
//! looping (and never reports `Subscribed`).
//!
//! It also demonstrates the cross-process boundary documented in ADR 0011: the
//! publisher (a different process) **cannot** know the stream is unconsumable —
//! its publish still ACKs against the incompatible stream — which is exactly why
//! the gateway-side fail-loud/unhealthy signal is the only honest one available.
//!
//! Uses a **real NATS server** via `testcontainers-modules` (requires Docker, `-js`
//! enabled), matching the AAASM-3885 e2e — nothing is faked.

use std::time::{Duration, Instant};

use aa_gateway::ops::nats::{spawn_bridge_with_health, STREAM_NAME, SUBJECT_WILDCARD};
use aa_gateway::ops::{BridgeHealthState, OpControlNatsConfig, OpControlNatsPublisher, OpControlPublisher};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_proto::assembly::policy::v1::OpControlSignal;
use async_nats::jetstream;
use std::sync::Arc;
use testcontainers_modules::nats::{Nats, NatsServerCmd};
use testcontainers_modules::testcontainers::core::IntoContainerPort;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

/// Reserve an ephemeral host port, then release it so the container can bind it.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Start a NATS container with JetStream enabled (`-js`), pinned to `host_port`.
async fn start_nats(host_port: u16) -> ContainerAsync<Nats> {
    let cmd = NatsServerCmd::default().with_jetstream();
    Nats::default()
        .with_cmd(&cmd)
        .with_mapped_port(host_port, 4222.tcp())
        .start()
        .await
        .expect("start nats testcontainer (is Docker running?)")
}

/// Pre-provision an `AA_OPCONTROL` stream with an **incompatible immutable
/// config**: `Memory` storage (the gateway ensures `File`). The subjects still
/// cover `assembly.opcontrol.>` so a publish keeps ACKing against it — modelling
/// the dangerous silent-non-delivery case, not a trivially-missing stream.
async fn preprovision_incompatible_stream(url: &str) {
    let client = async_nats::connect(url).await.expect("connect to NATS");
    let context = jetstream::new(client);
    context
        .create_stream(jetstream::stream::Config {
            name: STREAM_NAME.to_string(),
            subjects: vec![SUBJECT_WILDCARD.to_string()],
            retention: jetstream::stream::RetentionPolicy::Limits,
            // Immutable mismatch vs the gateway's File storage.
            storage: jetstream::stream::StorageType::Memory,
            ..Default::default()
        })
        .await
        .expect("pre-provision incompatible AA_OPCONTROL stream");
}

fn agent(id: &str) -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: id.into(),
    }
}

/// With a pre-provisioned, incompatible `AA_OPCONTROL` stream the gateway bridge
/// must fail loud: it surfaces `StreamUnavailable` (op-control delivery DOWN)
/// rather than silently looping, and never reports `Subscribed`.
#[tokio::test]
async fn incompatible_preprovisioned_stream_makes_bridge_fail_loud_not_silently_loop() {
    let host_port = free_port();
    let url = format!("nats://127.0.0.1:{host_port}");
    let _nats = start_nats(host_port).await;

    // Operator pre-provisioned the stream with an irreconcilable immutable config.
    preprovision_incompatible_stream(&url).await;

    // Start the gateway bridge against it, observing its health.
    let publisher = Arc::new(OpControlPublisher::new());
    let (_bridge, health) = spawn_bridge_with_health(OpControlNatsConfig::new(url.clone()), Arc::clone(&publisher));

    // The bridge must reach the fail-loud StreamUnavailable state — it can never
    // reconcile the stream, so it surfaces delivery-down instead of looping silently.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        assert!(
            Instant::now() < deadline,
            "bridge never surfaced StreamUnavailable; last state = {:?}",
            health.get(),
        );
        // It must NEVER report healthy against an unconsumable stream.
        assert_ne!(
            health.get(),
            BridgeHealthState::Subscribed,
            "bridge must not report Subscribed for an incompatible/unconsumable stream",
        );
        if health.is_delivery_down() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Cross-process boundary (ADR 0011): the publisher is a different process and
    // CANNOT know the stream is unconsumable — its publish still ACKs (the silent
    // 200) against the incompatible-but-present stream. This is precisely why the
    // gateway-side fail-loud signal above is the only honest indicator available.
    let api_publisher = OpControlNatsPublisher::connect(&OpControlNatsConfig::new(url.clone()))
        .await
        .expect("aa-api side connects to NATS")
        .with_ack_timeout(Duration::from_secs(2));
    let publish_result = api_publisher
        .publish_agent_halt(agent("agent-x"), OpControlSignal::Terminate)
        .await;
    assert!(
        publish_result.is_ok(),
        "the publisher cannot detect the gateway's config mismatch — its ACK against \
         the present (incompatible) stream still succeeds, which is why the gateway must \
         fail loud; got {publish_result:?}",
    );

    // And the gateway still reports delivery-down despite that successful publish.
    assert!(
        health.is_delivery_down(),
        "op-control delivery must remain down while the stream stays incompatible",
    );
}
