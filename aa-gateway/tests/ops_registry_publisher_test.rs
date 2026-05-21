//! End-to-end integration test for AAASM-1657 PR-H — the integration
//! capstone. Exercises the chain:
//!
//!   PolicyServiceImpl(check_action ALLOW) → OpsRegistry(ingest_with_agent + allow)
//!     → operator-driven OpsRegistry::pause/resume/terminate
//!     → OpControlPublisher fan-out to the subscribed SDK
//!     → registry sweep removes terminal entries after TTL
//!
//! The SDK side is simulated via a direct `OpControlPublisher::subscribe()`
//! receiver (the same channel any tonic OpControlStream client would land
//! on) — avoids standing up a gRPC server for this Rust-side test. End-to-
//! end SDK roundtrips are covered by the per-SDK integration tests in
//! AAASM-1654 (python), AAASM-1655 (node), and AAASM-1656 (go).

use std::sync::Arc;
use std::time::Duration;

use aa_gateway::ops::{OpControlPublisher, OpState, OpsRegistry};
use aa_proto::assembly::common::v1::AgentId;
use aa_proto::assembly::policy::v1::OpControlSignal;
use tokio::time::timeout;

fn agent(id: &str) -> AgentId {
    AgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: id.into(),
    }
}

#[tokio::test]
async fn full_lifecycle_publishes_each_signal_and_sweep_removes_terminal_entry() {
    let publisher = Arc::new(OpControlPublisher::new());
    let registry = Arc::new(OpsRegistry::new().with_publisher(Arc::clone(&publisher)));
    let mut rx = publisher.subscribe();

    // ── 1. ingest + allow (simulates PolicyServiceImpl on Allow) ────────
    registry.ingest_with_agent("trace-1:span-1".into(), agent("agent-7"));
    registry.allow("trace-1:span-1").unwrap();
    assert_eq!(registry.get("trace-1:span-1").unwrap().state, OpState::Running);

    // ── 2. operator pauses ──────────────────────────────────────────────
    registry.pause("trace-1:span-1").unwrap();
    let env = timeout(Duration::from_secs(1), rx.recv()).await.unwrap().unwrap();
    assert_eq!(env.message.op_id, "trace-1:span-1");
    assert_eq!(env.message.signal, OpControlSignal::Pause as i32);
    assert_eq!(env.agent_id.agent_id, "agent-7");

    // ── 3. operator resumes ─────────────────────────────────────────────
    registry.resume("trace-1:span-1").unwrap();
    let env = timeout(Duration::from_secs(1), rx.recv()).await.unwrap().unwrap();
    assert_eq!(env.message.signal, OpControlSignal::Resume as i32);

    // ── 4. SDK marks the op complete ────────────────────────────────────
    registry.complete("trace-1:span-1").unwrap();
    assert_eq!(registry.get("trace-1:span-1").unwrap().state, OpState::Completing);
    // No publish for complete — Completing is the SDK-initiated terminal
    // state, not an operator signal that needs to flow back.

    // ── 5. sweep removes the Completing entry after TTL elapses ─────────
    // Use a 0-second TTL to bypass the time barrier in test (the
    // `spawn_sweep_task_with(registry, tick, 0)` daemon would do this in
    // prod with a real TTL; we drive the sweep manually here so the test
    // doesn't sleep for 60s).
    let removed = registry.sweep(0);
    assert_eq!(removed, 1);
    assert!(registry.get("trace-1:span-1").is_none());
    assert!(registry.agent_for("trace-1:span-1").is_none(), "agent map also pruned");
}

#[tokio::test]
async fn deny_path_terminates_op_and_publishes_terminate() {
    // Mirrors what PolicyServiceImpl.terminate_op does on a Deny decision.
    let publisher = Arc::new(OpControlPublisher::new());
    let registry = Arc::new(OpsRegistry::new().with_publisher(Arc::clone(&publisher)));
    let mut rx = publisher.subscribe();

    registry.ingest_with_agent("trace-deny:span-0".into(), agent("agent-9"));
    registry.terminate("trace-deny:span-0").unwrap();

    let env = timeout(Duration::from_secs(1), rx.recv()).await.unwrap().unwrap();
    assert_eq!(env.message.signal, OpControlSignal::Terminate as i32);
    assert_eq!(env.agent_id.agent_id, "agent-9");
    assert_eq!(registry.get("trace-deny:span-0").unwrap().state, OpState::Terminated,);
}

#[tokio::test]
async fn sweep_preserves_active_states() {
    let publisher = Arc::new(OpControlPublisher::new());
    let registry = Arc::new(OpsRegistry::new().with_publisher(Arc::clone(&publisher)));

    registry.ingest_with_agent("running".into(), agent("a"));
    registry.allow("running").unwrap();
    registry.ingest_with_agent("paused".into(), agent("b"));
    registry.allow("paused").unwrap();
    registry.pause("paused").unwrap();
    registry.ingest("pending-with-no-agent".into());

    // TTL 0 → would sweep anything terminal. Active states must survive.
    let removed = registry.sweep(0);
    assert_eq!(removed, 0);
    assert!(registry.get("running").is_some());
    assert!(registry.get("paused").is_some());
    assert!(registry.get("pending-with-no-agent").is_some());
}
