//! End-to-end: an HTTP policy mutation drives the push-invalidation channel
//! (Story AAASM-2377, follow-up AAASM-2544).
//!
//! Proves the production wiring contract: when the aa-api `create_policy` HTTP
//! handler and the gateway `InvalidationService` share ONE hub-attached
//! `PolicyEngine`, a real `POST /api/v1/policies` causes a subscribed Assembly's
//! L1 cache to be invalidated — with no direct `apply_yaml`/hub call in the
//! test. The composition root (which shares the hub) is the only thing a real
//! deployment must provide; this test stands it up in-process.
//!
//! Correctness, not latency, is what this test guards: it asserts the
//! invalidation DOES propagate to the subscriber. A generous, CI-load-tolerant
//! timeout bounds the wait so a genuinely broken wiring fails fast; it is not a
//! tight wall-clock budget (that flaked under parallel-CPU contention,
//! AAASM-3394).

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tonic::transport::Server;
use tower::ServiceExt;

use aa_gateway::invalidation::InvalidationServiceImpl;
use aa_proto::assembly::gateway::v1::invalidation_service_server::InvalidationServiceServer;
use aa_runtime::invalidation_client::{InvalidationClient, InvalidationSink};
use aa_runtime::l1_cache::PolicyL1Cache;

#[tokio::test]
async fn http_policy_mutation_invalidates_subscribed_l1() {
    // ── aa-api HTTP app on a hub-attached engine ────────────────────────────
    let state = common::test_state();
    // The composition root shares this exact hub between the HTTP engine and
    // the gRPC InvalidationService — retrieved here via the engine getter,
    // before `build_app` consumes the state.
    let hub = state
        .policy_engine
        .invalidation_hub()
        .expect("test_state attaches an invalidation hub");
    let app = aa_api::server::build_app(state);

    // ── Real gateway InvalidationService on the SAME hub, over loopback gRPC ─
    let grpc = std::net::TcpListener::bind("127.0.0.1:0").expect("bind grpc port");
    let grpc_addr = grpc.local_addr().expect("grpc local_addr");
    drop(grpc); // free the port for tonic to bind (loopback test).
    let service = InvalidationServiceImpl::new(Arc::clone(&hub));
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(InvalidationServiceServer::new(service))
            .serve(grpc_addr)
            .await
            .expect("serve InvalidationService");
    });

    // ── Assembly subscriber: L1 cache fed by the real InvalidationClient ────
    let cache: Arc<PolicyL1Cache<bool>> = Arc::new(PolicyL1Cache::new());
    cache.insert("agent-x", true);
    let sink: Arc<dyn InvalidationSink> = Arc::clone(&cache) as Arc<dyn InvalidationSink>;
    let client = InvalidationClient::start(format!("http://{grpc_addr}"), "asm-http-e2e".to_string(), vec![sink]);

    // Wait until the subscriber has registered with the gateway hub.
    tokio::time::timeout(Duration::from_secs(5), async {
        while hub.subscriber_count() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("InvalidationClient subscribed to the gateway within 5 s");

    // ── Mutate policy via the real HTTP API — NOT via apply_yaml/hub directly ─
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/policies")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "policy_yaml": "tools:\n  bash:\n    allow: false\n" }).to_string(),
        ))
        .expect("build create_policy request");
    let response = app.oneshot(request).await.expect("create_policy request");
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "create_policy should return 201"
    );

    // Correctness assertion: the subscribed L1 entry MUST be invalidated as a
    // result of the HTTP mutation. The timeout is generous so this stays
    // deterministic under CI parallel-CPU contention; it bounds the wait only so
    // a genuinely broken push-invalidation wiring fails fast rather than hanging.
    tokio::time::timeout(Duration::from_secs(5), async {
        while cache.contains("agent-x") {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("HTTP policy mutation must invalidate the subscribed L1 cache");

    client.abort();
    server.abort();
}
