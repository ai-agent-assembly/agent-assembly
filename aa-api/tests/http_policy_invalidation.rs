//! End-to-end: an HTTP policy mutation drives the push-invalidation channel
//! (Story AAASM-2377, follow-up AAASM-2544).
//!
//! Proves the production wiring contract: when the aa-api `create_policy` HTTP
//! handler and the gateway `InvalidationService` share ONE hub-attached
//! `PolicyEngine`, a real `POST /api/v1/policies` causes a subscribed Assembly's
//! L1 cache to be invalidated within 100 ms — with no direct `apply_yaml`/hub
//! call in the test. The composition root (which shares the hub) is the only
//! thing a real deployment must provide; this test stands it up in-process.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tonic::transport::Server;
use tower::ServiceExt;

use aa_gateway::invalidation::InvalidationServiceImpl;
use aa_proto::assembly::gateway::v1::invalidation_service_server::InvalidationServiceServer;
use aa_runtime::invalidation_client::{InvalidationClient, InvalidationSink};
use aa_runtime::l1_cache::PolicyL1Cache;

#[tokio::test]
async fn http_policy_mutation_invalidates_subscribed_l1_within_100ms() {
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
    let start = Instant::now();
    let response = app.oneshot(request).await.expect("create_policy request");
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "create_policy should return 201"
    );

    // The subscribed L1 entry must disappear within 100 ms of the HTTP mutation.
    tokio::time::timeout(Duration::from_millis(100), async {
        while cache.contains("agent-x") {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("HTTP policy mutation invalidated the subscribed L1 within 100 ms");
    assert!(start.elapsed() < Duration::from_millis(100));

    client.abort();
    server.abort();
}
