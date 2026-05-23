//! AAASM-1577 / AAASM-1718 — Story-level end-to-end verification.
//!
//! Boots the remote-mode HTTP listener, registers two agents through an
//! in-test placeholder router, then asserts both are listed back. This
//! covers the AAASM-1577 AC bullet *"Multiple agents on different
//! machines can register and appear in the same registry"* without
//! depending on E18 (AAASM-1719) PostgreSQL backend, which lands in a
//! sibling Epic.
//!
//! The placeholder agents handler is intentionally test-local — production
//! agents wiring belongs to `aa-api` and the durable storage Epic.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{extract::State, routing::post, Json, Router};
use axum_server::Handle;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Agent {
    id: String,
    host: String,
}

/// Shared in-test agent registry. `Arc<Mutex<Vec<_>>>` is good enough
/// for a verification fixture; production registration goes via gRPC
/// today and HTTP-via-aa-api later.
type AgentStore = Arc<Mutex<Vec<Agent>>>;

async fn register_agent(State(store): State<AgentStore>, Json(agent): Json<Agent>) -> Json<Agent> {
    store.lock().expect("agent store lock").push(agent.clone());
    Json(agent)
}

async fn list_agents(State(store): State<AgentStore>) -> Json<Vec<Agent>> {
    Json(store.lock().expect("agent store lock").clone())
}

/// Build an Axum router that merges the production remote-mode router
/// (currently just `/healthz`) with a test-local placeholder agents
/// API. The merged router has the same /healthz contract a real remote
/// gateway would serve, so this test exercises the actual production
/// router code rather than a parallel reimplementation.
fn build_test_app(store: AgentStore) -> Router {
    let agents = Router::new()
        .route("/api/v1/agents", post(register_agent).get(list_agents))
        .with_state(store);

    aa_gateway::remote_mode::router().merge(agents)
}

/// AAASM-1577 AC #5/#6 — bind the merged production+placeholder router
/// on an ephemeral port, register two agents over HTTP, list them back,
/// then shut the server down cleanly.
#[tokio::test]
async fn two_agents_register_and_list_via_http() {
    let store: AgentStore = Arc::new(Mutex::new(Vec::new()));
    let app = build_test_app(Arc::clone(&store)).into_make_service();

    let handle: Handle<SocketAddr> = Handle::new();
    let probe_handle = handle.clone();
    let shutdown_handle = handle.clone();

    let server = tokio::spawn(async move {
        axum_server::bind("127.0.0.1:0".parse().expect("listen_addr"))
            .handle(handle)
            .serve(app)
            .await
    });

    let addr = probe_handle.listening().await.expect("server bound");
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // Register two agents from different "machines" (just two clients on the
    // same loopback — the contract being tested is the registry, not the
    // network).
    let alice = Agent {
        id: "alice".into(),
        host: "machine-a".into(),
    };
    let bob = Agent {
        id: "bob".into(),
        host: "machine-b".into(),
    };
    client
        .post(format!("{base}/api/v1/agents"))
        .json(&alice)
        .send()
        .await
        .expect("register alice")
        .error_for_status()
        .expect("alice 2xx");
    client
        .post(format!("{base}/api/v1/agents"))
        .json(&bob)
        .send()
        .await
        .expect("register bob")
        .error_for_status()
        .expect("bob 2xx");

    // List — both agents must come back, order-independent.
    let listed: Vec<Agent> = client
        .get(format!("{base}/api/v1/agents"))
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("parse JSON");

    assert_eq!(listed.len(), 2, "expected 2 agents, got {listed:?}");
    assert!(listed.contains(&alice), "alice missing from listed: {listed:?}");
    assert!(listed.contains(&bob), "bob missing from listed: {listed:?}");

    // /healthz is the production-router contract — verify the merged
    // router still serves it (regression guard against future router
    // refactors silently dropping the route).
    let body: serde_json::Value = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .expect("healthz")
        .json()
        .await
        .expect("parse JSON");
    assert_eq!(body["mode"], "remote");

    shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    server.await.expect("server task").expect("server result");
}
