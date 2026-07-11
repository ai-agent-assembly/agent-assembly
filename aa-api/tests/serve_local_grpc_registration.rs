//! Integration test for the local-mode gRPC agent-registration path (AAASM-4447).
//!
//! Reproduces the end-to-end scenario the fix targets: an SDK registers over the
//! gRPC `AgentLifecycleService` (the exact `aa-sdk-client` wire path, including
//! the possession-proof challenge handshake) and the agent must immediately be
//! visible on the REST `/api/v1/agents` surface — because both are served over
//! the SAME `Arc<AgentRegistry>`.
//!
//! This test goes RED if the fix is reverted: without the embedded gRPC listener
//! there is nothing to connect to on the registration port, and without the
//! shared durable registry a gRPC-registered agent would not appear in REST.

use std::future::pending;

use aa_sdk_client::config::AssemblyConfig;
use aa_sdk_client::gateway::{build_challenge_request, build_register_request, GatewayRegistrationClient};

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Build an `AssemblyConfig` pointing at the given gateway gRPC endpoint.
fn sdk_config(agent_id: &str, endpoint: String) -> AssemblyConfig {
    AssemblyConfig {
        agent_id: agent_id.to_string(),
        socket_path: None,
        gateway_endpoint: Some(endpoint),
        team_id: None,
        parent_agent_id: None,
        sdk_version: None,
    }
}

#[tokio::test]
async fn grpc_registered_agent_is_visible_via_rest() {
    // A hermetic per-test durable registry DB — never the developer's real
    // `~/.aasm/local.db`.
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("local.db");

    // Auth off so the bypass caller is admin and can list team-less agents
    // (the SDK registers without a team).
    let state = aa_api::AppState::local_hardened_at(aa_api::LocalAuth::Off, db_path)
        .await
        .expect("local_hardened_at must construct");
    let registry = std::sync::Arc::clone(&state.agent_registry);

    // Bind an ephemeral loopback port so the test is parallel-safe (the shipped
    // binary uses the fixed :50051; the serving logic is identical).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral gRPC port");
    let grpc_addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("http://{grpc_addr}");

    // The gRPC server future never completes on its own (pending shutdown); race
    // it against the client work so it is dropped when the assertions finish.
    let serve = aa_api::server::serve_lifecycle_grpc(listener, registry, pending::<()>());

    let work = async {
        // --- SDK registration over gRPC (the real aa-sdk-client wire path). ---
        let config = sdk_config("grpc-reg-test-agent", endpoint.clone());
        let mut client = GatewayRegistrationClient::connect(endpoint)
            .await
            .expect("connect to embedded gRPC AgentLifecycleService");
        let challenge = client
            .request_challenge(build_challenge_request(&config))
            .await
            .expect("request_challenge succeeds");
        let request = build_register_request(
            &config,
            "grpc-reg-test-agent".to_string(),
            "langgraph".to_string(),
            &challenge.nonce,
        );
        let response = client.register(request).await.expect("register succeeds");
        assert!(
            !response.credential_token.is_empty(),
            "registration must mint a credential token"
        );

        // --- The agent must now be visible on the REST surface (shared registry). ---
        let app = aa_api::build_app(state);
        let rest_response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/agents")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("REST request");
        assert_eq!(rest_response.status(), StatusCode::OK);

        let bytes = to_bytes(rest_response.into_body(), usize::MAX).await.expect("body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

        assert!(
            json["total"].as_u64().unwrap_or(0) >= 1,
            "the gRPC-registered agent must be counted in /api/v1/agents; got {json}"
        );
        let names: Vec<&str> = json["items"]
            .as_array()
            .expect("items array")
            .iter()
            .filter_map(|it| it["name"].as_str())
            .collect();
        assert!(
            names.contains(&"grpc-reg-test-agent"),
            "the registered agent name must appear in the REST listing; got {names:?}"
        );
    };

    tokio::select! {
        served = serve => panic!("gRPC server exited before the client work finished: {served:?}"),
        () = work => {}
    }
}
