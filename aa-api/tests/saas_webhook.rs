//! End-to-end tests for `POST /v1/devtools/saas/{provider}/events`.
//!
//! Covers every status code listed in AAASM-924's "Response codes" table:
//! 202 / 400 / 401 / 404 / 503.
//!
//! Builds an in-process axum `Router` from the real `build_app` and exercises
//! it via `tower::ServiceExt::oneshot` — no real TCP listener.

mod common;

use std::sync::Arc;

use aa_api::routes::devtools::secret_cache::{SecretCache, SecretResolver};
use aa_api::server::build_app;
use aa_api::state::AppState;
use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::sync::mpsc;
use tower::ServiceExt;

const TEST_SECRET: &[u8] = b"webhook-test-secret";

type HmacSha256 = Hmac<Sha256>;

struct StaticResolver {
    value: Vec<u8>,
}

impl SecretResolver for StaticResolver {
    fn resolve(&self, _secret_ref: &str) -> Option<Vec<u8>> {
        Some(self.value.clone())
    }
}

fn compute_hmac(secret: &[u8], body: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("valid key");
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

/// Build an AppState with:
/// - A `SecretCache` backed by `StaticResolver` (returns `TEST_SECRET`).
/// - An `audit_sender` connected to an `mpsc` channel of the given capacity.
///
/// Returns the state plus the receiver so tests can assert events landed.
fn test_state_with_audit(capacity: usize) -> (AppState, mpsc::Receiver<aa_core::AuditEntry>) {
    let mut state = common::test_state();
    let resolver: Arc<dyn SecretResolver> = Arc::new(StaticResolver {
        value: TEST_SECRET.to_vec(),
    });
    state.saas_secret_cache = Arc::new(SecretCache::with_resolver(resolver));
    let (tx, rx) = mpsc::channel(capacity);
    state.audit_sender = Some(tx);
    (state, rx)
}

fn claude_ai_body() -> &'static [u8] {
    br#"{
        "event_id": "evt_01H",
        "timestamp": "2026-05-20T08:30:00Z",
        "actor": {"email": "alice@example.com"},
        "action": {"tool": "bash"}
    }"#
}

fn chatgpt_body() -> &'static [u8] {
    br#"{
        "id": "evt-01H",
        "created": "2026-05-20T08:30:00Z",
        "user": {"email": "bob@example.com"},
        "action": "chat.completion"
    }"#
}

fn cursor_body() -> &'static [u8] {
    br#"{
        "event_id": "cur_evt_01H",
        "ts": "2026-05-20T08:30:00Z",
        "user": "carol@example.com",
        "op": "edit.apply"
    }"#
}

fn signed_request(provider_path: &str, header_name: &str, header_value: String, body: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/devtools/saas/{provider_path}/events"))
        .header(
            HeaderName::from_bytes(header_name.as_bytes()).unwrap(),
            HeaderValue::from_str(&header_value).unwrap(),
        )
        .body(Body::from(body.to_vec()))
        .unwrap()
}

#[tokio::test]
async fn claude_ai_valid_signature_returns_202_and_writes_audit() {
    let (state, mut rx) = test_state_with_audit(8);
    let app = build_app(state);

    let body = claude_ai_body();
    let sig = format!("sha256={}", hex::encode(compute_hmac(TEST_SECRET, body)));
    let response = app
        .oneshot(signed_request("claude-ai", "anthropic-signature", sig, body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let entry = rx.try_recv().expect("audit entry was enqueued");
    assert_eq!(entry.spawned_by_tool(), Some("saas:claude-ai"));
}

#[tokio::test]
async fn chatgpt_valid_signature_returns_202_and_writes_audit() {
    let (state, mut rx) = test_state_with_audit(8);
    let app = build_app(state);

    let body = chatgpt_body();
    let sig = format!("sha256={}", hex::encode(compute_hmac(TEST_SECRET, body)));
    let response = app
        .oneshot(signed_request("chatgpt", "openai-signature", sig, body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let entry = rx.try_recv().expect("audit entry was enqueued");
    assert_eq!(entry.spawned_by_tool(), Some("saas:chatgpt"));
}

#[tokio::test]
async fn cursor_cloud_valid_signature_returns_202_and_writes_audit() {
    let (state, mut rx) = test_state_with_audit(8);
    let app = build_app(state);

    let body = cursor_body();
    let sig = hex::encode(compute_hmac(TEST_SECRET, body)); // no "sha256=" prefix
    let response = app
        .oneshot(signed_request("cursor-cloud", "x-cursor-signature", sig, body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let entry = rx.try_recv().expect("audit entry was enqueued");
    assert_eq!(entry.spawned_by_tool(), Some("saas:cursor"));
}

#[tokio::test]
async fn claude_ai_bad_signature_returns_401() {
    let (state, _rx) = test_state_with_audit(8);
    let app = build_app(state);

    let body = claude_ai_body();
    let mut bad = compute_hmac(TEST_SECRET, body);
    bad[0] ^= 0xff;
    let sig = format!("sha256={}", hex::encode(bad));
    let response = app
        .oneshot(signed_request("claude-ai", "anthropic-signature", sig, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn chatgpt_bad_signature_returns_401() {
    let (state, _rx) = test_state_with_audit(8);
    let app = build_app(state);

    let body = chatgpt_body();
    let mut bad = compute_hmac(TEST_SECRET, body);
    bad[0] ^= 0xff;
    let sig = format!("sha256={}", hex::encode(bad));
    let response = app
        .oneshot(signed_request("chatgpt", "openai-signature", sig, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cursor_cloud_bad_signature_returns_401() {
    let (state, _rx) = test_state_with_audit(8);
    let app = build_app(state);

    let body = cursor_body();
    let mut bad = compute_hmac(TEST_SECRET, body);
    bad[0] ^= 0xff;
    let sig = hex::encode(bad);
    let response = app
        .oneshot(signed_request("cursor-cloud", "x-cursor-signature", sig, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_signature_header_returns_401() {
    let (state, _rx) = test_state_with_audit(8);
    let app = build_app(state);

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/devtools/saas/claude-ai/events")
        .body(Body::from(claude_ai_body().to_vec()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_body_returns_400() {
    let (state, _rx) = test_state_with_audit(8);
    let app = build_app(state);

    let body = b"not valid json";
    let sig = format!("sha256={}", hex::encode(compute_hmac(TEST_SECRET, body)));
    let response = app
        .oneshot(signed_request("claude-ai", "anthropic-signature", sig, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_provider_path_returns_404() {
    let (state, _rx) = test_state_with_audit(8);
    let app = build_app(state);

    let body = b"{}";
    let sig = format!("sha256={}", hex::encode(compute_hmac(TEST_SECRET, body)));
    let response = app
        .oneshot(signed_request("not-a-provider", "anthropic-signature", sig, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn audit_pipeline_backpressure_returns_503() {
    // Channel with capacity 1, then fill it so try_send returns Full.
    let (mut state, _rx) = test_state_with_audit(1);
    // Pre-fill the channel via the existing sender — but we need to hold the
    // receiver as well so the channel isn't closed. The receiver returned by
    // `test_state_with_audit` is the only one; keep it alive for the duration.
    let tx_clone = state.audit_sender.clone().unwrap();
    // Use a separate sender clone to push a synthetic entry to fill the slot.
    let filler = aa_core::AuditEntry::new(
        0,
        0,
        aa_core::AuditEventType::ToolCallIntercepted,
        aa_core::AgentId::from_bytes([0u8; 16]),
        aa_core::SessionId::from_bytes([0u8; 16]),
        "{}".into(),
        [0u8; 32],
    );
    tx_clone.try_send(filler).expect("fill capacity");
    // Now another attempt will fail with TrySendError::Full.
    state.audit_sender = Some(tx_clone);
    let app = build_app(state);

    let body = claude_ai_body();
    let sig = format!("sha256={}", hex::encode(compute_hmac(TEST_SECRET, body)));
    let response = app
        .oneshot(signed_request("claude-ai", "anthropic-signature", sig, body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn audit_pipeline_disconnected_returns_503() {
    let mut state = common::test_state();
    let resolver: Arc<dyn SecretResolver> = Arc::new(StaticResolver {
        value: TEST_SECRET.to_vec(),
    });
    state.saas_secret_cache = Arc::new(SecretCache::with_resolver(resolver));
    // audit_sender stays None — simulates pipeline unconnected.
    let app = build_app(state);

    let body = claude_ai_body();
    let sig = format!("sha256={}", hex::encode(compute_hmac(TEST_SECRET, body)));
    let response = app
        .oneshot(signed_request("claude-ai", "anthropic-signature", sig, body))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = std::str::from_utf8(&bytes).unwrap_or("");
    assert!(
        body_str.contains("Audit pipeline is not connected"),
        "expected pipeline-not-connected detail, got: {body_str}"
    );
}
