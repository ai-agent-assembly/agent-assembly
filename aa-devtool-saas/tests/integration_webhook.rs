//! Integration tests for the SaaS webhook signature verification flow.
//!
//! These tests build a minimal axum router that mirrors the `aa-api` webhook
//! handler logic without importing `aa-api` itself. The router is tested via
//! `tower::ServiceExt::oneshot` — no real TCP server is spawned.

use axum::body::{Body, Bytes};
use axum::extract::Path;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::routing::post;
use axum::Router;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::ServiceExt;

type HmacSha256 = Hmac<Sha256>;

/// Compute an HMAC-SHA256 over `body` using `secret`.
fn compute_hmac(secret: &[u8], body: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("valid key");
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

/// Build a minimal router that exercises the signature-verification logic used
/// by the `aa-api` webhook handler.
fn build_test_router(test_secret: &'static [u8]) -> Router {
    Router::new().route(
        "/v1/devtools/saas/{provider}/events",
        post(
            move |Path(provider_str): Path<String>, headers: HeaderMap, body: Bytes| async move {
                use aa_devtool_saas::provider::SaasProvider;
                use aa_devtool_saas::signature::{self, SignatureError};

                let provider = match provider_str.as_str() {
                    "claude-ai" => SaasProvider::ClaudeAi,
                    "chatgpt" => SaasProvider::ChatGpt,
                    "cursor-cloud" => SaasProvider::CursorCloud,
                    _ => return StatusCode::BAD_REQUEST,
                };

                // Convert axum HeaderMap to http::HeaderMap (same type — axum re-exports http).
                match signature::verify(&provider, &headers, &body, test_secret) {
                    Ok(()) => StatusCode::ACCEPTED,
                    Err(SignatureError::MissingHeader) | Err(SignatureError::InvalidSignature) => {
                        StatusCode::UNAUTHORIZED
                    }
                }
            },
        ),
    )
}

#[tokio::test]
async fn signed_event_ingested_via_webhook_returns_202() {
    let secret = b"integration-test-secret";
    let body = b"{\"event\":\"tool_call\",\"tool\":\"bash\"}";

    let sig_bytes = compute_hmac(secret, body);
    let sig_header = format!("sha256={}", hex::encode(&sig_bytes));

    let request = Request::builder()
        .method("POST")
        .uri("/v1/devtools/saas/claude-ai/events")
        .header(
            HeaderName::from_static("anthropic-signature"),
            HeaderValue::from_str(&sig_header).unwrap(),
        )
        .body(Body::from(body.as_ref()))
        .unwrap();

    let router = build_test_router(secret);
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn bad_hmac_returns_401() {
    let secret = b"integration-test-secret";
    let body = b"{\"event\":\"tool_call\",\"tool\":\"bash\"}";

    // Compute a valid HMAC then flip one hex character to produce an invalid signature.
    let sig_bytes = compute_hmac(secret, body);
    let mut hex_str = hex::encode(&sig_bytes);
    // Flip the last character: '0'→'1', anything-else→'0'.
    let last = hex_str.pop().unwrap();
    hex_str.push(if last == '0' { '1' } else { '0' });
    let bad_sig_header = format!("sha256={hex_str}");

    let request = Request::builder()
        .method("POST")
        .uri("/v1/devtools/saas/claude-ai/events")
        .header(
            HeaderName::from_static("anthropic-signature"),
            HeaderValue::from_str(&bad_sig_header).unwrap(),
        )
        .body(Body::from(body.as_ref()))
        .unwrap();

    let router = build_test_router(secret);
    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
