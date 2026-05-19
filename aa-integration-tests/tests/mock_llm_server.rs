//! Tests for the `MockLlmServer` fixture itself (AAASM-1547).
//!
//! Lives in its own test binary rather than inside `common/mock_llm.rs` so
//! the fixture-level assertions run once, not once per integration-test
//! binary that imports `common`.

mod common;

use common::MockLlmServer;
use reqwest::Client;

/// AAASM-1547 AC: "tests prove counter increments".
///
/// Three POSTs in sequence to the mock's base URL — `request_count()` must
/// reach `3`. Counter is the canonical signal that the `block` policy in
/// AAASM-1521 / AAASM-1549 will use to assert "upstream received zero
/// requests", so the increment path needs to be unambiguous.
#[tokio::test]
async fn request_count_increments_per_inbound_request() {
    let mock = MockLlmServer::start().await.expect("mock starts");
    let client = Client::new();
    for _ in 0..3 {
        let resp = client
            .post(&mock.url)
            .body("hello")
            .send()
            .await
            .expect("POST succeeds against mock");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
    }
    assert_eq!(mock.request_count(), 3);
}

/// AAASM-1547 AC: "captures inbound request body verbatim" + "body
/// retrievable".
///
/// A POST with a JSON body, a non-default path, and a custom header — every
/// field on the recorded request must round-trip exactly. The body byte
/// equality is the load-bearing assertion for the AAASM-1521
/// `redact_only`-policy test, which needs to inspect what *actually*
/// reached the upstream after redaction.
#[tokio::test]
async fn captures_request_body_path_and_headers_verbatim() {
    let mock = MockLlmServer::start().await.expect("mock starts");
    let payload = r#"{"prompt":"hello world","model":"gpt-4o"}"#;
    let resp = Client::new()
        .post(format!("{}/v1/chat/completions", mock.url))
        .header("authorization", "Bearer test-key-do-not-redact")
        .header("content-type", "application/json")
        .body(payload.to_owned())
        .send()
        .await
        .expect("POST succeeds against mock");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let recorded = {
        let guard = mock.history.lock().expect("history mutex");
        guard.last().cloned().expect("at least one recorded request")
    };

    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.path, "/v1/chat/completions");
    assert_eq!(recorded.body, payload.as_bytes(), "body must be captured verbatim");
    assert_eq!(mock.last_body().as_deref(), Some(payload));
    assert!(
        recorded
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("authorization") && v == "Bearer test-key-do-not-redact"),
        "authorization header should be captured verbatim, got: {:?}",
        recorded.headers,
    );
}
