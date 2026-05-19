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
