//! In-process mock LLM upstream server for end-to-end integration tests
//! (AAASM-1547 / F116 ST-I follow-up).
//!
//! `MockLlmServer` binds an axum router to a random loopback port, records
//! every inbound request (method, path, headers, body) into a shared
//! `Arc<Mutex<Vec<RecordedRequest>>>`, and replies with a configurable canned
//! response. It is hermetic — each instance owns its own port, history, and
//! background tokio task; instances do not share global state and can be
//! constructed in parallel across tests.
//!
//! The fixture unblocks the deferred secret-detection assertions from
//! AAASM-1521 / AAASM-1549, which need to prove that:
//!
//! * when policy is `block`, the upstream receives zero requests
//!   (`mock.request_count() == 0`), and
//! * when policy is `redact_only`, the upstream receives the *redacted* form
//!   of the body (`mock.last_body()` contains the placeholder, not the raw
//!   secret).
//!
//! Typical usage:
//!
//! ```ignore
//! let mock = common::MockLlmServer::start().await?;
//! configure_sut_upstream(&mock.url);
//! send_request_through_sut(&mock.url).await?;
//! assert_eq!(mock.request_count(), 1);
//! assert!(mock.last_body().unwrap().contains("REDACTED"));
//! ```

/// A single inbound HTTP request captured by [`MockLlmServer`].
///
/// All fields are populated verbatim from the inbound request — no
/// canonicalisation, no header filtering — so tests can assert on the exact
/// bytes that crossed the wire.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    /// HTTP method as a string (e.g. `"POST"`).
    pub method: String,
    /// Request path including any leading slash (e.g. `"/v1/chat/completions"`).
    pub path: String,
    /// Header name/value pairs in the order they appeared on the wire.
    /// Names are lower-case (axum's normalised form); values are the raw
    /// string representation.
    pub headers: Vec<(String, String)>,
    /// Request body bytes, captured verbatim before any framework parsing.
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// Body interpreted as UTF-8, if it is valid UTF-8.
    pub fn body_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.body).ok()
    }
}
