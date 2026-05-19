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

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

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

/// Default canned response body returned by [`MockLlmServer::start`].
/// Shaped as a minimal OpenAI-compatible chat-completion envelope so the SUT
/// (when treating the mock as an LLM upstream) deserialises it without
/// special-casing.
const DEFAULT_RESPONSE_BODY: &str = r#"{"id":"mock","object":"chat.completion","choices":[]}"#;
const DEFAULT_RESPONSE_CONTENT_TYPE: &str = "application/json";

/// Shared state injected into the axum route handler.
///
/// Cloned once into the `Router::with_state(...)` call; the `Arc` on `history`
/// is what lets the handler push into the same vector the test reads from.
#[derive(Clone)]
struct CaptureState {
    history: Arc<Mutex<Vec<RecordedRequest>>>,
    response_status: StatusCode,
    response_body: Bytes,
    response_content_type: String,
}

/// Hermetic mock LLM upstream — binds an axum router to a random loopback
/// port, records every inbound request into a shared history, and replies
/// with a canned response. One instance per test; instances do not share
/// global state.
pub struct MockLlmServer {
    /// Base URL the test should configure the SUT to call (e.g.
    /// `http://127.0.0.1:54321`). No trailing slash; the server's fallback
    /// route accepts any path, so the SUT can append whatever shape it
    /// expects from a real upstream (`/v1/chat/completions`, etc).
    pub url: String,
    /// Shared, thread-safe history of inbound requests in arrival order.
    /// Cloned `Arc` for direct access; the accessors on `MockLlmServer`
    /// wrap the lock for the common cases.
    pub history: Arc<Mutex<Vec<RecordedRequest>>>,
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_handle: Option<JoinHandle<()>>,
}

impl MockLlmServer {
    /// Start the mock with the default canned response (200 OK,
    /// `application/json`, minimal chat-completion envelope).
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_inner(
            StatusCode::OK,
            Bytes::from_static(DEFAULT_RESPONSE_BODY.as_bytes()),
            DEFAULT_RESPONSE_CONTENT_TYPE.to_owned(),
        )
        .await
    }

    async fn start_inner(
        response_status: StatusCode,
        response_body: Bytes,
        response_content_type: String,
    ) -> anyhow::Result<Self> {
        let history = Arc::new(Mutex::new(Vec::new()));
        let state = CaptureState {
            history: Arc::clone(&history),
            response_status,
            response_body,
            response_content_type,
        };

        let app = Router::new().fallback(any(capture_handler)).with_state(state);

        let port = portpicker::pick_unused_port().ok_or_else(|| anyhow::anyhow!("no free TCP port"))?;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server_handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        Ok(Self {
            url: format!("http://{bound_addr}"),
            history,
            addr: bound_addr,
            shutdown_tx: Some(shutdown_tx),
            server_handle: Some(server_handle),
        })
    }
}

impl Drop for MockLlmServer {
    fn drop(&mut self) {
        // Signal graceful shutdown first; abort the JoinHandle as a fallback
        // in case the listener task is wedged in a future the shutdown
        // signal can't preempt (matches `TopologyTestEnv`'s pattern in
        // `common/mod.rs`).
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

/// Axum fallback handler — records every inbound request, then returns the
/// configured canned response.
async fn capture_handler(
    State(state): State<CaptureState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let recorded = RecordedRequest {
        method: method.to_string(),
        path: uri.path().to_owned(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or_default().to_owned()))
            .collect(),
        body: body.to_vec(),
    };
    state
        .history
        .lock()
        .expect("mock LLM history mutex poisoned")
        .push(recorded);

    let mut response = state.response_body.clone().into_response();
    *response.status_mut() = state.response_status;
    if let Ok(value) = state.response_content_type.parse() {
        response.headers_mut().insert(axum::http::header::CONTENT_TYPE, value);
    }
    response
}
