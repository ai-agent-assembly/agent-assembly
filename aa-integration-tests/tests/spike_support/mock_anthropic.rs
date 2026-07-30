//! Anthropic-shaped mock model provider for the AAASM-5276 Spike.
//!
//! Two shapes, because the Spike has to measure two *different* interception
//! mechanisms and they terminate at different layers:
//!
//! * [`AnthropicMock`] — plain-HTTP `/v1/messages` recorder. This is what
//!   `ANTHROPIC_BASE_URL` points at (**Mechanism B**), and what the real
//!   `claude` binary talks to when AASM is *not* in the path. It exists to
//!   prove the negative result: base-URL redirection routes around AASM
//!   entirely.
//! * [`TlsCapturingUpstream`] — TLS-terminating recorder signed by the proxy's
//!   own CA, dialled by `aa-proxy` through its `upstream_override` test knob.
//!   This is the far side of **Mechanism A** (`HTTPS_PROXY` + MitM), so what it
//!   records is what actually left the host *after* the credential scanner ran.
//!
//! Both record every inbound body verbatim. The Spike's load-bearing assertion
//! is not "no secret was received" on its own — that is trivially satisfiable by
//! a broken test where no traffic flowed — but "at least one request arrived
//! **and** no body contains the raw value in any encoding checked". See
//! [`assert_recorded_and_secret_absent`].
//!
//! Marked Spike scaffolding: AAASM-5278 supersedes this with the productised
//! verification path.

use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aa_proxy::tls::CaStore;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use base64::Engine as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

/// Response body the mock returns for `POST /v1/messages`.
///
/// Shaped as a non-streaming Anthropic Messages envelope because the real
/// `claude` binary (v2.1.220) deserialises it and exits 0 — verified on the
/// target machine before this fixture was written. A wrong shape makes the
/// binary retry 11 times with exponential backoff instead of failing fast, which
/// looks like a network problem rather than a contract problem.
pub const ANTHROPIC_MOCK_RESPONSE: &str = r#"{"id":"msg_aaasm5276_mock","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"AAASM5276-MOCK-REPLY"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":4}}"#;

/// A single inbound request captured by a mock provider, verbatim.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    /// HTTP method as a string (e.g. `"POST"`).
    pub method: String,
    /// Request path including query string, as it arrived on the wire.
    pub path: String,
    /// Header name/value pairs in arrival order.
    pub headers: Vec<(String, String)>,
    /// Body bytes, captured before any framework parsing.
    pub body: Vec<u8>,
}

/// Shared request log. Cloned `Arc` into the request handler; the test holds the
/// other end.
pub type RequestLog = Arc<Mutex<Vec<RecordedRequest>>>;

// ── Mechanism B mock: plain HTTP `/v1/messages` ─────────────────────────────

#[derive(Clone)]
struct CaptureState {
    log: RequestLog,
    response_status: StatusCode,
    response_body: Bytes,
}

/// Plain-HTTP Anthropic-shaped mock provider on a random loopback port.
///
/// Point `ANTHROPIC_BASE_URL` at [`AnthropicMock::url`] and the real `claude`
/// binary will POST `/v1/messages?beta=true` here. AASM is **not** in that path;
/// that is the point of the fixture.
pub struct AnthropicMock {
    /// Base URL with no trailing slash, e.g. `http://127.0.0.1:54321`.
    pub url: String,
    /// Shared request log in arrival order.
    pub log: RequestLog,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl AnthropicMock {
    /// Start the mock with the standard 200/Messages-envelope response.
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with(StatusCode::OK, ANTHROPIC_MOCK_RESPONSE).await
    }

    /// Start the mock with a caller-chosen status and body.
    pub async fn start_with(status: StatusCode, body: &str) -> anyhow::Result<Self> {
        let log: RequestLog = Arc::new(Mutex::new(Vec::new()));
        let state = CaptureState {
            log: Arc::clone(&log),
            response_status: status,
            response_body: Bytes::from(body.to_owned()),
        };
        let app = Router::new().fallback(any(capture_handler)).with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        Ok(Self {
            url: format!("http://{addr}"),
            log,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        })
    }

    /// Number of requests recorded so far.
    pub fn request_count(&self) -> usize {
        self.log.lock().expect("mock log mutex").len()
    }

    /// Snapshot of every recorded body, in arrival order.
    pub fn bodies(&self) -> Vec<Vec<u8>> {
        self.log
            .lock()
            .expect("mock log mutex")
            .iter()
            .map(|r| r.body.clone())
            .collect()
    }

    /// `(method, path)` of every recorded request, in arrival order.
    ///
    /// Evidence that the traffic really is Anthropic Messages traffic and not
    /// some unrelated side-channel fetch that happened to hit the mock.
    pub fn request_lines(&self) -> Vec<(String, String)> {
        self.log
            .lock()
            .expect("mock log mutex")
            .iter()
            .map(|r| (r.method.clone(), r.path.clone()))
            .collect()
    }

    /// Header names present on the most recent request, lower-cased.
    pub fn last_header_names(&self) -> Vec<String> {
        self.log
            .lock()
            .expect("mock log mutex")
            .last()
            .map(|r| r.headers.iter().map(|(k, _)| k.to_ascii_lowercase()).collect())
            .unwrap_or_default()
    }

    /// Block (async) until at least `n` requests have been recorded, or the
    /// deadline expires. Returns the observed count either way so the caller
    /// asserts rather than hangs.
    pub async fn wait_for_requests(&self, n: usize, timeout: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let count = self.request_count();
            if count >= n || tokio::time::Instant::now() >= deadline {
                return count;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for AnthropicMock {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

async fn capture_handler(
    State(state): State<CaptureState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.log.lock().expect("mock log mutex").push(RecordedRequest {
        method: method.to_string(),
        path: uri.to_string(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or_default().to_owned()))
            .collect(),
        body: body.to_vec(),
    });
    let mut response = state.response_body.clone().into_response();
    *response.status_mut() = state.response_status;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        "application/json".parse().expect("static"),
    );
    response
}

// ── Mechanism A mock: TLS-terminating upstream behind the proxy ─────────────

/// TLS-terminating capture upstream, signed by the proxy's own CA.
///
/// `aa-proxy`'s `upstream_override` redirects every upstream dial here, so the
/// proxy's client connects with `ServerName = api.anthropic.com` and this
/// server's leaf cert (issued for that name by the same CA) matches. What lands
/// in [`TlsCapturingUpstream::log`] is the post-scan body the proxy chose to
/// forward.
pub struct TlsCapturingUpstream {
    /// Loopback address to hand to `ProxyConfig::upstream_override`.
    pub addr: SocketAddr,
    /// Shared request log in arrival order.
    pub log: RequestLog,
    _abort: tokio::task::AbortHandle,
}

impl TlsCapturingUpstream {
    /// Start the upstream with a leaf certificate signed by `ca` for `hostname`.
    pub async fn start(ca: &CaStore, hostname: &str) -> anyhow::Result<Self> {
        let ck = ca
            .sign_cert(hostname)
            .map_err(|e| anyhow::anyhow!("ca sign_cert: {e}"))?;
        let cert = CertificateDer::from(ck.cert_der.clone());
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(ck.key_der.clone()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let log: RequestLog = Arc::new(Mutex::new(Vec::new()));
        let log_task = Arc::clone(&log);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let log = Arc::clone(&log_task);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    // Serve requests until the peer closes: the real `claude`
                    // binary reuses a keep-alive connection for retries and for
                    // its side-channel fetches, and dropping after one exchange
                    // makes those look like network failures.
                    loop {
                        match read_one_request(&mut tls).await {
                            Some(recorded) => {
                                log.lock().expect("upstream log mutex").push(recorded);
                                let body = ANTHROPIC_MOCK_RESPONSE.as_bytes();
                                let head = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                                    body.len()
                                );
                                if tls.write_all(head.as_bytes()).await.is_err() {
                                    return;
                                }
                                if tls.write_all(body).await.is_err() {
                                    return;
                                }
                                let _ = tls.flush().await;
                            }
                            None => return,
                        }
                    }
                });
            }
        });

        Ok(Self {
            addr,
            log,
            _abort: handle.abort_handle(),
        })
    }

    /// Number of requests recorded so far.
    pub fn request_count(&self) -> usize {
        self.log.lock().expect("upstream log mutex").len()
    }

    /// Snapshot of every recorded body, in arrival order.
    pub fn bodies(&self) -> Vec<Vec<u8>> {
        self.log
            .lock()
            .expect("upstream log mutex")
            .iter()
            .map(|r| r.body.clone())
            .collect()
    }

    /// `(method, path)` of every recorded request, in arrival order.
    pub fn request_lines(&self) -> Vec<(String, String)> {
        self.log
            .lock()
            .expect("upstream log mutex")
            .iter()
            .map(|r| (r.method.clone(), r.path.clone()))
            .collect()
    }

    /// Header names present on the most recent request, lower-cased.
    pub fn last_header_names(&self) -> Vec<String> {
        self.log
            .lock()
            .expect("upstream log mutex")
            .last()
            .map(|r| r.headers.iter().map(|(k, _)| k.to_ascii_lowercase()).collect())
            .unwrap_or_default()
    }

    /// Body of the most recent request as UTF-8, when it is valid UTF-8.
    pub fn last_body(&self) -> Option<String> {
        self.log
            .lock()
            .expect("upstream log mutex")
            .last()
            .and_then(|r| String::from_utf8(r.body.clone()).ok())
    }

    /// Block (async) until at least `n` requests have arrived, or the deadline
    /// expires. Returns the observed count either way.
    pub async fn wait_for_requests(&self, n: usize, timeout: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let count = self.request_count();
            if count >= n || tokio::time::Instant::now() >= deadline {
                return count;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Read exactly one `Content-Length`-framed HTTP request off a TLS stream.
///
/// Returns `None` on EOF or a malformed head; the caller treats that as
/// connection close. Chunked transfer-encoding is deliberately unsupported — the
/// proxy re-frames redacted bodies with an explicit `Content-Length`, and the
/// real `claude` binary sends one too (measured: `Content-Length: 91153`).
async fn read_one_request<S>(tls: &mut S) -> Option<RecordedRequest>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        match tls.read(&mut tmp).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    let head = std::str::from_utf8(&buf[..head_end]).ok()?;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim().to_owned(), v.trim().to_owned());
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            headers.push((k, v));
        }
    }

    let body_start = head_end + 4;
    while buf.len() < body_start + content_length {
        match tls.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let end = (body_start + content_length).min(buf.len());
    Some(RecordedRequest {
        method,
        path,
        headers,
        body: buf[body_start..end].to_vec(),
    })
}

// ── Encoding-aware secret-absence assertion ─────────────────────────────────

/// Every representation of `secret` this harness searches for in a captured
/// body. Returned as `(label, needle_bytes)` so a failure names *which*
/// encoding leaked.
///
/// The set is deliberately enumerated rather than described as "any encoding":
/// a secret spliced mid-way into a larger base64 blob at an unchecked alignment
/// would evade all of these, so the Spike reports the checked set, not a
/// universal claim.
pub fn secret_encodings(secret: &str) -> Vec<(&'static str, Vec<u8>)> {
    let mut out: Vec<(&'static str, Vec<u8>)> = vec![("raw", secret.as_bytes().to_vec())];

    // JSON string escaping — what a body built by `serde_json` carries.
    let json = serde_json::to_string(secret).unwrap_or_default();
    let json_inner = json.trim_matches('"').to_owned();
    if json_inner != secret {
        out.push(("json-escaped", json_inner.into_bytes()));
    }

    // Base64 at all three byte alignments: a secret embedded at an arbitrary
    // offset in a base64 blob encodes differently depending on its start phase.
    for pad in 0..3usize {
        let mut padded = vec![b'A'; pad];
        padded.extend_from_slice(secret.as_bytes());
        let encoded = base64::engine::general_purpose::STANDARD.encode(&padded);
        // Drop the leading characters that encode the alignment filler, and the
        // trailing partial group, leaving only the stable interior.
        let start = pad.div_ceil(3) * 4;
        let stable: String = encoded
            .chars()
            .skip(start)
            .take(encoded.len().saturating_sub(start + 4))
            .collect();
        if stable.len() >= 8 {
            out.push((
                match pad {
                    0 => "base64-align0",
                    1 => "base64-align1",
                    _ => "base64-align2",
                },
                stable.into_bytes(),
            ));
        }
    }

    out.push(("hex", hex::encode(secret.as_bytes()).into_bytes()));
    out
}

/// Every form of a captured body this harness searches: the bytes as received,
/// plus a gzip-decoded view when the body is gzip-framed, plus a
/// whole-body-base64-decoded view.
fn body_views(body: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut views = vec![("as-received".to_owned(), body.to_vec())];

    if body.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        if flate2::read::GzDecoder::new(body).read_to_end(&mut out).is_ok() {
            views.push(("gzip-decoded".to_owned(), out));
        }
    }

    if let Ok(text) = std::str::from_utf8(body) {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()) {
            views.push(("base64-decoded".to_owned(), decoded));
        }
    }

    views
}

/// Search `bodies` for any encoding of `secret`. Returns
/// `(body_index, view_label, encoding_label)` for the first hit, or `None`.
pub fn find_secret(bodies: &[Vec<u8>], secret: &str) -> Option<(usize, String, &'static str)> {
    let needles = secret_encodings(secret);
    for (i, body) in bodies.iter().enumerate() {
        for (view_label, view) in body_views(body) {
            for (enc_label, needle) in &needles {
                if !needle.is_empty() && view.windows(needle.len()).any(|w| w == needle.as_slice()) {
                    return Some((i, view_label, enc_label));
                }
            }
        }
    }
    None
}

/// The Spike's core protection assertion: traffic **did** flow to the provider
/// and **no** captured body carries the secret in any checked encoding.
///
/// The `!bodies.is_empty()` half is load-bearing. Without it a harness that
/// silently sent nothing would report the same "no secret received" result as a
/// harness that proved redaction worked. `context` names the mechanism under
/// test so a failure message says which one leaked.
pub fn assert_recorded_and_secret_absent(bodies: &[Vec<u8>], secret: &str, context: &str) {
    assert!(
        !bodies.is_empty(),
        "{context}: mock provider recorded ZERO requests — the interception path was never \
         exercised, so 'the secret did not arrive' proves nothing",
    );
    if let Some((idx, view, enc)) = find_secret(bodies, secret) {
        panic!("{context}: raw synthetic secret found in captured body #{idx} (view={view}, encoding={enc})");
    }
}

/// The inverse assertion, for the scenarios whose *correct* outcome is that the
/// provider received the secret — `Observe` mode (11.10) and an unmanaged
/// launch (11.11). Asserting this positively is what stops a non-protecting
/// configuration from being displayable as a protecting one.
pub fn assert_recorded_and_secret_present(bodies: &[Vec<u8>], secret: &str, context: &str) {
    assert!(!bodies.is_empty(), "{context}: mock provider recorded ZERO requests");
    assert!(
        find_secret(bodies, secret).is_some(),
        "{context}: expected the raw synthetic secret to reach the provider (this configuration \
         does NOT protect), but no captured body contained it — the harness is not exercising \
         the path it claims to",
    );
}
