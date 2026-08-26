//! Shared controlled-upstream recorder (AAASM-5902).
//!
//! Promoted from `spike_support::mock_anthropic::TlsCapturingUpstream` — the
//! most mature of ~4 near-duplicate `TlsCapturingUpstream` implementations that
//! had accumulated in this crate (each written for one journey's TLS-behind-the-
//! proxy needs). This module is the one call site (`spike_support::mock_anthropic`)
//! migrates to; the other ~3 copies elsewhere in the crate are out of this
//! subtask's scope and are left as-is.
//!
//! Two start modes, because a fake upstream is used for two different fidelity
//! claims (AAASM-5875's fidelity model):
//!
//! * [`CapturingUpstream::start_tls`] — TLS-terminating, signed by the caller's
//!   own CA. This is what `aa-proxy`'s `upstream_override` dials: what lands in
//!   [`CapturingUpstream::requests`] is the post-scan body the proxy actually
//!   forwards, over the wire it actually forwards it on.
//! * [`CapturingUpstream::start_plain`] — plain HTTP, for provider mocks reached
//!   by direct base-URL redirection rather than through the proxy's MitM path.

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
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

/// A single inbound request captured by [`CapturingUpstream`], verbatim.
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

type RequestLog = Arc<Mutex<Vec<RecordedRequest>>>;

/// What [`CapturingUpstream`] answers every captured request with.
#[derive(Clone, Debug)]
pub struct UpstreamOptions {
    /// Hostname the TLS leaf is signed for. Only used by [`CapturingUpstream::start_tls`].
    pub hostname: String,
    /// HTTP status to answer every request with.
    pub response_status: StatusCode,
    /// Response body bytes.
    pub response_body: Vec<u8>,
    /// `Content-Type` header value on the response.
    pub content_type: String,
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        Self {
            hostname: "api.anthropic.com".to_owned(),
            response_status: StatusCode::OK,
            response_body: br#"{"id":"msg_canary_mock","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"MOCK-REPLY"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":4}}"#.to_vec(),
            content_type: "application/json".to_owned(),
        }
    }
}

/// A controlled fake upstream that records every request it receives.
///
/// Either TLS-terminating (dialled by a real `aa-proxy`'s `upstream_override`)
/// or plain HTTP (dialled by direct base-URL redirection), depending on which
/// constructor started it.
pub struct CapturingUpstream {
    /// Loopback address to hand to the caller under test.
    pub addr: SocketAddr,
    log: RequestLog,
    _abort: tokio::task::AbortHandle,
    /// Held for the instance's lifetime: dropping it resolves the plain-HTTP
    /// server's graceful-shutdown future. `None` for a TLS instance, which
    /// tears down via `_abort` instead. Must stay a field, not a local dropped
    /// at the end of `start_plain` — dropping it there would resolve the
    /// shutdown signal immediately, killing the server before it serves a
    /// single request.
    _shutdown_tx: Option<oneshot::Sender<()>>,
}

impl CapturingUpstream {
    /// Start a TLS-terminating upstream with a leaf certificate signed by `ca`
    /// for `opts.hostname`.
    pub async fn start_tls(ca: &CaStore, opts: UpstreamOptions) -> anyhow::Result<Self> {
        let ck = ca
            .sign_cert(&opts.hostname)
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
        let response_head = build_response_head(&opts);
        let response_body = opts.response_body.clone();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let log = Arc::clone(&log_task);
                let response_head = response_head.clone();
                let response_body = response_body.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    // Serve requests until the peer closes: a real client may
                    // reuse a keep-alive connection for retries or side-channel
                    // fetches, and dropping after one exchange would make those
                    // look like network failures rather than what they are.
                    loop {
                        match read_one_request(&mut tls).await {
                            Some(recorded) => {
                                log.lock().expect("upstream log mutex").push(recorded);
                                if tls.write_all(response_head.as_bytes()).await.is_err() {
                                    return;
                                }
                                if tls.write_all(&response_body).await.is_err() {
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
            _shutdown_tx: None,
        })
    }

    /// Start a plain-HTTP upstream (no TLS) for direct base-URL redirection.
    pub async fn start_plain(opts: UpstreamOptions) -> anyhow::Result<Self> {
        let log: RequestLog = Arc::new(Mutex::new(Vec::new()));
        let state = PlainState {
            log: Arc::clone(&log),
            response_status: opts.response_status,
            response_body: Bytes::from(opts.response_body.clone()),
            content_type: opts.content_type.clone(),
        };
        let app = Router::new().fallback(any(plain_capture_handler)).with_state(state);

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
            addr,
            log,
            _abort: handle.abort_handle(),
            _shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Number of requests recorded so far.
    pub fn request_count(&self) -> usize {
        self.log.lock().expect("upstream log mutex").len()
    }

    /// Snapshot of every recorded request, in arrival order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.log.lock().expect("upstream log mutex").clone()
    }

    /// Body of the most recent request as UTF-8, when it is valid UTF-8.
    pub fn last_body(&self) -> Option<String> {
        self.log
            .lock()
            .expect("upstream log mutex")
            .last()
            .and_then(|r| String::from_utf8(r.body.clone()).ok())
    }

    /// Block (async) until at least `n` requests have arrived, or `within`
    /// expires. Returns the observed count either way so the caller asserts
    /// rather than hangs.
    pub async fn wait_for_requests(&self, n: usize, within: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let count = self.request_count();
            if count >= n || tokio::time::Instant::now() >= deadline {
                return count;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn build_response_head(opts: &UpstreamOptions) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ct}\r\nContent-Length: {len}\r\n\r\n",
        status = opts.response_status.as_str(),
        reason = opts.response_status.canonical_reason().unwrap_or(""),
        ct = opts.content_type,
        len = opts.response_body.len(),
    )
}

#[derive(Clone)]
struct PlainState {
    log: RequestLog,
    response_status: StatusCode,
    response_body: Bytes,
    content_type: String,
}

async fn plain_capture_handler(
    State(state): State<PlainState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.log.lock().expect("upstream log mutex").push(RecordedRequest {
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
    if let Ok(ct) = state.content_type.parse() {
        response.headers_mut().insert(axum::http::header::CONTENT_TYPE, ct);
    }
    response
}

/// Read exactly one `Content-Length`-framed HTTP request off a TLS stream.
///
/// Returns `None` on EOF or a malformed head; the caller treats that as
/// connection close. Chunked transfer-encoding is deliberately unsupported — a
/// redacting proxy re-frames bodies with an explicit `Content-Length`, and
/// real LLM-provider clients send one too.
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
