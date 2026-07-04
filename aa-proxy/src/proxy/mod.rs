//! TCP accept loop and CONNECT tunnel handling.
//!
//! `ProxyServer` owns the bound TCP listener, the TLS context (CA + cert cache),
//! and the interceptor. It is the top-level runtime object of the proxy.

pub mod http;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, OnceCell};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use aa_runtime::gateway_client::GatewayClient;
use aa_runtime::pipeline::PipelineEvent;

use crate::audit_jsonl::{ProxyAuditDecision, ProxyAuditEntry};
use crate::config::ProxyConfig;
use crate::credentials::CredentialStore;
use crate::error::ProxyError;
use crate::intercept::detect::{detect_api, LlmApiPattern};
use crate::intercept::event::ProxyEvent;
use crate::intercept::mcp::{is_unenforceable_tool_call, parse_mcp_request};
use crate::intercept::{InterceptVerdict, Interceptor, VerdictDecision};
use crate::mcp_enforce::{evaluate_mcp_call, McpDecision};
use crate::proxy::http::{
    read_http_request, read_http_response, read_line_capped, serialize_http_request, serialize_http_request_with_auth,
    serialize_http_response, HttpRequest, MAX_HEADER_BYTES, MAX_HEADER_COUNT, MAX_HEADER_LINE_LEN,
};
use crate::tls::{CaStore, CertCache};

/// A TLS `ServerCertVerifier` that accepts any certificate.
///
/// This is intentionally insecure — it exists only to allow integration tests
/// to use self-signed upstream servers without installing their CAs.
/// Gated behind [`ProxyConfig::skip_upstream_tls_verify`].
#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a JSON-RPC 2.0 error response body carrying the policy reason.
///
/// `id` is fixed at `null` because the proxy denies before parsing the
/// inbound envelope's `id` field — most MCP clients accept a null id on
/// errors emitted by a transport-layer interceptor.
fn build_jsonrpc_error_response(code: i32, message: &str) -> String {
    let msg_json = serde_json::to_string(message).unwrap_or_else(|_| "\"policy deny\"".into());
    format!(r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":{code},"message":{msg_json}}}}}"#)
}

/// Fail-closed client response for an MCP upstream response the proxy could not
/// parse (chunked / malformed) and therefore could not scan for secrets
/// (AAASM-3997).
///
/// The pre-3997 behaviour relayed the un-parsed upstream bytes verbatim, which
/// leaked an *unredacted* upstream body straight to the agent — defeating
/// response-side credential redaction on any response the parser chokes on.
/// Rather than forward bytes we never inspected, return a JSON-RPC error
/// envelope so the agent gets a clean, secret-free failure. The returned bytes
/// never contain any upstream content.
fn mcp_unparseable_response_bytes() -> Vec<u8> {
    let body = build_jsonrpc_error_response(
        -32000,
        "MCP response could not be inspected for secrets and was withheld (fail-closed)",
    );
    format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body,
    )
    .into_bytes()
}

/// The running proxy server.
///
/// Create via [`ProxyServer::new`], then drive the accept loop with
/// [`ProxyServer::run`]. Internally wrapped in `Arc` so connection
/// tasks can share the TLS context and interceptor.
pub struct ProxyServer {
    config: ProxyConfig,
    ca: CaStore,
    certs: CertCache,
    interceptor: Interceptor,
    /// Optional sink for [`ProxyAuditEntry`] records. When `Some`, the data
    /// path emits one entry per intercepted LLM request that carried
    /// credential findings (or that was blocked under `Block` policy).
    /// `None` means no JSONL persistence — useful for unit tests that only
    /// observe the broadcast event stream.
    audit_jsonl_tx: Option<mpsc::Sender<ProxyAuditEntry>>,
    /// Lazily-initialised gRPC client for the `aa-gateway` PolicyService.
    /// Populated at startup by [`ProxyServer::run`] when
    /// [`ProxyConfig::gateway_endpoint`] is `Some`; stays empty otherwise.
    ///
    /// The inner `Mutex` serialises concurrent `check_action` RPCs from
    /// connection tasks — the underlying tonic client is `&mut self`-keyed.
    /// The outer `OnceCell` lets the connect step run inside `run()`'s
    /// async context without requiring an async constructor.
    gateway_client: OnceCell<Arc<Mutex<GatewayClient>>>,
    /// Per-host real provider credentials, injected at egress (AAASM-3578).
    /// Loaded from operator configuration at construction; the agent runtime
    /// never sees these. Empty by default — when no key is configured for a
    /// host the agent's own request is forwarded unchanged (backward compat).
    credentials: Arc<CredentialStore>,
}

impl ProxyServer {
    /// Construct a `ProxyServer` without a JSONL audit sink. The legacy
    /// pipeline-event broadcast still fires.
    pub fn new(config: ProxyConfig, ca: CaStore, event_tx: broadcast::Sender<PipelineEvent>) -> Arc<Self> {
        Self::new_with_audit_sink(config, ca, event_tx, None)
    }

    /// Construct a `ProxyServer` that also persists `ProxyAuditEntry`
    /// records on `audit_jsonl_tx` (typically owned by a [`crate::audit_jsonl::JsonlWriter`]).
    pub fn new_with_audit_sink(
        config: ProxyConfig,
        ca: CaStore,
        event_tx: broadcast::Sender<PipelineEvent>,
        audit_jsonl_tx: Option<mpsc::Sender<ProxyAuditEntry>>,
    ) -> Arc<Self> {
        let certs = CertCache::new(config.cert_cache_capacity);
        Arc::new(Self {
            config,
            ca,
            certs,
            interceptor: Interceptor::new(event_tx),
            audit_jsonl_tx,
            gateway_client: OnceCell::new(),
            credentials: Arc::new(CredentialStore::from_env()),
        })
    }

    /// Replace the egress-injection credential store on an as-yet-unshared
    /// `ProxyServer`. Intended for integration tests that need to inject a
    /// known provider key without setting a process-wide env var; production
    /// builds populate the store from `AA_PROXY_PROVIDER_KEYS` in the
    /// constructors above.
    ///
    /// Returns the `Arc<Self>` unchanged when it is already shared (more than
    /// one strong reference), since the store can only be swapped before the
    /// accept loop starts.
    pub fn with_credentials(mut self: Arc<Self>, credentials: CredentialStore) -> Arc<Self> {
        if let Some(inner) = Arc::get_mut(&mut self) {
            inner.credentials = Arc::new(credentials);
        } else {
            tracing::warn!("with_credentials called on a shared ProxyServer; ignoring");
        }
        self
    }

    /// Bind the TCP listener and enter the accept loop.
    ///
    /// This future runs until the process is killed or an unrecoverable error
    /// occurs. It is called from [`crate::run`].
    pub async fn run(self: &Arc<Self>) -> Result<(), ProxyError> {
        // Connect to the gateway when an endpoint is configured.
        //
        // AAASM-3357: MCP enforcement is a governance path. When an endpoint is
        // configured the operator has asked the proxy to enforce — so a failed
        // connection must NOT silently degrade to fail-open. The default is
        // fail-closed: refuse to start so the operator notices the gateway is
        // down rather than letting denied MCP `tools/call`s through unchecked.
        // Operators who explicitly accept availability over enforcement can set
        // `AA_PROXY_MCP_FAIL_OPEN=1` to restore the historical soft degradation.
        if let Some(endpoint) = &self.config.gateway_endpoint {
            match GatewayClient::connect(endpoint).await {
                Ok(client) => {
                    let _ = self.gateway_client.set(Arc::new(Mutex::new(client)));
                    tracing::info!(%endpoint, "connected to aa-gateway PolicyService for MCP enforcement");
                }
                Err(e) if self.config.mcp_fail_open => {
                    tracing::warn!(
                        %endpoint,
                        error = %e,
                        "failed to connect to aa-gateway; MCP enforcement disabled (AA_PROXY_MCP_FAIL_OPEN is set, failing OPEN)",
                    );
                }
                Err(e) => {
                    tracing::error!(
                        %endpoint,
                        error = %e,
                        "failed to connect to aa-gateway; MCP enforcement is configured but the gateway is unreachable. \
                         Refusing to start (fail-closed). Fix the gateway, or set AA_PROXY_MCP_FAIL_OPEN=1 to start anyway \
                         and forward MCP traffic WITHOUT enforcement.",
                    );
                    return Err(ProxyError::Config(format!(
                        "aa-gateway unreachable at {endpoint}: {e} (fail-closed; set AA_PROXY_MCP_FAIL_OPEN=1 to override)"
                    )));
                }
            }
        }

        let listener = TcpListener::bind(self.config.bind_addr).await?;
        tracing::info!(addr = %self.config.bind_addr, "proxy listening");

        let mut sigint =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).map_err(ProxyError::Io)?;
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(ProxyError::Io)?;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer) = result?;
                    tracing::debug!(%peer, "accepted connection");
                    let server = Arc::clone(self);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream).await {
                            tracing::warn!(%peer, error = %e, "connection error");
                        }
                    });
                }
                _ = sigint.recv() => {
                    tracing::info!("received SIGINT, shutting down");
                    break;
                }
                _ = sigterm.recv() => {
                    tracing::info!("received SIGTERM, shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Build and dispatch a [`ProxyAuditEntry`] over the configured sink.
    ///
    /// No-op when `audit_jsonl_tx` is `None`. `try_send` is intentional —
    /// a slow JSONL writer must not stall the data path; a dropped entry
    /// is preferable to back-pressuring the proxy.
    async fn emit_audit_entry(
        self: &Arc<Self>,
        host: &str,
        req: &HttpRequest,
        verdict: &InterceptVerdict,
        decision: ProxyAuditDecision,
    ) {
        let Some(tx) = self.audit_jsonl_tx.as_ref() else { return };
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let redacted_body = verdict
            .redacted_body
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok().map(|s| s.to_owned()));
        let entry = ProxyAuditEntry {
            ts_ms,
            agent_id: None,
            host: host.to_owned(),
            method: req.method.clone(),
            path: req.target.clone(),
            decision,
            credential_findings: verdict.findings.clone(),
            redacted_body,
        };
        if let Err(e) = tx.try_send(entry) {
            tracing::warn!(error = %e, "proxy audit jsonl channel full or closed, dropping entry");
        }
    }

    /// Resolve `target` and open a TCP connection, re-validating every resolved
    /// address against the SSRF denylist immediately before connecting.
    ///
    /// This is the DNS-rebinding defense (AAASM-3130): a hostname that passes
    /// the allowlist at CONNECT time can resolve to — or be flipped to — an
    /// internal address (loopback, RFC-1918, link-local, cloud metadata) by the
    /// time the proxy actually dials. We refuse any such address here. Resolved
    /// addresses are filtered, not just the first, so a poisoned A-record set
    /// cannot slip an internal IP through behind a public one.
    async fn connect_revalidated(&self, target: &str) -> Result<TcpStream, ProxyError> {
        let addrs: Vec<_> = tokio::net::lookup_host(target)
            .await
            .map_err(|e| ProxyError::Config(format!("dns resolution failed for {target}: {e}")))?
            .collect();
        if addrs.is_empty() {
            return Err(ProxyError::Config(format!("no addresses resolved for {target}")));
        }
        let safe: Vec<_> = addrs
            .into_iter()
            .filter(|addr| {
                // Test-only escape hatch: in-process tests dial a loopback mock.
                // Never relaxed in production (see `allow_private_connect_targets`).
                self.config.allow_private_connect_targets || !crate::ssrf::is_blocked_ip(addr.ip())
            })
            .collect();
        if safe.is_empty() {
            return Err(ProxyError::Config(format!(
                "ssrf: {target} resolved only to blocked address range"
            )));
        }
        Ok(TcpStream::connect(&safe[..]).await?)
    }

    /// Dial the upstream TLS endpoint (TCP connect + ClientHello).
    ///
    /// Honours [`ProxyConfig::upstream_override`] when set — used by
    /// integration tests to redirect the dial to a local mock without
    /// hijacking DNS or modifying the client's CONNECT line.
    async fn dial_upstream_tls(
        self: &Arc<Self>,
        host: &str,
        target: &str,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ProxyError> {
        let upstream_tcp = match self.config.upstream_override {
            // Integration-test path: the dial is redirected to a trusted local
            // mock, so the SSRF re-validation below would (correctly) reject it.
            // Skip it here; the override is never set in production.
            Some(addr) => TcpStream::connect(addr).await?,
            None => self.connect_revalidated(target).await?,
        };
        let client_config = if self.config.skip_upstream_tls_verify {
            // Integration-test-only path: skip certificate verification so tests
            // can use self-signed upstream servers without installing their CAs.
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
                .with_no_client_auth()
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                let _ = root_store.add(cert);
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| ProxyError::Tls(e.to_string()))?;
        let upstream_tls = connector
            .connect(server_name, upstream_tcp)
            .await
            .map_err(|e| ProxyError::Tls(e.to_string()))?;
        tracing::debug!(%host, "upstream TLS handshake complete");
        Ok(upstream_tls)
    }

    /// Non-LLM, gateway-aware data path: read the HTTP request inside the
    /// MitM TLS tunnel, try to parse it as an MCP `tools/call` envelope, and
    /// either enforce the gateway's decision on the wire or forward the
    /// body transparently.
    ///
    /// Branches:
    ///
    /// * **MCP detected, gateway returns `Allow` or `Redact`** — forward the
    ///   original body to upstream and continue bidirectional copy.
    ///   (`Redact` is logged and forwarded as `Allow` for now — response-side
    ///   rewriting lands in AAASM-1941.)
    /// * **MCP detected, gateway returns `Deny`** — write a JSON-RPC 2.0
    ///   error envelope to the client TLS stream, do not dial upstream.
    /// * **MCP detected, gateway RPC failed** — log the error, fall through
    ///   to transparent forward. Soft-degradation matches `aa-runtime`'s
    ///   policy.
    /// * **Body is not MCP** — transparently forward what was read plus the
    ///   remaining stream.
    async fn handle_non_llm_with_gateway(
        self: &Arc<Self>,
        client_tls: tokio_rustls::server::TlsStream<TcpStream>,
        gateway: &Arc<Mutex<GatewayClient>>,
        host: &str,
        target: &str,
    ) -> Result<(), ProxyError> {
        let mut client_reader = BufReader::new(client_tls);
        let Some(req) = read_http_request(&mut client_reader).await? else {
            return Ok(());
        };

        // AAASM-3580: re-enforce the egress allowlist against the in-tunnel
        // host before any gateway dispatch or upstream dial. Mirrors the LLM
        // path so a forged Host cannot bypass the allowlist on the MCP route.
        if let Some(reason) = self.in_tunnel_deny_reason(&req) {
            let in_host = Self::effective_request_host(&req).unwrap_or(host);
            tracing::info!(connect_host = %host, in_tunnel_host = %in_host, "in-tunnel egress denied: {reason}");
            self.interceptor.emit_policy_decision(in_host, true).await;
            let mut client_tls = client_reader.into_inner();
            client_tls
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }

        // MCP detection. On a successful request-side eval, carry the parsed
        // call AND its serialised args bytes forward so the response-side
        // path below can re-use both for audit emission (args go into
        // `ToolCallDetail.args_json`).
        let mcp_call: Option<(crate::intercept::mcp::McpToolCall, Vec<u8>)> = if let Some(call) =
            parse_mcp_request(&req.body)
        {
            let target_url = format!("https://{host}{path}", path = req.target);
            // Serialise args once and reuse across the audit emissions on
            // both the request-side (Allow/Deny) and the response-side
            // (post-redact) paths.
            let args_bytes = serde_json::to_vec(&call.arguments).unwrap_or_default();
            match evaluate_mcp_call(gateway, &call, &target_url, "", "").await {
                Ok(McpDecision::Allow) | Ok(McpDecision::Redact { .. }) => {
                    tracing::info!(
                        tool_name = %call.tool_name,
                        %host,
                        "MCP call allowed by gateway, forwarding to upstream with response-side scanning",
                    );
                    self.interceptor
                        .emit_mcp_decision(&call.tool_name, &args_bytes, false, "")
                        .await;
                    Some((call, args_bytes))
                }
                Ok(McpDecision::Deny { reason }) => {
                    tracing::info!(
                        tool_name = %call.tool_name,
                        %host,
                        %reason,
                        "MCP call denied by gateway, returning JSON-RPC error envelope",
                    );
                    self.interceptor
                        .emit_mcp_decision(&call.tool_name, &args_bytes, true, &reason)
                        .await;
                    let body = build_jsonrpc_error_response(-32000, &reason);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let mut client_tls = client_reader.into_inner();
                    client_tls.write_all(resp.as_bytes()).await?;
                    let _ = client_tls.shutdown().await;
                    return Ok(());
                }
                Err(e) if self.config.mcp_fail_open => {
                    tracing::warn!(
                        tool_name = %call.tool_name,
                        %host,
                        error = %e,
                        "gateway CheckAction failed; forwarding without enforcement (AA_PROXY_MCP_FAIL_OPEN is set, failing OPEN)",
                    );
                    None
                }
                Err(e) => {
                    // AAASM-3357: fail-closed — a governance check that
                    // cannot reach its authority must not pass through. Deny
                    // the MCP call with a JSON-RPC error envelope, mirroring
                    // an explicit gateway Deny.
                    let reason = "MCP enforcement unavailable: gateway CheckAction failed (fail-closed)";
                    tracing::error!(
                        tool_name = %call.tool_name,
                        %host,
                        error = %e,
                        "gateway CheckAction failed; denying MCP call (fail-closed). \
                         Set AA_PROXY_MCP_FAIL_OPEN=1 to forward without enforcement instead.",
                    );
                    self.interceptor
                        .emit_mcp_decision(&call.tool_name, &args_bytes, true, reason)
                        .await;
                    let body = build_jsonrpc_error_response(-32000, reason);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body,
                    );
                    let mut client_tls = client_reader.into_inner();
                    client_tls.write_all(resp.as_bytes()).await?;
                    let _ = client_tls.shutdown().await;
                    return Ok(());
                }
            }
        } else if is_unenforceable_tool_call(&req.body) {
            // AAASM-4070: `parse_mcp_request` only deserialises a single
            // JSON-RPC object, so a `tools/call` wrapped in a batch array
            // (`[{…tools/call…}]`) or malformed just enough to fail strict
            // extraction returned `None` above — and the pre-fix `else` branch
            // forwarded that body upstream with NO gateway CheckAction and NO
            // credential/DLP scan. A steered agent used a one-element batch to
            // slip a denied tool call past enforcement. Fail closed: this body
            // is a tool-call attempt the enforcement path cannot evaluate, so
            // deny it with a JSON-RPC error envelope instead of forwarding,
            // mirroring an explicit gateway Deny. Non-MCP traffic is unaffected
            // (the detector only fires on `method == "tools/call"`).
            let reason = "MCP tools/call in unsupported JSON-RPC framing (batch array or malformed envelope) cannot be enforced and was rejected (fail-closed)";
            tracing::warn!(
                %host,
                "MCP tools/call bypass attempt via batch/malformed framing; denying (fail-closed). \
                 The gateway CheckAction and credential scan cannot evaluate this envelope.",
            );
            self.interceptor.emit_mcp_decision("unknown", &[], true, reason).await;
            // -32600 = JSON-RPC "Invalid Request": the proxy does not accept
            // this framing for an enforceable tool call.
            let body = build_jsonrpc_error_response(-32600, reason);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body,
            );
            let mut client_tls = client_reader.into_inner();
            client_tls.write_all(resp.as_bytes()).await?;
            let _ = client_tls.shutdown().await;
            return Ok(());
        } else {
            None
        };

        // Forward the (consumed) request body to upstream.
        let upstream_tls = self.dial_upstream_tls(host, target).await?;
        let outgoing = serialize_http_request(&req, &req.body);
        let mut client_tls = client_reader.into_inner();
        let (upstream_read, mut upstream_write) = tokio::io::split(upstream_tls);
        upstream_write.write_all(&outgoing).await?;

        if let Some((call, args_bytes)) = mcp_call {
            // MCP response path (AAASM-1930 ST-Q-3): read the upstream
            // response body-aware, run the proxy's credential scanner on
            // the body, and forward a redacted version when findings are
            // present. The scanner is the same `aa_security::CredentialScanner`
            // the gateway uses internally for ToolResult evaluation, so
            // the redaction shape matches what `mcp_redact_secrets.yaml`
            // would produce gateway-side. A future iteration could swap
            // this for a second `CheckAction` carrying ToolResult to
            // centralise policy decisions at the gateway — the gateway-
            // side ToolResult flow landed in AAASM-1941 for that purpose.
            let mut upstream_reader = BufReader::new(upstream_read);
            match read_http_response(&mut upstream_reader).await {
                Ok(Some(resp)) => {
                    let body_to_forward = match self.interceptor.redact_response_body(&resp.body) {
                        Some(redacted) => {
                            tracing::info!(
                                tool_name = %call.tool_name,
                                "MCP response carried sensitive payload, redacting before forwarding to client",
                            );
                            self.interceptor
                                .emit_mcp_decision(&call.tool_name, &args_bytes, false, "response redacted")
                                .await;
                            redacted
                        }
                        None => resp.body.clone(),
                    };
                    let modified = serialize_http_response(&resp, &body_to_forward);
                    client_tls.write_all(&modified).await?;
                }
                Ok(None) => {
                    // Upstream closed without writing a response — nothing to forward.
                }
                Err(e) => {
                    // AAASM-3997: an MCP response we cannot parse cannot be
                    // scanned or redacted. Relaying the un-parsed upstream bytes
                    // (the pre-3997 behaviour) would leak an *unredacted* body —
                    // potentially carrying credentials the response-side scanner
                    // would have stripped — straight to the agent. Fail closed:
                    // withhold the upstream body and return a JSON-RPC error
                    // envelope instead. (We still never copy client→upstream, so
                    // AAASM-3864's no-uninspected-request property holds.)
                    tracing::warn!(
                        tool_name = %call.tool_name,
                        error = %e,
                        "MCP response parse failed; withholding unredacted upstream body (fail-closed)",
                    );
                    self.interceptor
                        .emit_mcp_decision(
                            &call.tool_name,
                            &args_bytes,
                            true,
                            "response unparseable, withheld (fail-closed)",
                        )
                        .await;
                    client_tls.write_all(&mcp_unparseable_response_bytes()).await?;
                }
            }
        } else {
            // Not MCP (or RPC failed) — relay only the upstream response back to
            // the client. AAASM-3864 (a): we never copy further client bytes
            // upstream, so a follow-up request pipelined on the tunnel cannot
            // reach upstream un-inspected. The serialized request carries
            // `Connection: close`, bounding this relay.
            let mut upstream_read = upstream_read;
            tokio::io::copy(&mut upstream_read, &mut client_tls).await?;
        }
        let _ = client_tls.shutdown().await;
        Ok(())
    }

    /// Evaluate egress policy for a `CONNECT` host. Returns `Some(reason)` when
    /// the connection must be denied — the host is on the deny-list, or (when a
    /// non-empty network allowlist is configured) it matches no allowlist
    /// pattern. Returns `None` when the connection is allowed. An empty
    /// allowlist preserves the pre-AAASM-1943 default-open behaviour.
    fn connect_deny_reason(&self, host: &str) -> Option<&'static str> {
        // SSRF guard (AAASM-3130): an IP-literal CONNECT target pointed at
        // loopback / RFC-1918 / link-local / cloud-metadata space must be
        // refused regardless of the allowlist — a hostname allowlist cannot
        // express "but not internal addresses". Names are re-validated after
        // resolution in `dial_upstream_tls` (DNS-rebind defense).
        if !self.config.allow_private_connect_targets {
            if let Some(true) = crate::ssrf::blocked_ip_literal(host) {
                return Some("ssrf: blocked address range");
            }
        }
        // AAASM-3983: canonicalise the host ONCE (lowercase + strip a single
        // trailing dot) before the denied_hosts and allowlist comparisons. The
        // byte-exact `denied == host` check let `EVIL.COM` or `evil.com.` evade
        // a lowercase `evil.com` denylist entry, and the allowlist matcher —
        // though it lowercases — never stripped a trailing dot, so `evil.com.`
        // slipped past it too. Compare canonical-to-canonical on both sides.
        let host = canonical_host(host);
        let host = host.as_str();
        if self
            .config
            .denied_hosts
            .iter()
            .any(|denied| canonical_host(denied) == host)
        {
            return Some("host policy");
        }
        if !aa_core::policy::is_host_allowed_by_egress_allowlist(host, &self.config.network_allowlist) {
            return Some("network allowlist");
        }
        None
    }

    /// Re-enforce the egress policy against the host the agent actually sent
    /// **inside** the MitM tunnel — the in-tunnel `Host` header or an
    /// absolute-form request target — not just the CONNECT line (AAASM-3580).
    ///
    /// Returns `Some(reason)` when the request must be denied. This defeats the
    /// prompt-injection → proxy-bypass attack: the agent CONNECTs to an
    /// allowlisted host (opening the tunnel) but then forges
    /// `Host: evil.attacker.com` to exfiltrate to a non-allowlisted endpoint.
    /// Because the allowlist is re-checked here against the agent-supplied host,
    /// the forged host is rejected before the proxy dials upstream.
    ///
    /// When the in-tunnel host is empty (no Host header, origin-form target) the
    /// CONNECT-time check already covered the destination, so this is a no-op.
    /// An empty allowlist keeps the default-open behaviour unchanged.
    fn in_tunnel_deny_reason(&self, req: &HttpRequest) -> Option<&'static str> {
        let host = Self::effective_request_host(req)?;
        self.connect_deny_reason(host)
    }

    /// Extract the effective upstream host the in-tunnel request addresses.
    ///
    /// Prefers an absolute-form request target (`https://host/...`); otherwise
    /// falls back to the `Host` header. The port (if any) is stripped so the
    /// result is comparable against the allowlist/denylist host grammar.
    /// Returns `None` when neither yields a host.
    fn effective_request_host(req: &HttpRequest) -> Option<&str> {
        // Absolute-form target, e.g. "https://evil.attacker.com/v1/..." or
        // "http://evil.attacker.com/...". Strip the scheme, then keep up to the
        // first '/' (path) — leaving "host[:port]".
        let from_target = req
            .target
            .strip_prefix("https://")
            .or_else(|| req.target.strip_prefix("http://"))
            .map(|rest| rest.split('/').next().unwrap_or(rest));

        let host_port = from_target.or_else(|| req.header("host"))?;
        let host = host_port.split(':').next().unwrap_or(host_port).trim();
        if host.is_empty() {
            None
        } else {
            Some(host)
        }
    }

    /// Inspect, enforce, and forward an LLM-pattern HTTPS request inside an
    /// already-established TLS MitM tunnel.
    ///
    /// Reads the inbound HTTP request so the credential scanner runs against
    /// the real body bytes before any byte reaches upstream. On a `Block`
    /// verdict, returns `403` to the client without dialing upstream. Otherwise
    /// dials upstream and forwards the (possibly redacted) request, then runs a
    /// bidirectional copy until either side closes.
    async fn handle_llm_mitm(
        self: &Arc<Self>,
        client_tls: tokio_rustls::server::TlsStream<TcpStream>,
        host: &str,
        target: &str,
        pattern: LlmApiPattern,
    ) -> Result<(), ProxyError> {
        let mut client_reader = BufReader::new(client_tls);
        let Some(req) = read_http_request(&mut client_reader).await? else {
            // Client closed without sending a request line — nothing
            // to do, just return cleanly.
            return Ok(());
        };

        // AAASM-3580: re-enforce the egress allowlist against the host the agent
        // sent INSIDE the tunnel, not just the CONNECT line. A forged
        // `Host: evil.attacker.com` is rejected here, before any upstream dial.
        if let Some(reason) = self.in_tunnel_deny_reason(&req) {
            let in_host = Self::effective_request_host(&req).unwrap_or(host);
            tracing::info!(connect_host = %host, in_tunnel_host = %in_host, "in-tunnel egress denied: {reason}");
            self.interceptor.emit_policy_decision(in_host, true).await;
            let mut client_tls = client_reader.into_inner();
            client_tls
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }

        let verdict = self
            .interceptor
            .intercept_request(&req.body, self.config.credential_action);

        // Emit the legacy ProxyEvent for the audit broadcast — keeps
        // existing subscribers wired up unchanged.
        let event = ProxyEvent {
            agent_id: None,
            pattern,
            method: req.method.clone(),
            path: req.target.clone(),
            request_body: Some(bytes::Bytes::copy_from_slice(&req.body)),
            response_body: None,
            timestamp: SystemTime::now(),
        };
        self.interceptor.intercept(&event).await?;

        if verdict.decision == VerdictDecision::Block {
            tracing::info!(
                %host,
                findings = verdict.findings.len(),
                "credential_action=Block: refusing forward, returning 403",
            );
            self.emit_audit_entry(host, &req, &verdict, ProxyAuditDecision::Blocked)
                .await;
            let mut client_tls = client_reader.into_inner();
            client_tls
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }

        // Dial upstream only after we have decided not to block.
        let upstream_tls = self.dial_upstream_tls(host, target).await?;

        // AAASM-3578: credential injection. When a real, non-expired provider
        // key is configured for this host the store builds the egress
        // `Authorization` value (`Bearer <key>`); the serializer then strips the
        // agent's own credential headers and injects the real one. The secret is
        // expanded only into this local buffer, never logged. When no key is
        // configured (or it has expired, AAASM-3586) the agent's request is
        // forwarded unchanged (backward compatible).
        let injected_auth: Option<Vec<u8>> = self.credentials.authorization_for(host);
        if injected_auth.is_some() {
            tracing::debug!(%host, "injecting real provider credential at egress");
        }
        let injected_auth_ref = injected_auth.as_deref();

        let outgoing_bytes = match verdict.decision {
            VerdictDecision::ForwardRedacted => {
                let body = verdict
                    .redacted_body
                    .as_deref()
                    .expect("ForwardRedacted always carries redacted_body");
                let bytes = serialize_http_request_with_auth(&req, body, injected_auth_ref);
                self.emit_audit_entry(host, &req, &verdict, ProxyAuditDecision::ForwardedRedacted)
                    .await;
                bytes
            }
            VerdictDecision::AlertAndForward => {
                let bytes = serialize_http_request_with_auth(&req, &req.body, injected_auth_ref);
                // Emit an audit entry so operators can see the alert-mode
                // decision (findings are still recorded, body is not).
                self.emit_audit_entry(host, &req, &verdict, ProxyAuditDecision::Forwarded)
                    .await;
                bytes
            }
            _ => serialize_http_request_with_auth(&req, &req.body, injected_auth_ref),
        };

        let mut upstream_tls = upstream_tls;
        upstream_tls.write_all(&outgoing_bytes).await?;

        // AAASM-3864 (a): relay only the upstream response back to the client,
        // then tear the tunnel down. We never copy further client bytes upstream,
        // so a second request pipelined on this keep-alive tunnel cannot reach
        // upstream un-inspected. The serialized request carries `Connection:
        // close`, so upstream closes after one response (bounding this copy).
        let mut client_tls = client_reader.into_inner();
        tokio::io::copy(&mut upstream_tls, &mut client_tls).await?;
        let _ = client_tls.shutdown().await;
        Ok(())
    }

    /// Handle a single accepted TCP connection.
    ///
    /// Reads the first HTTP request line to determine whether this is a
    /// `CONNECT` tunnel (HTTPS) or a plain HTTP request.
    async fn handle_connection(self: &Arc<Self>, stream: TcpStream) -> Result<(), ProxyError> {
        let mut reader = BufReader::new(stream);

        // Read the first request line, e.g. "CONNECT api.openai.com:443 HTTP/1.1\r\n"
        // AAASM-3922: bound the line so an unbounded read cannot OOM the proxy
        // before CONNECT/plain-HTTP routing even begins.
        let mut request_line = String::new();
        read_line_capped(&mut reader, &mut request_line, MAX_HEADER_LINE_LEN, MAX_HEADER_BYTES).await?;
        let request_line = request_line.trim_end();

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(ProxyError::Config("malformed HTTP request line".into()));
        }

        let method = parts[0];
        let target = parts[1];

        if method.eq_ignore_ascii_case("CONNECT") {
            self.handle_connect_tunnel(reader, target).await
        } else {
            self.handle_plain_http(reader, request_line, method, target).await
        }
    }

    /// Handle a `CONNECT` tunnel: enforce egress policy, open the tunnel, then
    /// either raw-tunnel (llm_only non-LLM hosts) or perform TLS MitM and route
    /// to the LLM / gateway / passthrough handler by detected API pattern.
    async fn handle_connect_tunnel(
        self: &Arc<Self>,
        mut reader: BufReader<TcpStream>,
        target: &str,
    ) -> Result<(), ProxyError> {
        // Consume remaining headers (we only need the request line for CONNECT).
        // AAASM-3922: cap the drained head (per-line + total budget + count) so an
        // unbounded header read cannot OOM the proxy.
        let mut head_budget = MAX_HEADER_BYTES;
        let mut header_count = 0usize;
        let mut header_line = String::new();
        loop {
            header_line.clear();
            let n = read_line_capped(&mut reader, &mut header_line, MAX_HEADER_LINE_LEN, head_budget).await?;
            head_budget -= n;
            if header_line.trim().is_empty() {
                break;
            }
            header_count += 1;
            if header_count > MAX_HEADER_COUNT {
                return Err(ProxyError::Config(format!(
                    "CONNECT request exceeds maximum {MAX_HEADER_COUNT} header lines; refusing (fail-closed)"
                )));
            }
        }

        // Extract hostname (strip port) and canonicalise it (AAASM-3983:
        // lowercase + strip a single trailing dot) so the deny check, cert
        // generation, LLM-pattern detection, SNI, and upstream dial all consume
        // one canonical form. Without this an `api.openai.com.` CONNECT would be
        // classified Unknown and raw-tunnelled under llm_only, and case/dot
        // variants would evade the denylist. `target` (with port) is retained
        // for the DNS/connect calls, which tolerate the trailing dot.
        let host = canonical_host(target);
        let host = host.as_str();

        // Egress policy: deny-list, then AAASM-1943 network allowlist.
        // Both return 403 + emit a deny decision and end the connection.
        if let Some(reason) = self.connect_deny_reason(host) {
            tracing::info!(%host, "CONNECT denied: {reason}");
            let mut stream = reader.into_inner();
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            self.interceptor.emit_policy_decision(host, true).await;
            return Ok(());
        }

        // Send 200 Connection Established to tell the client the tunnel is open.
        let mut stream = reader.into_inner();
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        tracing::debug!(host = target, "CONNECT tunnel established");

        // Emit allow audit event for the accepted connection.
        self.interceptor.emit_policy_decision(host, false).await;

        // When llm_only is enabled, skip TLS MitM for non-LLM hosts and
        // just tunnel the raw TCP bytes transparently.
        if self.config.llm_only && detect_api(host) == LlmApiPattern::Unknown {
            tracing::debug!(%host, "llm_only mode — transparent tunnel (no MitM)");
            return self.transparent_tunnel(stream, target).await;
        }

        // --- TLS MitM: act as TLS server to the client ---
        let ck = self.certs.get_or_insert(host, &self.ca)?;
        let cert = CertificateDer::from(ck.cert_der.clone());
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(ck.key_der.clone()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| ProxyError::Tls(e.to_string()))?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let client_tls = acceptor
            .accept(stream)
            .await
            .map_err(|e| ProxyError::Tls(e.to_string()))?;

        tracing::debug!(%host, "TLS MitM (client side) handshake complete");

        let pattern = detect_api(host);

        // For LLM patterns, read the inbound HTTP request inside the
        // tunnel so the credential scanner can run against the real
        // body bytes before any byte reaches upstream. For non-LLM
        // patterns we fall through to the gateway/passthrough handler.
        if pattern != LlmApiPattern::Unknown {
            return self.handle_llm_mitm(client_tls, host, target, pattern).await;
        }

        // Non-LLM pattern.
        //
        // When a gateway client is configured, attempt MCP detection
        // on the inbound HTTPS request body: a JSON-RPC 2.0 `tools/call`
        // envelope is dispatched to the gateway PolicyService and
        // enforced on the wire (Deny → JSON-RPC error envelope, Allow →
        // forward, Redact → forward unchanged until AAASM-1941 lands
        // response-side rewriting). Non-MCP bodies fall through to a
        // transparent forward of the bytes we've already read.
        //
        // When no gateway is configured, preserve the historical raw
        // bidirectional copy (no body inspection at all).
        if let Some(gateway) = self.gateway_client.get() {
            self.handle_non_llm_with_gateway(client_tls, gateway, host, target)
                .await?;
        } else {
            let upstream_tls = self.dial_upstream_tls(host, target).await?;
            let (mut client_read, mut client_write) = tokio::io::split(client_tls);
            let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_tls);

            let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
            let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

            tokio::select! {
                r = client_to_upstream => { r?; }
                r = upstream_to_client => { r?; }
            }
        }

        Ok(())
    }

    /// Raw bidirectional copy between an established client `stream` and the
    /// re-validated upstream for `target`. Used by the llm_only transparent-
    /// tunnel path, which forwards bytes without MitM. SSRF re-validation covers
    /// this path too — it is the most likely SSRF vector when the host resolves
    /// to an internal address.
    async fn transparent_tunnel(self: &Arc<Self>, stream: TcpStream, target: &str) -> Result<(), ProxyError> {
        let upstream = match self.config.upstream_override {
            Some(addr) => TcpStream::connect(addr).await?,
            None => self.connect_revalidated(target).await?,
        };
        let (mut cr, mut cw) = tokio::io::split(stream);
        let (mut ur, mut uw) = tokio::io::split(upstream);
        tokio::select! {
            r = tokio::io::copy(&mut cr, &mut uw) => { r?; }
            r = tokio::io::copy(&mut ur, &mut cw) => { r?; }
        }
        Ok(())
    }

    /// Forward a plain (non-CONNECT) HTTP request: parse the host from the
    /// target/Host header, SSRF-revalidate the upstream (AAASM-3140), re-serialise
    /// the request line + headers, then bidirectionally copy the bodies.
    async fn handle_plain_http(
        self: &Arc<Self>,
        mut reader: BufReader<TcpStream>,
        request_line: &str,
        method: &str,
        target: &str,
    ) -> Result<(), ProxyError> {
        tracing::debug!(method = method, target = target, "plain HTTP request");

        // Consume remaining request headers.
        // AAASM-3922: cap the head (per-line + total budget + count) so an
        // unbounded header read cannot OOM the proxy.
        let mut headers = Vec::new();
        let mut head_budget = MAX_HEADER_BYTES;
        let mut header_line = String::new();
        loop {
            header_line.clear();
            let n = read_line_capped(&mut reader, &mut header_line, MAX_HEADER_LINE_LEN, head_budget).await?;
            head_budget -= n;
            if header_line.trim().is_empty() {
                break;
            }
            if headers.len() >= MAX_HEADER_COUNT {
                return Err(ProxyError::Config(format!(
                    "plain-HTTP request exceeds maximum {MAX_HEADER_COUNT} header lines; refusing (fail-closed)"
                )));
            }
            headers.push(header_line.clone());
        }

        // Parse host from the target URL or Host header.
        //
        // AAASM-3891: this is owned (`String`) rather than `&'static str` via
        // `.leak()`. The previous `.leak()` permanently leaked one host string
        // per plain-HTTP request, so a steered agent issuing repeated origin-form
        // `http://` requests caused unbounded memory growth.
        let host: String = parse_plain_http_host(target, &headers);

        // AAASM-3864 (b): enforce the same egress denylist + network allowlist
        // the CONNECT path applies. Without this an `http://` scheme-downgrade
        // bypasses `denied_hosts`/`network_allowlist` — the SSRF resolved-IP
        // recheck below only guards address ranges, not policy hosts. Deny here
        // (before any upstream dial), mirroring the CONNECT path's 403.
        let deny_host = host.split(':').next().unwrap_or(&host);
        if let Some(reason) = self.connect_deny_reason(deny_host) {
            tracing::info!(host = %deny_host, "plain-HTTP egress denied: {reason}");
            self.interceptor.emit_policy_decision(deny_host, true).await;
            let mut stream = reader.into_inner();
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let _ = stream.shutdown().await;
            return Ok(());
        }

        // AAASM-3984: refuse plaintext (`http://`) egress to a known LLM
        // provider. The credential-scanning DLP (scan → block/redact) only runs
        // on the HTTPS MitM path (`handle_llm_mitm`); the plain-HTTP path below
        // is a raw bidirectional copy with no `intercept_request` scan. LLM
        // provider APIs are HTTPS-only, so a cleartext request to an LLM host is
        // always a protocol-downgrade bypass — a steered agent could exfiltrate
        // secrets in cleartext with zero inspection. Refuse it here (fail-closed,
        // 403) rather than raw-copying it upstream un-inspected. `detect_api`
        // canonicalizes case/port/trailing-dot, so downgrade variants like
        // `http://API.OpenAI.CoM.` are caught too. Legitimate LLM traffic is
        // HTTPS and continues to be inspected by `handle_llm_mitm`.
        if detect_api(deny_host) != LlmApiPattern::Unknown {
            tracing::info!(
                host = %deny_host,
                "plain-HTTP egress to LLM host refused: cleartext downgrade bypasses DLP",
            );
            self.interceptor.emit_policy_decision(deny_host, true).await;
            let mut stream = reader.into_inner();
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let _ = stream.shutdown().await;
            return Ok(());
        }

        // Connect to upstream via plain TCP.
        let upstream_addr = if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:80")
        };
        // SSRF re-validation (AAASM-3140): the plain-HTTP forward path must
        // route through the same resolved-IP denylist as the CONNECT/tunnel
        // paths. Without this, a steered agent making a plain `http://`
        // request could reach loopback / RFC-1918 / `169.254.169.254` after
        // DNS resolution, bypassing the AAASM-3130 hardening.
        let mut upstream = match self.config.upstream_override {
            Some(addr) => TcpStream::connect(addr).await?,
            None => self.connect_revalidated(&upstream_addr).await?,
        };

        // Re-serialise and forward the original request.
        upstream.write_all(request_line.as_bytes()).await?;
        upstream.write_all(b"\r\n").await?;
        for h in &headers {
            upstream.write_all(h.as_bytes()).await?;
        }
        upstream.write_all(b"\r\n").await?;

        // Bidirectional copy between client and upstream.
        let stream = reader.into_inner();
        let (mut client_read, mut client_write) = tokio::io::split(stream);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

        let c2u = tokio::io::copy(&mut client_read, &mut upstream_write);
        let u2c = tokio::io::copy(&mut upstream_read, &mut client_write);

        tokio::select! {
            r = c2u => { r?; }
            r = u2c => { r?; }
        }

        Ok(())
    }
}

/// Canonicalise a host for policy comparison and LLM-pattern detection
/// (AAASM-3983).
///
/// DNS names are case-insensitive (RFC 4343) and a single trailing dot denotes
/// the (equivalent) fully-qualified form — `API.OPENAI.COM` and
/// `api.openai.com.` both address the same host as `api.openai.com`. Comparing
/// hosts byte-exact (as the `denied_hosts` check did) or lowercasing without
/// stripping the trailing dot (as the allowlist matcher did) let a caller evade
/// a `denied_hosts` entry or the LLM-only MitM path by varying only case or a
/// trailing dot. Canonicalising once — strip the port, strip a single trailing
/// dot, lowercase — closes that bypass. The result carries no port.
fn canonical_host(host: &str) -> String {
    let no_port = host.split(':').next().unwrap_or(host);
    let no_dot = no_port.strip_suffix('.').unwrap_or(no_port);
    no_dot.to_ascii_lowercase()
}

/// Parse the upstream host for a plain (non-CONNECT) HTTP request from the
/// origin-form target (`http://host/...`) or, failing that, the `Host:` header.
///
/// AAASM-3891: returns an **owned** `String`. The previous inline implementation
/// produced a `&'static str` via `.leak()` so both branches shared a type, which
/// permanently leaked one host string per request and let repeated plain-HTTP
/// requests grow proxy memory without bound. Returning an owned value keeps the
/// host on the stack frame and frees it when the request completes.
fn parse_plain_http_host(target: &str, headers: &[String]) -> String {
    if let Some(url_host) = target.strip_prefix("http://") {
        url_host.split('/').next().unwrap_or(url_host).to_string()
    } else {
        headers
            .iter()
            .find_map(|h| {
                let lower = h.to_ascii_lowercase();
                lower
                    .starts_with("host:")
                    .then(|| h["host:".len()..].trim().to_string())
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unparseable_mcp_response_is_fail_closed_and_carries_no_upstream_bytes() {
        // AAASM-3997: the fail-closed response for an unparseable MCP upstream
        // response must be a clean JSON-RPC error envelope, never a passthrough
        // of upstream bytes (which could carry credentials the scanner never saw).
        let bytes = mcp_unparseable_response_bytes();
        let text = String::from_utf8(bytes).expect("valid UTF-8 HTTP response");

        // A well-formed HTTP error response, not a relayed 200 upstream body.
        assert!(text.starts_with("HTTP/1.1 502"), "expected a 502 status line: {text}");
        assert!(
            text.contains("\"jsonrpc\":\"2.0\""),
            "expected a JSON-RPC error body: {text}"
        );
        assert!(text.contains("fail-closed"), "expected the fail-closed reason: {text}");

        // The envelope is synthesized from constants only: a would-be leaked
        // upstream secret can never appear in it.
        assert!(
            !text.contains("sk-LEAKED-UPSTREAM-SECRET"),
            "fail-closed response must not echo upstream content"
        );
    }

    async fn server_with(denied_hosts: Vec<String>, allowlist: Vec<String>) -> Arc<ProxyServer> {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let mut config = ProxyConfig {
            bind_addr: ([127, 0, 0, 1], 0).into(),
            ca_dir: dir.path().to_path_buf(),
            cert_cache_capacity: 8,
            llm_only: true,
            mitm_hosts: Vec::new(),
            denied_hosts,
            network_allowlist: allowlist,
            skip_upstream_tls_verify: false,
            credential_action: crate::config::CredentialAction::default(),
            upstream_override: None,
            gateway_endpoint: None,
            mcp_fail_open: false,
            // These unit tests assert the SSRF guard blocks loopback/RFC-1918.
            allow_private_connect_targets: false,
        };
        config.bind_addr = ([127, 0, 0, 1], 0).into();
        let (tx, _rx) = broadcast::channel(8);
        ProxyServer::new(config, ca, tx)
    }

    #[test]
    fn parse_plain_http_host_from_origin_form_target() {
        // Origin-form `http://host/path` targets resolve the host from the URL.
        let host = parse_plain_http_host("http://api.openai.com/v1/chat", &[]);
        assert_eq!(host, "api.openai.com");
    }

    #[test]
    fn parse_plain_http_host_falls_back_to_host_header() {
        // A bare path target resolves the host from the (case-insensitive) Host
        // header instead.
        let headers = vec!["HOST: api.example.com\r\n".to_string()];
        let host = parse_plain_http_host("/v1/chat", &headers);
        assert_eq!(host, "api.example.com");
    }

    #[test]
    fn parse_plain_http_host_returns_owned_string_not_leaked() {
        // AAASM-3891 regression: the host must be an owned `String` rather than a
        // `&'static str` produced by `.leak()`. Owned values are reclaimed when
        // dropped, so repeated plain-HTTP requests no longer leak one host per
        // request. Two calls returning equal-but-independent owned values (the
        // second freed on drop) demonstrate no static interning/leak is in play.
        let headers = vec!["Host: api.example.com\r\n".to_string()];
        let first = parse_plain_http_host("/x", &headers);
        let second = parse_plain_http_host("/x", &headers);
        assert_eq!(first, "api.example.com");
        assert_eq!(first, second);
        drop(second); // an owned String drops here; a leaked &'static str could not.
        assert_eq!(first, "api.example.com");
    }

    #[tokio::test]
    async fn connect_deny_reason_blocks_metadata_ip_literal() {
        // SSRF: the cloud metadata endpoint as an IP literal must be denied
        // even with an empty allowlist (which is otherwise allow-all).
        let server = server_with(vec![], vec![]).await;
        assert_eq!(
            server.connect_deny_reason("169.254.169.254"),
            Some("ssrf: blocked address range")
        );
    }

    #[tokio::test]
    async fn connect_deny_reason_blocks_loopback_and_rfc1918_literals() {
        let server = server_with(vec![], vec![]).await;
        assert!(server.connect_deny_reason("127.0.0.1").is_some());
        assert!(server.connect_deny_reason("10.0.0.5").is_some());
        assert!(server.connect_deny_reason("192.168.1.1").is_some());
    }

    #[tokio::test]
    async fn connect_deny_reason_ssrf_check_precedes_allowlist() {
        // Even if an operator allowlists the literal, the SSRF guard wins —
        // a hostname allowlist must never be a way to reach internal space.
        let server = server_with(vec![], vec!["169.254.169.254".to_string()]).await;
        assert_eq!(
            server.connect_deny_reason("169.254.169.254"),
            Some("ssrf: blocked address range")
        );
    }

    #[tokio::test]
    async fn connect_deny_reason_allows_public_host() {
        let server = server_with(vec![], vec![]).await;
        assert_eq!(server.connect_deny_reason("api.openai.com"), None);
        assert_eq!(server.connect_deny_reason("1.1.1.1"), None);
    }

    #[test]
    fn canonical_host_strips_port_trailing_dot_and_case() {
        // AAASM-3983: port, single trailing dot, and case are all normalised.
        assert_eq!(canonical_host("EVIL.COM"), "evil.com");
        assert_eq!(canonical_host("evil.com."), "evil.com");
        assert_eq!(canonical_host("Evil.Com.:443"), "evil.com");
        assert_eq!(canonical_host("evil.com"), "evil.com");
    }

    #[tokio::test]
    async fn connect_deny_reason_denylist_defeats_case_and_trailing_dot_evasion() {
        // AAASM-3983: a lowercase `evil.com` denylist entry must catch the
        // uppercase and trailing-dot variants, which previously slipped past
        // the byte-exact comparison.
        let server = server_with(vec!["evil.com".to_string()], vec![]).await;
        assert_eq!(server.connect_deny_reason("evil.com"), Some("host policy"));
        assert_eq!(server.connect_deny_reason("EVIL.COM"), Some("host policy"));
        assert_eq!(server.connect_deny_reason("evil.com."), Some("host policy"));
        assert_eq!(server.connect_deny_reason("Evil.Com.:443"), Some("host policy"));
    }

    #[tokio::test]
    async fn connect_deny_reason_allowlist_rejects_trailing_dot_non_member() {
        // With api.openai.com allowlisted, a trailing-dot form of a *different*
        // host must still be rejected (it is not a member), and the trailing-dot
        // form of the allowlisted host must be permitted.
        let server = server_with(vec![], vec!["api.openai.com".to_string()]).await;
        assert_eq!(server.connect_deny_reason("evil.com."), Some("network allowlist"));
        assert_eq!(server.connect_deny_reason("api.openai.com."), None);
        assert_eq!(server.connect_deny_reason("API.OPENAI.COM"), None);
    }

    fn req_with(headers: Vec<(&str, &str)>, target: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            target: target.into(),
            version: "HTTP/1.1".into(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn effective_request_host_prefers_absolute_target_then_host_header() {
        // Absolute-form target wins over the Host header.
        let req = req_with(vec![("Host", "api.openai.com")], "https://evil.attacker.com/v1/x");
        assert_eq!(ProxyServer::effective_request_host(&req), Some("evil.attacker.com"));
        // Origin-form target falls back to the Host header, port stripped.
        let req = req_with(vec![("Host", "api.openai.com:443")], "/v1/chat/completions");
        assert_eq!(ProxyServer::effective_request_host(&req), Some("api.openai.com"));
        // Neither yields a host.
        let req = req_with(vec![], "/v1/x");
        assert_eq!(ProxyServer::effective_request_host(&req), None);
    }

    #[tokio::test]
    async fn in_tunnel_deny_reason_blocks_forged_host_under_allowlist() {
        // AAASM-3580: with api.openai.com allowlisted, an in-tunnel forged
        // `Host: evil.attacker.com` must be denied by the re-enforced allowlist.
        let server = server_with(vec![], vec!["api.openai.com".to_string()]).await;
        let forged = req_with(vec![("Host", "evil.attacker.com")], "/v1/chat/completions");
        assert_eq!(server.in_tunnel_deny_reason(&forged), Some("network allowlist"));
        // The allowlisted host inside the tunnel is permitted.
        let ok = req_with(vec![("Host", "api.openai.com")], "/v1/chat/completions");
        assert_eq!(server.in_tunnel_deny_reason(&ok), None);
    }

    #[tokio::test]
    async fn in_tunnel_deny_reason_empty_allowlist_is_default_open() {
        // Backward compatibility: no allowlist configured → no in-tunnel denial.
        let server = server_with(vec![], vec![]).await;
        let req = req_with(vec![("Host", "anything.example.com")], "/v1/x");
        assert_eq!(server.in_tunnel_deny_reason(&req), None);
    }

    #[tokio::test]
    async fn plain_http_forward_blocks_ssrf_resolved_ip() {
        // AAASM-3140 / AAASM-3864 regression: a plain-HTTP (non-CONNECT) request
        // targeting an internal-address literal must be refused. With the egress
        // denylist now enforced on the plain-HTTP path the loopback literal is
        // caught by the SSRF guard inside `connect_deny_reason`, returning an
        // explicit 403 (fail-closed) before any upstream dial.
        use tokio::io::AsyncReadExt;
        let server = server_with(vec![], vec![]).await;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        // Plain HTTP request targeting a loopback literal — a blocked range.
        client
            .write_all(b"GET http://127.0.0.1/secret HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();

        server
            .handle_connection(server_stream)
            .await
            .expect("denied request returns Ok after writing 403");

        let mut buf = String::new();
        client.read_to_string(&mut buf).await.unwrap();
        assert!(
            buf.contains("403"),
            "plain-HTTP request to a blocked IP must be refused with 403, got: {buf:?}"
        );
    }

    #[tokio::test]
    async fn plain_http_to_llm_host_is_refused() {
        // AAASM-3984: a cleartext `http://` request to a known LLM provider must
        // be refused (403) before any upstream dial. The plain-HTTP path does no
        // credential scanning, so allowing a downgrade to reach an LLM host would
        // let a steered agent exfiltrate the secret in this body with zero DLP.
        // The empty allowlist permits the public host past the egress gate, so
        // the 403 here proves the LLM-downgrade refusal (not the egress check).
        use tokio::io::AsyncReadExt;
        let server = server_with(vec![], vec![]).await;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        let body = "{\"api_key\":\"sk-secretvalue1234567890\"}";
        let req = format!(
            "POST http://api.openai.com/v1/chat HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body,
        );
        client.write_all(req.as_bytes()).await.unwrap();

        server
            .handle_connection(server_stream)
            .await
            .expect("refused request returns Ok after writing 403");

        let mut buf = String::new();
        client.read_to_string(&mut buf).await.unwrap();
        assert!(
            buf.contains("403"),
            "cleartext plain-HTTP request to an LLM host must be refused with 403, got: {buf:?}"
        );
    }

    #[tokio::test]
    async fn plain_http_to_llm_host_trailing_dot_is_refused() {
        // AAASM-3983 + AAASM-3984: the trailing-dot / mixed-case downgrade
        // variant must also be refused — detect_api canonicalizes the host.
        use tokio::io::AsyncReadExt;
        let server = server_with(vec![], vec![]).await;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        client
            .write_all(b"POST http://API.OpenAI.CoM./v1/chat HTTP/1.1\r\nHost: API.OpenAI.CoM.\r\n\r\n")
            .await
            .unwrap();

        server
            .handle_connection(server_stream)
            .await
            .expect("refused request returns Ok after writing 403");

        let mut buf = String::new();
        client.read_to_string(&mut buf).await.unwrap();
        assert!(
            buf.contains("403"),
            "trailing-dot cleartext request to an LLM host must be refused with 403, got: {buf:?}"
        );
    }
}
