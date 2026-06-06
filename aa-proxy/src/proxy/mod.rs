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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, OnceCell};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use aa_runtime::gateway_client::GatewayClient;
use aa_runtime::pipeline::PipelineEvent;

use crate::audit_jsonl::{ProxyAuditDecision, ProxyAuditEntry};
use crate::config::ProxyConfig;
use crate::error::ProxyError;
use crate::intercept::detect::{detect_api, LlmApiPattern};
use crate::intercept::event::ProxyEvent;
use crate::intercept::mcp::parse_mcp_request;
use crate::intercept::{InterceptVerdict, Interceptor, VerdictDecision};
use crate::mcp_enforce::{evaluate_mcp_call, McpDecision};
use crate::proxy::http::{
    read_http_request, read_http_response, serialize_http_request, serialize_http_response, HttpRequest,
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

/// The running proxy server.
///
/// Create via [`ProxyServer::new`], then drive the accept loop with
/// [`ProxyServer::run`]. Internally wrapped in [`Arc`] so connection
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
        })
    }

    /// Bind the TCP listener and enter the accept loop.
    ///
    /// This future runs until the process is killed or an unrecoverable error
    /// occurs. It is called from [`crate::run`].
    pub async fn run(self: &Arc<Self>) -> Result<(), ProxyError> {
        // Best-effort connect to the gateway when an endpoint is configured.
        // A connection failure here is logged but does not fail startup —
        // MCP enforcement simply stays disabled and the proxy continues to
        // serve the credential-scanner path. This matches `aa-runtime`'s
        // policy that a missing gateway is a soft degradation, not a fatal
        // error.
        if let Some(endpoint) = &self.config.gateway_endpoint {
            match GatewayClient::connect(endpoint).await {
                Ok(client) => {
                    let _ = self.gateway_client.set(Arc::new(Mutex::new(client)));
                    tracing::info!(%endpoint, "connected to aa-gateway PolicyService for MCP enforcement");
                }
                Err(e) => {
                    tracing::warn!(
                        %endpoint,
                        error = %e,
                        "failed to connect to aa-gateway; MCP enforcement disabled",
                    );
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
            Some(addr) => TcpStream::connect(addr).await?,
            None => TcpStream::connect(target).await?,
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

        // MCP detection. On a successful request-side eval, carry the parsed
        // call AND its serialised args bytes forward so the response-side
        // path below can re-use both for audit emission (args go into
        // `ToolCallDetail.args_json`).
        let mcp_call: Option<(crate::intercept::mcp::McpToolCall, Vec<u8>)> =
            if let Some(call) = parse_mcp_request(&req.body) {
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
                    Err(e) => {
                        tracing::warn!(
                            tool_name = %call.tool_name,
                            %host,
                            error = %e,
                            "gateway CheckAction failed, forwarding without enforcement",
                        );
                        None
                    }
                }
            } else {
                None
            };

        // Forward the (consumed) request body to upstream.
        let upstream_tls = self.dial_upstream_tls(host, target).await?;
        let outgoing = serialize_http_request(&req, &req.body);
        let (mut client_read, mut client_write) = tokio::io::split(client_reader.into_inner());
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
                    client_write.write_all(&modified).await?;
                }
                Ok(None) => {
                    // Upstream closed without writing a response — nothing to forward.
                }
                Err(e) => {
                    // Could not parse the response (e.g. chunked, malformed) —
                    // fall back to transparent copy from where we left off.
                    tracing::warn!(
                        tool_name = %call.tool_name,
                        error = %e,
                        "MCP response parse failed, falling back to transparent copy",
                    );
                    let mut upstream_read = upstream_reader.into_inner();
                    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
                    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);
                    tokio::select! {
                        r = client_to_upstream => { r?; }
                        r = upstream_to_client => { r?; }
                    }
                }
            }
        } else {
            // Not MCP (or RPC failed) — transparent bidirectional copy for
            // any remaining stream activity (mirrors the historical behaviour).
            let mut upstream_read = upstream_read;
            let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
            let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);
            tokio::select! {
                r = client_to_upstream => { r?; }
                r = upstream_to_client => { r?; }
            }
        }
        Ok(())
    }

    /// Handle a single accepted TCP connection.
    ///
    /// Reads the first HTTP request line to determine whether this is a
    /// `CONNECT` tunnel (HTTPS) or a plain HTTP request.
    async fn handle_connection(self: &Arc<Self>, stream: TcpStream) -> Result<(), ProxyError> {
        let mut reader = BufReader::new(stream);

        // Read the first request line, e.g. "CONNECT api.openai.com:443 HTTP/1.1\r\n"
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;
        let request_line = request_line.trim_end();

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(ProxyError::Config("malformed HTTP request line".into()));
        }

        let method = parts[0];
        let target = parts[1];

        if method.eq_ignore_ascii_case("CONNECT") {
            // Consume remaining headers (we only need the request line for CONNECT).
            let mut header_line = String::new();
            loop {
                header_line.clear();
                reader.read_line(&mut header_line).await?;
                if header_line.trim().is_empty() {
                    break;
                }
            }

            // Extract hostname (strip port) for deny check and certificate generation.
            let host = target.split(':').next().unwrap_or(target);

            // Deny check: if the host is on the deny list, return 403 immediately.
            if self.config.denied_hosts.iter().any(|denied| denied == host) {
                tracing::info!(%host, "CONNECT denied by host policy");
                let inner = reader.into_inner();
                let mut stream = inner;
                stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                self.interceptor.emit_policy_decision(host, true).await;
                return Ok(());
            }

            // AAASM-1943: network egress allowlist enforcement. When the
            // configured allowlist is non-empty, only hosts matching at
            // least one pattern (exact / *.suffix / *) may CONNECT. Empty
            // allowlist preserves the pre-AAASM-1943 default-open behaviour.
            if !aa_core::policy::is_host_allowed_by_egress_allowlist(host, &self.config.network_allowlist) {
                tracing::info!(
                    %host,
                    patterns = self.config.network_allowlist.len(),
                    "CONNECT denied by network allowlist"
                );
                let inner = reader.into_inner();
                let mut stream = inner;
                stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                self.interceptor.emit_policy_decision(host, true).await;
                return Ok(());
            }

            // Send 200 Connection Established to tell the client the tunnel is open.
            let inner = reader.into_inner();
            let mut stream = inner;
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

            tracing::debug!(host = target, "CONNECT tunnel established");

            // Emit allow audit event for the accepted connection.
            self.interceptor.emit_policy_decision(host, false).await;

            // When llm_only is enabled, skip TLS MitM for non-LLM hosts and
            // just tunnel the raw TCP bytes transparently.
            if self.config.llm_only && detect_api(host) == LlmApiPattern::Unknown {
                tracing::debug!(%host, "llm_only mode — transparent tunnel (no MitM)");
                let upstream = TcpStream::connect(target).await?;
                let (mut cr, mut cw) = tokio::io::split(stream);
                let (mut ur, mut uw) = tokio::io::split(upstream);
                tokio::select! {
                    r = tokio::io::copy(&mut cr, &mut uw) => { r?; }
                    r = tokio::io::copy(&mut ur, &mut cw) => { r?; }
                }
                return Ok(());
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
            // patterns we fall through to a raw bidirectional copy below.
            if pattern != LlmApiPattern::Unknown {
                let mut client_reader = BufReader::new(client_tls);
                let Some(req) = read_http_request(&mut client_reader).await? else {
                    // Client closed without sending a request line — nothing
                    // to do, just return cleanly.
                    return Ok(());
                };

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

                let outgoing_bytes = match verdict.decision {
                    VerdictDecision::ForwardRedacted => {
                        let body = verdict
                            .redacted_body
                            .as_deref()
                            .expect("ForwardRedacted always carries redacted_body");
                        let bytes = serialize_http_request(&req, body);
                        self.emit_audit_entry(host, &req, &verdict, ProxyAuditDecision::ForwardedRedacted)
                            .await;
                        bytes
                    }
                    VerdictDecision::AlertAndForward => {
                        let bytes = serialize_http_request(&req, &req.body);
                        // Emit an audit entry so operators can see the alert-mode
                        // decision (findings are still recorded, body is not).
                        self.emit_audit_entry(host, &req, &verdict, ProxyAuditDecision::Forwarded)
                            .await;
                        bytes
                    }
                    _ => serialize_http_request(&req, &req.body),
                };

                let (mut client_read, mut client_write) = tokio::io::split(client_reader.into_inner());
                let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream_tls);

                upstream_write.write_all(&outgoing_bytes).await?;

                let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
                let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

                tokio::select! {
                    r = client_to_upstream => { r?; }
                    r = upstream_to_client => { r?; }
                }
                return Ok(());
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
        } else {
            // Plain HTTP request forwarding.
            tracing::debug!(method = method, target = target, "plain HTTP request");

            // Consume remaining request headers.
            let mut headers = Vec::new();
            let mut header_line = String::new();
            loop {
                header_line.clear();
                reader.read_line(&mut header_line).await?;
                if header_line.trim().is_empty() {
                    break;
                }
                headers.push(header_line.clone());
            }

            // Parse host from the target URL or Host header.
            let host = if let Some(url_host) = target.strip_prefix("http://") {
                url_host.split('/').next().unwrap_or(url_host)
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
                    .leak()
            };

            // Connect to upstream via plain TCP.
            let upstream_addr = if host.contains(':') {
                host.to_string()
            } else {
                format!("{host}:80")
            };
            let mut upstream = TcpStream::connect(&upstream_addr).await?;

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
}
