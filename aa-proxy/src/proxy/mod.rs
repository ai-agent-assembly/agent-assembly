//! TCP accept loop and CONNECT tunnel handling.
//!
//! `ProxyServer` owns the bound TCP listener, the TLS context (CA + cert cache),
//! and the interceptor. It is the top-level runtime object of the proxy.

pub mod http;

use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, OnceCell};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use aa_runtime::gateway_client::GatewayClient;
use aa_runtime::pipeline::PipelineEvent;

use crate::audit_jsonl::{bound_persisted_body, ProxyAuditDecision, ProxyAuditEntry};
use crate::config::ProxyConfig;
use crate::credentials::CredentialStore;
use crate::error::ProxyError;
use crate::intercept::detect::{detect_api, LlmApiPattern};
use crate::intercept::event::ProxyEvent;
use crate::intercept::mcp::{is_unenforceable_tool_call, parse_mcp_request};
use crate::intercept::{InterceptVerdict, Interceptor, ResponseScan, VerdictDecision};
use crate::mcp_enforce::{evaluate_mcp_call, McpDecision};
use crate::probe_adjudication::{ProbeAdjudication, ProbeCorrelation, PROBE_CORRELATION_HEADER};
use crate::proxy::http::{
    read_http_request, read_http_response, read_line_capped, serialize_http_request, serialize_http_request_with_auth,
    serialize_http_response, HttpRequest, MAX_BODY_LEN, MAX_HEADER_BYTES, MAX_HEADER_COUNT, MAX_HEADER_LINE_LEN,
};
use crate::tls::{CaStore, CertCache};
use crate::transmission_evidence::{self, DecisionRecord, ForwardAuthorized, ForwardObservation};

use aa_core::types::sensitive_data::{ExecutionEvidence, TransmissionEvidence};

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

/// Which request a decision record is about.
///
/// Bundled rather than passed as three loose `&str`s: the recorders take the
/// identity, the verdict, the outcome and the evidence, and threading the
/// probe correlation through pushed every one of them past clippy's argument
/// limit. It also stops `host`/`method`/`target` being transposed at a call
/// site, which no test would have caught.
#[derive(Clone, Copy)]
struct RequestIdentity<'a> {
    /// Target host, no port.
    host: &'a str,
    /// HTTP method of the intercepted request.
    method: &'a str,
    /// Raw request target; redacted before it reaches the record.
    target: &'a str,
}

/// The observation shared by every rule that refuses a request before a
/// credential verdict exists (AAASM-5358).
///
/// These are the *most* provable preventions the proxy makes — the denylist,
/// the network allowlist, in-tunnel host forgery, a plaintext downgrade to an
/// LLM host, a gateway `tools/call` deny — because the 403 or JSON-RPC error is
/// written in place of a dial that has no code path after it.
///
/// It is **logged and not persisted**. These branches refuse before
/// `intercept_request` runs, so there is no sensitive-data decision event to
/// attach evidence to, and synthesising one would invent events the audit trail
/// has never counted. The consequence is real and should be stated rather than
/// glossed: until a producer exists for them, the §8 prevention metric cannot
/// see the proxy's strongest refusals. Persisting them is follow-up work, not
/// something this constant achieves.
const NOT_FORWARDED_BY_RULE: ExecutionEvidence = transmission_evidence::not_forwarded_by_rule();

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

/// Build an HTTP 200 response carrying a JSON-RPC error envelope.
fn http_jsonrpc_error_response(code: i32, reason: &str) -> String {
    let body = build_jsonrpc_error_response(code, reason);
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    )
}

/// Outcome of MCP request-side evaluation for the non-LLM MitM path.
enum McpEvalOutcome {
    /// Forward allowed — carry the call and serialised args for response-side scanning.
    Forward(crate::intercept::mcp::McpToolCall, Vec<u8>),
    /// Denied — connection should be closed after writing the given response.
    Deny(String),
    /// No MCP call detected, or gateway unavailable with fail-open — proceed without MCP handling.
    Skip,
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
    ///
    /// This is the **refusal** path's recorder: it takes evidence as a
    /// parameter and produces no dial key, because a branch that returns to the
    /// client has no wire to reach. Forwarding branches must go through
    /// [`ForwardObservation::persist`], which supplies its own evidence and is
    /// the only source of a [`ForwardAuthorized`] (AAASM-5358).
    async fn emit_audit_entry(
        self: &Arc<Self>,
        id: RequestIdentity<'_>,
        verdict: &InterceptVerdict,
        decision: ProxyAuditDecision,
        execution: ExecutionEvidence,
        probe_correlation: Option<String>,
    ) {
        self.decision_record(id, verdict, decision, execution, probe_correlation)
            .send(self.audit_jsonl_tx.as_ref(), execution);
    }

    /// Assemble the identifying half of a decision record.
    ///
    /// `execution` is consulted, not stored: a body the proxy has just reported
    /// as *still carrying a sensitive value* is not persisted. The "no raw
    /// value on disk" guarantee would otherwise be exactly as strong as the
    /// scrubber, in the one branch where the proxy itself says the scrubber did
    /// not hold.
    fn decision_record(
        &self,
        id: RequestIdentity<'_>,
        verdict: &InterceptVerdict,
        decision: ProxyAuditDecision,
        execution: ExecutionEvidence,
        probe_correlation: Option<String>,
    ) -> DecisionRecord {
        let redacted_body = if execution.transmission == TransmissionEvidence::ForwardedCarryingSensitiveValue {
            None
        } else {
            verdict
                .redacted_body
                .as_ref()
                .and_then(|b| std::str::from_utf8(b).ok().map(|s| bound_persisted_body(s.to_owned())))
        };
        DecisionRecord {
            host: id.host.to_owned(),
            method: id.method.to_owned(),
            // The target can carry a secret in its query string (`?key=…`,
            // `?token=…`, a presigned `?X-Amz-Signature=…`), so it is redacted
            // through the same scanner as the body before being persisted — the
            // body-only redaction left target secrets in cleartext (AAASM-4738).
            path: self.interceptor.redact_target(id.target),
            decision,
            findings: verdict.findings.clone(),
            redacted_body,
            probe_correlation,
        }
    }

    /// Persist a forwarding decision and take the key to the wire.
    ///
    /// The single choke point between "we resolved to forward" and any dial.
    /// The evidence written is the observation's own — this function never sees
    /// an `ExecutionEvidence` parameter, so it cannot record one observation
    /// and authorize another.
    ///
    /// `decision` is `None` for a branch with no decision event to write: a
    /// clean body decided nothing, and minting an event for it would change
    /// what the audit trail counts.
    async fn record_forwarding(
        self: &Arc<Self>,
        observation: ForwardObservation,
        id: RequestIdentity<'_>,
        verdict: &InterceptVerdict,
        decision: Option<ProxyAuditDecision>,
        probe_correlation: Option<String>,
    ) -> ForwardAuthorized {
        let record = decision
            .map(|decision| self.decision_record(id, verdict, decision, observation.evidence(), probe_correlation));
        observation.persist(self.audit_jsonl_tx.as_ref(), record)
    }

    /// The probe correlation id on an in-tunnel request, when it carries a
    /// well-formed one.
    ///
    /// Only `handle_llm_mitm` *adjudicates* a probe, but every handler can
    /// *receive* one, and the record has to say so wherever it lands: under
    /// `credential_action=block` a probe's request is refused before any dial
    /// on the non-LLM MitM and plain-HTTP paths too, producing a record that
    /// satisfies every ADR 0032 §8 condition. Unmarked, each of those is a
    /// synthetic prevention indistinguishable from a real one (AAASM-5358).
    fn probe_correlation(req: &HttpRequest) -> Option<String> {
        req.header(PROBE_CORRELATION_HEADER)
            .and_then(ProbeCorrelation::parse)
            .map(|c| c.as_str().to_owned())
    }

    /// The plain-HTTP form of [`Self::probe_correlation`], reading the raw
    /// header lines that path buffers instead of an [`HttpRequest`].
    fn probe_correlation_plain(headers: &[String]) -> Option<String> {
        plain_http_header_value(headers, PROBE_CORRELATION_HEADER)
            .as_deref()
            .and_then(ProbeCorrelation::parse)
            .map(|c| c.as_str().to_owned())
    }

    /// Which decision event, if any, a forwarding verdict writes.
    ///
    /// `ForwardRedacted` and `AlertAndForward` both found something and both
    /// forwarded; a clean `Forward` decided nothing. Shared by all three
    /// forwarding paths so plain-HTTP cannot drift from the MitM handlers
    /// again — it previously omitted `alert_only` entirely, silently emptying
    /// the detected-but-forwarded numerator for cleartext traffic.
    fn forwarding_audit_decision(decision: VerdictDecision) -> Option<ProxyAuditDecision> {
        match decision {
            VerdictDecision::ForwardRedacted => Some(ProxyAuditDecision::ForwardedRedacted),
            VerdictDecision::AlertAndForward => Some(ProxyAuditDecision::Forwarded),
            VerdictDecision::Forward | VerdictDecision::Block => None,
        }
    }

    /// State what will be on the wire for a verdict that resolved to forward
    /// (AAASM-5358).
    ///
    /// The re-inspection question is "what do the bytes that are about to go
    /// carry", which is not answerable from the verdict alone:
    ///
    /// * a redaction produces a **different** payload from the one the scan
    ///   ran on, so it is re-scanned — a redaction that failed to scrub must
    ///   read as still carrying a value, never as protection;
    /// * `alert_only` forwards the original body, which the scan already found
    ///   a value in, so no second pass is needed to know what it carries;
    /// * a clean verdict and a disabled scanner are indistinguishable from the
    ///   verdict alone (both are `Forward` with no findings), and only the
    ///   first may be reported as clean — hence
    ///   [`Interceptor::inspects`](crate::intercept::Interceptor::inspects)
    ///   rather than a second full scan on the hot path.
    fn observe_forwarding(&self, verdict: &InterceptVerdict) -> ForwardObservation {
        let reinspection = match verdict.decision {
            VerdictDecision::ForwardRedacted => verdict
                .redacted_body
                .as_deref()
                .and_then(|bytes| self.interceptor.forwarded_payload_is_clean(bytes)),
            VerdictDecision::AlertAndForward => Some(false),
            VerdictDecision::Forward => self.interceptor.inspects().then_some(true),
            // Unreachable from a forwarding branch. If a future refactor routes
            // a refusal through here, "cannot say" is the answer that cannot
            // become a false protection claim.
            VerdictDecision::Block => None,
        };
        transmission_evidence::forwarded(verdict.decision, self.config.credential_action, reinspection)
    }

    /// Evidence for a request the protection-probe protocol answered here
    /// instead of relaying (AAASM-5358).
    ///
    /// A probe request is withheld by *that protocol*, not by the policy, so
    /// only a genuine `Block` may be recorded as non-transmission. Recording
    /// the other branches that way would be true about the bytes and a lie
    /// about the cause: under `redact_only` the verdict is transforming, so all
    /// four conditions of ADR 0032 §8 would hold and every probe run would
    /// manufacture a "prevented transmission" for traffic the policy would in
    /// fact have forwarded in redacted form — inflating the exact metric the
    /// probe exists to measure.
    fn probe_execution_evidence(&self, verdict: &InterceptVerdict) -> ExecutionEvidence {
        match verdict.decision {
            VerdictDecision::Block => {
                transmission_evidence::not_forwarded(verdict.decision, self.config.credential_action)
            }
            _ => transmission_evidence::terminated_by_probe_protocol(verdict.decision, self.config.credential_action),
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
    ///
    /// Takes a [`ForwardAuthorized`] because this is the *shared* bottom of
    /// every route to the wire — the TLS dial, the plain-HTTP dial, and the
    /// transparent tunnel all end here. Gating only the first two left the
    /// tunnel (which under the default `llm_only: true` carries all non-LLM
    /// traffic) reachable without an observation (AAASM-5358).
    async fn connect_revalidated(&self, target: &str, _authorized: ForwardAuthorized) -> Result<TcpStream, ProxyError> {
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
    ///
    /// `authorized` is the AAASM-5358 invariant rather than an input: it is
    /// passed straight down to [`Self::connect_revalidated`], which is the
    /// shared bottom of every route to the wire. A [`ForwardAuthorized`] can
    /// only come from [`ForwardObservation::persist`], so reaching this
    /// function at all means the observation it was minted with has already
    /// been recorded.
    async fn dial_upstream_tls(
        self: &Arc<Self>,
        host: &str,
        target: &str,
        authorized: ForwardAuthorized,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ProxyError> {
        let upstream_tcp = match self.config.upstream_override {
            // Integration-test path: the dial is redirected to a trusted local
            // mock, so the SSRF re-validation below would (correctly) reject it.
            // Skip it here; the override is never set in production.
            Some(addr) => TcpStream::connect(addr).await?,
            None => self.connect_revalidated(target, authorized).await?,
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

    /// Dial the plain-HTTP upstream, honouring
    /// [`ProxyConfig::upstream_override`] and otherwise re-validating the
    /// resolved addresses against the SSRF denylist.
    ///
    /// Takes a [`ForwardAuthorized`] for the same reason
    /// [`Self::dial_upstream_tls`] does: this is the plain-HTTP path's route to
    /// the wire, and it must be unreachable from a branch that recorded the
    /// payload as withheld.
    async fn dial_upstream_plain(
        &self,
        upstream_addr: &str,
        authorized: ForwardAuthorized,
    ) -> Result<TcpStream, ProxyError> {
        match self.config.upstream_override {
            Some(addr) => Ok(TcpStream::connect(addr).await?),
            None => self.connect_revalidated(upstream_addr, authorized).await,
        }
    }

    /// Evaluate an MCP call against the gateway and return the routing outcome.
    ///
    /// Extracted from `handle_non_llm_mitm` to reduce cognitive complexity.
    async fn evaluate_mcp_request(
        &self,
        gateway: &Arc<Mutex<GatewayClient>>,
        req: &HttpRequest,
        host: &str,
    ) -> McpEvalOutcome {
        let Some(call) = parse_mcp_request(&req.body) else {
            // Not a parseable MCP call — check for bypass attempt.
            if is_unenforceable_tool_call(&req.body) {
                let reason = "MCP tools/call in unsupported JSON-RPC framing (batch array or malformed envelope) cannot be enforced and was rejected (fail-closed)";
                tracing::warn!(
                    %host,
                    "MCP tools/call bypass attempt via batch/malformed framing; denying (fail-closed). \
                     The gateway CheckAction and credential scan cannot evaluate this envelope.",
                );
                self.interceptor.emit_mcp_decision("unknown", &[], true, reason).await;
                return McpEvalOutcome::Deny(http_jsonrpc_error_response(-32600, reason));
            }
            return McpEvalOutcome::Skip;
        };

        let target_url = format!("https://{host}{path}", path = req.target);
        let args_bytes = serde_json::to_vec(&call.arguments).unwrap_or_default();

        match evaluate_mcp_call(gateway, &call, &target_url, "", "").await {
            // `Redact` is bucketed with `Allow` as a forward: the proxy's own
            // DLP scanner redacts both request and upstream response (see the
            // `McpDecision::Redact` doc), so the gateway's `RedactInstructions`
            // need no separate replay here.
            Ok(McpDecision::Allow) | Ok(McpDecision::Redact { .. }) => {
                tracing::info!(
                    tool_name = %call.tool_name,
                    %host,
                    "MCP call allowed by gateway, forwarding to upstream with response-side scanning",
                );
                self.interceptor
                    .emit_mcp_decision(&call.tool_name, &args_bytes, false, "")
                    .await;
                McpEvalOutcome::Forward(call, args_bytes)
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
                McpEvalOutcome::Deny(http_jsonrpc_error_response(-32000, &reason))
            }
            Err(e) if self.config.mcp_fail_open => {
                tracing::warn!(
                    tool_name = %call.tool_name,
                    %host,
                    error = %e,
                    "gateway CheckAction failed; forwarding without enforcement (AA_PROXY_MCP_FAIL_OPEN is set, failing OPEN)",
                );
                McpEvalOutcome::Skip
            }
            Err(e) => {
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
                McpEvalOutcome::Deny(http_jsonrpc_error_response(-32000, reason))
            }
        }
    }

    /// Handle MCP response scanning and relay to the client.
    ///
    /// Extracted from `handle_non_llm_mitm` to reduce cognitive complexity.
    async fn relay_mcp_response(
        &self,
        upstream_read: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>,
        client_tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
        call: &crate::intercept::mcp::McpToolCall,
        args_bytes: &[u8],
    ) -> Result<(), ProxyError> {
        let mut upstream_reader = BufReader::new(upstream_read);
        match read_http_response(&mut upstream_reader).await {
            Ok(Some(resp)) => {
                let content_encoding = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
                    .map(|(_, v)| v.as_str());
                self.handle_mcp_response_body(&resp, content_encoding, client_tls, call, args_bytes)
                    .await
            }
            Ok(None) => Ok(()), // Upstream closed without writing a response.
            Err(e) => {
                tracing::warn!(
                    tool_name = %call.tool_name,
                    error = %e,
                    "MCP response parse failed; withholding unredacted upstream body (fail-closed)",
                );
                self.interceptor
                    .emit_mcp_decision(
                        &call.tool_name,
                        args_bytes,
                        true,
                        "response unparseable, withheld (fail-closed)",
                    )
                    .await;
                client_tls.write_all(&mcp_unparseable_response_bytes()).await?;
                Ok(())
            }
        }
    }

    /// Handle MCP response body scanning and forwarding.
    async fn handle_mcp_response_body(
        &self,
        resp: &http::HttpResponse,
        content_encoding: Option<&str>,
        client_tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
        call: &crate::intercept::mcp::McpToolCall,
        args_bytes: &[u8],
    ) -> Result<(), ProxyError> {
        match self.interceptor.redact_response_body(&resp.body, content_encoding) {
            ResponseScan::Withhold => {
                tracing::warn!(
                    tool_name = %call.tool_name,
                    "MCP response body not inspectable (content-encoding); withholding (fail-closed)",
                );
                self.interceptor
                    .emit_mcp_decision(
                        &call.tool_name,
                        args_bytes,
                        true,
                        "response encoding not inspectable, withheld (fail-closed)",
                    )
                    .await;
                client_tls.write_all(&mcp_unparseable_response_bytes()).await?;
            }
            ResponseScan::Redact(redacted) => {
                tracing::info!(
                    tool_name = %call.tool_name,
                    "MCP response carried sensitive payload, redacting before forwarding to client",
                );
                self.interceptor
                    .emit_mcp_decision(&call.tool_name, args_bytes, false, "response redacted")
                    .await;
                let modified = serialize_http_response(resp, &redacted);
                client_tls.write_all(&modified).await?;
            }
            ResponseScan::Forward => {
                let modified = serialize_http_response(resp, &resp.body);
                client_tls.write_all(&modified).await?;
            }
        }
        Ok(())
    }

    /// Non-LLM MitM data path: read the HTTP request inside the MitM TLS
    /// tunnel, run credential-DLP on the body, and — when a `gateway` is
    /// configured — also enforce MCP `tools/call` decisions on the wire.
    ///
    /// AAASM-4126: this path runs the credential scanner (`intercept_request`)
    /// on **every** MitM'd non-LLM body before forwarding, so a secret POSTed to
    /// a provider outside the built-in `detect_api` set (reached via
    /// `llm_only=false` or an operator `mitm_hosts` entry) is scanned exactly as
    /// an LLM-host body is. `gateway` is `Option` because DLP must run whether or
    /// not MCP enforcement is configured; the previous no-gateway path
    /// raw-copied the body upstream un-inspected.
    ///
    /// Branches:
    ///
    /// * **MCP detected, gateway returns `Allow` or `Redact`** — forward the
    ///   (DLP-scanned) body to upstream and relay the redacted response.
    /// * **MCP detected, gateway returns `Deny`** — write a JSON-RPC 2.0
    ///   error envelope to the client TLS stream, do not dial upstream.
    /// * **MCP detected, gateway RPC failed** — deny (fail-closed) unless
    ///   `mcp_fail_open` is set.
    /// * **Body is not MCP (or no gateway)** — DLP-scan, then forward the
    ///   (possibly redacted) body and relay the upstream response. A `Block`
    ///   verdict returns 403 without dialing upstream.
    async fn handle_non_llm_mitm(
        self: &Arc<Self>,
        client_tls: tokio_rustls::server::TlsStream<TcpStream>,
        gateway: Option<&Arc<Mutex<GatewayClient>>>,
        host: &str,
        target: &str,
    ) -> Result<(), ProxyError> {
        let mut client_reader = BufReader::new(client_tls);
        let Some(req) = read_http_request(&mut client_reader).await? else {
            return Ok(());
        };

        // AAASM-3580: re-enforce the egress allowlist against the in-tunnel
        // host before any gateway dispatch or upstream dial.
        if let Some(reason) = self.in_tunnel_deny_reason(&req) {
            let in_host = Self::effective_request_host(&req).unwrap_or(host);
            tracing::info!(
                connect_host = %host,
                in_tunnel_host = %in_host,
                transmission = NOT_FORWARDED_BY_RULE.transmission.as_str(),
                "in-tunnel egress denied: {reason}",
            );
            self.interceptor.emit_policy_decision(in_host, true).await;
            let mut client_tls = client_reader.into_inner();
            client_tls
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }

        // MCP detection — only when a gateway is configured.
        let mcp_call: Option<(crate::intercept::mcp::McpToolCall, Vec<u8>)> = match gateway {
            Some(gw) => match self.evaluate_mcp_request(gw, &req, host).await {
                McpEvalOutcome::Forward(call, args_bytes) => Some((call, args_bytes)),
                McpEvalOutcome::Deny(resp) => {
                    tracing::info!(
                        %host,
                        transmission = NOT_FORWARDED_BY_RULE.transmission.as_str(),
                        "MCP call refused; answering the client instead of dialling upstream",
                    );
                    let mut client_tls = client_reader.into_inner();
                    client_tls.write_all(resp.as_bytes()).await?;
                    let _ = client_tls.shutdown().await;
                    return Ok(());
                }
                McpEvalOutcome::Skip => None,
            },
            None => None,
        };

        // AAASM-4126: run credential-DLP on the request body for EVERY MitM'd
        // non-LLM host.
        let verdict = self.interceptor.intercept_request(
            &req.body,
            req.header("content-encoding"),
            self.config.credential_action,
        );
        if verdict.decision == VerdictDecision::Block {
            tracing::info!(
                %host,
                findings = verdict.findings.len(),
                "credential_action=Block on non-LLM MitM host: refusing forward, returning 403",
            );
            self.emit_audit_entry(
                RequestIdentity {
                    host,
                    method: &req.method,
                    target: &req.target,
                },
                &verdict,
                ProxyAuditDecision::Blocked,
                transmission_evidence::not_forwarded(verdict.decision, self.config.credential_action),
                Self::probe_correlation(&req),
            )
            .await;
            let mut client_tls = client_reader.into_inner();
            client_tls
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }

        // AAASM-5358: record the observation, and take the key the dial needs.
        // The evidence persisted here is the observation's own — there is no
        // route from this branch to the wire that does not go through it.
        let authorized = self
            .record_forwarding(
                self.observe_forwarding(&verdict),
                RequestIdentity {
                    host,
                    method: &req.method,
                    target: &req.target,
                },
                &verdict,
                Self::forwarding_audit_decision(verdict.decision),
                Self::probe_correlation(&req),
            )
            .await;
        let forward_body: &[u8] = match verdict.decision {
            VerdictDecision::ForwardRedacted => verdict
                .redacted_body
                .as_deref()
                .expect("ForwardRedacted always carries redacted_body"),
            _ => &req.body,
        };

        // Forward the (consumed, DLP-scanned) request body to upstream.
        let upstream_tls = self.dial_upstream_tls(host, target, authorized).await?;
        let outgoing = serialize_http_request(&req, forward_body);
        let mut client_tls = client_reader.into_inner();
        let (upstream_read, mut upstream_write) = tokio::io::split(upstream_tls);
        upstream_write.write_all(&outgoing).await?;

        if let Some((call, args_bytes)) = mcp_call {
            // MCP response path: read, scan, and relay the upstream response.
            self.relay_mcp_response(upstream_read, &mut client_tls, &call, &args_bytes)
                .await?;
        } else {
            // Not MCP — relay only the upstream response back to the client.
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
            // AAASM-4829: strip brackets/port first so a bracketed IPv6 literal
            // like `[::1]:443` still parses as `::1` — otherwise the SSRF guard
            // silently misses it (the bracketed form fails `parse::<IpAddr>()`).
            if let Some(true) = crate::ssrf::blocked_ip_literal(strip_host_port(host)) {
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
        // AAASM-4829: defense-in-depth against in-tunnel header host-splitting.
        // Check BOTH the absolute-form request target host AND the `Host` header
        // and deny if EITHER is disallowed — an agent must not pass the egress
        // check by pointing the target at an allowlisted host while smuggling a
        // disallowed host in the `Host` header (or vice versa). Previously only
        // the target-preferred "effective" host was checked, so a mismatched
        // pair let the un-checked half slip past the allowlist.
        [Self::target_request_host(req), Self::header_request_host(req)]
            .into_iter()
            .flatten()
            .find_map(|host| self.connect_deny_reason(host))
    }

    /// Extract the effective upstream host the in-tunnel request addresses.
    ///
    /// Prefers an absolute-form request target (`https://host/...`); otherwise
    /// falls back to the `Host` header. The port (if any) is stripped so the
    /// result is comparable against the allowlist/denylist host grammar.
    /// Returns `None` when neither yields a host. Used for logging; the egress
    /// decision in [`Self::in_tunnel_deny_reason`] checks *both* hosts, not just
    /// this preferred one.
    fn effective_request_host(req: &HttpRequest) -> Option<&str> {
        Self::target_request_host(req).or_else(|| Self::header_request_host(req))
    }

    /// Host named by an absolute-form request target (`https://host/...` or
    /// `http://host/...`), with brackets/port stripped, or `None` for an
    /// origin-form target (`/path`).
    fn target_request_host(req: &HttpRequest) -> Option<&str> {
        let rest = req
            .target
            .strip_prefix("https://")
            .or_else(|| req.target.strip_prefix("http://"))?;
        let host_port = rest.split('/').next().unwrap_or(rest);
        let host = strip_host_port(host_port);
        (!host.is_empty()).then_some(host)
    }

    /// Host named by the `Host` header, with brackets/port stripped, or `None`
    /// when the header is absent or empty.
    fn header_request_host(req: &HttpRequest) -> Option<&str> {
        let host = strip_host_port(req.header("host")?);
        (!host.is_empty()).then_some(host)
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
            tracing::info!(
                connect_host = %host,
                in_tunnel_host = %in_host,
                transmission = NOT_FORWARDED_BY_RULE.transmission.as_str(),
                "in-tunnel egress denied: {reason}",
            );
            self.interceptor.emit_policy_decision(in_host, true).await;
            let mut client_tls = client_reader.into_inner();
            client_tls
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }

        let verdict = self.interceptor.intercept_request(
            &req.body,
            req.header("content-encoding"),
            self.config.credential_action,
        );

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

        // AAASM-5300: a protection probe's own request is adjudicated exactly
        // like any other — the verdict above is the same call the real data path
        // makes, under the same configured `credential_action` — and is then
        // *answered* here instead of relayed. See `crate::probe_adjudication`
        // for why terminating it is the only safe direction: the body carries a
        // synthetic credential, and under a non-enforcing policy the ordinary
        // path would forward it to the real provider.
        //
        // Only this (LLM-pattern) handler speaks the protocol. A probe request
        // that lands anywhere else is *handled* like any other request — which
        // under `credential_action=block` means refused, not forwarded — so a
        // probe must establish that it is talking to an adjudicating proxy
        // before it sends anything sensitive. Those other handlers still mark
        // the record with the correlation id (AAASM-5358), because a refusal
        // there is a real refusal of synthetic traffic and a consumer has to be
        // able to exclude it.
        if let Some(correlation) = req.header(PROBE_CORRELATION_HEADER).and_then(ProbeCorrelation::parse) {
            let (audit_decision, forwarded_is_clean) = match verdict.decision {
                VerdictDecision::Block => (ProxyAuditDecision::Blocked, None),
                VerdictDecision::ForwardRedacted => {
                    let bytes = verdict.redacted_body.as_deref().unwrap_or(&req.body);
                    (
                        ProxyAuditDecision::ForwardedRedacted,
                        self.interceptor.forwarded_payload_is_clean(bytes),
                    )
                }
                _ => (
                    ProxyAuditDecision::Forwarded,
                    self.interceptor.forwarded_payload_is_clean(&req.body),
                ),
            };
            let adjudication = ProbeAdjudication::new(&correlation, &verdict, forwarded_is_clean);
            let execution = self.probe_execution_evidence(&verdict);
            tracing::info!(
                %host,
                correlation = %correlation.as_str(),
                decision = ?adjudication.decision,
                transmission = execution.transmission.as_str(),
                "adjudicated a protection probe request; answering it instead of forwarding upstream",
            );
            // AAASM-5358: mark the record as synthetic. Under `block` this
            // refusal is real and satisfies every §8 condition, so without the
            // marker each probe run would contribute a prevented transmission
            // indistinguishable from a real leak that was stopped.
            self.decision_record(
                RequestIdentity {
                    host,
                    method: &req.method,
                    target: &req.target,
                },
                &verdict,
                audit_decision,
                execution,
                Some(correlation.as_str().to_owned()),
            )
            .send(self.audit_jsonl_tx.as_ref(), execution);
            let mut client_tls = client_reader.into_inner();
            client_tls.write_all(&adjudication.http_response()).await?;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }

        if verdict.decision == VerdictDecision::Block {
            tracing::info!(
                %host,
                findings = verdict.findings.len(),
                "credential_action=Block: refusing forward, returning 403",
            );
            self.emit_audit_entry(
                RequestIdentity {
                    host,
                    method: &req.method,
                    target: &req.target,
                },
                &verdict,
                ProxyAuditDecision::Blocked,
                transmission_evidence::not_forwarded(verdict.decision, self.config.credential_action),
                Self::probe_correlation(&req),
            )
            .await;
            let mut client_tls = client_reader.into_inner();
            client_tls
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let _ = client_tls.shutdown().await;
            return Ok(());
        }

        // AAASM-5358: the audit entry for a forwarding branch used to be emitted
        // *after* the dial, so a request whose dial failed left no record at
        // all. It is now written here, before the dial, and writing it is what
        // produces the key `dial_upstream_tls` demands.
        let authorized = self
            .record_forwarding(
                self.observe_forwarding(&verdict),
                RequestIdentity {
                    host,
                    method: &req.method,
                    target: &req.target,
                },
                &verdict,
                Self::forwarding_audit_decision(verdict.decision),
                Self::probe_correlation(&req),
            )
            .await;

        // Dial upstream only after we have decided not to block.
        let upstream_tls = self.dial_upstream_tls(host, target, authorized).await?;

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
                serialize_http_request_with_auth(&req, body, injected_auth_ref)
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

        // When llm_only is enabled, skip TLS MitM for hosts we don't intercept
        // and just tunnel the raw TCP bytes transparently. AAASM-4126: the set
        // of intercepted hosts is no longer just the three built-in LLM
        // providers — an operator-configured `mitm_hosts` entry is MitM'd (and
        // therefore DLP-scanned) too, so a secret to another provider isn't
        // silently tunnelled past the scanner.
        if self.config.llm_only && !self.should_mitm(host) {
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

        // Non-LLM pattern (this host is MitM'd because llm_only is off, or it
        // was added to `mitm_hosts`). Route through the non-LLM handler, which
        // reads the inbound request, runs credential-DLP on the body
        // (AAASM-4126) and — when a gateway is configured — also enforces MCP
        // `tools/call` decisions on the wire. Passing the gateway as `Option`
        // means a body reaching upstream is always scanned, whether or not a
        // gateway is configured (the historical no-gateway path raw-copied the
        // body upstream un-inspected, which let a secret to any MitM'd non-LLM
        // host bypass DLP).
        self.handle_non_llm_mitm(client_tls, self.gateway_client.get(), host, target)
            .await?;

        Ok(())
    }

    /// Whether the proxy should TLS-MitM (and therefore body-scan) traffic to
    /// `host`. `true` for a built-in LLM provider (`detect_api`) or any host
    /// matching the operator-configured [`ProxyConfig::mitm_hosts`] set. Under
    /// `llm_only`, hosts for which this returns `false` are transparent-tunnelled
    /// without inspection; when `llm_only` is `false` every host is MitM'd and
    /// this gate is not consulted. `host` must already be canonicalised.
    fn should_mitm(&self, host: &str) -> bool {
        detect_api(host) != LlmApiPattern::Unknown
            // fail-closed variant: an empty `mitm_hosts` adds nothing (returns
            // false) rather than matching every host.
            || aa_core::policy::is_host_allowed_by_egress_allowlist_fail_closed(host, &self.config.mitm_hosts)
    }

    /// Raw bidirectional copy between an established client `stream` and the
    /// re-validated upstream for `target`. Used by the llm_only transparent-
    /// tunnel path, which forwards bytes without MitM. SSRF re-validation covers
    /// this path too — it is the most likely SSRF vector when the host resolves
    /// to an internal address.
    async fn transparent_tunnel(self: &Arc<Self>, stream: TcpStream, target: &str) -> Result<(), ProxyError> {
        // AAASM-5358: this path relays bytes it never inspected, so the honest
        // observation is "forwarded, and nothing looked at it" — never clean.
        // There is no decision event to write (no verdict was taken), but the
        // observation still has to exist, because it is what unlocks the dial.
        let authorized = transmission_evidence::forwarded(
            VerdictDecision::Forward,
            self.config.credential_action,
            // Not "the scanner is disabled" but "this route does not scan".
            None,
        )
        .persist(self.audit_jsonl_tx.as_ref(), None);
        let upstream = match self.config.upstream_override {
            Some(addr) => TcpStream::connect(addr).await?,
            None => self.connect_revalidated(target, authorized).await?,
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
        // AAASM-4863: a secret can ride in the plain-HTTP target's query string
        // (`?token=…`, a presigned `?X-Amz-Signature=…`) exactly as in the audit
        // path, so it is redacted through the same scanner (AAASM-4738) before
        // reaching this debug log — the raw target must never be logged in
        // cleartext.
        let redacted_target = self.interceptor.redact_target(target);
        tracing::debug!(method = method, target = %redacted_target, "plain HTTP request");

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
        let deny_host = strip_host_port(&host);
        if let Some(reason) = self.connect_deny_reason(deny_host) {
            tracing::info!(
                host = %deny_host,
                transmission = NOT_FORWARDED_BY_RULE.transmission.as_str(),
                "plain-HTTP egress denied: {reason}",
            );
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
                transmission = NOT_FORWARDED_BY_RULE.transmission.as_str(),
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

        // AAASM-4897: close the plain-HTTP DLP bypass. The HTTPS MitM path scans
        // every request body through `intercept_request` (credential/DLP), but
        // this plain-HTTP path historically raw-copied the body upstream
        // un-inspected — so a steered agent could exfiltrate a secret over
        // cleartext `http://` to any non-LLM host with zero inspection. Buffer
        // the body (bounded by MAX_BODY_LEN) and run the same scan before
        // forwarding, mirroring `handle_llm_mitm`.
        //
        // A `Transfer-Encoding: chunked` body is un-inspectable by this parser
        // (the same gap the MitM path fails closed on), so refuse it rather than
        // stream it past the scanner.
        if headers.iter().any(|h| {
            let l = h.to_ascii_lowercase();
            l.starts_with("transfer-encoding:") && l.contains("chunked")
        }) {
            return Err(ProxyError::Config(
                "plain-HTTP chunked request bodies are not inspectable; refusing (fail-closed)".into(),
            ));
        }

        let content_length = plain_http_content_length(&headers)?;
        // Only requests that carry a body are buffered+scanned; a bodyless
        // request (GET) has nothing to scan. Either way the forward path below
        // now forces `Connection: close` and relays only the upstream response,
        // so exactly one request/response crosses this connection (AAASM-4934).
        let mut verdict: Option<InterceptVerdict> = None;
        let scanned_body: Option<Vec<u8>> = if content_length > 0 {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).await?;

            let content_encoding = plain_http_header_value(&headers, "content-encoding");
            let scanned =
                self.interceptor
                    .intercept_request(&body, content_encoding.as_deref(), self.config.credential_action);
            if scanned.decision == VerdictDecision::Block {
                // AAASM-5358: this refusal is as pre-transmission as the MitM
                // path's — the 403 is written and no dial follows — but it
                // persisted nothing at all before now.
                let execution = transmission_evidence::not_forwarded(scanned.decision, self.config.credential_action);
                tracing::info!(
                    host = %deny_host,
                    findings = scanned.findings.len(),
                    transmission = execution.transmission.as_str(),
                    "plain-HTTP credential_action=Block: refusing forward, returning 403",
                );
                self.emit_audit_entry(
                    RequestIdentity {
                        host: deny_host,
                        method,
                        target,
                    },
                    &scanned,
                    ProxyAuditDecision::Blocked,
                    execution,
                    Self::probe_correlation_plain(&headers),
                )
                .await;
                self.interceptor.emit_policy_decision(deny_host, true).await;
                let mut stream = reader.into_inner();
                stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    .await?;
                let _ = stream.shutdown().await;
                return Ok(());
            }
            let forwarded = match scanned.decision {
                VerdictDecision::ForwardRedacted => {
                    let redacted = scanned
                        .redacted_body
                        .as_deref()
                        .expect("ForwardRedacted always carries redacted_body")
                        .to_vec();
                    // The redacted body length differs, so rewrite Content-Length
                    // to keep the framing the upstream sees accurate.
                    rewrite_plain_http_content_length(&mut headers, redacted.len());
                    Some(redacted)
                }
                _ => Some(body),
            };
            verdict = Some(scanned);
            forwarded
        } else {
            None
        };

        // AAASM-5358: state what is about to go, and let writing that record be
        // what unlocks the dial. A bodyless request had nothing to inspect,
        // which is reported as "forwarded, not inspected" — never as clean.
        //
        // The audit decision comes from the same helper the MitM handlers use.
        // This path previously wrote a record only for `ForwardRedacted`, so an
        // `alert_only` deployment detected a credential in cleartext traffic,
        // forwarded it, and persisted nothing at all.
        let authorized = match verdict.as_ref() {
            Some(verdict) => {
                self.record_forwarding(
                    self.observe_forwarding(verdict),
                    RequestIdentity {
                        host: deny_host,
                        method,
                        target,
                    },
                    verdict,
                    Self::forwarding_audit_decision(verdict.decision),
                    Self::probe_correlation_plain(&headers),
                )
                .await
            }
            None => transmission_evidence::forwarded(VerdictDecision::Forward, self.config.credential_action, None)
                .persist(self.audit_jsonl_tx.as_ref(), None),
        };

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
        let mut upstream = self.dial_upstream_plain(&upstream_addr, authorized).await?;

        // Re-serialise and forward the request, forcing `Connection: close`.
        //
        // AAASM-4934: the DLP scan above inspects only the *first* request on
        // this connection. Historically the request was forwarded with the
        // client's own headers (often `Connection: keep-alive`) and the exchange
        // finished with a *bidirectional* copy — so a second request pipelined on
        // the same keep-alive connection was relayed client→upstream with no
        // scan, re-opening the exfiltration hole AAASM-4897 closed for request
        // one. Mirror the MitM path (`serialize_http_request_with_auth`): drop
        // any inbound `Connection` header and emit a single `Connection: close`,
        // then relay only the upstream→client direction below. Together these
        // enforce one inspected request/response per connection — a second,
        // un-scanned request can never reach upstream.
        upstream.write_all(request_line.as_bytes()).await?;
        upstream.write_all(b"\r\n").await?;
        for h in &headers {
            if h.to_ascii_lowercase().starts_with("connection:") {
                continue;
            }
            upstream.write_all(h.as_bytes()).await?;
        }
        upstream.write_all(b"Connection: close\r\n").await?;
        upstream.write_all(b"\r\n").await?;

        // Forward the buffered, DLP-scanned request body (AAASM-4897).
        if let Some(body) = scanned_body.as_deref() {
            upstream.write_all(body).await?;
        }

        // AAASM-4934: relay only the upstream response back to the client, then
        // tear the connection down — mirroring the MitM path's single-exchange
        // relay. We never copy further client bytes upstream, so a second request
        // pipelined on this connection cannot reach upstream un-inspected. The
        // forced `Connection: close` makes upstream close after one response,
        // bounding this copy.
        let mut client_stream = reader.into_inner();
        tokio::io::copy(&mut upstream, &mut client_stream).await?;
        let _ = client_stream.shutdown().await;

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
    let no_port = strip_host_port(host);
    let no_dot = no_port.strip_suffix('.').unwrap_or(no_port);
    no_dot.to_ascii_lowercase()
}

/// Strip an optional `:port` suffix from a host, correctly handling a bracketed
/// IPv6 literal (AAASM-4829).
///
/// A bare `host.split(':').next()` mangles IPv6 literals: `[::1]:443` becomes
/// `[`, which both lets the CONNECT-time `ssrf::blocked_ip_literal` check miss
/// the real address (it can no longer `parse::<IpAddr>()`) and over-blocks
/// legitimate IPv6 under a denylist. This unwraps the brackets and drops the
/// port so the returned value is the real literal (`::1`).
///
/// Rules:
/// - `[<ipv6>]:port` / `[<ipv6>]` → `<ipv6>` (brackets and port removed).
/// - `host:port` (single `:`) → `host`.
/// - a bare, unbracketed IPv6 literal (multiple `:`, no brackets) is returned
///   whole — an IPv6 address requires brackets to carry a port, so every colon
///   is part of the address.
/// - anything else is returned unchanged (trimmed).
fn strip_host_port(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        // Bracketed IPv6 literal — take the text up to the closing bracket,
        // discarding any `:port` that follows it. A malformed value with no
        // closing bracket falls back to the un-bracketed remainder.
        return match rest.find(']') {
            Some(end) => &rest[..end],
            None => rest,
        };
    }
    match host.rfind(':') {
        // More than one colon and no brackets → bare IPv6 literal, no port.
        Some(idx) if host[..idx].contains(':') => host,
        Some(idx) => &host[..idx],
        None => host,
    }
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

/// Find the value of a plain-HTTP header by name (case-insensitive) from the
/// raw header lines captured in [`ProxyServer::handle_plain_http`]. Each line
/// still carries its trailing CRLF, so the value is trimmed.
fn plain_http_header_value(headers: &[String], name: &str) -> Option<String> {
    let prefix = format!("{}:", name.to_ascii_lowercase());
    headers.iter().find_map(|h| {
        h.to_ascii_lowercase()
            .starts_with(&prefix)
            .then(|| h[prefix.len()..].trim().to_string())
    })
}

/// Parse and validate the plain-HTTP `Content-Length`. Absent → `0` (empty
/// body). Rejects a length above [`MAX_BODY_LEN`] fail-closed so a buffered
/// body cannot OOM the proxy (AAASM-4897, mirroring the MitM path's cap).
///
/// AAASM-4934: a header that is *present but unparseable* (`Content-Length: abc`,
/// a negative, a duplicated/comma-joined value) fails closed rather than
/// silently collapsing to `0`. The old `unwrap_or(0)` treated such a request as
/// bodyless, so its actual body bytes skipped the DLP scan and were relayed
/// upstream un-inspected — the same class of exfiltration hole this ticket
/// closes for keep-alive. An absent header still legitimately means no body.
fn plain_http_content_length(headers: &[String]) -> Result<usize, ProxyError> {
    let content_length = match plain_http_header_value(headers, "content-length") {
        None => 0,
        Some(v) => v.parse::<usize>().map_err(|_| {
            ProxyError::Config(format!(
                "plain-HTTP Content-Length {v:?} is not a valid length; refusing (fail-closed)"
            ))
        })?,
    };
    if content_length > MAX_BODY_LEN {
        return Err(ProxyError::Config(format!(
            "plain-HTTP Content-Length {content_length} exceeds maximum {MAX_BODY_LEN}; refusing (fail-closed)"
        )));
    }
    Ok(content_length)
}

/// Rewrite the `Content-Length` header line in place to `new_len` after a
/// redacting DLP scan changed the body length (AAASM-4897). The CRLF is kept so
/// the re-serialised head stays well-framed.
fn rewrite_plain_http_content_length(headers: &mut [String], new_len: usize) {
    for h in headers.iter_mut() {
        if h.to_ascii_lowercase().starts_with("content-length:") {
            *h = format!("Content-Length: {new_len}\r\n");
            return;
        }
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
    async fn plain_http_debug_target_is_redacted() {
        // AAASM-4863 regression: the `handle_plain_http` debug log renders the
        // target through `redact_target` (the AAASM-4738 helper) so a secret
        // riding in the query string never reaches the log in cleartext. This
        // pins the exact value the `target = %…` field would carry.
        let server = server_with(vec![], vec![]).await;
        // A well-known synthetic OpenAI key the default scanner detects. Not real.
        let target = "/v1/chat?token=sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab";
        // `redact_target` returns the exact String the `target = %…` debug field
        // renders (its `Display` is identity).
        let logged = server.interceptor.redact_target(target);
        assert!(
            !logged.contains("sk-TESTONLY-NOT-REAL"),
            "debug target must not contain the raw secret: {logged}"
        );
        assert!(
            logged.contains("[REDACTED:"),
            "debug target must carry a redaction label: {logged}"
        );
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

    #[test]
    fn plain_http_content_length_fails_closed_on_unparseable_value() {
        // AAASM-4934: an absent header means no body (Ok(0)), but a present but
        // unparseable value must fail closed rather than collapse to 0 — a `0`
        // would skip the DLP scan on the real body and relay it un-inspected.
        assert_eq!(plain_http_content_length(&[]).unwrap(), 0);
        assert_eq!(
            plain_http_content_length(&["Content-Length: 5\r\n".to_string()]).unwrap(),
            5
        );
        assert!(plain_http_content_length(&["Content-Length: abc\r\n".to_string()]).is_err());
        assert!(plain_http_content_length(&["Content-Length: -1\r\n".to_string()]).is_err());
    }

    #[test]
    fn strip_host_port_handles_bracketed_ipv6() {
        // AAASM-4829: a bracketed IPv6 literal must yield the real address, not
        // the mangled `[` that `split(':')` produced.
        assert_eq!(strip_host_port("[::1]:443"), "::1");
        assert_eq!(strip_host_port("[::1]"), "::1");
        assert_eq!(strip_host_port("[2001:db8::1]:8443"), "2001:db8::1");
        // Bare (unbracketed) IPv6 literal has no port — every colon is address.
        assert_eq!(strip_host_port("::1"), "::1");
        assert_eq!(strip_host_port("2001:db8::1"), "2001:db8::1");
        // IPv4 / DNS host:port and bare hosts behave as before.
        assert_eq!(strip_host_port("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(strip_host_port("api.openai.com:443"), "api.openai.com");
        assert_eq!(strip_host_port("api.openai.com"), "api.openai.com");
    }

    #[test]
    fn canonical_host_preserves_bracketed_ipv6_literal() {
        // AAASM-4829: the previous `split(':')` mangled `[::1]:443` into `[`,
        // breaking both denylist compares and the SSRF check.
        assert_eq!(canonical_host("[::1]:443"), "::1");
        assert_eq!(canonical_host("[2001:DB8::1]:8443"), "2001:db8::1");
    }

    #[tokio::test]
    async fn connect_deny_reason_blocks_bracketed_ipv6_loopback() {
        // AAASM-4829: `[::1]:443` must be caught by the SSRF guard. Before the
        // bracket-aware port strip, `blocked_ip_literal("[::1]:443")` failed to
        // parse and the loopback literal slipped through fail-open.
        let server = server_with(vec![], vec![]).await;
        assert_eq!(
            server.connect_deny_reason("[::1]:443"),
            Some("ssrf: blocked address range")
        );
        assert_eq!(server.connect_deny_reason("[::1]"), Some("ssrf: blocked address range"));
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
    async fn in_tunnel_deny_reason_blocks_disallowed_host_header_with_allowed_target() {
        // AAASM-4829: header host-splitting defense. The absolute-form target
        // points at the allowlisted host, but the `Host` header smuggles a
        // disallowed one. Because BOTH hosts are now checked, the forged header
        // is denied even though the target alone would have passed.
        let server = server_with(vec![], vec!["api.openai.com".to_string()]).await;
        let split = req_with(
            vec![("Host", "evil.attacker.com")],
            "https://api.openai.com/v1/chat/completions",
        );
        assert_eq!(server.in_tunnel_deny_reason(&split), Some("network allowlist"));
        // The symmetric case: allowed header, disallowed absolute target.
        let split2 = req_with(
            vec![("Host", "api.openai.com")],
            "https://evil.attacker.com/v1/chat/completions",
        );
        assert_eq!(server.in_tunnel_deny_reason(&split2), Some("network allowlist"));
        // Both halves allowlisted → permitted.
        let ok = req_with(vec![("Host", "api.openai.com")], "https://api.openai.com/v1/chat");
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

    async fn server_with_action(
        action: crate::config::CredentialAction,
        upstream_override: Option<std::net::SocketAddr>,
    ) -> Arc<ProxyServer> {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let config = ProxyConfig {
            bind_addr: ([127, 0, 0, 1], 0).into(),
            ca_dir: dir.path().to_path_buf(),
            cert_cache_capacity: 8,
            llm_only: true,
            mitm_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            network_allowlist: Vec::new(),
            skip_upstream_tls_verify: false,
            credential_action: action,
            upstream_override,
            gateway_endpoint: None,
            mcp_fail_open: false,
            allow_private_connect_targets: false,
        };
        let (tx, _rx) = broadcast::channel(8);
        ProxyServer::new(config, ca, tx)
    }

    #[tokio::test]
    async fn plain_http_body_with_credential_is_blocked() {
        // AAASM-4897: the plain-HTTP path now runs the same credential DLP as the
        // HTTPS MitM path. A cleartext POST to a non-LLM host whose body carries
        // a secret must be refused (403) under credential_action=Block, instead
        // of being raw-copied upstream un-inspected.
        let server = server_with_action(crate::config::CredentialAction::Block, None).await;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        // Synthetic OpenAI-style key the default scanner detects. Not real.
        let body = "{\"token\":\"sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab\"}";
        let req = format!(
            "POST http://example.com/v1/ingest HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body,
        );
        client.write_all(req.as_bytes()).await.unwrap();

        server
            .handle_connection(server_stream)
            .await
            .expect("blocked request returns Ok after writing 403");

        let mut buf = String::new();
        client.read_to_string(&mut buf).await.unwrap();
        assert!(
            buf.contains("403"),
            "plain-HTTP body carrying a credential must be refused with 403 (DLP now runs), got: {buf:?}"
        );
    }

    #[tokio::test]
    async fn plain_http_body_with_credential_is_redacted_before_forward() {
        // AAASM-4897: under the default RedactOnly action the plain-HTTP body is
        // scanned and the secret redacted *before* it reaches upstream — the raw
        // credential must never leave the host in cleartext.
        use tokio::io::AsyncReadExt as _;

        // Mock upstream: capture what the proxy forwards, then reply 200.
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut received = Vec::new();
            let mut chunk = [0u8; 4096];
            // Read until the whole small request has arrived (headers + body).
            loop {
                match tokio::time::timeout(std::time::Duration::from_millis(500), sock.read(&mut chunk)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        received.extend_from_slice(&chunk[..n]);
                        if received.windows(4).any(|w| w == b"\r\n\r\n") && received.len() > 40 {
                            break;
                        }
                    }
                    Ok(Err(_)) => break,
                }
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let _ = sock.shutdown().await;
            received
        });

        let server = server_with_action(crate::config::CredentialAction::RedactOnly, Some(upstream_addr)).await;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        let secret = "sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab";
        let body = format!("{{\"token\":\"{secret}\"}}");
        let req = format!(
            "POST http://example.com/v1/ingest HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body,
        );
        client.write_all(req.as_bytes()).await.unwrap();

        server.handle_connection(server_stream).await.expect("forwarded ok");

        let forwarded = upstream_task.await.unwrap();
        let forwarded_str = String::from_utf8_lossy(&forwarded);
        assert!(
            !forwarded_str.contains(secret),
            "raw secret must never reach upstream in cleartext, got: {forwarded_str:?}"
        );
        assert!(
            forwarded_str.contains("[REDACTED:"),
            "forwarded body must carry a redaction marker, got: {forwarded_str:?}"
        );
    }

    #[tokio::test]
    async fn audit_entry_never_writes_raw_secret_in_request_target() {
        // AAASM-4738 regression: a secret carried in the request target's query
        // string (e.g. `?key=…`, `?token=…`, a presigned `?X-Amz-Signature=…`)
        // must be redacted before it reaches the proxy audit JSONL, exactly as
        // the body is. Previously `emit_audit_entry` stored `req.target`
        // verbatim, leaking the secret in cleartext.
        use crate::audit_jsonl::JsonlWriter;

        // Synthetic AWS access key from AWS public documentation. Not real.
        const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

        let dir = tempfile::tempdir().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let config = ProxyConfig {
            bind_addr: ([127, 0, 0, 1], 0).into(),
            ca_dir: dir.path().to_path_buf(),
            cert_cache_capacity: 8,
            llm_only: true,
            mitm_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            network_allowlist: Vec::new(),
            skip_upstream_tls_verify: false,
            credential_action: crate::config::CredentialAction::default(),
            upstream_override: None,
            gateway_endpoint: None,
            mcp_fail_open: false,
            allow_private_connect_targets: false,
        };

        let jsonl_path = dir.path().join("proxy-audit.jsonl");
        let (audit_tx, rx) = mpsc::channel(4);
        let writer = JsonlWriter::new(&jsonl_path, rx).await.expect("open jsonl writer");
        let handle = tokio::spawn(writer.run());

        let (event_tx, _event_rx) = broadcast::channel(8);
        let server = ProxyServer::new_with_audit_sink(config, ca, event_tx, Some(audit_tx));

        let req = HttpRequest {
            method: "POST".into(),
            target: format!("/v1/upload?X-Amz-Credential=demo&key={FAKE_AWS_ACCESS_KEY}"),
            version: "HTTP/1.1".into(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        // A clean body verdict — the secret rides only in the target, so this
        // isolates target redaction from the already-covered body path.
        let verdict = InterceptVerdict {
            decision: VerdictDecision::Forward,
            findings: Vec::new(),
            redacted_body: None,
        };
        let execution = server.observe_forwarding(&verdict).evidence();
        server
            .emit_audit_entry(
                RequestIdentity {
                    host: "api.example.com",
                    method: &req.method,
                    target: &req.target,
                },
                &verdict,
                ProxyAuditDecision::Forwarded,
                execution,
                None,
            )
            .await;

        // Drop the last server reference so its audit sender closes and the
        // writer task drains and exits.
        drop(server);
        handle.await.expect("writer task joins cleanly");

        let on_disk = tokio::fs::read_to_string(&jsonl_path).await.expect("read JSONL");
        assert!(
            !on_disk.contains(FAKE_AWS_ACCESS_KEY),
            "SECURITY INVARIANT VIOLATED: raw secret from request target present in proxy audit JSONL: {on_disk}",
        );
        assert!(
            on_disk.contains("[REDACTED:AwsAccessKey]"),
            "JSONL must carry the [REDACTED:AwsAccessKey] marker for the target secret, got: {on_disk}",
        );
    }

    // ── AAASM-5358: execution evidence on the real data path ────────────────

    /// Synthetic OpenAI-style key the default scanner detects. Not a real
    /// credential.
    const EVIDENCE_TEST_SECRET: &str = "sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab";

    /// A proxy with a live audit sink, so a test observes the record the data
    /// path actually persists rather than a value it recomputes for itself.
    async fn server_with_audit(
        action: crate::config::CredentialAction,
        upstream_override: Option<std::net::SocketAddr>,
    ) -> (Arc<ProxyServer>, mpsc::Receiver<ProxyAuditEntry>) {
        let dir = tempfile::tempdir().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let config = ProxyConfig {
            bind_addr: ([127, 0, 0, 1], 0).into(),
            ca_dir: dir.path().to_path_buf(),
            cert_cache_capacity: 8,
            llm_only: true,
            mitm_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            network_allowlist: Vec::new(),
            skip_upstream_tls_verify: false,
            credential_action: action,
            upstream_override,
            gateway_endpoint: None,
            mcp_fail_open: false,
            allow_private_connect_targets: false,
        };
        let (tx, _rx) = broadcast::channel(8);
        let (audit_tx, audit_rx) = mpsc::channel(8);
        (
            ProxyServer::new_with_audit_sink(config, ca, tx, Some(audit_tx)),
            audit_rx,
        )
    }

    /// Drive one plain-HTTP request through the real `handle_connection` entry
    /// point and hand back whatever the client received.
    async fn drive_plain_http(server: &Arc<ProxyServer>, request: &str) -> String {
        use tokio::io::AsyncReadExt as _;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        // The dial-failure case returns Err; the test asserts on the audit
        // record either way, so the result is deliberately not unwrapped.
        let _ = server.handle_connection(server_stream).await;
        let mut buf = String::new();
        let _ = client.read_to_string(&mut buf).await;
        buf
    }

    /// A body whose redaction re-inspects **clean** — the ordinary successful
    /// scrub.
    fn scrubbable_body() -> String {
        format!("leaking {EVIDENCE_TEST_SECRET} here")
    }

    /// A body whose redaction re-inspects **dirty**: the scanner's generic
    /// high-entropy recognizer matches the `[REDACTED:GenericHighEntropy]`
    /// marker it just wrote. Whether that is a false positive is not this
    /// ticket's question — what matters is that the evidence reports what
    /// re-inspection actually said, not what the decision intended.
    fn unscrubbable_body() -> String {
        format!("{{\"token\":\"{EVIDENCE_TEST_SECRET}\"}}")
    }

    /// Take the one decision record a forwarded request must leave, asserting
    /// there is exactly one.
    ///
    /// `try_recv` on its own reads only the *first* entry, so a false
    /// `NotForwarded` line emitted alongside the true record — the additive
    /// drift, and the one that corrupts the metric because consumers count
    /// lines rather than first-lines — passed unnoticed. These tests run
    /// against a live upstream, so the count is asserted where the bytes
    /// genuinely went.
    async fn take_single_forwarding_record(rx: &mut mpsc::Receiver<ProxyAuditEntry>) -> ProxyAuditEntry {
        let first = rx.try_recv().expect("the forward persisted a decision record");
        // Let any additional emission land before concluding there is none.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let mut extra = Vec::new();
        while let Ok(entry) = rx.try_recv() {
            extra.push(entry);
        }
        assert!(
            extra.is_empty(),
            "a forwarded request wrote {} extra record(s): {extra:#?}",
            extra.len()
        );
        assert!(
            !first.execution.establishes_non_transmission(),
            "a forwarded request left a record claiming the payload was withheld: {first:#?}"
        );
        first
    }

    fn credential_post(target: &str, host: &str) -> String {
        credential_post_with(target, host, &unscrubbable_body())
    }

    fn credential_post_with(target: &str, host: &str, body: &str) -> String {
        format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body,
        )
    }

    /// The one observation this product can make truthfully, made on the real
    /// data path: a refused request never reached a dial, and the record says
    /// so.
    ///
    /// The record is asserted non-empty *first* — a "no raw secret" assertion
    /// over an absent or empty entry passes for the wrong reason.
    #[tokio::test]
    async fn a_refused_plain_http_request_persists_non_transmission_evidence() {
        let (server, mut audit_rx) = server_with_audit(crate::config::CredentialAction::Block, None).await;
        let response = drive_plain_http(&server, &credential_post("http://example.com/v1/ingest", "example.com")).await;
        assert!(
            response.contains("403"),
            "the request must be refused, got: {response:?}"
        );

        let entry = audit_rx.try_recv().expect("the refusal persisted a decision record");

        // Non-vacuity: this record has content, so the security assertions
        // below are being made about something.
        assert_eq!(entry.decision, ProxyAuditDecision::Blocked);
        assert_eq!(entry.host, "example.com");
        assert!(
            !entry.credential_findings.is_empty(),
            "a blocked credential body must carry its findings, else the assertions below are vacuous"
        );

        assert!(
            entry.execution.establishes_non_transmission(),
            "a pre-transmission refusal is the only shape that may support a prevention claim, got {:?}",
            entry.execution
        );
        assert_eq!(entry.execution.transmission.as_str(), "not_forwarded");

        let serialized = serde_json::to_string(&entry).expect("the record serializes");
        assert!(
            !serialized.contains(EVIDENCE_TEST_SECRET),
            "SECURITY INVARIANT VIOLATED: raw value in the persisted record: {serialized}"
        );
    }

    /// Redaction **forwards** the scrubbed bytes. The record must say
    /// transmitted, never prevented — the mistake the `CredentialLeakBlocked`
    /// name made, asserted here against the real path rather than the type.
    #[tokio::test]
    async fn a_redacted_plain_http_request_records_a_transmission_not_a_prevention() {
        use tokio::io::AsyncReadExt as _;
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut chunk = [0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), sock.read(&mut chunk)).await;
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let _ = sock.shutdown().await;
        });

        let (server, mut audit_rx) =
            server_with_audit(crate::config::CredentialAction::RedactOnly, Some(upstream_addr)).await;
        drive_plain_http(
            &server,
            &credential_post_with("http://example.com/v1/ingest", "example.com", &scrubbable_body()),
        )
        .await;
        let _ = upstream_task.await;

        let entry = take_single_forwarding_record(&mut audit_rx).await;
        assert_eq!(entry.decision, ProxyAuditDecision::ForwardedRedacted);
        assert!(
            !entry.credential_findings.is_empty(),
            "a redacted body must carry its findings, else the assertions below are vacuous"
        );
        assert_eq!(entry.execution.transmission.as_str(), "forwarded_clean");
        assert!(entry.execution.transmission.proves_transmission());
        assert!(
            !entry.execution.establishes_non_transmission(),
            "a successful redaction is a transformed transmission, not a prevented one"
        );
    }

    /// The other half of the same rule: the evidence is about the **bytes**. A
    /// redaction whose output still re-inspects as carrying a value is recorded
    /// as exactly that, not smoothed into `forwarded_clean` because the
    /// decision was "redact".
    #[tokio::test]
    async fn a_redaction_whose_bytes_still_reinspect_dirty_says_so() {
        use tokio::io::AsyncReadExt as _;
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut chunk = [0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), sock.read(&mut chunk)).await;
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let _ = sock.shutdown().await;
        });

        let (server, mut audit_rx) =
            server_with_audit(crate::config::CredentialAction::RedactOnly, Some(upstream_addr)).await;
        drive_plain_http(
            &server,
            &credential_post_with("http://example.com/v1/ingest", "example.com", &unscrubbable_body()),
        )
        .await;
        let _ = upstream_task.await;

        let entry = audit_rx.try_recv().expect("the redaction persisted a decision record");
        assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
        assert_eq!(
            entry.execution.transmission.as_str(),
            "forwarded_carrying_sensitive_value"
        );
        assert!(!entry.execution.establishes_non_transmission());
    }

    /// The ordering claim, tested where it can actually fail: the upstream is a
    /// closed port, so the dial errors out. The record must already exist — if
    /// the emission ever moves back after the dial, this request leaves no
    /// trace and the test fails.
    #[tokio::test]
    async fn the_record_exists_even_when_the_upstream_dial_fails() {
        // Bind then drop, so the address is real and nothing is listening on it.
        let dead = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let (server, mut audit_rx) =
            server_with_audit(crate::config::CredentialAction::RedactOnly, Some(dead_addr)).await;
        drive_plain_http(&server, &credential_post("http://example.com/v1/ingest", "example.com")).await;

        let entry = audit_rx
            .try_recv()
            .expect("the observation must be recorded before the dial, not after it");
        assert_eq!(entry.decision, ProxyAuditDecision::ForwardedRedacted);
        assert!(entry.execution.transmission.proves_transmission());
    }

    /// A bodyless request has nothing to inspect. "Not inspected" is the honest
    /// answer; "clean" would be a claim no scan supports.
    #[tokio::test]
    async fn a_bodyless_forward_observes_an_uninspected_payload_not_a_clean_one() {
        let (server, _audit_rx) = server_with_audit(crate::config::CredentialAction::RedactOnly, None).await;
        let evidence =
            transmission_evidence::forwarded(VerdictDecision::Forward, server.config.credential_action, None)
                .evidence();
        assert_eq!(evidence.transmission.as_str(), "forwarded_not_inspected");
        assert!(!evidence.transmission.proves_non_transmission());
    }

    /// The probe branch. Only a genuine block is attributed to the policy; every
    /// other verdict says "not recorded", because the probe protocol — not the
    /// decision — is why those bytes stayed here.
    #[tokio::test]
    async fn a_probe_request_only_claims_non_transmission_when_the_policy_blocked_it() {
        let (server, _audit_rx) = server_with_audit(crate::config::CredentialAction::RedactOnly, None).await;

        let blocked = InterceptVerdict {
            decision: VerdictDecision::Block,
            findings: Vec::new(),
            redacted_body: None,
        };
        assert!(
            server.probe_execution_evidence(&blocked).establishes_non_transmission(),
            "a policy block during a probe really did withhold the payload"
        );

        for decision in [
            VerdictDecision::Forward,
            VerdictDecision::ForwardRedacted,
            VerdictDecision::AlertAndForward,
        ] {
            let verdict = InterceptVerdict {
                decision,
                findings: Vec::new(),
                redacted_body: Some(bytes::Bytes::from_static(b"redacted")),
            };
            let evidence = server.probe_execution_evidence(&verdict);
            assert_eq!(
                evidence.transmission.as_str(),
                "not_recorded",
                "{decision:?}: the probe protocol withheld these bytes, not the policy"
            );
            assert!(
                !evidence.establishes_non_transmission(),
                "{decision:?}: a probe must not manufacture a prevented transmission"
            );
        }
    }

    /// Every branch that can reach a dial reports transmission. Stated over the
    /// server's own observer rather than the pure function, so a call site that
    /// starts feeding it the wrong re-inspection is caught here.
    #[tokio::test]
    async fn no_forwarding_observation_ever_claims_the_payload_stayed_here() {
        let (server, _audit_rx) = server_with_audit(crate::config::CredentialAction::RedactOnly, None).await;
        let verdicts = [
            InterceptVerdict {
                decision: VerdictDecision::Forward,
                findings: Vec::new(),
                redacted_body: None,
            },
            InterceptVerdict {
                decision: VerdictDecision::ForwardRedacted,
                findings: Vec::new(),
                redacted_body: Some(bytes::Bytes::from_static(b"[REDACTED:OpenAiKey]")),
            },
            InterceptVerdict {
                decision: VerdictDecision::AlertAndForward,
                findings: Vec::new(),
                redacted_body: None,
            },
        ];
        for verdict in verdicts {
            let evidence = server.observe_forwarding(&verdict).evidence();
            assert!(
                evidence.transmission.proves_transmission(),
                "{:?} authorized a dial without recording that bytes went",
                verdict.decision
            );
            assert!(
                !evidence.establishes_non_transmission(),
                "{:?} would have counted as a prevented transmission",
                verdict.decision
            );
        }
    }

    /// `alert_only` detects a credential, forwards it unchanged, and must still
    /// leave a record — the detected-but-forwarded numerator is exactly what a
    /// dry-run deployment exists to produce.
    ///
    /// The plain-HTTP path wrote a record only for `ForwardRedacted`, so every
    /// cleartext alert-mode detection was silently invisible. Driven end to end
    /// through `handle_connection` rather than asserted on `observe_forwarding`,
    /// which cannot see the sink and so could never have caught the omission.
    #[tokio::test]
    async fn an_alert_only_plain_http_detection_is_recorded_as_an_observed_transmission() {
        use tokio::io::AsyncReadExt as _;
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut chunk = [0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), sock.read(&mut chunk)).await;
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let _ = sock.shutdown().await;
        });

        let (server, mut audit_rx) =
            server_with_audit(crate::config::CredentialAction::AlertOnly, Some(upstream_addr)).await;
        drive_plain_http(
            &server,
            &credential_post_with("http://example.com/v1/ingest", "example.com", &scrubbable_body()),
        )
        .await;
        let _ = upstream_task.await;

        let entry = take_single_forwarding_record(&mut audit_rx).await;
        assert_eq!(entry.decision, ProxyAuditDecision::Forwarded);
        assert!(
            !entry.credential_findings.is_empty(),
            "the record must carry the findings that were detected, else it counts nothing"
        );
        assert_eq!(entry.execution.mode, aa_core::policy::EnforcementMode::Observe);
        assert!(entry.execution.transmission.proves_transmission());
        assert!(
            !entry.execution.establishes_non_transmission(),
            "a dry-run forward is never a prevention"
        );
    }

    /// The record must not carry bytes the proxy has just reported as still
    /// carrying a sensitive value. In that branch the proxy's own re-inspection
    /// says the scrubber did not hold, so persisting its output would rest the
    /// "no raw value on disk" guarantee on the thing it just distrusted.
    #[tokio::test]
    async fn a_body_that_reinspects_dirty_is_not_persisted() {
        use tokio::io::AsyncReadExt as _;
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut chunk = [0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), sock.read(&mut chunk)).await;
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let _ = sock.shutdown().await;
        });

        let (server, mut audit_rx) =
            server_with_audit(crate::config::CredentialAction::RedactOnly, Some(upstream_addr)).await;
        drive_plain_http(
            &server,
            &credential_post_with("http://example.com/v1/ingest", "example.com", &unscrubbable_body()),
        )
        .await;
        let _ = upstream_task.await;

        let entry = take_single_forwarding_record(&mut audit_rx).await;
        // Non-vacuity: this is the dirty branch, and the record has content.
        assert_eq!(
            entry.execution.transmission.as_str(),
            "forwarded_carrying_sensitive_value"
        );
        assert!(!entry.credential_findings.is_empty());
        assert!(
            entry.redacted_body.is_none(),
            "bytes the proxy reported as still carrying a value must not be persisted, got {:?}",
            entry.redacted_body
        );
    }

    /// The control for the previous test: it must be possible for a body to be
    /// persisted at all, otherwise "not persisted" asserts nothing.
    #[tokio::test]
    async fn a_body_that_reinspects_clean_is_persisted() {
        use tokio::io::AsyncReadExt as _;
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut chunk = [0u8; 4096];
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), sock.read(&mut chunk)).await;
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let _ = sock.shutdown().await;
        });

        let (server, mut audit_rx) =
            server_with_audit(crate::config::CredentialAction::RedactOnly, Some(upstream_addr)).await;
        drive_plain_http(
            &server,
            &credential_post_with("http://example.com/v1/ingest", "example.com", &scrubbable_body()),
        )
        .await;
        let _ = upstream_task.await;

        let entry = take_single_forwarding_record(&mut audit_rx).await;
        assert_eq!(entry.execution.transmission.as_str(), "forwarded_clean");
        let body = entry.redacted_body.expect("a clean scrub is persisted");
        assert!(body.contains("[REDACTED:"), "got {body}");
        assert!(!body.contains(EVIDENCE_TEST_SECRET));
    }
}
