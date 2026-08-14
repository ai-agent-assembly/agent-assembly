//! The shipped protection probe: produce traffic on the protected path, and
//! report only what the core adjudicated about it.
//!
//! # What makes this evidence rather than an inference
//!
//! [`UnadjudicatedProbe`](crate::probe::UnadjudicatedProbe) is honest and
//! useless: a client on the **near** side of the proxy sees its request go out
//! and nothing obviously fail, and neither fact says what the provider would
//! have received. This probe does not try to infer it. It marks its own request
//! with an opaque correlation identifier, and the proxy — the component that
//! runs the scanner and constructs the bytes that would leave the machine —
//! answers with the verdict for *that* request, including a re-inspection of the
//! payload it resolved to forward. `Redacted` is reported only when the proxy
//! says it scrubbed the body **and** that the scrubbed bytes carry no
//! credential.
//!
//! # Why two exchanges
//!
//! The adjudication request carries a synthetic credential on purpose. A proxy
//! that does not speak the probe protocol would forward that body to the real
//! provider — measuring the deployment by leaking to it. So the probe first
//! sends a **preflight** whose body carries nothing sensitive and whose only job
//! is to prove that the thing on the other end adjudicates and answers. Only
//! after that does the second exchange carry the secret. Every failure of the
//! first exchange ends the run before anything sensitive is written to a socket.
//!
//! # Why it cannot read anyone else's verdict
//!
//! There is no verdict store and no query. A verdict arrives only as the
//! response to the request that produced it, on the probe's own TLS connection,
//! and is accepted only when it echoes the identifier this run minted. The probe
//! gains no audit read of any kind.
//!
//! # Fail-closed, everywhere
//!
//! Unreachable proxy, unreadable trust material, a refused tunnel, an untrusted
//! MitM certificate, a peer that does not answer with an adjudication, a verdict
//! for a different request, a timeout — every one of them is
//! [`Inconclusive`](aa_devtool_contract::ExerciseOutcome::Inconclusive). "Cannot
//! tell" is never rendered as "fine".

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aa_devtool_contract::ExerciseOutcome;
use async_trait::async_trait;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::probe::{ProbeReport, ProbeRequest, ProtectionProbe};

/// Header the probe marks its own request with. Mirrors
/// `aa_proxy::probe_adjudication::PROBE_CORRELATION_HEADER`.
pub const PROBE_CORRELATION_HEADER: &str = "x-agent-assembly-probe";

/// Schema tag the probe requires on an adjudication. Mirrors
/// `aa_proxy::probe_adjudication::PROBE_ADJUDICATION_SCHEMA`.
pub const PROBE_ADJUDICATION_SCHEMA: &str = "agent-assembly.probe-adjudication/1";

/// Ceiling on one CONNECT + TLS + request/response exchange.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on the adjudication document the probe will read.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// The probe the product ships for Claude Code.
///
/// Stateless: every run mints fresh correlation identifiers and holds nothing
/// between runs.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProxyAdjudicatedProbe;

#[async_trait]
impl ProtectionProbe for ProxyAdjudicatedProbe {
    async fn run(&self, request: &ProbeRequest) -> ProbeReport {
        let Some(addr) = proxy_addr(&request.proxy_url) else {
            return inconclusive(format!(
                "the receipted proxy endpoint {} is not an address this probe can dial, so nothing \
                 was exercised",
                request.proxy_url
            ));
        };
        let config = match client_trusting_pem(&request.ca_pem).await {
            Ok(config) => Arc::new(config),
            Err(reason) => {
                return inconclusive(format!(
                    "the trust material at {} could not be read ({reason}), so the model path was \
                     never exercised",
                    request.ca_pem.display()
                ))
            }
        };

        // Exchange 1 — capability preflight. Nothing sensitive is in this body,
        // and nothing sensitive is sent at all unless it comes back adjudicated.
        let preflight_id = correlation_id();
        let preflight = exchange(
            addr,
            Arc::clone(&config),
            &request.target_host,
            &preflight_id,
            "agent assembly protection probe: capability preflight, no credential in this body",
        )
        .await;
        if let Err(reason) = preflight
            .and_then(|raw| adjudication_for(&preflight_id, &raw).map_err(|e| e.into_reason(&request.proxy_url)))
        {
            return inconclusive(format!(
                "{reason}; the probe therefore sent nothing down the {} path and cannot report on it",
                request.target_host
            ));
        }

        // Exchange 2 — the adjudicated one.
        let id = correlation_id();
        let raw = match exchange(
            addr,
            Arc::clone(&config),
            &request.target_host,
            &id,
            &format!(
                "agent assembly protection probe: please audit this synthetic credential: {}",
                request.synthetic_secret
            ),
        )
        .await
        {
            Ok(raw) => raw,
            Err(reason) => return inconclusive(reason),
        };
        match adjudication_for(&id, &raw) {
            Ok(adjudication) => report_for(&adjudication, &request.target_host),
            Err(e) => inconclusive(e.into_reason(&request.proxy_url)),
        }
    }
}

/// The adjudication document, as the probe reads it.
///
/// Deliberately a **mirror** of `aa_proxy::probe_adjudication::ProbeAdjudication`
/// rather than the type itself: `aa-proxy` depends (transitively) on this crate,
/// so the dependency cannot be reversed. `decision` and `forwarded_payload` stay
/// `String` so a token this build does not know is inconclusive rather than a
/// deserialization error that reads the same as an unreachable proxy. A
/// cross-crate conformance test pins the two shapes together.
#[derive(Debug, Clone, Deserialize)]
struct Adjudication {
    schema: String,
    correlation_id: String,
    decision: String,
    findings: usize,
    forwarded_payload: String,
}

/// Why a response was not usable as evidence about this probe's request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NotEvidence {
    /// The peer answered, but not with an adjudication.
    NotAnAdjudication,
    /// The peer adjudicated a *different* request.
    ForAnotherRequest,
}

impl NotEvidence {
    fn into_reason(self, proxy_url: &str) -> String {
        match self {
            Self::NotAnAdjudication => format!(
                "the endpoint at {proxy_url} did not answer with a protection adjudication, so no \
                 component reported what it did with the probe traffic"
            ),
            Self::ForAnotherRequest => format!(
                "the endpoint at {proxy_url} answered with an adjudication of a different request; a \
                 verdict the probe did not produce is not evidence about the probe"
            ),
        }
    }
}

/// The adjudication in `response`, when it is one and when it is *this* run's.
///
/// The correlation check is the reason a probe cannot pass on someone else's
/// verdict, and is the only thing binding the returned document to the request
/// this probe sent.
fn adjudication_for(expected_id: &str, response: &str) -> Result<Adjudication, NotEvidence> {
    let body = response.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(response);
    let adjudication: Adjudication = serde_json::from_str(body.trim()).map_err(|_| NotEvidence::NotAnAdjudication)?;
    if adjudication.schema != PROBE_ADJUDICATION_SCHEMA {
        return Err(NotEvidence::NotAnAdjudication);
    }
    if adjudication.correlation_id != expected_id {
        return Err(NotEvidence::ForAnotherRequest);
    }
    Ok(adjudication)
}

/// What an adjudication means for the protection ladder.
///
/// `forwarded_redacted` is protective **only** with a clean re-inspection of the
/// forwarded bytes: a proxy that decided to redact and produced a payload still
/// carrying the credential protected nothing, and a proxy with no scanner cannot
/// say what it produced.
fn report_for(adjudication: &Adjudication, host: &str) -> ProbeReport {
    let findings = adjudication.findings;
    match adjudication.decision.as_str() {
        "blocked" => ProbeReport {
            outcome: ExerciseOutcome::Blocked,
            detail: format!(
                "the core refused the probe request to {host} on {findings} credential finding(s); \
                 nothing was forwarded"
            ),
        },
        "forwarded_redacted" => match adjudication.forwarded_payload.as_str() {
            "clean" => ProbeReport {
                outcome: ExerciseOutcome::Redacted,
                detail: format!(
                    "the core redacted {findings} credential finding(s) from the probe request to \
                     {host}, and re-inspection of the bytes it resolved to forward found none"
                ),
            },
            other => ProbeReport {
                outcome: ExerciseOutcome::Leaked,
                detail: format!(
                    "the core redacted the probe request to {host}, but the payload it resolved to \
                     forward was reported as `{other}` rather than clean"
                ),
            },
        },
        "alerted_and_forwarded" => ProbeReport {
            outcome: ExerciseOutcome::ObservedOnly,
            detail: format!(
                "the core recorded {findings} credential finding(s) on the probe request to {host} \
                 and would have forwarded the payload unmodified; observing is not protecting"
            ),
        },
        "forwarded" => ProbeReport {
            outcome: ExerciseOutcome::Leaked,
            detail: format!(
                "the core would have forwarded the probe request to {host} unmodified, so the \
                 synthetic credential the probe planted was not acted on"
            ),
        },
        other => inconclusive(format!(
            "the core reported a decision this build cannot read (`{other}`), so the probe traffic \
             is unadjudicated as far as this client is concerned"
        )),
    }
}

/// One CONNECT + TLS + request/response against the proxy, returning the raw
/// response text.
///
/// Every failure is returned as a user-facing reason rather than an error type:
/// the caller's only response to any of them is the same inconclusive report.
async fn exchange(
    proxy: SocketAddr,
    config: Arc<ClientConfig>,
    host: &str,
    correlation_id: &str,
    text: &str,
) -> Result<String, String> {
    let attempt = async {
        let mut tcp = TcpStream::connect(proxy)
            .await
            .map_err(|e| format!("the Agent Assembly proxy at {proxy} is not accepting connections ({e})"))?;
        let target = format!("{host}:443");
        tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .map_err(|e| format!("the tunnel request to {proxy} could not be written ({e})"))?;

        let mut reader = BufReader::new(tcp);
        let mut status = String::new();
        reader
            .read_line(&mut status)
            .await
            .map_err(|e| format!("the proxy at {proxy} closed before answering the tunnel request ({e})"))?;
        loop {
            let mut header = String::new();
            let n = reader
                .read_line(&mut header)
                .await
                .map_err(|e| format!("the proxy at {proxy} closed mid-response ({e})"))?;
            if n == 0 || header.trim().is_empty() {
                break;
            }
        }
        if !status.contains("200") {
            return Err(format!(
                "the proxy refused the tunnel to {host} ({}), so no traffic was adjudicated",
                status.trim()
            ));
        }

        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|e| format!("{host} is not a name this probe can request a certificate for ({e})"))?;
        let mut tls = TlsConnector::from(config)
            .connect(server_name, reader.into_inner())
            .await
            .map_err(|e| {
                format!(
                    "the intercepting proxy's certificate for {host} was not trusted ({e}), so the \
                     model path was never inspected"
                )
            })?;

        tls.write_all(request_bytes(host, correlation_id, text).as_bytes())
            .await
            .map_err(|e| format!("the probe request to {host} could not be written ({e})"))?;
        tls.flush()
            .await
            .map_err(|e| format!("the probe request to {host} could not be flushed ({e})"))?;

        read_http_message(&mut tls)
            .await
            .map_err(|e| format!("the response to the probe request to {host} could not be read ({e})"))
    };

    match tokio::time::timeout(EXCHANGE_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "the probe exchange with {proxy} did not complete within {}s, so nothing was adjudicated",
            EXCHANGE_TIMEOUT.as_secs()
        )),
    }
}

/// Read one HTTP response: the head, then exactly the `Content-Length` bytes it
/// declares, then stop.
///
/// Reading to end-of-stream instead would block on any peer that keeps the
/// connection open — which every ordinary provider response does — and turn a
/// perfectly legible "that was not an adjudication" into a timeout. The whole
/// read stays bounded by [`MAX_RESPONSE_BYTES`]; a response with no
/// `Content-Length` is read until the peer closes or the budget runs out.
async fn read_http_message<S>(stream: &mut S) -> std::io::Result<String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut want: Option<usize> = None;
    loop {
        if let Some(total) = want {
            if buf.len() >= total {
                break;
            }
        }
        if buf.len() >= MAX_RESPONSE_BYTES {
            break;
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if want.is_none() {
            if let Some(head_len) = find_head_end(&buf) {
                let head = String::from_utf8_lossy(&buf[..head_len]).to_ascii_lowercase();
                let body_len = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                want = Some(head_len.saturating_add(body_len));
            }
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Index just past the blank line ending an HTTP head.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// The Anthropic Messages request the probe sends, shaped like the traffic the
/// tool produces so the proxy's pattern detection, extraction and scanner all
/// see production-shaped bytes.
fn request_bytes(host: &str, correlation_id: &str, text: &str) -> String {
    let body = serde_json::json!({
        "model": "claude-sonnet-4-5",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    })
    .to_string();
    format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         anthropic-version: 2023-06-01\r\n{PROBE_CORRELATION_HEADER}: {correlation_id}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
}

/// A fresh opaque correlation identifier: 32 lowercase hex characters of OS
/// entropy, generated here and derived from nothing about the payload.
fn correlation_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn inconclusive(detail: impl Into<String>) -> ProbeReport {
    ProbeReport {
        outcome: ExerciseOutcome::Inconclusive,
        detail: detail.into(),
    }
}

/// The address behind a `http://host:port` proxy URL.
fn proxy_addr(url: &str) -> Option<SocketAddr> {
    url.strip_prefix("http://")
        .unwrap_or(url)
        .trim_end_matches('/')
        .parse()
        .ok()
}

/// A rustls client trusting exactly the certificate authority the install
/// materialised — and nothing else, not even the host's own root store.
///
/// That narrowness is the point: this handshake is the condition-C1
/// measurement, so it must fail when the PEM is not the authority the proxy is
/// presenting leaves from. The crypto provider is passed explicitly rather than
/// installed process-wide, because a library has no business deciding a
/// process-global default for its host.
async fn client_trusting_pem(pem_path: &std::path::Path) -> Result<ClientConfig, String> {
    let pem = tokio::fs::read(pem_path).await.map_err(|e| e.to_string())?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    if certs.is_empty() {
        return Err("it contains no certificate".to_owned());
    }
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|e| e.to_string())?;
    }
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::probe::SYNTHETIC_SECRET;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_ID: &str = "fedcba9876543210fedcba9876543210";

    fn wire(id: &str, decision: &str, payload: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
             {{\"schema\":\"{PROBE_ADJUDICATION_SCHEMA}\",\"correlation_id\":\"{id}\",\
             \"decision\":\"{decision}\",\"findings\":1,\"forwarded_payload\":\"{payload}\"}}"
        )
    }

    #[test]
    fn correlation_ids_are_opaque_fresh_and_not_derived_from_anything() {
        let a = correlation_id();
        let b = correlation_id();
        assert_ne!(a, b, "every run must mint a fresh identifier");
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        assert!(
            !SYNTHETIC_SECRET.contains(&a) && !a.contains(&SYNTHETIC_SECRET[..8]),
            "the identifier must not be derived from the payload"
        );
    }

    /// The load-bearing guard: a verdict this probe did not produce is not
    /// evidence about this probe, however protective it reads.
    #[test]
    fn a_verdict_for_another_request_is_not_evidence() {
        let err = adjudication_for(ID, &wire(OTHER_ID, "blocked", "not_forwarded"))
            .expect_err("an adjudication of another request must be refused");
        assert_eq!(err, NotEvidence::ForAnotherRequest);
        let report = inconclusive(err.into_reason("http://127.0.0.1:8899"));
        assert!(!report.outcome.is_protective());
        assert!(report.detail.contains("different request"), "{}", report.detail);
    }

    /// The other load-bearing guard: with no adjudication in hand there is
    /// nothing to pass on.
    #[test]
    fn a_response_that_is_not_an_adjudication_cannot_pass() {
        for response in [
            "HTTP/1.1 200 OK\r\n\r\n{\"id\":\"msg_1\",\"content\":[{\"text\":\"hello\"}]}",
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            "",
            "HTTP/1.1 200 OK\r\n\r\n{\"schema\":\"something.else/1\",\"correlation_id\":\"0123456789abcdef0123456789abcdef\",\"decision\":\"blocked\",\"findings\":1,\"forwarded_payload\":\"not_forwarded\"}",
        ] {
            let err = adjudication_for(ID, response).expect_err("must not be read as evidence: {response}");
            assert_eq!(err, NotEvidence::NotAnAdjudication, "{response}");
        }
    }

    #[test]
    fn a_block_is_protective() {
        let a = adjudication_for(ID, &wire(ID, "blocked", "not_forwarded")).expect("adjudicated");
        let report = report_for(&a, "api.anthropic.com");
        assert_eq!(report.outcome, ExerciseOutcome::Blocked);
        assert!(report.outcome.is_protective());
    }

    #[test]
    fn a_redaction_is_protective_only_when_the_forwarded_bytes_were_clean() {
        let clean = adjudication_for(ID, &wire(ID, "forwarded_redacted", "clean")).expect("adjudicated");
        assert_eq!(
            report_for(&clean, "api.anthropic.com").outcome,
            ExerciseOutcome::Redacted
        );

        for payload in ["carries_credential", "not_inspected", "not_forwarded"] {
            let dirty = adjudication_for(ID, &wire(ID, "forwarded_redacted", payload)).expect("adjudicated");
            let report = report_for(&dirty, "api.anthropic.com");
            assert!(
                !report.outcome.is_protective(),
                "`{payload}` must not read as protection: {report:?}"
            );
        }
    }

    #[test]
    fn observing_is_not_protecting_and_forwarding_is_a_leak() {
        let observed = adjudication_for(ID, &wire(ID, "alerted_and_forwarded", "carries_credential")).expect("ok");
        assert_eq!(
            report_for(&observed, "api.anthropic.com").outcome,
            ExerciseOutcome::ObservedOnly
        );

        let forwarded = adjudication_for(ID, &wire(ID, "forwarded", "carries_credential")).expect("ok");
        assert_eq!(
            report_for(&forwarded, "api.anthropic.com").outcome,
            ExerciseOutcome::Leaked
        );
    }

    /// A decision token from a newer core is not a licence to guess.
    #[test]
    fn an_unreadable_decision_is_inconclusive() {
        let a = adjudication_for(ID, &wire(ID, "quarantined_for_review", "clean")).expect("adjudicated");
        let report = report_for(&a, "api.anthropic.com");
        assert_eq!(report.outcome, ExerciseOutcome::Inconclusive);
    }

    #[test]
    fn no_report_this_probe_produces_may_carry_the_secret() {
        let details = [
            report_for(
                &adjudication_for(ID, &wire(ID, "forwarded_redacted", "clean")).expect("ok"),
                "api.anthropic.com",
            )
            .detail,
            report_for(
                &adjudication_for(ID, &wire(ID, "forwarded", "carries_credential")).expect("ok"),
                "api.anthropic.com",
            )
            .detail,
            NotEvidence::ForAnotherRequest.into_reason("http://127.0.0.1:8899"),
            NotEvidence::NotAnAdjudication.into_reason("http://127.0.0.1:8899"),
        ];
        for detail in details {
            assert!(
                !detail.contains(SYNTHETIC_SECRET),
                "SECURITY INVARIANT VIOLATED: {detail}"
            );
            assert!(!detail.contains("sk-ant-"), "{detail}");
        }
    }

    /// The request the probe writes carries the correlation header and the
    /// secret only in the body — never in the identifier and never in a header.
    #[test]
    fn the_correlation_header_never_carries_the_payload() {
        let wire = request_bytes("api.anthropic.com", ID, &format!("audit this: {SYNTHETIC_SECRET}"));
        let (head, body) = wire.split_once("\r\n\r\n").expect("head then body");
        assert!(head.contains(&format!("{PROBE_CORRELATION_HEADER}: {ID}")));
        assert!(!head.contains(SYNTHETIC_SECRET), "the head must not carry the secret");
        assert!(body.contains(SYNTHETIC_SECRET), "the body is what gets adjudicated");
    }

    /// The preflight body is what the probe sends before it knows anything about
    /// the peer, so it must be free of the credential.
    #[test]
    fn the_preflight_body_carries_no_credential() {
        let wire = request_bytes(
            "api.anthropic.com",
            ID,
            "agent assembly protection probe: capability preflight, no credential in this body",
        );
        assert!(!wire.contains("sk-ant-"), "{wire}");
    }

    #[test]
    fn a_proxy_url_that_is_not_dialable_is_rejected() {
        assert!(proxy_addr("http://127.0.0.1:8899").is_some());
        assert!(proxy_addr("127.0.0.1:8899").is_some());
        assert!(proxy_addr("http://proxy.internal:8899").is_none());
        assert!(proxy_addr("").is_none());
    }
}
