//! The adjudicating protection probe the conformance suite injects.
//!
//! # Why the product does not ship this
//!
//! [`UnadjudicatedProbe`](aa_devtool_claude_code::probe::UnadjudicatedProbe) is
//! the default because a client on the **near** side of the proxy cannot see
//! the forwarded body, and reporting
//! [`Redacted`](aa_devtool_contract::ExerciseOutcome::Redacted) without having
//! seen it is precisely the vacuous pass the evidence model exists to prevent.
//! The conformance harness can adjudicate only because it owns the mock
//! provider and can read what actually arrived.
//!
//! # The one variable the C1 regression turns
//!
//! [`AdjudicatingProbe::trust_switch`] flips whether the probe's client trusts
//! the certificate authority the install materialised and `NODE_EXTRA_CA_CERTS`
//! points at. With it off, the probe's root store is empty — exactly what a Node
//! runtime that never received the variable sees when the proxy presents its
//! MitM-issued leaf. Nothing else about the run changes, so a failure can only
//! be attributed to CA trust.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aa_devtool_claude_code::probe::{ProbeReport, ProbeRequest, ProtectionProbe};
use aa_devtool_contract::ExerciseOutcome;
use async_trait::async_trait;
use base64::Engine as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

use crate::spike_support::proxy_harness::{drive_emulated_client, ANTHROPIC_HOST};
use crate::spike_support::{find_secret, TlsCapturingUpstream};

/// A probe that reports what the provider actually received.
pub struct AdjudicatingProbe {
    upstream: Arc<TlsCapturingUpstream>,
    trust_injected_ca: Arc<AtomicBool>,
}

impl AdjudicatingProbe {
    /// Build a probe adjudicating against `upstream`, trusting the injected CA.
    pub fn new(upstream: Arc<TlsCapturingUpstream>) -> Self {
        Self {
            upstream,
            trust_injected_ca: Arc::new(AtomicBool::new(true)),
        }
    }

    /// The switch that turns condition C1 on and off mid-test.
    pub fn trust_switch(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.trust_injected_ca)
    }
}

#[async_trait]
impl ProtectionProbe for AdjudicatingProbe {
    async fn run(&self, request: &ProbeRequest) -> ProbeReport {
        let Some(addr) = proxy_addr(&request.proxy_url) else {
            return inconclusive(format!(
                "the receipted proxy endpoint {} is not an address this probe can dial",
                request.proxy_url
            ));
        };
        let before = self.upstream.request_count();

        let config = if self.trust_injected_ca.load(Ordering::SeqCst) {
            match client_trusting_pem(&request.ca_pem).await {
                Ok(config) => config,
                Err(e) => return inconclusive(format!("the trust material could not be read: {e}")),
            }
        } else {
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth()
        };

        let prompt = format!("please audit this credential: {}", request.synthetic_secret);
        let result = match drive_emulated_client(addr, Arc::new(config), &prompt).await {
            Ok(result) => result,
            Err(e) => return inconclusive(format!("the probe could not reach the proxy: {e}")),
        };
        if !result.connected() {
            return inconclusive(format!(
                "the proxy refused the tunnel ({}), so no traffic was adjudicated",
                result.connect_status.trim()
            ));
        }
        if let Some(response) = &result.inner_response {
            if response.starts_with("TLS error") {
                return inconclusive(
                    "the intercepting proxy's certificate was not trusted, so the model path was \
                     never inspected"
                        .to_string(),
                );
            }
        }

        let bodies: Vec<Vec<u8>> = self.upstream.bodies().into_iter().skip(before).collect();
        // The load-bearing clause of scenario 11.3: with no recorded request,
        // "no raw secret arrived" is true and proves nothing.
        if bodies.is_empty() {
            return inconclusive("the provider recorded no request, so nothing was adjudicated".to_string());
        }
        match find_secret(&bodies, &request.synthetic_secret) {
            Some((idx, view, encoding)) => ProbeReport {
                outcome: ExerciseOutcome::Leaked,
                detail: format!("the provider received the credential unredacted (body #{idx}, {view}, {encoding})"),
            },
            None => ProbeReport {
                outcome: ExerciseOutcome::Redacted,
                detail: format!(
                    "{} request(s) reached the provider and none carried the credential",
                    bodies.len()
                ),
            },
        }
    }
}

fn inconclusive(detail: String) -> ProbeReport {
    ProbeReport {
        outcome: ExerciseOutcome::Inconclusive,
        detail,
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

/// A rustls client config trusting exactly one PEM file.
async fn client_trusting_pem(pem_path: &std::path::Path) -> anyhow::Result<ClientConfig> {
    let pem = tokio::fs::read_to_string(pem_path).await?;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(body)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(der))?;
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

// ── Raw probe-protocol exchange (AAASM-5300) ────────────────────────────────

/// Drive one raw probe-protocol exchange through the proxy, with a
/// caller-chosen correlation identifier, and return the response text.
///
/// The shipped probe mints its own identifier and never discloses it, so this
/// is how a scenario observes the *binding* the probe depends on: that the
/// verdict the proxy answers with is the verdict for the request that carried
/// that identifier, and for no other.
pub async fn raw_probe_exchange(
    proxy: SocketAddr,
    ca_pem: &std::path::Path,
    correlation_id: &str,
    text: &str,
) -> anyhow::Result<String> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let config = client_trusting_pem(ca_pem).await?;
    let target = format!("{ANTHROPIC_HOST}:443");
    let mut tcp = TcpStream::connect(proxy).await?;
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(tcp);
    let mut status = String::new();
    reader.read_line(&mut status).await?;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header).await?;
        if n == 0 || header.trim().is_empty() {
            break;
        }
    }
    anyhow::ensure!(
        status.contains("200"),
        "the proxy refused the tunnel: {}",
        status.trim()
    );

    let server_name = ServerName::try_from(ANTHROPIC_HOST.to_owned())?;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name, reader.into_inner())
        .await?;
    let body = serde_json::json!({
        "model": "claude-sonnet-4-5",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    })
    .to_string();
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {ANTHROPIC_HOST}\r\nContent-Type: application/json\r\n\
         anthropic-version: 2023-06-01\r\n{}: {correlation_id}\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        aa_proxy::probe_adjudication::PROBE_CORRELATION_HEADER,
        body.len(),
    );
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
