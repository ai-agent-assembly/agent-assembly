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
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};

use crate::spike_support::proxy_harness::drive_emulated_client;
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
