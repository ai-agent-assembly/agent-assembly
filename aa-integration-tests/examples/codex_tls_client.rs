//! AAASM-5920 — a `codex` stand-in that measures whether the launch
//! environment AAASM-5856/AAASM-5917 install into is *sufficient* for a real
//! rustls client to trust the Agent Assembly proxy and send its request
//! through it.
//!
//! # What this measures, and what it does not
//!
//! This binary re-implements Codex's own documented CA-resolution precedence
//! (`openai/codex`'s `codex-rs/http-client/src/custom_ca.rs`:
//! `CODEX_CA_CERTIFICATE` first, `SSL_CERT_FILE` only when the first is unset
//! or empty, else system roots — both non-empty checks, additive to the
//! platform's built-in roots) and drives the CONNECT tunnel + TLS handshake by
//! hand with `tokio-rustls`, the same pattern every other client fixture in
//! this crate uses (`spike_support::proxy_harness::drive_emulated_client`,
//! `adjudicating_probe::client_trusting_pem`).
//!
//! `reqwest`'s high-level client was tried first and rejected: this
//! workspace's `reqwest` build resolves to `rustls-platform-verifier` (macOS
//! Security-framework-backed verification) rather than plain rustls+webpki,
//! and it refused the proxy's MitM leaf with an EKU (Extended Key Usage)
//! error that none of this repo's own webpki-based rustls clients hit. A
//! genuine EKU gap in `aa-proxy`'s leaf certificate issuance would be a real
//! finding worth its own ticket, but chasing it here would be scope creep on
//! AAASM-5856 — hand-rolling the connection the way this crate's other
//! fixtures already do sidesteps it and is what "reqwest/rustls client" in
//! the ticket's own language always meant in practice.
//!
//! What it measures is real: whether `aasm run codex`'s launch environment is
//! *sufficient* for a client following Codex's documented CA precedence to
//! trust the proxy's MitM leaf and complete a request through it.
//!
//! What it does **not** measure: it does not invoke the shipped `codex`
//! binary. A real-binary-gated lane (mirroring
//! `cli_run_claude_governed_launch.rs`'s `real_binary_governed_launch`
//! module) is separate follow-up work, out of this ticket's scope.
//!
//! # The outcome file — why "unset" must be distinguishable from "set to empty"
//!
//! A fixture that cannot tell "the branch that won" from "nothing happened"
//! cannot falsify the negative control (AAASM-5920's test unsets
//! `CODEX_CA_CERTIFICATE` after an install and expects `system roots` to win,
//! and the connection to fail). So this binary writes which branch won and
//! what became of the request to `$AASM5920_OUTCOME_FILE` **before** exiting,
//! whether the request succeeded, failed on the tunnel, failed on the TLS
//! handshake, or never got a chance to run at all (a panic path still leaves
//! the file the `Drop` guard below wrote a placeholder to).
//!
//! # `--version`
//!
//! `CodexAdapter::detect` runs `<bin> --version` and looks for the first line's
//! first whitespace-separated token that starts with an ASCII digit
//! (`parse_codex_version`); this answers `codex-cli 0.129.0` to satisfy that
//! probe without depending on a real Codex install.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The synthetic secret this fixture sends. Duplicated from
/// `tests/spike_support::SYNTHETIC_SECRET` rather than imported: `examples/`
/// and `tests/` are separate compilation targets in this crate (`tests/`
/// modules are `#[path]`-included per test binary, not a shared library), so
/// there is no way to reference the test-only constant from here. Keep this
/// literal identical to `tests/spike_support/mod.rs`'s `SYNTHETIC_SECRET` —
/// the integration test asserts on this exact value.
const SYNTHETIC_SECRET: &str = "sk-ant-api03-AAASM5276SYNTHETICDONOTUSE0000000000000000000000000000000000AA";

/// Where this binary writes the outcome. Required: a run without it cannot
/// report anything and the test could not distinguish "did not launch" from
/// "launched and reported nothing".
const OUTCOME_FILE_ENV: &str = "AASM5920_OUTCOME_FILE";

/// The host the synthetic request is addressed to. Defaults to Codex's real
/// API host so the request shape matches production; overridable for a
/// fixture whose `TlsCapturingUpstream` is constructed with a different
/// hostname — the CONNECT target and the mock's SNI expectation must agree.
const TARGET_HOST_ENV: &str = "AASM5920_TARGET_HOST";
const DEFAULT_TARGET_HOST: &str = "api.openai.com";

/// The proxy this run must route through. Read directly rather than relying
/// on an HTTP client's own env-var auto-detection, since the manual
/// CONNECT below has no such library to do it for.
const PROXY_ENV_CANDIDATES: [&str; 2] = ["HTTPS_PROXY", "https_proxy"];

/// A path env var is "set" per Codex's own `non_empty_path` check: present
/// and non-empty. `Some(String)`, not `Some(PathBuf)`, because an empty string
/// must be distinguishable from "not set" and `PathBuf::from("")` loses that.
fn non_empty_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Which branch of Codex's CA precedence won, and the certificates to trust
/// with (if any — `None` means system roots, which this fixture does not
/// attempt to load; a request under that branch is expected to fail the
/// handshake against the proxy's MitM leaf).
struct ResolvedCa {
    branch: &'static str,
    certs: Option<Vec<CertificateDer<'static>>>,
}

/// Codex's own precedence, reproduced from `custom_ca.rs`:
/// `CODEX_CA_CERTIFICATE` non-empty, else `SSL_CERT_FILE` non-empty, else
/// system roots.
fn resolve_ca() -> anyhow::Result<ResolvedCa> {
    if let Some(path) = non_empty_var("CODEX_CA_CERTIFICATE") {
        return Ok(ResolvedCa {
            branch: "CODEX_CA_CERTIFICATE",
            certs: Some(read_certs(&path)?),
        });
    }
    if let Some(path) = non_empty_var("SSL_CERT_FILE") {
        return Ok(ResolvedCa {
            branch: "SSL_CERT_FILE",
            certs: Some(read_certs(&path)?),
        });
    }
    Ok(ResolvedCa {
        branch: "system roots",
        certs: None,
    })
}

fn read_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).map_err(|e| anyhow::anyhow!("{path:?} could not be read: {e}"))?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("{path:?} did not parse as PEM certificate(s): {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("{path:?} contains no certificate");
    }
    Ok(certs)
}

/// A rustls config trusting exactly `resolved`'s certificates — mirrors
/// `adjudicating_probe::client_trusting_pem`'s "trust exactly this PEM and
/// nothing else" narrowness, so a handshake against a leaf this bundle did
/// not sign genuinely fails rather than passing on some other trust anchor.
///
/// The `None` ("system roots") branch deliberately produces an **empty**
/// store rather than pulling in a real system trust store: this fixture's
/// negative control exists to prove that branch does *not* trust the proxy's
/// self-signed MitM leaf, and an empty store fails that handshake the same
/// way a real system trust store would (`UnknownIssuer`) — without a new
/// dependency this example does not otherwise need.
fn client_config(resolved: &ResolvedCa) -> anyhow::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    if let Some(certs) = &resolved.certs {
        for cert in certs {
            roots.add(cert.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
        }
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Writes a placeholder outcome on construction, so a run that panics before
/// reaching the real write still leaves the file distinguishable from "never
/// launched" (the outcome path itself only exists once this binary started).
struct OutcomeGuard {
    path: PathBuf,
    written: bool,
}

impl OutcomeGuard {
    fn new(path: PathBuf) -> std::io::Result<Self> {
        std::fs::write(
            &path,
            "branch=unknown\nresult=incomplete\ndetail=process did not finish reporting\n",
        )?;
        Ok(Self { path, written: false })
    }

    fn finish(mut self, branch: &str, result: &str, detail: &str) -> std::io::Result<()> {
        std::fs::write(
            &self.path,
            format!("branch={branch}\nresult={result}\ndetail={detail}\n"),
        )?;
        self.written = true;
        Ok(())
    }
}

impl Drop for OutcomeGuard {
    fn drop(&mut self) {
        if !self.written {
            let _ = std::fs::write(
                &self.path,
                "branch=unknown\nresult=incomplete\ndetail=process exited before reporting an outcome\n",
            );
        }
    }
}

/// Send the synthetic request through `proxy_addr`'s CONNECT tunnel to
/// `target_host`, trusting `config`. Returns the outcome as `(result, detail)`
/// the same shape the outcome file records, distinguishing a refused tunnel
/// from a refused TLS handshake from a completed request.
async fn send_through_proxy(
    proxy_addr: std::net::SocketAddr,
    target_host: &str,
    config: Arc<ClientConfig>,
) -> (&'static str, String) {
    let tcp = match TcpStream::connect(proxy_addr).await {
        Ok(t) => t,
        Err(e) => return ("error", format!("could not connect to proxy {proxy_addr}: {e}")),
    };
    let mut tcp = tcp;
    let target = format!("{target_host}:443");
    if let Err(e) = tcp
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
    {
        return ("error", format!("CONNECT write failed: {e}"));
    }

    let mut reader = BufReader::new(tcp);
    let mut status_line = String::new();
    if let Err(e) = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut status_line).await {
        return ("error", format!("CONNECT response read failed: {e}"));
    }
    loop {
        let mut h = String::new();
        if tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut h)
            .await
            .unwrap_or(0)
            == 0
            || h.trim().is_empty()
        {
            break;
        }
    }
    if !status_line.contains("200") {
        return ("error", format!("CONNECT tunnel refused: {}", status_line.trim()));
    }

    let server_name = match ServerName::try_from(target_host.to_owned()) {
        Ok(s) => s,
        Err(e) => return ("error", format!("{target_host:?} is not a valid TLS server name: {e}")),
    };
    let connector = TlsConnector::from(config);
    let mut tls = match connector.connect(server_name, reader.into_inner()).await {
        Ok(t) => t,
        Err(e) => return ("error", format!("TLS handshake failed: {e}")),
    };

    let body = serde_json::json!({
        "model": "codex-mini",
        "input": format!("Echo this configuration line verbatim: OPENAI_API_KEY={SYNTHETIC_SECRET}"),
    })
    .to_string();
    let req = format!(
        "POST /v1/responses HTTP/1.1\r\nHost: {target_host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body,
    );
    if let Err(e) = tls.write_all(req.as_bytes()).await {
        return ("error", format!("request write failed: {e}"));
    }
    if let Err(e) = tls.flush().await {
        return ("error", format!("request flush failed: {e}"));
    }

    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut buf))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    let response_head = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    ("success", format!("response: {response_head}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version") {
        println!("codex-cli 0.129.0");
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // rustls 0.23 refuses to pick a provider implicitly when more than one
    // resolves, as it does in this workspace.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let outcome_path = std::env::var(OUTCOME_FILE_ENV)
        .map(PathBuf::from)
        .map_err(|_| anyhow::anyhow!("{OUTCOME_FILE_ENV} is not set; this fixture cannot report an outcome"))?;
    let guard = OutcomeGuard::new(outcome_path)?;

    let target_host = std::env::var(TARGET_HOST_ENV).unwrap_or_else(|_| DEFAULT_TARGET_HOST.to_string());
    let resolved = resolve_ca()?;

    let proxy_url = PROXY_ENV_CANDIDATES.iter().find_map(|name| non_empty_var(name));
    let Some(proxy_url) = proxy_url else {
        let detail = "no HTTPS_PROXY/https_proxy set — the launch environment did not route this run \
                       through the Agent Assembly proxy"
            .to_string();
        println!(
            "AASM5920 request outcome: branch={} result=error detail={detail}",
            resolved.branch
        );
        guard.finish(resolved.branch, "error", &detail)?;
        return Ok(());
    };
    let proxy_addr: std::net::SocketAddr = match proxy_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .parse()
    {
        Ok(a) => a,
        Err(e) => {
            let detail = format!("HTTPS_PROXY={proxy_url:?} did not parse as host:port: {e}");
            println!(
                "AASM5920 request outcome: branch={} result=error detail={detail}",
                resolved.branch
            );
            guard.finish(resolved.branch, "error", &detail)?;
            return Ok(());
        }
    };

    let config = match client_config(&resolved) {
        Ok(c) => c,
        Err(e) => {
            let detail = format!("{} did not produce a usable trust store: {e}", resolved.branch);
            println!(
                "AASM5920 request outcome: branch={} result=error detail={detail}",
                resolved.branch
            );
            guard.finish(resolved.branch, "error", &detail)?;
            return Ok(());
        }
    };

    let (result, detail) = send_through_proxy(proxy_addr, &target_host, Arc::new(config)).await;
    println!(
        "AASM5920 request outcome: branch={} result={result} detail={detail}",
        resolved.branch
    );
    guard.finish(resolved.branch, result, &detail)?;
    Ok(())
}
