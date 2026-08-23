//! Mechanism A harness: `HTTPS_PROXY` + `aa-proxy` MitM (AAASM-5276 Spike).
//!
//! `aa-proxy` is a **forward** CONNECT MitM proxy keyed on host
//! (`aa-proxy/src/intercept/detect.rs:32` maps `api.anthropic.com` →
//! `LlmApiPattern::Anthropic`). Nothing in the workspace serves an
//! Anthropic-compatible `/v1/messages` endpoint, so this is the *only*
//! model-path interception AASM can offer Claude Code today — which is why the
//! Spike measures it directly rather than through a gateway abstraction.
//!
//! Two drivers reach the same proxy:
//!
//! * [`drive_emulated_client`] — a rustls client that speaks the Anthropic
//!   Messages request shape. Runs on every platform, so the deterministic
//!   protection assertions are not gated on a macOS binary.
//! * [`ClaudeLaunch`] — the real `claude` binary, spawned with `HTTPS_PROXY`
//!   and `NODE_EXTRA_CA_CERTS`. Skips cleanly where the binary is absent.
//!
//! `NODE_TLS_REJECT_UNAUTHORIZED` is never set: if MitM TLS fails, that failure
//! is the finding.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aa_proxy::audit_jsonl::ProxyAuditEntry;
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::proxy::ProxyServer;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use base64::Engine as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio_rustls::TlsConnector;

/// Host Claude Code (and the emulated client) reaches for the Messages API.
pub const ANTHROPIC_HOST: &str = "api.anthropic.com";

/// Install rustls's default crypto provider exactly once per process.
///
/// Both `aws-lc-rs` and `ring` resolve in this workspace, so rustls 0.23 refuses
/// to choose one implicitly.
pub fn install_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A running proxy under test.
pub struct ProxyHarness {
    /// Address to point `HTTPS_PROXY` at.
    pub addr: SocketAddr,
    /// Directory holding `ca-cert.pem`, for `NODE_EXTRA_CA_CERTS`.
    pub ca_dir: std::path::PathBuf,
    /// Runtime pipeline events the proxy emitted. Held so the channel stays
    /// open; drained by the audit-hygiene scenario.
    pub events: broadcast::Receiver<PipelineEvent>,
    abort: tokio::task::AbortHandle,
    /// Wall-clock time the proxy took to accept its first connection.
    pub startup: Duration,
}

impl ProxyHarness {
    /// Start a proxy that MitMs every host, redirects all upstream dials to
    /// `upstream`, and applies `action` to credential findings.
    pub async fn start(
        ca_dir: &Path,
        ca: CaStore,
        action: CredentialAction,
        upstream: SocketAddr,
        audit_tx: Option<mpsc::Sender<ProxyAuditEntry>>,
    ) -> anyhow::Result<Self> {
        let port = portpicker::pick_unused_port().ok_or_else(|| anyhow::anyhow!("no free TCP port"))?;
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let config = ProxyConfig {
            bind_addr,
            ca_dir: ca_dir.to_path_buf(),
            cert_cache_capacity: 32,
            // MitM every host: the real binary also talks to side-channel hosts
            // (an MCP registry among them) and the Spike wants those bodies in
            // the capture set too, so a secret leaking down a side channel is
            // not silently out of scope.
            llm_only: false,
            mitm_hosts: Vec::new(),
            denied_hosts: Vec::new(),
            network_allowlist: Vec::new(),
            skip_upstream_tls_verify: true,
            credential_action: action,
            upstream_override: Some(upstream),
            gateway_endpoint: None,
            mcp_fail_open: false,
            network_fail_open: false,
            allow_private_connect_targets: false,
        };
        let (tx, events) = broadcast::channel(256);
        let server = ProxyServer::new_with_audit_sink(config, ca, tx, audit_tx);
        let started = std::time::Instant::now();
        let jh = tokio::spawn(async move {
            let _ = server.run().await;
        });
        let abort = jh.abort_handle();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if TcpStream::connect(bind_addr).await.is_ok() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("proxy did not start on {bind_addr}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Ok(Self {
            addr: bind_addr,
            ca_dir: ca_dir.to_path_buf(),
            events,
            abort,
            startup: started.elapsed(),
        })
    }

    /// Proxy URL in the form `HTTPS_PROXY` expects.
    pub fn proxy_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Path to the CA PEM, for `NODE_EXTRA_CA_CERTS`.
    pub fn ca_pem(&self) -> std::path::PathBuf {
        self.ca_dir.join("ca-cert.pem")
    }

    /// Stop the proxy — the 11.9 "core stopped mid-session" lever.
    pub fn stop(&self) {
        self.abort.abort();
    }

    /// Whether the proxy still accepts connections. Drives the fail-closed
    /// assertion: after [`stop`](Self::stop) this must become `false`.
    pub async fn is_reachable(&self) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(self.addr)).await,
            Ok(Ok(_))
        )
    }
}

impl Drop for ProxyHarness {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

/// Build a rustls client config trusting the proxy's CA, so the MitM-issued
/// leaf for `api.anthropic.com` verifies.
pub async fn client_trusting_proxy_ca(ca_dir: &Path) -> anyhow::Result<ClientConfig> {
    let pem = tokio::fs::read_to_string(ca_dir.join("ca-cert.pem")).await?;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(body)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(der))?;
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Outcome of driving one request through the proxy.
#[derive(Debug)]
pub struct DriveResult {
    /// CONNECT response status line.
    pub connect_status: String,
    /// Inner HTTP response text, or `None` when CONNECT itself was refused.
    pub inner_response: Option<String>,
    /// Wall-clock time from opening the TCP connection to reading the response.
    pub elapsed: Duration,
}

impl DriveResult {
    /// Whether the CONNECT tunnel was established.
    pub fn connected(&self) -> bool {
        self.connect_status.contains("200")
    }
}

/// Drive one Anthropic Messages request through the proxy with a rustls client.
///
/// Emulates the request shape the real binary sends (`POST /v1/messages`,
/// `anthropic-version` header, JSON body) so the proxy's Anthropic extractor and
/// the credential scanner see production-shaped bytes. This is emulated traffic,
/// not real-binary traffic — the Spike reports the two separately.
pub async fn drive_emulated_client(
    proxy_addr: SocketAddr,
    client_config: Arc<ClientConfig>,
    prompt: &str,
) -> anyhow::Result<DriveResult> {
    let started = std::time::Instant::now();
    let mut tcp = TcpStream::connect(proxy_addr).await?;
    let target = format!("{ANTHROPIC_HOST}:443");
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;

    let mut reader = BufReader::new(tcp);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).await?;
        if h.trim().is_empty() {
            break;
        }
    }
    if !status_line.contains("200") {
        return Ok(DriveResult {
            connect_status: status_line,
            inner_response: None,
            elapsed: started.elapsed(),
        });
    }

    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from(ANTHROPIC_HOST.to_owned())?;
    let mut tls = match connector.connect(server_name, reader.into_inner()).await {
        Ok(t) => t,
        Err(e) => {
            return Ok(DriveResult {
                connect_status: status_line,
                inner_response: Some(format!("TLS error: {e}")),
                elapsed: started.elapsed(),
            });
        }
    };

    let body = serde_json::json!({
        "model": "claude-sonnet-4-5",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
    })
    .to_string();
    let req = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {ANTHROPIC_HOST}\r\nContent-Type: application/json\r\n\
         anthropic-version: 2023-06-01\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    tls.write_all(req.as_bytes()).await?;
    tls.flush().await?;

    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut buf))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    Ok(DriveResult {
        connect_status: status_line,
        inner_response: Some(String::from_utf8_lossy(&buf[..n]).into_owned()),
        elapsed: started.elapsed(),
    })
}

/// Drive one Anthropic Messages request **straight** at a plain-HTTP endpoint,
/// with no proxy in the path.
///
/// Used for Mechanism B (base-URL redirection) and for the unmanaged-launch
/// bypass scenario: both must show the secret arriving raw.
pub async fn drive_direct(base_url: &str, prompt: &str) -> anyhow::Result<Duration> {
    let started = std::time::Instant::now();
    let body = serde_json::json!({
        "model": "claude-sonnet-4-5",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}],
    });
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/v1/messages"))
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .await?;
    anyhow::ensure!(resp.status().is_success(), "mock provider returned {}", resp.status());
    let _ = resp.bytes().await?;
    Ok(started.elapsed())
}

// ── Real-binary launch ──────────────────────────────────────────────────────

/// Outcome of spawning the real `claude` binary.
#[derive(Debug)]
pub struct ClaudeRun {
    /// Process exit status as reported, or `None` on timeout.
    pub exit_code: Option<i32>,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Wall-clock duration of the run.
    pub elapsed: Duration,
    /// Whether the run hit the harness timeout.
    pub timed_out: bool,
}

/// Builder for a headless `claude -p` run against a throwaway config home.
///
/// Every run sets `CLAUDE_CONFIG_DIR` and `HOME` into the temp tree, so the
/// developer's real `~/.claude` is never a candidate path for any writer.
pub struct ClaudeLaunch {
    bin: std::path::PathBuf,
    home: std::path::PathBuf,
    cwd: std::path::PathBuf,
    env: Vec<(String, String)>,
    prompt: String,
    timeout: Duration,
}

impl ClaudeLaunch {
    /// Start a launch pinned to `bin`, a throwaway `home`, and a working `cwd`.
    pub fn new(bin: &Path, home: &Path, cwd: &Path, prompt: impl Into<String>) -> Self {
        Self {
            bin: bin.to_path_buf(),
            home: home.to_path_buf(),
            cwd: cwd.to_path_buf(),
            env: Vec::new(),
            prompt: prompt.into(),
            timeout: Duration::from_secs(120),
        }
    }

    /// Add an environment variable to the child.
    pub fn env(mut self, key: &str, value: impl Into<String>) -> Self {
        self.env.push((key.to_owned(), value.into()));
        self
    }

    /// Override the harness timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Spawn the binary, wait until `evidence_ready()` returns true (or
    /// `patience` expires), then terminate it and collect what it produced.
    ///
    /// Measured on the target machine: with every host MitM'd onto a single
    /// mock upstream, `claude -p` emits its Messages request within a few
    /// seconds but then never exits — its side channels (MCP registry,
    /// `/api/event_logging`) never get the answers they expect. Waiting for a
    /// clean exit would cost 150s per run for evidence that is complete after
    /// ~15s, so the harness collects the evidence and stops the child.
    pub async fn run_until(self, patience: Duration, evidence_ready: impl Fn() -> bool) -> anyhow::Result<ClaudeRun> {
        let mut cmd = self.command();
        let started = std::time::Instant::now();
        let mut child = cmd.spawn()?;

        let deadline = tokio::time::Instant::now() + patience;
        let mut exited = None;
        loop {
            if let Some(status) = child.try_wait()? {
                exited = Some(status);
                break;
            }
            if evidence_ready() || tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let timed_out = exited.is_none();
        if timed_out {
            let _ = child.kill().await;
        }
        let output = child.wait_with_output().await?;
        Ok(ClaudeRun {
            exit_code: exited.and_then(|s| s.code()),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            elapsed: started.elapsed(),
            timed_out,
        })
    }

    fn command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.bin);
        cmd.arg("-p")
            .arg(&self.prompt)
            .current_dir(&self.cwd)
            // SAFETY: both must point into the temp tree. `CLAUDE_CONFIG_DIR`
            // redirects Claude Code's own config home; `HOME` covers every other
            // consumer (including the AASM adapter's `$HOME` fallback).
            .env("HOME", &self.home)
            .env("CLAUDE_CONFIG_DIR", self.home.join(".claude"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        cmd
    }

    /// Spawn the binary and wait for it to exit on its own.
    pub async fn run(self) -> anyhow::Result<ClaudeRun> {
        let mut cmd = self.command();
        let started = std::time::Instant::now();
        let child = cmd.spawn()?;
        match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(output) => {
                let output = output?;
                Ok(ClaudeRun {
                    exit_code: output.status.code(),
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    elapsed: started.elapsed(),
                    timed_out: false,
                })
            }
            Err(_) => Ok(ClaudeRun {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                elapsed: started.elapsed(),
                timed_out: true,
            }),
        }
    }
}
