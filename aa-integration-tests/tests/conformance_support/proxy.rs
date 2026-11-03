//! A live `aa-proxy` that can be stopped and brought back on the same address.
//!
//! # Why not reuse the Spike's `ProxyHarness`
//!
//! [`crate::spike_support::proxy_harness::ProxyHarness`] picks its own port and
//! offers no way back once [`stop`](Self::stop) has been called. That is enough
//! to measure "a stopped core refuses connections" but not enough for the
//! conformance suite's runtime-failure scenario, which has to prove the third
//! clause too: **recovery is possible after the runtime restarts**. Recovery is
//! only meaningful at the *same* endpoint, because the endpoint is what the
//! receipt records and what the installed launch environment points at — coming
//! back on a different port would be a reinstall, not a recovery.
//!
//! So the first start lets the proxy pick its own port and report it, and every
//! restart rebinds that same port.
//!
//! # Why the port is not picked here (AAASM-6435)
//!
//! Picking a free port, releasing it, and letting the proxy bind it later is a
//! race: the conformance tests run as parallel processes, two of them can pick
//! the same port, and the loser's bind fails inside a task nobody awaits. A
//! "can I connect to it" readiness check then succeeds against the *other*
//! test's proxy, whose certificate authority is a different one, and the client
//! reports `BadSignature`. A successful connect proves something is listening,
//! not that it is this proxy. Readiness is therefore taken from the proxy's own
//! `ready_file` (AAASM-5859), which it writes only after its bind has succeeded
//! and which names the process that wrote it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aa_proxy::audit_jsonl::ProxyAuditEntry;
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::proxy::ProxyServer;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

/// A proxy whose lifetime the test controls.
pub struct RestartableProxy {
    /// The address every start binds. Port 0 until the first start reports the
    /// real one; stable across a stop/start cycle after that, which is what
    /// makes "recovered" distinguishable from "reinstalled".
    pub addr: SocketAddr,
    ca_dir: PathBuf,
    /// Where the proxy writes its bound address once it is listening.
    ready_file: PathBuf,
    upstream: SocketAddr,
    action: CredentialAction,
    audit_tx: Option<mpsc::Sender<ProxyAuditEntry>>,
    /// Held so the broadcast channel keeps a receiver and the proxy's pipeline
    /// sends do not fail for want of one.
    _events: Option<broadcast::Receiver<PipelineEvent>>,
    abort: Option<tokio::task::AbortHandle>,
}

impl RestartableProxy {
    /// Start a proxy that MitMs every host, redirects all upstream dials to
    /// `upstream`, and applies `action` to credential findings.
    ///
    /// `llm_only` is off deliberately: the tool's side channels carry prompt
    /// and telemetry bodies too (AAASM-5276 condition C5), and a capture set
    /// scoped to the model endpoint alone would let a secret leaking down one
    /// of them pass unnoticed.
    pub async fn start(
        ca_dir: &Path,
        upstream: SocketAddr,
        action: CredentialAction,
        audit_tx: Option<mpsc::Sender<ProxyAuditEntry>>,
    ) -> anyhow::Result<Self> {
        Self::start_at(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            ca_dir,
            upstream,
            action,
            audit_tx,
        )
        .await
    }

    /// Like [`start`](Self::start), but binding `addr`. Port 0 asks the proxy to
    /// choose and report the real port; a concrete port is bound exactly, and
    /// the start fails if something else already holds it.
    pub async fn start_at(
        addr: SocketAddr,
        ca_dir: &Path,
        upstream: SocketAddr,
        action: CredentialAction,
        audit_tx: Option<mpsc::Sender<ProxyAuditEntry>>,
    ) -> anyhow::Result<Self> {
        let mut this = Self {
            addr,
            ca_dir: ca_dir.to_path_buf(),
            ready_file: ca_dir.join("proxy.ready"),
            upstream,
            action,
            audit_tx,
            _events: None,
            abort: None,
        };
        this.spawn().await?;
        Ok(this)
    }

    /// URL in the form `HTTPS_PROXY` — and the integration's receipt — expects.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stop accepting connections. The 11.9 "core stopped mid-session" lever.
    pub fn stop(&mut self) {
        if let Some(abort) = self.abort.take() {
            abort.abort();
        }
    }

    /// Bring the proxy back on the same address.
    pub async fn restart(&mut self) -> anyhow::Result<()> {
        self.stop();
        // Wait for the listener to actually go, so the rebind is not racing the
        // aborted task's drop.
        for _ in 0..200 {
            if !self.is_reachable().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.spawn().await
    }

    /// Whether the proxy still accepts connections.
    pub async fn is_reachable(&self) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(self.addr)).await,
            Ok(Ok(_))
        )
    }

    /// The address the proxy reports it is listening on, but only when this very
    /// process's proxy wrote it and it is the address asked for (any port when
    /// port 0 was asked). A leftover file, or one written by another process,
    /// is not readiness.
    fn reported_addr(&self) -> Option<SocketAddr> {
        let text = std::fs::read_to_string(&self.ready_file).ok()?;
        let mut lines = text.lines();
        let reported: SocketAddr = lines.next()?.parse().ok()?;
        let pid: u32 = lines.next()?.parse().ok()?;
        let asked_for_it = self.addr.port() == 0 || reported == self.addr;
        (pid == std::process::id() && asked_for_it).then_some(reported)
    }

    /// Bind and serve, retrying a few times so a lingering listener from the
    /// previous incarnation cannot turn a recovery into a flake.
    async fn spawn(&mut self) -> anyhow::Result<()> {
        let mut last = None;
        for attempt in 0..5 {
            // A file left by the previous incarnation must not read as this
            // one's readiness.
            let _ = std::fs::remove_file(&self.ready_file);
            let ca = CaStore::load_or_create(&self.ca_dir)
                .await
                .map_err(|e| anyhow::anyhow!("certificate authority: {e}"))?;
            let config = ProxyConfig {
                bind_addr: self.addr,
                ca_dir: self.ca_dir.clone(),
                cert_cache_capacity: 32,
                llm_only: false,
                mitm_hosts: Vec::new(),
                denied_hosts: Vec::new(),
                network_allowlist: Vec::new(),
                skip_upstream_tls_verify: true,
                credential_action: self.action,
                upstream_override: Some(self.upstream),
                gateway_endpoint: None,
                mcp_fail_open: false,
                network_fail_open: false,
                agent_id: None,
                ready_file: Some(self.ready_file.clone()),
                parent_pid: None,
                allow_private_connect_targets: false,
                trusted_config_path: None,
            };
            let (tx, events) = broadcast::channel(256);
            let server = ProxyServer::new_with_audit_sink(config, ca, tx, self.audit_tx.clone());
            let handle = tokio::spawn(async move {
                let _ = server.run().await;
            });
            let abort = handle.abort_handle();

            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                // `run` returning means the bind (or startup) failed: whatever
                // answers on this address is not our proxy.
                if handle.is_finished() {
                    break;
                }
                if let Some(bound) = self.reported_addr() {
                    self.addr = bound;
                    self._events = Some(events);
                    self.abort = Some(abort);
                    return Ok(());
                }
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            abort.abort();
            last = Some(anyhow::anyhow!(
                "proxy did not accept on {} (attempt {})",
                self.addr,
                attempt + 1
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("proxy did not start on {}", self.addr)))
    }
}

impl Drop for RestartableProxy {
    fn drop(&mut self) {
        self.stop();
    }
}
