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
//! So this harness reserves the port up front and rebinds it on every start.

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
    /// The address every start binds. Stable across a stop/start cycle, which
    /// is what makes "recovered" distinguishable from "reinstalled".
    pub addr: SocketAddr,
    ca_dir: PathBuf,
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
        let port = portpicker::pick_unused_port().ok_or_else(|| anyhow::anyhow!("no free TCP port"))?;
        let mut this = Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            ca_dir: ca_dir.to_path_buf(),
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

    /// Bind and serve, retrying a few times so a lingering listener from the
    /// previous incarnation cannot turn a recovery into a flake.
    async fn spawn(&mut self) -> anyhow::Result<()> {
        let mut last = None;
        for attempt in 0..5 {
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
                ready_file: None,
                allow_private_connect_targets: false,
            };
            let (tx, events) = broadcast::channel(256);
            let server = ProxyServer::new_with_audit_sink(config, ca, tx, self.audit_tx.clone());
            let handle = tokio::spawn(async move {
                let _ = server.run().await;
            });
            let abort = handle.abort_handle();

            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                if TcpStream::connect(self.addr).await.is_ok() {
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
