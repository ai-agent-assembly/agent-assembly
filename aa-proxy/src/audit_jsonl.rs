//! Proxy-side audit record for the MitM data path.
//!
//! [`ProxyAuditEntry`] is the small, self-contained record the proxy emits
//! after handling one intercepted request. It carries the decision the proxy
//! made (forward / forward-redacted / block) plus any `credential_findings`
//! produced by the in-path scanner, but never the raw secret bytes.
//!
//! Layer naming note: unlike `aa-gateway::audit::AuditWriter` (which persists
//! a hash-chained `AuditEntry`), this module is the proxy's purpose-built
//! sink. The two records have different shapes because the proxy and the
//! gateway observe different things; see the JSONL writer added in a later
//! commit for how this struct reaches disk.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use aa_core::CredentialFinding;

/// Decision recorded for a single intercepted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAuditDecision {
    /// Request forwarded unmodified (no findings, or policy `alert_only`).
    Forwarded,
    /// Request forwarded with secrets replaced by `[REDACTED:<Kind>]`
    /// markers in the body (policy `redact_only`).
    ForwardedRedacted,
    /// Request blocked at the proxy; upstream never dialled (policy `block`).
    Blocked,
}

/// A single audit record emitted by the proxy's data path.
///
/// `redacted_body` carries the *post-scan* body bytes (the form that was or
/// would have been forwarded). The original raw body is never stored — only
/// its redacted projection. `credential_findings` is the per-match metadata
/// produced by `CredentialScanner`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuditEntry {
    /// Wall-clock timestamp in milliseconds since the Unix epoch.
    pub ts_ms: i64,
    /// Agent identifier that owned the connection, when known.
    pub agent_id: Option<String>,
    /// Target host (no port) from the CONNECT line.
    pub host: String,
    /// HTTP method of the intercepted request inside the tunnel.
    pub method: String,
    /// Request path of the intercepted request inside the tunnel.
    pub path: String,
    /// What the proxy did with the request.
    pub decision: ProxyAuditDecision,
    /// Per-match scanner output. Empty when no secrets were detected.
    pub credential_findings: Vec<CredentialFinding>,
    /// Post-scan body content. `None` when the proxy bypassed the scanner.
    pub redacted_body: Option<String>,
}

/// Append-only JSONL writer.
///
/// Construct with [`JsonlWriter::new`], drive with `tokio::spawn(writer.run())`.
/// The task terminates when all senders drop and the channel closes.
pub struct JsonlWriter {
    receiver: mpsc::Receiver<ProxyAuditEntry>,
    file: tokio::io::BufWriter<tokio::fs::File>,
    path: PathBuf,
}

impl JsonlWriter {
    /// Open `path` in append mode (creating it if missing) and bind the
    /// supplied receiver. Parent directories must already exist.
    pub async fn new(path: &Path, receiver: mpsc::Receiver<ProxyAuditEntry>) -> io::Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self {
            receiver,
            file: tokio::io::BufWriter::new(file),
            path: path.to_path_buf(),
        })
    }

    /// Path the writer is appending to (useful for tests).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Background consumption loop.
    ///
    /// One entry per JSON line, flushed per write so external observers see
    /// the line as soon as the proxy returns to the client. Per-entry write
    /// failures are logged but do not stop the loop — losing one audit line
    /// is preferable to silently halting subsequent requests.
    pub async fn run(mut self) {
        tracing::info!(path = %self.path.display(), "proxy audit jsonl writer started");
        while let Some(entry) = self.receiver.recv().await {
            if let Err(e) = self.append(&entry).await {
                tracing::error!(error = %e, "proxy audit jsonl write failed");
            }
        }
        if let Err(e) = self.file.flush().await {
            tracing::error!(error = %e, "proxy audit jsonl final flush failed");
        }
        tracing::info!(path = %self.path.display(), "proxy audit jsonl writer stopped");
    }

    async fn append(&mut self, entry: &ProxyAuditEntry) -> io::Result<()> {
        let json = serde_json::to_string(entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.file.write_all(json.as_bytes()).await?;
        self.file.write_all(b"\n").await?;
        self.file.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic AWS access key from AWS public documentation. Not a real credential.
    const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    /// Security invariant: the raw secret value must never appear in the
    /// JSONL file on disk, even when the body that produced the finding
    /// embedded the secret verbatim. Drives the AAASM-1566 acceptance
    /// criterion "grep for the raw key against the JSONL file returns 0
    /// matches".
    #[tokio::test]
    async fn audit_writer_never_writes_raw_secret() {
        use aa_core::CredentialScanner;

        let body = format!(r#"{{"k":"{FAKE_AWS_ACCESS_KEY}"}}"#);
        let scan = CredentialScanner::new().scan(&body);
        assert!(
            !scan.findings.is_empty(),
            "scanner fixture invariant — AWS key must be detected"
        );
        let redacted = scan.redact(&body);

        let entry = ProxyAuditEntry {
            ts_ms: 1_700_000_000_000,
            agent_id: Some("agent-1".into()),
            host: "api.openai.com".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            decision: ProxyAuditDecision::ForwardedRedacted,
            credential_findings: scan.findings,
            redacted_body: Some(redacted),
        };

        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("proxy-audit.jsonl");
        let (tx, rx) = mpsc::channel(4);
        let writer = JsonlWriter::new(&path, rx).await.expect("open jsonl writer");
        let handle = tokio::spawn(writer.run());

        tx.send(entry).await.expect("send entry");
        drop(tx);
        handle.await.expect("writer task joins cleanly");

        let on_disk = tokio::fs::read_to_string(&path).await.expect("read JSONL");
        assert!(
            !on_disk.contains(FAKE_AWS_ACCESS_KEY),
            "SECURITY INVARIANT VIOLATED: raw secret present in proxy audit JSONL: {on_disk}",
        );
        assert!(
            on_disk.contains("[REDACTED:AwsAccessKey]"),
            "JSONL must carry the [REDACTED:AwsAccessKey] marker, got: {on_disk}",
        );
        assert_eq!(
            on_disk.matches('\n').count(),
            1,
            "single entry must produce exactly one trailing newline: {on_disk}",
        );
    }
}
