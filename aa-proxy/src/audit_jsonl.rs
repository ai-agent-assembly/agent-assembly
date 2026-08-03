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

use aa_core::types::sensitive_data::ExecutionEvidence;
use aa_security::CredentialFinding;

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
    /// What was **observed** about whether the payload left this process.
    ///
    /// [`Self::decision`] is what the proxy resolved to do; this is what
    /// happened to the bytes, and the two are not the same claim. A
    /// [`ProxyAuditDecision::ForwardedRedacted`] is a *transformed
    /// transmission* — the scrubbed bytes went — and only evidence recorded
    /// here can distinguish that from a payload that never left, which is the
    /// distinction ADR 0032 §8's prevention rule turns on (AAASM-5358).
    ///
    /// Built by [`crate::transmission_evidence`]; there is no default, because
    /// a record that omitted it would be an event with no execution evidence,
    /// and the whole point is that such an event exists and says so out loud
    /// rather than being absent.
    pub execution: ExecutionEvidence,
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

/// Bounded capacity of the audit channel.
///
/// The data path uses `try_send` and drops on overflow rather than
/// back-pressuring an intercepted request, so this bound is the amount of
/// writer lag the proxy will absorb before audit lines start being lost.
const AUDIT_CHANNEL_CAPACITY: usize = 1024;

/// Open the audit sink an operator asked for, and spawn the writer that drains
/// it.
///
/// `None` in, `None` out: no path configured means no persistence, which is
/// the historical default and leaves the data path byte-identical.
///
/// # Errors
///
/// Propagates the open failure rather than degrading to `None`. An operator who
/// configured an audit trail and silently got none would be in exactly the state
/// this whole work stream exists to prevent — believing a record exists when it
/// does not — so the proxy refuses to start instead.
pub async fn build_audit_sink(path: Option<&Path>) -> io::Result<Option<mpsc::Sender<ProxyAuditEntry>>> {
    let Some(path) = path else { return Ok(None) };
    let (tx, rx) = mpsc::channel(AUDIT_CHANNEL_CAPACITY);
    let writer = JsonlWriter::new(path, rx).await?;
    tokio::spawn(writer.run());
    Ok(Some(tx))
}

#[cfg(test)]
mod tests {
    use super::*;

    use aa_core::policy::EnforcementMode;
    use aa_core::types::sensitive_data::{EnforcementPoint, TransmissionEvidence};

    /// Synthetic AWS access key from AWS public documentation. Not a real credential.
    const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    /// Security invariant: the raw secret value must never appear in the
    /// JSONL file on disk, even when the body that produced the finding
    /// embedded the secret verbatim. Drives the AAASM-1566 acceptance
    /// criterion "grep for the raw key against the JSONL file returns 0
    /// matches".
    #[tokio::test]
    async fn audit_writer_never_writes_raw_secret() {
        use aa_security::CredentialScanner;

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
            execution: ExecutionEvidence::new(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::ForwardedClean,
                EnforcementMode::Enforce,
            ),
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

    /// Build a minimal clean entry (no findings, no redaction) for tests that
    /// care about framing rather than redaction.
    fn clean_entry(host: &str, decision: ProxyAuditDecision) -> ProxyAuditEntry {
        ProxyAuditEntry {
            ts_ms: 1_700_000_000_000,
            agent_id: None,
            host: host.into(),
            method: "GET".into(),
            path: "/".into(),
            decision,
            execution: ExecutionEvidence::unrecorded(EnforcementMode::Enforce),
            credential_findings: vec![],
            redacted_body: None,
        }
    }

    #[tokio::test]
    async fn writer_appends_one_jsonl_line_per_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (tx, rx) = mpsc::channel(8);
        let writer = JsonlWriter::new(&path, rx).await.unwrap();
        let handle = tokio::spawn(writer.run());

        for host in ["a.example", "b.example", "c.example"] {
            tx.send(clean_entry(host, ProxyAuditDecision::Forwarded)).await.unwrap();
        }
        drop(tx);
        handle.await.unwrap();

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = on_disk.lines().collect();
        assert_eq!(lines.len(), 3, "three entries → three lines");
        // Every line is independently valid JSON.
        for line in &lines {
            serde_json::from_str::<ProxyAuditEntry>(line).expect("each line is a valid entry");
        }
        assert!(on_disk.contains("a.example") && on_disk.contains("c.example"));
    }

    #[tokio::test]
    async fn writer_appends_to_existing_file_across_two_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        // First run writes one line, then the writer is dropped (file closed).
        {
            let (tx, rx) = mpsc::channel(4);
            let writer = JsonlWriter::new(&path, rx).await.unwrap();
            let handle = tokio::spawn(writer.run());
            tx.send(clean_entry("first.example", ProxyAuditDecision::Blocked))
                .await
                .unwrap();
            drop(tx);
            handle.await.unwrap();
        }

        // Second run opens the same path in append mode; the first line survives.
        {
            let (tx, rx) = mpsc::channel(4);
            let writer = JsonlWriter::new(&path, rx).await.unwrap();
            let handle = tokio::spawn(writer.run());
            tx.send(clean_entry("second.example", ProxyAuditDecision::Forwarded))
                .await
                .unwrap();
            drop(tx);
            handle.await.unwrap();
        }

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(on_disk.lines().count(), 2, "append mode preserves prior content");
        assert!(on_disk.contains("first.example"));
        assert!(on_disk.contains("second.example"));
    }

    #[tokio::test]
    async fn writer_with_no_entries_produces_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (tx, rx) = mpsc::channel(1);
        let writer = JsonlWriter::new(&path, rx).await.unwrap();
        let handle = tokio::spawn(writer.run());
        // Drop the sender immediately: the loop exits without writing anything.
        drop(tx);
        handle.await.unwrap();

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(on_disk.is_empty(), "no entries → empty file");
    }

    #[tokio::test]
    async fn writer_exposes_its_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (_tx, rx) = mpsc::channel(1);
        let writer = JsonlWriter::new(&path, rx).await.unwrap();
        assert_eq!(writer.path(), path.as_path());
    }

    #[tokio::test]
    async fn writer_new_errors_when_parent_dir_missing() {
        // `new` documents that parent dirs must already exist; opening under a
        // non-existent directory therefore surfaces an I/O error.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does/not/exist/audit.jsonl");
        let (_tx, rx) = mpsc::channel(1);
        // `JsonlWriter` is not `Debug`, so match the Result rather than using
        // `expect_err`, which requires `T: Debug`.
        match JsonlWriter::new(&path, rx).await {
            Ok(_) => panic!("opening under a missing parent dir must fail"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        }
    }

    #[test]
    fn decision_serializes_to_snake_case() {
        let cases = [
            (ProxyAuditDecision::Forwarded, "\"forwarded\""),
            (ProxyAuditDecision::ForwardedRedacted, "\"forwarded_redacted\""),
            (ProxyAuditDecision::Blocked, "\"blocked\""),
        ];
        for (decision, expected) in cases {
            assert_eq!(serde_json::to_string(&decision).unwrap(), expected);
            // Round-trips back to the same variant.
            let back: ProxyAuditDecision = serde_json::from_str(expected).unwrap();
            assert_eq!(back, decision);
        }
    }

    #[test]
    fn entry_round_trips_through_json_preserving_fields() {
        let entry = ProxyAuditEntry {
            ts_ms: 42,
            agent_id: Some("agent-x".into()),
            host: "api.example".into(),
            method: "POST".into(),
            path: "/v1/do".into(),
            decision: ProxyAuditDecision::ForwardedRedacted,
            execution: ExecutionEvidence::new(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::ForwardedClean,
                EnforcementMode::Enforce,
            ),
            credential_findings: vec![],
            redacted_body: Some("clean body".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ProxyAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ts_ms, 42);
        assert_eq!(back.agent_id.as_deref(), Some("agent-x"));
        assert_eq!(back.host, "api.example");
        assert_eq!(back.decision, ProxyAuditDecision::ForwardedRedacted);
        assert_eq!(back.redacted_body.as_deref(), Some("clean body"));
        assert_eq!(back.execution, entry.execution);
    }

    /// `build_audit_sink(None)` is the historical default: no path, no writer,
    /// nothing on disk.
    #[tokio::test]
    async fn no_configured_path_builds_no_sink() {
        let sink = build_audit_sink(None).await.expect("no path is not an error");
        assert!(sink.is_none(), "an unconfigured proxy must not construct a writer");
    }

    /// The wiring `run()` depends on: a configured path really does produce a
    /// live sender whose entries reach the file. Without this the sink would be
    /// constructed-in-name-only, which is the exact defect this ticket found in
    /// production.
    #[tokio::test]
    async fn a_configured_path_builds_a_sink_that_reaches_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let sink = build_audit_sink(Some(&path))
            .await
            .expect("open succeeds")
            .expect("a configured path yields a sender");

        sink.send(clean_entry("wired.example", ProxyAuditDecision::Blocked))
            .await
            .expect("the writer task is alive and draining");
        drop(sink);

        // The writer task owns the file; poll briefly for the flushed line
        // rather than assuming the spawn has been scheduled.
        let mut on_disk = String::new();
        for _ in 0..200 {
            on_disk = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            if !on_disk.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            on_disk.contains("wired.example"),
            "the sink returned by build_audit_sink never reached disk: {on_disk:?}"
        );
    }

    /// An operator who asked for an audit trail and cannot have one must be
    /// told, not silently given a proxy that records nothing.
    #[tokio::test]
    async fn an_unopenable_path_is_an_error_not_a_silent_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does/not/exist/audit.jsonl");
        match build_audit_sink(Some(&path)).await {
            Ok(_) => panic!("a configured-but-unopenable audit path must not degrade to no sink"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        }
    }

    /// The evidence has to survive serialisation to reach a reader at all, and
    /// it has to survive it *as the thing that was recorded* — a round trip that
    /// silently normalised `not_forwarded` into anything else would leave the
    /// prevention rule reading a value the proxy never observed.
    #[tokio::test]
    async fn non_transmission_evidence_survives_the_trip_to_disk() {
        let entry = ProxyAuditEntry {
            execution: ExecutionEvidence::new(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::NotForwarded,
                EnforcementMode::Enforce,
            ),
            ..clean_entry("api.example", ProxyAuditDecision::Blocked)
        };

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (tx, rx) = mpsc::channel(4);
        let writer = JsonlWriter::new(&path, rx).await.unwrap();
        let handle = tokio::spawn(writer.run());
        tx.send(entry).await.unwrap();
        drop(tx);
        handle.await.unwrap();

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(
            on_disk.contains("\"not_forwarded\""),
            "the on-disk line must spell the evidence: {on_disk}"
        );
        let back: ProxyAuditEntry = serde_json::from_str(on_disk.trim()).expect("the line parses");
        assert!(
            back.execution.establishes_non_transmission(),
            "the persisted record lost the only observation that can support a prevention claim"
        );
    }
}
