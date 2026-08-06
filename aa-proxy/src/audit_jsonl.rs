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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use aa_core::types::sensitive_data::ExecutionEvidence;
use aa_security::{CredentialFinding, CredentialKind};

/// Decision recorded for a single intercepted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAuditDecision {
    /// Request forwarded unmodified (no findings, or policy `alert_only`).
    Forwarded,
    /// Request forwarded with secrets replaced by `[REDACTED:<Kind>]`
    /// markers in the body (policy `redact_only`).
    ForwardedRedacted,
    /// Request blocked at the proxy; upstream never dialled — either by the
    /// credential verdict (policy `block`) or by a rule, in which case
    /// [`ProxyAuditEntry::refusal_rule`] names it.
    Blocked,
}

/// Which **rule** refused a request, on a record whose decision is
/// [`ProxyAuditDecision::Blocked`] (AAASM-5449).
///
/// These are the proxy's most provable preventions: each is applied before any
/// dial exists on the code path, so the 403 (or JSON-RPC error envelope) is
/// written *instead of* the bytes going. Until this field existed they were
/// logged and discarded, so ADR 0032 §8 could count redaction-with-forwarding
/// but not the refusals a reader would find hardest to argue with.
///
/// Why the rule belongs on the record rather than only in the log: a
/// fail-closed credential block and a denylist refusal are both `Blocked` with
/// an empty finding list, and a consumer that cannot tell them apart cannot
/// attribute a prevention to the control that made it.
///
/// `None` on a credential verdict's own refusal. What refused it is already
/// spelled by [`ProxyAuditEntry::credential_findings`] and the decision, and
/// relabelling those records would change what an existing line means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalRule {
    /// Operator denylist (`AA_PROXY_DENIED_HOSTS`) matched the host.
    EgressDenylist,
    /// A non-empty network allowlist did not match the host.
    EgressAllowlist,
    /// The host was an IP literal in a blocked range (loopback, RFC-1918,
    /// link-local, cloud metadata) — the SSRF guard.
    SsrfBlockedAddress,
    /// A cleartext `http://` request addressed a known LLM provider, which
    /// would bypass the HTTPS-only DLP path entirely.
    PlaintextLlmDowngrade,
    /// The gateway denied an MCP `tools/call`, or the call could not be
    /// evaluated and was refused fail-closed.
    McpToolCall,
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
    /// Which rule refused it, when a rule did (AAASM-5449).
    ///
    /// `None` for anything that is not a rule refusal, including the credential
    /// verdict's own `Blocked`. See [`RefusalRule`].
    pub refusal_rule: Option<RefusalRule>,
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
    /// Correlation id when this record describes a protection probe's own
    /// request, `None` for ordinary traffic.
    ///
    /// Probe traffic is synthetic. Under `credential_action=block` a probe's
    /// request is genuinely refused before any dial, so its record satisfies
    /// every condition of ADR 0032 §8 and would be counted as a prevented
    /// transmission — one per probe run, indistinguishable from a real leak
    /// that was stopped. A consumer computing a prevention rate has to be able
    /// to exclude synthetic traffic, and can only do that if the record says
    /// which it is (AAASM-5359/5360).
    ///
    /// The value is an opaque caller-minted id whose grammar is enforced by
    /// [`ProbeCorrelation`](crate::probe_adjudication::ProbeCorrelation) — 32
    /// lowercase hex characters, which is deliberately too short to be a
    /// content digest.
    pub probe_correlation: Option<String>,
    /// Per-match scanner output, projected for this tier. Empty when no secrets
    /// were detected.
    ///
    /// Capped at [`MAX_PERSISTED_FINDINGS`]; the overflow is counted in
    /// [`Self::findings_omitted`] rather than dropped silently.
    pub credential_findings: Vec<PersistedFinding>,
    /// How many findings the cap dropped from
    /// [`Self::credential_findings`].
    ///
    /// A truncated list that said nothing about being truncated would make the
    /// finding count on this record quietly wrong, and finding counts are a
    /// measure ADR 0032 §8 keeps deliberately separate from event counts.
    pub findings_omitted: u32,
    /// Post-scan body content.
    ///
    /// `None` when the proxy bypassed the scanner, when the caller had no body
    /// to persist, **and** when re-inspection reported the post-scan bytes as
    /// still carrying a sensitive value — see
    /// [`crate::proxy::ProxyServer::observe_forwarding`]. Persisting bytes the
    /// proxy has itself just declared unscrubbed would make the "no raw value
    /// on disk" guarantee exactly as strong as the scrubber, in the one case
    /// where the proxy knows the scrubber did not hold.
    pub redacted_body: Option<String>,
}

/// A scanner finding as it may be persisted **outside** the tamper-evident
/// audit tier.
///
/// `aa_security::CredentialFinding` carries a `pub offset` — the byte position
/// of the match in the original body — and ADR 0032 §9 permits offsets and
/// lengths **only** in the tamper-evident tier. This module's own header states
/// it is not that tier, and AAASM-5358 is what first constructs the writer in
/// production, so this PR is what would first put those offsets on disk.
///
/// `aa-security` already drew this line and drew it half-way: `end` is private
/// and `#[serde(skip)]` citing §9, while `offset` stays public and serializes.
/// Projecting here rather than widening that skip keeps the decision local to
/// the tier that has the constraint — the tamper-evident writer still needs the
/// offset.
///
/// File permissions are not a substitute. `0600` is access control; §9 is about
/// what may exist in the record at all, and an offset paired with a category
/// can identify a value in a small domain regardless of who can read the file.
///
/// `matched` is the redaction **label** (`[REDACTED:AwsAccessKey]`), derived
/// from `kind` and never the secret. It is kept because it is what a consumer
/// already reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedFinding {
    /// Category of the detected credential.
    pub kind: CredentialKind,
    /// Redaction label, e.g. `[REDACTED:AwsAccessKey]`.
    pub matched: String,
}

impl PersistedFinding {
    /// Project a scanner finding, discarding the byte offset.
    pub fn project(finding: &CredentialFinding) -> Self {
        Self {
            kind: finding.kind.clone(),
            matched: finding.matched.clone(),
        }
    }
}

/// Most findings persisted on a single record.
///
/// `redacted_body` alone does not bound a line: a 64 MiB body densely packed
/// with detectable patterns yields on the order of a million findings at ~50-80
/// serialized bytes each, so an uncapped vector turns one request into a line of
/// hundreds of megabytes on a sink with no rotation.
pub const MAX_PERSISTED_FINDINGS: usize = 256;

/// Project and cap a finding list, returning the retained rows and how many
/// were dropped.
pub fn bound_persisted_findings(findings: &[CredentialFinding]) -> (Vec<PersistedFinding>, u32) {
    let kept: Vec<PersistedFinding> = findings
        .iter()
        .take(MAX_PERSISTED_FINDINGS)
        .map(PersistedFinding::project)
        .collect();
    let omitted = findings.len().saturating_sub(kept.len()) as u32;
    (kept, omitted)
}

/// Longest post-scan body persisted on a single record.
///
/// The MitM path accepts bodies up to `MAX_BODY_LEN` (64 MiB), and the JSONL
/// sink has no rotation or retention, so an unbounded body turns one oversized
/// request into an unbounded line and an unbounded file. Truncation is on a
/// character boundary and marked, so a reader can tell a short body from a cut
/// one.
pub const MAX_PERSISTED_BODY_BYTES: usize = 8 * 1024;

/// Marker appended to a body that was cut at [`MAX_PERSISTED_BODY_BYTES`].
pub const BODY_TRUNCATION_MARKER: &str = "…[truncated]";

/// Bound a post-scan body to [`MAX_PERSISTED_BODY_BYTES`], on a character
/// boundary.
pub fn bound_persisted_body(body: String) -> String {
    if body.len() <= MAX_PERSISTED_BODY_BYTES {
        return body;
    }
    let cut = body
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= MAX_PERSISTED_BODY_BYTES)
        .last()
        .unwrap_or(0);
    let mut out = body[..cut].to_owned();
    out.push_str(BODY_TRUNCATION_MARKER);
    out
}

/// Count of audit entries dropped because the channel was full or closed.
///
/// A prevention metric derived from a silently lossy record is not
/// authoritative. `try_send` is the right call on the data path — a slow writer
/// must not stall an intercepted request — so the loss is *counted* rather than
/// prevented.
///
/// Scope, stated because the obvious reading overstates it: today the only
/// surfacing is the running total on the `warn!` each drop emits. Nothing in
/// this repo reads [`dropped_entries`] outside its own tests, so a consumer
/// cannot yet gate a published rate on it. Putting it on the proxy's metrics
/// output is follow-up work; the counter exists so that work has something to
/// read, not because the plumbing is finished.
static DROPPED_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Record one dropped entry, returning the new running total.
pub fn record_dropped_entry() -> u64 {
    DROPPED_ENTRIES.fetch_add(1, Ordering::Relaxed) + 1
}

/// Entries dropped since process start.
pub fn dropped_entries() -> u64 {
    DROPPED_ENTRIES.load(Ordering::Relaxed)
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
    ///
    /// The file is `0600`, and an existing file's mode is re-asserted on every
    /// open — the same discipline `CaStore` applies to the CA private key. The
    /// default `0644` would have been world-readable.
    ///
    /// What justifies that is what the record *does* carry: the destination
    /// host, the redacted request path, the redacted body, and which credential
    /// categories an agent was caught sending. That is a per-agent behavioural
    /// trail, and it does not belong to every local account on the machine.
    ///
    /// It is **not** justified by byte offsets: [`PersistedFinding`] discards
    /// `CredentialFinding.offset`, because ADR 0032 §9 permits offsets only in
    /// the tamper-evident tier and this module is explicitly not that tier.
    /// Permissions are access control; §9 is about what may exist in the record
    /// at all, and the two are not substitutes for one another.
    pub async fn new(path: &Path, receiver: mpsc::Receiver<ProxyAuditEntry>) -> io::Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .await?;
        // `mode()` applies only at creation, so an already-existing file keeps
        // whatever it had. Re-assert rather than trust.
        let mut perms = file.metadata().await?.permissions();
        if perms.mode() & 0o777 != 0o600 {
            perms.set_mode(0o600);
            file.set_permissions(perms).await?;
        }
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
            refusal_rule: None,
            execution: ExecutionEvidence::new(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::ForwardedClean,
                EnforcementMode::Enforce,
            ),
            probe_correlation: None,
            credential_findings: scan.findings.iter().map(PersistedFinding::project).collect(),
            findings_omitted: 0,
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
            refusal_rule: None,
            execution: ExecutionEvidence::unrecorded(EnforcementMode::Enforce),
            probe_correlation: None,
            credential_findings: vec![],
            findings_omitted: 0,
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
            refusal_rule: None,
            execution: ExecutionEvidence::new(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::ForwardedClean,
                EnforcementMode::Enforce,
            ),
            probe_correlation: None,
            credential_findings: vec![],
            findings_omitted: 0,
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

    /// ADR 0032 §9 permits byte offsets only in the tamper-evident tier, and
    /// this sink is not it. AAASM-5358 is what first constructs the writer in
    /// production, so without the projection this would be the change that put
    /// them on disk.
    #[tokio::test]
    async fn a_persisted_finding_carries_no_byte_offset() {
        use aa_security::CredentialScanner;

        let body = format!(r#"{{"k":"{FAKE_AWS_ACCESS_KEY}"}}"#);
        let scan = CredentialScanner::new().scan(&body);
        assert!(!scan.findings.is_empty(), "scanner fixture invariant");
        // Non-vacuity: the source finding really does carry an offset, and the
        // body is long enough that the offset is not coincidentally 0.
        let source_offset = scan.findings[0].offset;
        assert!(source_offset > 0, "fixture must produce a non-zero offset");

        let (projected, omitted) = bound_persisted_findings(&scan.findings);
        assert_eq!(omitted, 0);
        assert!(!projected.is_empty(), "otherwise the assertions below are vacuous");
        assert_eq!(projected[0].kind, scan.findings[0].kind);
        assert_eq!(projected[0].matched, scan.findings[0].matched);

        let entry = ProxyAuditEntry {
            credential_findings: projected,
            ..clean_entry("api.example", ProxyAuditDecision::ForwardedRedacted)
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            !json.contains("\"offset\""),
            "ADR 0032 §9: a byte offset must not reach this tier: {json}"
        );
        // The category — which §9 does permit — survives, so the record is
        // still useful.
        assert!(json.contains("AwsAccessKey"), "the category must survive: {json}");
    }

    /// `redacted_body` alone does not bound a line: the findings vector does
    /// too, and a densely-matching 64 MiB body produces on the order of a
    /// million of them.
    #[test]
    fn an_oversized_finding_list_is_capped_and_the_remainder_counted() {
        use aa_security::CredentialScanner;

        let one = CredentialScanner::new().scan(&format!(r#"{{"k":"{FAKE_AWS_ACCESS_KEY}"}}"#));
        assert!(!one.findings.is_empty(), "scanner fixture invariant");
        let many: Vec<_> = std::iter::repeat_with(|| one.findings[0].clone())
            .take(MAX_PERSISTED_FINDINGS + 37)
            .collect();

        let (kept, omitted) = bound_persisted_findings(&many);
        assert_eq!(kept.len(), MAX_PERSISTED_FINDINGS);
        assert_eq!(omitted, 37, "the remainder must be counted, not silently dropped");

        // Under the cap nothing is omitted, so the counter is not simply
        // always-positive.
        let (kept, omitted) = bound_persisted_findings(&many[..3]);
        assert_eq!(kept.len(), 3);
        assert_eq!(omitted, 0);
    }

    /// The sink is a new durable file holding a per-agent behavioural trail —
    /// destination hosts, redacted paths and bodies, and which credential
    /// categories an agent was caught sending. The default `0644` would have
    /// published all of it to every local account.
    ///
    /// Byte offsets are handled separately and are not on disk at all; see
    /// [`PersistedFinding`] and `a_persisted_finding_carries_no_byte_offset`.
    #[tokio::test]
    async fn the_audit_file_is_not_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (_tx, rx) = mpsc::channel(1);
        let _writer = JsonlWriter::new(&path, rx).await.unwrap();
        let mode = tokio::fs::metadata(&path).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit file mode was {mode:o}");
    }

    /// A file left over from an earlier, looser build must be tightened rather
    /// than inherited — `mode()` applies only at creation.
    #[tokio::test]
    async fn an_existing_loose_audit_file_is_tightened_on_open() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        tokio::fs::write(&path, b"").await.unwrap();
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .await
            .unwrap();
        // Non-vacuity: the file really is loose before the writer opens it.
        let before = tokio::fs::metadata(&path).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(before, 0o644);

        let (_tx, rx) = mpsc::channel(1);
        let _writer = JsonlWriter::new(&path, rx).await.unwrap();
        let after = tokio::fs::metadata(&path).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(after, 0o600, "an existing audit file kept mode {after:o}");
    }

    /// The MitM path accepts bodies up to 64 MiB and this sink has no rotation,
    /// so one oversized request must not become an unbounded line.
    #[test]
    fn an_oversized_body_is_truncated_on_a_character_boundary_and_marked() {
        let short = "already small".to_owned();
        assert_eq!(bound_persisted_body(short.clone()), short);

        // Multi-byte characters, so a naive byte slice would panic.
        let big = "é".repeat(MAX_PERSISTED_BODY_BYTES);
        assert!(big.len() > MAX_PERSISTED_BODY_BYTES);
        let bounded = bound_persisted_body(big);
        assert!(bounded.ends_with(BODY_TRUNCATION_MARKER), "truncation must be visible");
        assert!(
            bounded.len() <= MAX_PERSISTED_BODY_BYTES + BODY_TRUNCATION_MARKER.len(),
            "bounded body was {} bytes",
            bounded.len()
        );
    }

    /// A prevention metric computed over a silently lossy record is not
    /// authoritative. The data path is right to drop rather than block, so the
    /// loss has to be countable.
    #[test]
    fn dropped_entries_are_counted() {
        let before = dropped_entries();
        let first = record_dropped_entry();
        let second = record_dropped_entry();
        assert_eq!(first, before + 1);
        assert_eq!(second, before + 2);
        assert_eq!(dropped_entries(), before + 2);
    }

    /// A rule refusal and a fail-closed credential block are both `Blocked`
    /// with an empty finding list, so without this field a consumer cannot
    /// attribute a prevention to the control that made it (AAASM-5449).
    #[test]
    fn a_refusal_rule_round_trips_and_stays_absent_on_a_verdict_record() {
        let entry = ProxyAuditEntry {
            refusal_rule: Some(RefusalRule::EgressDenylist),
            ..clean_entry("evil.example", ProxyAuditDecision::Blocked)
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            json.contains("\"egress_denylist\""),
            "the rule must be spelled on the line: {json}"
        );
        let back: ProxyAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.refusal_rule, Some(RefusalRule::EgressDenylist));

        // Non-vacuity: the field really does distinguish, rather than being
        // present on every record.
        let verdict_block = clean_entry("api.example", ProxyAuditDecision::Blocked);
        assert!(
            verdict_block.refusal_rule.is_none(),
            "a credential verdict's refusal names no rule"
        );
    }

    /// Every rule is a distinct on-the-wire token: two rules that serialised to
    /// the same string would silently merge two controls into one count.
    #[test]
    fn every_refusal_rule_serializes_distinctly() {
        let rules = [
            RefusalRule::EgressDenylist,
            RefusalRule::EgressAllowlist,
            RefusalRule::SsrfBlockedAddress,
            RefusalRule::PlaintextLlmDowngrade,
            RefusalRule::McpToolCall,
        ];
        let mut seen = Vec::new();
        for rule in rules {
            let json = serde_json::to_string(&rule).unwrap();
            assert!(!seen.contains(&json), "{rule:?} collides with an earlier rule: {json}");
            let back: RefusalRule = serde_json::from_str(&json).unwrap();
            assert_eq!(back, rule);
            seen.push(json);
        }
        assert_eq!(seen.len(), rules.len());
    }

    /// A probe's own traffic must be identifiable in the record, so a consumer
    /// can exclude synthetic preventions from a rate.
    #[test]
    fn a_probe_record_round_trips_its_correlation_id() {
        let entry = ProxyAuditEntry {
            probe_correlation: Some("0123456789abcdef0123456789abcdef".into()),
            ..clean_entry("api.example", ProxyAuditDecision::Blocked)
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ProxyAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.probe_correlation.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        // Ordinary traffic stays distinguishable from synthetic traffic.
        let ordinary = clean_entry("api.example", ProxyAuditDecision::Blocked);
        assert!(ordinary.probe_correlation.is_none());
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
