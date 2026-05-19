//! Persistent, append-only audit writer for governance events.
//!
//! [`AuditWriter`] consumes [`AuditEntry`] values from an async mpsc channel
//! and appends each one as a single JSON line to a per-session JSONL file.
//! The hash chain in [`AuditEntry`] provides tamper-evidence; persistence
//! provides durability across process restarts.

use std::io;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use aa_core::AuditEntry;

/// Append-only JSONL audit writer backed by an mpsc channel.
///
/// Created once at server startup, then moved into a background `tokio::spawn`
/// task via [`AuditWriter::run`].
pub struct AuditWriter {
    receiver: mpsc::Receiver<AuditEntry>,
    file: tokio::io::BufWriter<tokio::fs::File>,
    path: PathBuf,
}

impl AuditWriter {
    /// Create a new writer that appends to `<audit_dir>/<agent_id>-<session_id>.jsonl`.
    ///
    /// Creates the `audit_dir` if it does not exist. Opens the target file in
    /// append mode so existing entries are preserved across restarts.
    pub async fn new(
        audit_dir: PathBuf,
        agent_id: &str,
        session_id: &str,
        receiver: mpsc::Receiver<AuditEntry>,
    ) -> io::Result<Self> {
        tokio::fs::create_dir_all(&audit_dir).await?;

        let filename = format!("{agent_id}-{session_id}.jsonl");
        let path = audit_dir.join(filename);

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        let file = tokio::io::BufWriter::new(file);

        Ok(Self { receiver, file, path })
    }

    /// Serialize one `AuditEntry` as a JSON line and append to the file.
    async fn append(&mut self, entry: &AuditEntry) -> io::Result<()> {
        let json = serde_json::to_string(entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.file.write_all(json.as_bytes()).await?;
        self.file.write_all(b"\n").await?;
        self.file.flush().await?;
        Ok(())
    }

    /// Background consumption loop — call via `tokio::spawn(writer.run())`.
    ///
    /// Drains the channel until the sender is dropped (server shutdown).
    /// Individual write failures are logged but do not kill the pipeline.
    pub async fn run(mut self) {
        tracing::info!(path = %self.path.display(), "audit writer started");
        while let Some(entry) = self.receiver.recv().await {
            if let Err(e) = self.append(&entry).await {
                tracing::error!(
                    error = %e,
                    seq = entry.seq(),
                    "audit write failed"
                );
            }
        }
        // Channel closed — sender dropped during shutdown. Flush remaining data.
        if let Err(e) = self.file.flush().await {
            tracing::error!(error = %e, "audit writer final flush failed");
        }
        tracing::info!(path = %self.path.display(), "audit writer stopped");
    }

    /// Verify the hash chain of a JSONL audit file.
    ///
    /// Reads every entry, checks each entry's internal hash integrity via
    /// [`AuditEntry::verify_integrity`], and verifies the `previous_hash`
    /// linkage between consecutive entries.
    pub async fn verify_chain(path: &Path) -> Result<VerifyResult, AuditError> {
        let file = tokio::fs::File::open(path).await?;
        let reader = tokio::io::BufReader::new(file);
        let mut lines = reader.lines();

        let mut entries_checked: u64 = 0;
        let mut previous_hash: Option<[u8; 32]> = None;

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line).map_err(|source| AuditError::Deserialize {
                line: entries_checked,
                source,
            })?;

            // Check internal hash integrity.
            if !entry.verify_integrity() {
                return Ok(VerifyResult {
                    is_valid: false,
                    entries_checked,
                    first_invalid: Some(entries_checked),
                });
            }

            // Check chain linkage: entry's previous_hash must match the prior
            // entry's entry_hash (or [0u8; 32] for the genesis entry).
            if let Some(expected) = previous_hash {
                if *entry.previous_hash() != expected {
                    return Ok(VerifyResult {
                        is_valid: false,
                        entries_checked,
                        first_invalid: Some(entries_checked),
                    });
                }
            }

            previous_hash = Some(*entry.entry_hash());
            entries_checked += 1;
        }

        Ok(VerifyResult {
            is_valid: true,
            entries_checked,
            first_invalid: None,
        })
    }

    /// Read the `entry_hash` of the last entry in a JSONL file.
    ///
    /// Returns `None` if the file does not exist or is empty.
    /// Skips blank or incomplete trailing lines (standard JSONL recovery).
    pub async fn read_last_hash(path: &Path) -> io::Result<Option<[u8; 32]>> {
        let file = match tokio::fs::File::open(path).await {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let reader = tokio::io::BufReader::new(file);
        let mut lines = reader.lines();
        let mut last_hash: Option<[u8; 32]> = None;

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => last_hash = Some(*entry.entry_hash()),
                Err(_) => {
                    // Incomplete trailing line from a crash — skip it.
                    continue;
                }
            }
        }
        Ok(last_hash)
    }
}

/// Result of a hash-chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    /// `true` if every entry's hash matches and the chain links correctly.
    pub is_valid: bool,
    /// Total number of entries checked.
    pub entries_checked: u64,
    /// Index of the first invalid entry, if any.
    pub first_invalid: Option<u64>,
}

/// Errors that can occur during audit operations.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON deserialization error at line {line}: {source}")]
    Deserialize { line: u64, source: serde_json::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::{AgentId, AuditEventType, CredentialScanner, Lineage, Redaction, SessionId};

    /// Synthetic AWS access key from AWS public documentation. Not a real credential.
    const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    #[tokio::test]
    async fn audit_writer_jsonl_never_contains_raw_secret() {
        let scanner = CredentialScanner::new();
        let scan = scanner.scan(FAKE_AWS_ACCESS_KEY);
        assert!(
            !scan.findings.is_empty(),
            "scanner fixture invariant — must detect AWS key"
        );
        let redacted_payload = scan.redact(FAKE_AWS_ACCESS_KEY);
        let redaction = Redaction {
            credential_findings: scan.findings,
            redacted_payload: Some(redacted_payload),
        };

        let entry = AuditEntry::new_with_lineage_and_redaction(
            0,
            1_700_000_000_000_000_000,
            AuditEventType::CredentialLeakBlocked,
            AgentId::from_bytes([5u8; 16]),
            SessionId::from_bytes([6u8; 16]),
            r#"{"action_type":"tool_call","decision":"redact"}"#.to_string(),
            [0u8; 32],
            Lineage::default(),
            redaction,
        );

        let tmp = tempfile::tempdir().expect("create tempdir");
        let (tx, rx) = mpsc::channel(4);
        let writer = AuditWriter::new(tmp.path().to_path_buf(), "agent-test", "session-test", rx)
            .await
            .expect("construct AuditWriter");
        let path = writer.path.clone();
        let handle = tokio::spawn(writer.run());

        tx.send(entry).await.expect("send entry to writer");
        drop(tx);
        handle.await.expect("writer task joins cleanly");

        let on_disk = tokio::fs::read_to_string(&path).await.expect("read JSONL");

        assert!(
            !on_disk.contains(FAKE_AWS_ACCESS_KEY),
            "SECURITY INVARIANT VIOLATED: raw secret present in audit JSONL on disk: {on_disk}",
        );
        assert!(
            on_disk.contains("[REDACTED:AwsAccessKey]"),
            "audit JSONL must carry the [REDACTED:AwsAccessKey] label, got: {on_disk}",
        );

        let verify = AuditWriter::verify_chain(&path).await.expect("verify_chain runs");
        assert!(verify.is_valid, "single redacted entry must verify cleanly");
        assert_eq!(verify.entries_checked, 1);
    }
}
