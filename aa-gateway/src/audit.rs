//! Persistent, append-only audit writer for governance events.
//!
//! [`AuditWriter`] consumes [`AuditEntry`] values from an async mpsc channel
//! and appends each one as a single JSON line to a per-session JSONL file.
//! The hash chain in [`AuditEntry`] provides tamper-evidence; persistence
//! provides durability across process restarts.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use aa_core::AuditEntry;

use crate::storage::{audit_entry_to_storage_event, StorageBackend};

/// The single hash-chain head and `seq` counter for one audit JSONL file.
///
/// Every producer writing to one file must share one `AuditChain` instance —
/// a private head per producer forks the chain into interleaved,
/// mutually-unverifiable runs (AAASM-5626). Before this type, `seq` and
/// `last_hash` were duplicated per-producer (`PolicyServiceImpl`,
/// `AuditServiceImpl`, and the escalation audit task each held their own),
/// and the chain head advanced *before* `try_send`, so a dropped entry left
/// the next successful entry's `previous_hash` pointing at an entry that was
/// never written — indistinguishable from a deleted/altered entry to
/// [`AuditWriter::verify_chain`]. `emit` fixes both: `seq` is still consumed
/// unconditionally (so a drop leaves a visible, verifiable gap — see
/// `VerifyOutcome::Incomplete`), but the chain head only advances when the
/// entry actually reaches the channel, and build+send happen under one lock
/// so two concurrent emitters can never chain A→B and send B→A.
pub struct AuditChain {
    tx: mpsc::Sender<AuditEntry>,
    drops: Arc<AtomicU64>,
    // A plain (non-async) mutex is correct here: `emit`'s critical section
    // never awaits — `build` is synchronous and `mpsc::Sender::try_send` is
    // non-blocking — so there is no reason to pay for an async-aware lock.
    state: std::sync::Mutex<ChainState>,
}

struct ChainState {
    next_seq: u64,
    last_hash: [u8; 32],
}

/// Result of [`AuditChain::emit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitOutcome {
    /// The entry reached the channel; the chain head advanced.
    Sent {
        /// The `seq` assigned to this entry.
        seq: u64,
    },
    /// The channel was full (backpressure); the entry was not written and
    /// the chain head did not advance. `seq` was still consumed, so this
    /// leaves a gap `verify_chain` reports as [`VerifyOutcome::Incomplete`].
    Dropped {
        /// The `seq` that was consumed and lost.
        seq: u64,
    },
    /// The channel's receiver (the `AuditWriter` task) has exited.
    Closed {
        /// The `seq` that was consumed and lost.
        seq: u64,
    },
}

impl AuditChain {
    /// `initial_hash`/`initial_seq` should be the last persisted
    /// `entry_hash`/`seq + 1` (via [`AuditWriter::read_last_hash`] /
    /// [`AuditWriter::read_last_seq`]) so the chain continues monotonically
    /// across a restart, or `([0u8; 32], 0)` for a fresh chain.
    pub fn new(tx: mpsc::Sender<AuditEntry>, drops: Arc<AtomicU64>, initial_hash: [u8; 32], initial_seq: u64) -> Self {
        Self {
            tx,
            drops,
            state: std::sync::Mutex::new(ChainState {
                next_seq: initial_seq,
                last_hash: initial_hash,
            }),
        }
    }

    /// Re-seed the `seq` counter, leaving the hash-chain head untouched.
    ///
    /// Test-compatibility seam for callers that construct a service with
    /// `[0u8; 32]` (no persisted `initial_hash` available) but still need to
    /// resume `seq` after `AuditWriter::read_last_seq` — mirrors the
    /// pre-`AuditChain` `with_initial_seq` builders. Production call sites
    /// pass both `initial_hash` and `initial_seq` to [`Self::new`] together
    /// instead.
    pub fn set_initial_seq(&self, initial_seq: u64) {
        self.state.lock().expect("audit chain mutex poisoned").next_seq = initial_seq;
    }

    /// Assign the next `seq`/`previous_hash`, build the entry via `build`,
    /// and `try_send` it — all under one lock, so the chain head only ever
    /// advances to an entry that is actually in the channel and no two
    /// concurrent callers can interleave their sends out of chain order.
    pub async fn emit<F>(&self, build: F) -> EmitOutcome
    where
        F: FnOnce(u64, [u8; 32]) -> AuditEntry,
    {
        let mut state = self.state.lock().expect("audit chain mutex poisoned");
        let seq = state.next_seq;
        // Consumed unconditionally: a lost entry must leave a visible seq
        // gap, not be silently reused by the next entry.
        state.next_seq += 1;
        let previous_hash = state.last_hash;

        let entry = build(seq, previous_hash);
        let entry_hash = *entry.entry_hash();

        match self.tx.try_send(entry) {
            Ok(()) => {
                state.last_hash = entry_hash;
                drop(state);
                EmitOutcome::Sent { seq }
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                drop(state);
                self.drops.fetch_add(1, Ordering::Relaxed);
                EmitOutcome::Dropped { seq }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                drop(state);
                EmitOutcome::Closed { seq }
            }
        }
    }
}

/// Append-only JSONL audit writer backed by an mpsc channel.
///
/// Created once at server startup, then moved into a background `tokio::spawn`
/// task via [`AuditWriter::run`].
pub struct AuditWriter {
    receiver: mpsc::Receiver<AuditEntry>,
    file: tokio::io::BufWriter<tokio::fs::File>,
    path: PathBuf,
    /// Optional durable [`StorageBackend`] for the dual-sink path.
    ///
    /// When set, every successful JSONL write is followed by
    /// `storage.append_audit_event(&storage_event)`. A storage write
    /// failure is logged at `tracing::error!` but does not stop the
    /// pipeline — JSONL stays the tamper-evident primary record, and a
    /// subsequent restart can replay missed entries from the JSONL file.
    ///
    /// `None` is the legacy behaviour preserved for existing callers that
    /// construct AuditWriter without storage.
    ///
    /// Introduced by Epic 18 Story S-I.3 (AAASM-1867).
    storage: Option<Arc<dyn StorageBackend>>,
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

        Ok(Self {
            receiver,
            file,
            path,
            storage: None,
        })
    }

    /// Attach a durable [`StorageBackend`] for the dual-sink path.
    ///
    /// After this builder is applied, every successful JSONL write is
    /// followed by `storage.append_audit_event(...)`. Storage write
    /// failures are logged but do not stop the JSONL pipeline.
    ///
    /// Introduced by Epic 18 Story S-I.3 (AAASM-1867).
    pub fn with_storage(mut self, storage: Arc<dyn StorageBackend>) -> Self {
        self.storage = Some(storage);
        self
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
    ///
    /// When `with_storage` has been applied (Epic 18 Story S-I.3), each
    /// successful JSONL write is followed by
    /// `storage.append_audit_event(...)` so post-restart queries against
    /// the StorageBackend see the same events the JSONL file holds. The
    /// JSONL chain remains the tamper-evident primary record; a storage
    /// failure logs at `tracing::error!` but does not halt the pipeline.
    pub async fn run(mut self) {
        tracing::info!(path = %self.path.display(), "audit writer started");
        // AAASM-5626 — the writer is the one place that sees every entry as
        // it actually arrives, so it is the cheapest place to log a `seq`
        // gap the instant it happens (a drop upstream via `AuditChain::emit`
        // consumed the seq but never sent the entry). `verify_chain` reports
        // the same gap later from the file alone; this is the live-process
        // signal an operator's `tracing` pipeline can alert on immediately.
        let mut last_seq: Option<u64> = None;
        while let Some(entry) = self.receiver.recv().await {
            if let Some(prev) = last_seq {
                if entry.seq() > prev + 1 {
                    tracing::warn!(
                        missing_from = prev + 1,
                        missing_to = entry.seq() - 1,
                        count = entry.seq() - prev - 1,
                        path = %self.path.display(),
                        "audit sequence gap — entries were lost before write"
                    );
                }
            }
            last_seq = Some(entry.seq());
            if let Err(e) = self.append(&entry).await {
                tracing::error!(
                    error = %e,
                    seq = entry.seq(),
                    "audit write failed"
                );
                // Skip the storage sink when the JSONL write itself failed —
                // we don't want storage to diverge from the tamper-evident
                // chain.
                continue;
            }
            if let Some(storage) = self.storage.as_ref() {
                let storage_event = audit_entry_to_storage_event(&entry);
                if let Err(err) = storage.append_audit_event(&storage_event).await {
                    tracing::error!(
                        error = %err,
                        seq = entry.seq(),
                        "audit storage write failed (JSONL line persisted; replay from JSONL on restart)"
                    );
                }
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
    ///
    /// A `seq` gap between consecutive entries with otherwise-intact hashes
    /// and linkage is reported as [`VerifyOutcome::Incomplete`], not
    /// [`VerifyOutcome::Tampered`] (AAASM-5626): entries lost to emission
    /// backpressure (see [`crate::service::audit_service`]'s bounded-channel
    /// `try_send`) leave a `seq` gap but never touch the chain, whereas an
    /// altered or removed entry breaks integrity or linkage. Integrity is
    /// checked first, then linkage, then `seq` — a `seq` gap never suppresses
    /// an integrity or linkage failure, so this cannot weaken the tamper
    /// signal: disguising a deletion as a drop would require rewriting the
    /// following entry's `previous_hash`, which breaks that entry's own
    /// `entry_hash` and is caught by the integrity check first.
    ///
    /// Does **not** require the first entry's `seq == 0` — a chain that
    /// begins mid-sequence after a restart is not itself evidence of loss.
    pub async fn verify_chain(path: &Path) -> Result<VerifyResult, AuditError> {
        let file = tokio::fs::File::open(path).await?;
        let reader = tokio::io::BufReader::new(file);
        let mut lines = reader.lines();

        let mut entries_checked: u64 = 0;
        let mut previous_hash: Option<[u8; 32]> = None;
        let mut previous_seq: Option<u64> = None;
        let mut missing_seq_ranges: Vec<(u64, u64)> = Vec::new();

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
                    outcome: VerifyOutcome::Tampered,
                    is_valid: false,
                    entries_checked,
                    first_invalid: Some(entries_checked),
                    missing_entries: missing_seq_ranges_total(&missing_seq_ranges),
                    missing_seq_ranges,
                });
            }

            // Check chain linkage: entry's previous_hash must match the prior
            // entry's entry_hash (or [0u8; 32] for the genesis entry).
            if let Some(expected) = previous_hash {
                if *entry.previous_hash() != expected {
                    return Ok(VerifyResult {
                        outcome: VerifyOutcome::Tampered,
                        is_valid: false,
                        entries_checked,
                        first_invalid: Some(entries_checked),
                        missing_entries: missing_seq_ranges_total(&missing_seq_ranges),
                        missing_seq_ranges,
                    });
                }
            }

            // Integrity and linkage both held — a seq gap here is entries
            // lost before reaching the file, not alteration.
            if let Some(prev) = previous_seq {
                if entry.seq() > prev + 1 {
                    missing_seq_ranges.push((prev + 1, entry.seq() - 1));
                }
            }

            previous_hash = Some(*entry.entry_hash());
            previous_seq = Some(entry.seq());
            entries_checked += 1;
        }

        let missing_entries = missing_seq_ranges_total(&missing_seq_ranges);
        let outcome = if missing_entries > 0 {
            VerifyOutcome::Incomplete
        } else {
            VerifyOutcome::Verified
        };
        Ok(VerifyResult {
            outcome,
            is_valid: outcome == VerifyOutcome::Verified,
            entries_checked,
            first_invalid: None,
            missing_seq_ranges,
            missing_entries,
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

    /// Read the `seq` of the last entry in a JSONL file.
    ///
    /// AAASM-3356 — on restart the service recovers the hash chain head via
    /// [`read_last_hash`](Self::read_last_hash) but previously re-seeded the
    /// `seq` counter at `0`, producing duplicate sequence numbers after a
    /// restart. Pairing this with `read_last_hash` lets the service seed the
    /// `seq` atomic from `last_seq + 1` so sequence numbers stay monotonic and
    /// unique across process restarts.
    ///
    /// Returns `None` if the file does not exist or is empty.
    /// Skips blank or incomplete trailing lines (standard JSONL recovery).
    pub async fn read_last_seq(path: &Path) -> io::Result<Option<u64>> {
        let file = match tokio::fs::File::open(path).await {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let reader = tokio::io::BufReader::new(file);
        let mut lines = reader.lines();
        let mut last_seq: Option<u64> = None;

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => last_seq = Some(entry.seq()),
                Err(_) => {
                    // Incomplete trailing line from a crash — skip it.
                    continue;
                }
            }
        }
        Ok(last_seq)
    }
}

/// The three outcomes [`AuditWriter::verify_chain`] can report (AAASM-5626).
///
/// A `seq` gap alone (backpressure loss, `Incomplete`) is deliberately kept
/// distinct from a hash/linkage failure (alteration or removal, `Tampered`):
/// the two used to be indistinguishable, which meant an operator running
/// `aasm audit verify-chain` after an incident could not tell a capacity
/// event from a compromise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Every hash matches, every link matches, `seq` is contiguous.
    Verified,
    /// Hashes and links match, but `seq` is not contiguous: entries were
    /// lost before reaching the file (emission backpressure, or a crash
    /// before flush). Every entry present is unaltered. This is **not**
    /// tamper evidence.
    Incomplete,
    /// An entry's `entry_hash` does not match its own fields, or its
    /// `previous_hash` does not match the preceding entry's `entry_hash`.
    Tampered,
}

/// Result of a hash-chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    /// Which of the three outcomes this file produced.
    pub outcome: VerifyOutcome,
    /// `true` iff `outcome == VerifyOutcome::Verified`. Retained for existing
    /// callers that only care pass/fail; an `Incomplete` file is `!is_valid`.
    pub is_valid: bool,
    /// Total number of entries checked.
    pub entries_checked: u64,
    /// Index of the first invalid entry, if `outcome == Tampered`.
    pub first_invalid: Option<u64>,
    /// Inclusive `seq` ranges present in no entry in the file, in file order.
    /// Empty unless `outcome == Incomplete`.
    pub missing_seq_ranges: Vec<(u64, u64)>,
    /// Total count of missing `seq` values across `missing_seq_ranges`.
    pub missing_entries: u64,
}

/// Sum the inclusive `(start, end)` ranges in `ranges` into a total count.
fn missing_seq_ranges_total(ranges: &[(u64, u64)]) -> u64 {
    ranges.iter().map(|(start, end)| end - start + 1).sum()
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
    use aa_core::{AgentId, AuditEventType, Lineage, SessionId};
    use aa_security::{CredentialScanner, Redaction};

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
