//! Read-only query interface for JSONL audit log files.
//!
//! [`AuditReader`] scans the audit directory produced by [`super::audit::AuditWriter`],
//! parses JSONL entries, and returns paginated results in reverse chronological order.

use std::io;
use std::path::PathBuf;

use tokio::io::AsyncBufReadExt;

use aa_core::audit::AuditEventType;
use aa_core::{AgentId, AuditEntry};

/// Read-only query interface for the JSONL audit log directory.
///
/// Reads files directly — does not tap the `AuditWriter` mpsc channel.
/// Safe to use concurrently with an active writer because each JSONL line
/// is self-contained and the reader skips incomplete trailing lines.
pub struct AuditReader {
    dir: PathBuf,
}

impl AuditReader {
    /// Create a new reader targeting the given audit directory.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// List audit entries with pagination and optional filters.
    ///
    /// Returns `(entries, total_matching)` where entries are sorted in
    /// reverse chronological order (newest first) and sliced to the
    /// requested `limit`/`offset` window.
    pub async fn list(
        &self,
        limit: usize,
        offset: usize,
        agent_id: Option<&str>,
        event_type: Option<&str>,
    ) -> io::Result<(Vec<AuditEntry>, u64)> {
        let mut all_entries = self.read_all_entries().await?;

        // Parse filter values once.
        let agent_filter: Option<AgentId> = agent_id.and_then(parse_agent_id);
        let event_filter: Option<Vec<AuditEventType>> = event_type.and_then(parse_event_type);

        // Apply filters.
        if agent_filter.is_some() || event_filter.is_some() {
            all_entries.retain(|entry| {
                if let Some(aid) = &agent_filter {
                    if entry.agent_id() != *aid {
                        return false;
                    }
                }
                if let Some(types) = &event_filter {
                    if !types.contains(&entry.event_type()) {
                        return false;
                    }
                }
                true
            });
        }

        // Sort by timestamp descending (newest first).
        all_entries.sort_by_key(|e| std::cmp::Reverse(e.timestamp_ns()));

        let total = all_entries.len() as u64;
        let page: Vec<AuditEntry> = all_entries.into_iter().skip(offset).take(limit).collect();

        Ok((page, total))
    }

    /// Return all `PolicyViolation` entries newer than `since_ns`.
    ///
    /// When `root` is provided, only entries whose `root_agent_id` matches (or whose
    /// `agent_id` equals the root, i.e. the root itself) are included, scoping the
    /// result to that delegation subtree.
    pub async fn list_violations(
        &self,
        since_ns: u64,
        root: Option<AgentId>,
    ) -> io::Result<Vec<AuditEntry>> {
        let all = self.read_all_entries().await?;
        Ok(all
            .into_iter()
            .filter(|e| {
                e.event_type() == AuditEventType::PolicyViolation
                    && e.timestamp_ns() >= since_ns
                    && root.map_or(true, |r| {
                        e.root_agent_id() == Some(r) || e.agent_id() == r
                    })
            })
            .collect())
    }

    /// Read and parse all JSONL files in the audit directory.
    async fn read_all_entries(&self) -> io::Result<Vec<AuditEntry>> {
        let mut entries = Vec::new();

        let mut dir = match tokio::fs::read_dir(&self.dir).await {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(entries),
            Err(e) => return Err(e),
        };

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }

            let file = tokio::fs::File::open(&path).await?;
            let reader = tokio::io::BufReader::new(file);
            let mut lines = reader.lines();

            while let Some(line) = lines.next_line().await? {
                if line.trim().is_empty() {
                    continue;
                }
                // Skip incomplete or corrupt lines (e.g. partial writes).
                if let Ok(audit_entry) = serde_json::from_str::<AuditEntry>(&line) {
                    entries.push(audit_entry);
                }
            }
        }

        Ok(entries)
    }
}

/// Parse a hex-encoded agent ID string into an [`AgentId`].
fn parse_agent_id(s: &str) -> Option<AgentId> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Some(AgentId::from_bytes(arr))
}

/// Parse an event-type filter string into the set of [`AuditEventType`] variants it matches.
///
/// Accepts two wire forms so both API consumers stay supported:
///
/// * **CamelCase variant name** (e.g. `"PolicyViolation"`, `"ApprovalGranted"`) →
///   matches that single variant. Used by callers that already know which
///   exact variant they want.
/// * **snake_case category** (e.g. `"violation"`, `"approval"`, `"budget"`) →
///   matches the whole family of related variants. Used by `aasm logs --type`,
///   whose `LogEventType::as_api_str` emits these.
///
/// Returns `None` for unrecognised strings so the caller drops the filter
/// rather than silently filtering against nothing.
fn parse_event_type(s: &str) -> Option<Vec<AuditEventType>> {
    use AuditEventType::*;
    match s {
        // CamelCase variant names (1:1).
        "ToolCallIntercepted" => Some(vec![ToolCallIntercepted]),
        "PolicyViolation" => Some(vec![PolicyViolation]),
        "CredentialLeakBlocked" => Some(vec![CredentialLeakBlocked]),
        "ApprovalRequested" => Some(vec![ApprovalRequested]),
        "ApprovalGranted" => Some(vec![ApprovalGranted]),
        "ApprovalDenied" => Some(vec![ApprovalDenied]),
        "ApprovalTimedOut" => Some(vec![ApprovalTimedOut]),
        "BudgetLimitApproached" => Some(vec![BudgetLimitApproached]),
        "BudgetLimitExceeded" => Some(vec![BudgetLimitExceeded]),

        // snake_case categories (1:N) — matches `aasm logs --type` wire form.
        "violation" => Some(vec![PolicyViolation]),
        "approval" => Some(vec![
            ApprovalRequested,
            ApprovalGranted,
            ApprovalDenied,
            ApprovalTimedOut,
            ApprovalRouted,
            ApprovalEscalated,
        ]),
        "budget" => Some(vec![BudgetLimitApproached, BudgetLimitExceeded]),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AuditEventType::*;

    #[test]
    fn camel_case_variant_name_yields_singleton() {
        assert_eq!(parse_event_type("PolicyViolation"), Some(vec![PolicyViolation]));
        assert_eq!(parse_event_type("ApprovalGranted"), Some(vec![ApprovalGranted]));
        assert_eq!(parse_event_type("BudgetLimitExceeded"), Some(vec![BudgetLimitExceeded]));
    }

    #[test]
    fn snake_case_violation_matches_policy_violation() {
        assert_eq!(parse_event_type("violation"), Some(vec![PolicyViolation]));
    }

    #[test]
    fn snake_case_approval_matches_full_approval_family() {
        let variants = parse_event_type("approval").expect("approval should parse");
        for v in [
            ApprovalRequested,
            ApprovalGranted,
            ApprovalDenied,
            ApprovalTimedOut,
            ApprovalRouted,
            ApprovalEscalated,
        ] {
            assert!(variants.contains(&v), "expected {v:?} in `approval` family");
        }
        assert_eq!(variants.len(), 6, "approval should match exactly six variants");
    }

    #[test]
    fn snake_case_budget_matches_both_budget_variants() {
        let variants = parse_event_type("budget").expect("budget should parse");
        assert!(variants.contains(&BudgetLimitApproached));
        assert!(variants.contains(&BudgetLimitExceeded));
        assert_eq!(variants.len(), 2);
    }

    #[test]
    fn unknown_string_returns_none() {
        assert_eq!(parse_event_type("garbage"), None);
        assert_eq!(parse_event_type(""), None);
    }
}
