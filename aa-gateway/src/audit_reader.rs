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
    pub async fn list_violations(&self, since_ns: u64, root: Option<AgentId>) -> io::Result<Vec<AuditEntry>> {
        let all = self.read_all_entries().await?;
        Ok(all
            .into_iter()
            .filter(|e| {
                e.event_type() == AuditEventType::PolicyViolation
                    && e.timestamp_ns() >= since_ns
                    && root.map_or(true, |r| e.root_agent_id() == Some(r) || e.agent_id() == r)
            })
            .collect())
    }

    /// Return all observe-mode shadow entries newer than `since_ns`.
    ///
    /// Shadow entries are the audit rows written when the policy evaluated
    /// non-Allow under observe mode: their event_type is the would-have-been
    /// decision and the payload carries `dry_run: true` plus `shadow_decision`
    /// and `shadow_reason`. Selection is on payload, not event_type, because
    /// the allowed-on-the-wire decision can take several event_type values.
    pub async fn list_dry_run(&self, since_ns: u64, root: Option<AgentId>) -> io::Result<Vec<AuditEntry>> {
        let all = self.read_all_entries().await?;
        Ok(all
            .into_iter()
            .filter(|e| {
                e.timestamp_ns() >= since_ns
                    && root.map_or(true, |r| e.root_agent_id() == Some(r) || e.agent_id() == r)
                    && payload_has_dry_run_true(e.payload())
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

/// Returns true when `payload` parses as a JSON object containing `"dry_run": true`.
///
/// Implemented as a free helper so the dry-run selector is independent of how
/// shadow payloads are constructed and tolerates non-JSON / malformed lines
/// the same way `aggregate_violations` tolerates missing fields — by returning
/// false rather than erroring.
fn payload_has_dry_run_true(payload: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .as_ref()
        .and_then(|v| v.get("dry_run"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
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
    use aa_core::audit::Lineage;
    use aa_core::SessionId;
    use std::io::Write;
    use tempfile::TempDir;
    use AuditEventType::*;

    const ROOT_BYTES: [u8; 16] = [0xAA; 16];
    const PARENT_BYTES: [u8; 16] = [0xBB; 16];
    const CHILD_BYTES: [u8; 16] = [0xCC; 16];
    const OTHER_BYTES: [u8; 16] = [0xDD; 16];
    const SESSION_BYTES: [u8; 16] = [0xEE; 16];

    fn make_entry(
        seq: u64,
        timestamp_ns: u64,
        event_type: AuditEventType,
        agent_id: AgentId,
        root: Option<AgentId>,
    ) -> AuditEntry {
        make_entry_with_payload(seq, timestamp_ns, event_type, agent_id, root, "{}")
    }

    fn make_entry_with_payload(
        seq: u64,
        timestamp_ns: u64,
        event_type: AuditEventType,
        agent_id: AgentId,
        root: Option<AgentId>,
        payload: &str,
    ) -> AuditEntry {
        let lineage = Lineage {
            root_agent_id: root,
            ..Lineage::default()
        };
        AuditEntry::new_with_lineage(
            seq,
            timestamp_ns,
            event_type,
            agent_id,
            SessionId::from_bytes(SESSION_BYTES),
            payload.to_string(),
            [0u8; 32],
            lineage,
        )
    }

    fn write_entries(dir: &std::path::Path, entries: &[AuditEntry]) {
        let path = dir.join("audit.jsonl");
        let mut f = std::fs::File::create(path).expect("create jsonl");
        for e in entries {
            let line = serde_json::to_string(e).expect("serialize entry");
            writeln!(f, "{line}").expect("write line");
        }
    }

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

    #[tokio::test]
    async fn list_violations_returns_empty_when_dir_missing() {
        let reader = AuditReader::new(PathBuf::from("/nonexistent/audit/dir"));
        let result = reader
            .list_violations(0, None)
            .await
            .expect("list_violations should not error on missing dir");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn list_violations_filters_by_event_type() {
        let tmp = TempDir::new().expect("tempdir");
        let child = AgentId::from_bytes(CHILD_BYTES);
        let entries = vec![
            make_entry(0, 100, AuditEventType::PolicyViolation, child, None),
            make_entry(1, 200, AuditEventType::ToolCallIntercepted, child, None),
            make_entry(2, 300, AuditEventType::ApprovalGranted, child, None),
            make_entry(3, 400, AuditEventType::PolicyViolation, child, None),
        ];
        write_entries(tmp.path(), &entries);

        let reader = AuditReader::new(tmp.path().to_path_buf());
        let violations = reader.list_violations(0, None).await.expect("list_violations");

        assert_eq!(violations.len(), 2);
        assert!(violations
            .iter()
            .all(|e| e.event_type() == AuditEventType::PolicyViolation));
    }

    #[tokio::test]
    async fn list_violations_filters_by_since_ns() {
        let tmp = TempDir::new().expect("tempdir");
        let child = AgentId::from_bytes(CHILD_BYTES);
        let entries = vec![
            make_entry(0, 100, AuditEventType::PolicyViolation, child, None),
            make_entry(1, 200, AuditEventType::PolicyViolation, child, None),
            make_entry(2, 300, AuditEventType::PolicyViolation, child, None),
        ];
        write_entries(tmp.path(), &entries);

        let reader = AuditReader::new(tmp.path().to_path_buf());
        let violations = reader.list_violations(200, None).await.expect("list_violations");

        // Both 200 and 300 satisfy >= 200; 100 does not.
        assert_eq!(violations.len(), 2);
        assert!(violations.iter().all(|e| e.timestamp_ns() >= 200));
    }

    #[tokio::test]
    async fn list_violations_scopes_by_root_agent_id() {
        let tmp = TempDir::new().expect("tempdir");
        let root = AgentId::from_bytes(ROOT_BYTES);
        let child = AgentId::from_bytes(CHILD_BYTES);
        let other = AgentId::from_bytes(OTHER_BYTES);

        let entries = vec![
            // child of root → included
            make_entry(0, 100, AuditEventType::PolicyViolation, child, Some(root)),
            // root itself violates → included
            make_entry(1, 200, AuditEventType::PolicyViolation, root, None),
            // unrelated subtree → excluded
            make_entry(
                2,
                300,
                AuditEventType::PolicyViolation,
                other,
                Some(AgentId::from_bytes(PARENT_BYTES)),
            ),
        ];
        write_entries(tmp.path(), &entries);

        let reader = AuditReader::new(tmp.path().to_path_buf());
        let scoped = reader.list_violations(0, Some(root)).await.expect("list_violations");

        assert_eq!(scoped.len(), 2);
        for entry in &scoped {
            let in_subtree = entry.root_agent_id() == Some(root) || entry.agent_id() == root;
            assert!(in_subtree, "entry should be in root subtree");
        }
    }

    #[tokio::test]
    async fn list_violations_skips_non_jsonl_files_and_malformed_lines() {
        let tmp = TempDir::new().expect("tempdir");
        let child = AgentId::from_bytes(CHILD_BYTES);
        write_entries(
            tmp.path(),
            &[make_entry(0, 100, AuditEventType::PolicyViolation, child, None)],
        );

        // Non-jsonl file should be ignored.
        std::fs::write(tmp.path().join("notes.txt"), "irrelevant").expect("write txt");

        // Malformed JSON line in a jsonl file should be skipped silently.
        let extra = tmp.path().join("partial.jsonl");
        let mut f = std::fs::File::create(&extra).expect("create extra jsonl");
        writeln!(f, "{{not valid json").expect("write garbage");
        writeln!(
            f,
            "{}",
            serde_json::to_string(&make_entry(1, 200, AuditEventType::PolicyViolation, child, None,)).unwrap()
        )
        .expect("write valid line");

        let reader = AuditReader::new(tmp.path().to_path_buf());
        let violations = reader.list_violations(0, None).await.expect("list_violations");

        assert_eq!(violations.len(), 2);
    }

    // ── list_dry_run ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_dry_run_returns_only_entries_with_dry_run_true() {
        let tmp = TempDir::new().expect("tempdir");
        let child = AgentId::from_bytes(CHILD_BYTES);
        let entries = vec![
            // dry_run shadow entry — included
            make_entry_with_payload(
                0,
                100,
                AuditEventType::ToolCallIntercepted,
                child,
                None,
                r#"{"dry_run":true,"shadow_decision":"deny"}"#,
            ),
            // enforce-mode allow — excluded (no dry_run field)
            make_entry_with_payload(
                1,
                200,
                AuditEventType::ToolCallIntercepted,
                child,
                None,
                r#"{"decision":"Allow"}"#,
            ),
            // explicit dry_run:false — excluded
            make_entry_with_payload(
                2,
                300,
                AuditEventType::ToolCallIntercepted,
                child,
                None,
                r#"{"dry_run":false}"#,
            ),
        ];
        write_entries(tmp.path(), &entries);

        let reader = AuditReader::new(tmp.path().to_path_buf());
        let dry_run = reader.list_dry_run(0, None).await.expect("list_dry_run");

        assert_eq!(dry_run.len(), 1);
        assert_eq!(dry_run[0].seq(), 0);
    }

    #[tokio::test]
    async fn list_dry_run_filters_by_since_ns_and_root() {
        let tmp = TempDir::new().expect("tempdir");
        let root = AgentId::from_bytes(ROOT_BYTES);
        let child = AgentId::from_bytes(CHILD_BYTES);
        let other = AgentId::from_bytes(OTHER_BYTES);

        let entries = vec![
            // too old, excluded by since_ns
            make_entry_with_payload(
                0,
                100,
                AuditEventType::ToolCallIntercepted,
                child,
                Some(root),
                r#"{"dry_run":true}"#,
            ),
            // in subtree + newer — included
            make_entry_with_payload(
                1,
                500,
                AuditEventType::ToolCallIntercepted,
                child,
                Some(root),
                r#"{"dry_run":true,"shadow_decision":"deny"}"#,
            ),
            // newer but unrelated subtree — excluded by root scope
            make_entry_with_payload(
                2,
                600,
                AuditEventType::ToolCallIntercepted,
                other,
                Some(AgentId::from_bytes(PARENT_BYTES)),
                r#"{"dry_run":true}"#,
            ),
        ];
        write_entries(tmp.path(), &entries);

        let reader = AuditReader::new(tmp.path().to_path_buf());
        let scoped = reader.list_dry_run(200, Some(root)).await.expect("list_dry_run");

        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].seq(), 1);
    }

    #[tokio::test]
    async fn list_dry_run_returns_empty_when_dir_missing() {
        let reader = AuditReader::new(PathBuf::from("/nonexistent/audit/dir"));
        let result = reader
            .list_dry_run(0, None)
            .await
            .expect("list_dry_run should not error on missing dir");
        assert!(result.is_empty());
    }

    #[test]
    fn payload_has_dry_run_true_accepts_only_explicit_true() {
        assert!(payload_has_dry_run_true(r#"{"dry_run":true}"#));
        assert!(!payload_has_dry_run_true(r#"{"dry_run":false}"#));
        assert!(!payload_has_dry_run_true(r#"{"dry_run":"true"}"#));
        assert!(!payload_has_dry_run_true(r#"{"other":1}"#));
        assert!(!payload_has_dry_run_true("not-json"));
    }
}
