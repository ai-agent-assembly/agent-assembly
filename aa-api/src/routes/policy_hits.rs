//! Per-document 24h policy-decision hit counts (AAASM-5107).
//!
//! AAASM-5096 shipped the `hits24h` contract on `PolicyResponse`,
//! `TeamPolicyResponse`, and the capability-matrix `Policy`, but the field was
//! always absent because nothing on the audit-write path recorded *which*
//! policy document produced a decision. AAASM-5107 captures the deciding
//! document's content digest at decision time
//! ([`aa_gateway::policy::PolicyDocument::content_digest`]) and records it on
//! each policy-decision audit entry — both as the first-class
//! `AuditEntry::policy_doc_id` field and as a `policy_doc_id` key in the entry's
//! payload JSON.
//!
//! This module reads the last-24h audit window once per request and tallies
//! those digests into a [`PolicyHitCounts`] the three surfaces look their own
//! documents up in.
//!
//! ## Absent-vs-zero discipline
//!
//! [`PolicyHitCounts::count`] returns `Some(n)` with `n >= 1` for a document
//! that fired at least once in the window, and `None` for one that did not.
//! `hits24h` is therefore **never `0` on the wire** — a document with no
//! recorded decision is *absent*, exactly the AAASM-5096 discipline that keeps
//! "fired zero times" distinct from "no data to report". A window read that
//! fails or a document whose digest never appears both surface as absent, never
//! as a misleading `0`.

use std::collections::HashMap;

use aa_gateway::audit_reader::AuditReader;

/// The 24-hour window, in nanoseconds, that a per-document hit count spans.
const WINDOW_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// Cap on audit events scanned when building the counts, mirroring the analytics
/// aggregations' bound so a hot window cannot make this read unbounded.
const MAX_EVENTS: usize = 100_000;

/// Per-document count of policy decisions recorded in the last 24 hours, keyed by
/// the deciding document's content digest (`"sha256:<hex>"`).
#[derive(Debug, Default, Clone)]
pub struct PolicyHitCounts {
    by_doc: HashMap<String, u64>,
}

impl PolicyHitCounts {
    /// Build the counts from the last-24h audit window read through `reader`.
    ///
    /// Each audit entry's deciding-document digest is read from the first-class
    /// `AuditEntry::policy_doc_id` field, falling back to the `policy_doc_id` key
    /// in the entry's payload JSON (older entries persisted before the top-level
    /// field was populated may carry only the payload copy). Entries with no
    /// digest — non-decision events, or decisions the engine could not attribute
    /// to a cascade document — are skipped.
    pub async fn from_window(reader: &AuditReader) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(u64::MAX);
        let since = now.saturating_sub(WINDOW_NS);

        let (entries, _total) = reader
            .list_windowed(since, MAX_EVENTS, 0, None, None, None)
            .await
            .unwrap_or_default();

        let mut by_doc: HashMap<String, u64> = HashMap::new();
        for entry in &entries {
            if let Some(id) = doc_id_of(entry) {
                *by_doc.entry(id).or_insert(0) += 1;
            }
        }
        Self { by_doc }
    }

    /// The number of decisions attributed to `digest` in the window, or `None`
    /// when the document fired zero times — absent, never `0`. See the module
    /// docs for the absent-vs-zero rationale.
    pub fn count(&self, digest: &str) -> Option<u64> {
        self.by_doc.get(digest).copied()
    }
}

/// Resolve a policy-decision audit entry's deciding-document digest: the
/// first-class field first, then the `policy_doc_id` payload key.
fn doc_id_of(entry: &aa_core::audit::AuditEntry) -> Option<String> {
    if let Some(id) = entry.policy_doc_id() {
        return Some(id.to_string());
    }
    let payload: serde_json::Value = serde_json::from_str(entry.payload()).ok()?;
    payload
        .get("policy_doc_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_when_document_never_fired() {
        let counts = PolicyHitCounts::default();
        assert_eq!(
            counts.count("sha256:never-seen"),
            None,
            "a document with no recorded decision must be absent, not Some(0)",
        );
    }

    #[test]
    fn present_count_reflects_tally() {
        let mut by_doc = HashMap::new();
        by_doc.insert("sha256:aaa".to_string(), 3);
        by_doc.insert("sha256:bbb".to_string(), 1);
        let counts = PolicyHitCounts { by_doc };
        assert_eq!(counts.count("sha256:aaa"), Some(3));
        assert_eq!(counts.count("sha256:bbb"), Some(1));
        assert_eq!(counts.count("sha256:ccc"), None);
    }

    #[test]
    fn doc_id_prefers_first_class_field_then_payload() {
        use aa_core::audit::{AuditEntry, AuditEventType, Lineage};
        use aa_core::identity::{AgentId, SessionId};
        use aa_security::Redaction;

        let agent = AgentId::from_bytes([1u8; 16]);
        let session = SessionId::from_bytes([2u8; 16]);

        // First-class field set → used verbatim regardless of payload.
        let with_field = AuditEntry::new_with_lineage_redaction_and_attribution(
            0,
            1_000,
            AuditEventType::PolicyViolation,
            agent,
            session,
            r#"{"policy_doc_id":"sha256:from-payload"}"#.into(),
            [0u8; 32],
            Lineage::default(),
            Redaction::default(),
            Some("sha256:from-field".to_string()),
        );
        assert_eq!(doc_id_of(&with_field).as_deref(), Some("sha256:from-field"));

        // No first-class field → fall back to the payload copy.
        let payload_only = AuditEntry::new(
            0,
            1_000,
            AuditEventType::PolicyViolation,
            agent,
            session,
            r#"{"policy_doc_id":"sha256:from-payload"}"#.into(),
            [0u8; 32],
        );
        assert_eq!(doc_id_of(&payload_only).as_deref(), Some("sha256:from-payload"));

        // Neither → None.
        let neither = AuditEntry::new(
            0,
            1_000,
            AuditEventType::PolicyViolation,
            agent,
            session,
            r#"{"action_type":"tool_call"}"#.into(),
            [0u8; 32],
        );
        assert_eq!(doc_id_of(&neither), None);
    }
}
