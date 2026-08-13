//! Per-agent policy-violation counts derived from the audit log (AAASM-5103).
//!
//! The registry once carried a mutable `AgentRecord.policy_violations_count`
//! field, but nothing on any enforcement path ever incremented it — it was
//! initialised to `0` at every construction site and only ever moved off `0` in
//! test fixtures. The Fleet / Topology "flagged" badge derived from it was
//! therefore permanently dead for every real agent. AAASM-5103 removes that dead
//! field and derives the count from the canonical source instead: the
//! `PolicyViolation` audit events the analytics `agent-enforcement` aggregation
//! (AAASM-5084) already counts.
//!
//! This module reads the audit log once per request and tallies those events by
//! agent id in a single grouped pass — no per-agent scan and no N+1 lookup. Each
//! surface then looks its own agents up in the resulting map (an O(1)
//! `HashMap::get`), exactly the pattern [`crate::routes::policy_hits`] uses for
//! per-document hit counts.
//!
//! ## Flagged semantics
//!
//! An agent is flagged when it has recorded at least one policy violation
//! ([`AgentViolationCounts::is_flagged`] is `count > 0`). This supersedes the old
//! `>= 50` threshold: that threshold only ever mattered against a counter that
//! never moved, so no real agent could reach it. A single recorded violation is
//! the signal a governance surface must not silently drop.

use std::collections::HashMap;

use aa_gateway::audit_reader::AuditReader;

use aa_core::audit::AuditEventType;

/// Cap on audit events scanned when building the counts, mirroring the analytics
/// aggregations' bound ([`crate::routes::analytics`]) and
/// [`crate::routes::policy_hits`] so a hot log cannot make this read unbounded.
const MAX_EVENTS: usize = 100_000;

/// Per-agent count of `PolicyViolation` audit events, keyed by the raw 16-byte
/// agent id.
#[derive(Debug, Default, Clone)]
pub struct AgentViolationCounts {
    by_agent: HashMap<[u8; 16], u32>,
}

impl AgentViolationCounts {
    /// Build the counts by tallying every `PolicyViolation` audit event, grouped
    /// by agent id, in a single pass over the bounded audit read.
    ///
    /// Reads the full retained window (`since = 0`) rather than a rolling 24h
    /// slice: "flagged" is a lifetime property of an agent — the counter this
    /// replaces was cumulative — so a violation must keep the agent flagged for
    /// as long as the audit log retains the event, not for 24h. The read stays
    /// bounded by [`MAX_EVENTS`] (newest-first), so an unbounded log cannot turn
    /// one request into an unbounded scan.
    pub async fn from_audit(reader: &AuditReader) -> Self {
        let (entries, _total) = reader
            .list_windowed(0, MAX_EVENTS, 0, None, None, None)
            .await
            .unwrap_or_default();

        let mut by_agent: HashMap<[u8; 16], u32> = HashMap::new();
        for entry in &entries {
            if entry.event_type() == AuditEventType::PolicyViolation {
                *by_agent.entry(*entry.agent_id().as_bytes()).or_insert(0) += 1;
            }
        }
        Self { by_agent }
    }

    /// The number of policy violations recorded for `agent_id` (0 when none).
    pub fn count(&self, agent_id: &[u8; 16]) -> u32 {
        self.by_agent.get(agent_id).copied().unwrap_or(0)
    }

    /// Whether `agent_id` is policy-flagged — it has recorded at least one
    /// violation (`count > 0`, AAASM-5103).
    pub fn is_flagged(&self, agent_id: &[u8; 16]) -> bool {
        self.count(agent_id) > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_unflagged_when_agent_absent() {
        let counts = AgentViolationCounts::default();
        assert_eq!(counts.count(&[9u8; 16]), 0);
        assert!(!counts.is_flagged(&[9u8; 16]));
    }

    #[test]
    fn present_count_flags_the_agent() {
        let mut by_agent = HashMap::new();
        by_agent.insert([1u8; 16], 3u32);
        by_agent.insert([2u8; 16], 1u32);
        let counts = AgentViolationCounts { by_agent };

        assert_eq!(counts.count(&[1u8; 16]), 3);
        assert!(counts.is_flagged(&[1u8; 16]));
        // A single violation is enough — count > 0, not the old >= 50 threshold.
        assert_eq!(counts.count(&[2u8; 16]), 1);
        assert!(counts.is_flagged(&[2u8; 16]));
        // An agent with no recorded violation is not flagged.
        assert_eq!(counts.count(&[3u8; 16]), 0);
        assert!(!counts.is_flagged(&[3u8; 16]));
    }
}
