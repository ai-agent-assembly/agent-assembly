//! Canonical runtime verdict vocabulary (AAASM-5086, ADR 0018).
//!
//! [`RuntimeVerdict`] is the single source of truth for the **5-way** runtime
//! decision the dashboard renders per enforced action: `allow` / `narrow` /
//! `scrub` / `pending` / `deny` (`design/v1/hi-fi/agent-detail.jsx`,
//! `scrub.jsx`). It is deliberately distinct from two pre-existing 3-to-4-state
//! vocabularies and must not be conflated with either:
//!
//! - the proto wire enum [`Decision`](aa_proto::assembly::common::v1::Decision)
//!   (`allow` / `deny` / `pending` / `redact`) that the gateway writes to the
//!   audit log — the coarse enforcement outcome, blind to whether a `deny` was a
//!   full block or a scoped narrowing, or whether an `allow` passed clean or was
//!   scrubbed en route; and
//! - the capability-matrix [`Decision`](crate::models::capability::Decision)
//!   (`allow` / `narrow` / `approval` / `deny` / `na`) that describes a *static*
//!   (agent × resource × verb) permission cell, not a *runtime* per-action
//!   outcome.
//!
//! This enum freezes the vocabulary now so the read-side contract (the enriched
//! per-decision record on `GET /api/v1/agents/{id}/decisions`) is stable for the
//! Bucket-B backend program. **Deriving a `RuntimeVerdict` at decision time is
//! not implemented here** — it requires instrumenting the enforcement hot path
//! and is the ADR-0018-gated follow-up (AAASM-5086 follow-up); until then the
//! field is surfaced as `null`. See ADR 0018 for the decision-capture plan.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The canonical 5-way runtime verdict for a single enforced action.
///
/// Wire form is lowercase (`"allow"`, `"narrow"`, `"scrub"`, `"pending"`,
/// `"deny"`) to match the dashboard's verdict styling keys. The variants are
/// ordered least-to-most restrictive; do not reorder for wire stability, but the
/// order carries no serialized meaning (each variant serializes by name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeVerdict {
    /// Action permitted unchanged.
    Allow,
    /// Action permitted but scoped down (e.g. a broad write narrowed to specific
    /// paths) — distinct from a full `deny` so the UI can show partial success.
    Narrow,
    /// Action permitted, but its payload had secrets/PII stripped (L3 scrubbing)
    /// before reaching the destination — distinct from `allow` so scrubbed
    /// traffic is visible.
    Scrub,
    /// Action held awaiting human approval (maps to proto `Decision::PENDING`).
    Pending,
    /// Action blocked outright.
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_lowercase_five_way_vocabulary() {
        assert_eq!(serde_json::to_string(&RuntimeVerdict::Allow).unwrap(), r#""allow""#);
        assert_eq!(serde_json::to_string(&RuntimeVerdict::Narrow).unwrap(), r#""narrow""#);
        assert_eq!(serde_json::to_string(&RuntimeVerdict::Scrub).unwrap(), r#""scrub""#);
        assert_eq!(serde_json::to_string(&RuntimeVerdict::Pending).unwrap(), r#""pending""#);
        assert_eq!(serde_json::to_string(&RuntimeVerdict::Deny).unwrap(), r#""deny""#);
    }

    #[test]
    fn round_trips_through_json() {
        for v in [
            RuntimeVerdict::Allow,
            RuntimeVerdict::Narrow,
            RuntimeVerdict::Scrub,
            RuntimeVerdict::Pending,
            RuntimeVerdict::Deny,
        ] {
            let s = serde_json::to_string(&v).unwrap();
            let back: RuntimeVerdict = serde_json::from_str(&s).unwrap();
            assert_eq!(v, back);
        }
    }

    /// The runtime verdict is a distinct vocabulary from the capability-matrix
    /// `Decision`: it has a `scrub`/`pending` where the matrix has
    /// `approval`/`na`. Guards against a future accidental merge of the two.
    #[test]
    fn scrub_is_not_a_capability_decision_variant() {
        // `scrub` must deserialize as a runtime verdict...
        assert_eq!(
            serde_json::from_str::<RuntimeVerdict>(r#""scrub""#).unwrap(),
            RuntimeVerdict::Scrub
        );
        // ...but is not a member of the capability `Decision` enum.
        assert!(serde_json::from_str::<crate::models::capability::Decision>(r#""scrub""#).is_err());
    }
}
