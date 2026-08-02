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

/// Ties [`RuntimeVerdict`] to `aa-core`'s mirror of it (AAASM-5384).
///
/// ADR 0032 D-2 freezes ADR 0018's five-way verdict, and that freeze is asserted
/// in two files that nothing else connects: the enum above, and
/// `aa_core::types::sensitive_data::RuntimeVerdictLabel::ALL`, a hand-maintained
/// list of the same five wire labels. `aa-core` cannot import the enum — the
/// dependency runs the other way, deliberately, so `RuntimeVerdict` can carry a
/// `utoipa::ToSchema` derive (ADR 0018) — so the sensitive-data event stream
/// carries the *label*, and the label is a mirror. `aa-api` is the only crate
/// that can see both types, which is why the contract test lives here.
#[cfg(test)]
mod aa_core_label_contract {
    use super::*;
    use aa_core::types::sensitive_data::RuntimeVerdictLabel;

    /// Every [`RuntimeVerdict`], in ADR 0018's order.
    ///
    /// Spelled out because Rust has no variant reflection. [`variant_index`] is
    /// what keeps this list from silently going stale.
    const VERDICTS_IN_ADR_0018_ORDER: [RuntimeVerdict; 5] = [
        RuntimeVerdict::Allow,
        RuntimeVerdict::Narrow,
        RuntimeVerdict::Scrub,
        RuntimeVerdict::Pending,
        RuntimeVerdict::Deny,
    ];

    /// The position ADR 0018 assigns each variant.
    ///
    /// This exists for its `match`, not its return value. The arms are
    /// exhaustive with no `_` fallback, so **adding** a `RuntimeVerdict` variant
    /// stops `aa-api` compiling, and **removing** one leaves both this match and
    /// [`VERDICTS_IN_ADR_0018_ORDER`] naming a variant that no longer exists.
    ///
    /// Without it the test below would be vacuous against a sixth variant: a
    /// hand-written five-element array simply would not mention it, both lists
    /// would still be five long, and every assertion would still pass.
    fn variant_index(verdict: RuntimeVerdict) -> usize {
        match verdict {
            RuntimeVerdict::Allow => 0,
            RuntimeVerdict::Narrow => 1,
            RuntimeVerdict::Scrub => 2,
            RuntimeVerdict::Pending => 3,
            RuntimeVerdict::Deny => 4,
        }
    }

    /// [`RuntimeVerdict`] serializes to exactly `RuntimeVerdictLabel::ALL` —
    /// same length, same spellings, same order.
    ///
    /// # Why order matters
    ///
    /// The comparison is positional rather than set-based, because a set
    /// comparison would still pass with `ALL` permuted and `ALL`'s order is
    /// load-bearing in `aa-core`: it is documented as "the order [ADR 0018]
    /// defines them", it is the order `from_wire` searches, and
    /// `RuntimeVerdictLabel`'s hand-written `schemars` schema repeats the same
    /// five strings in the same order. Anyone reconciling those by eye is
    /// checking order, so this test checks order too.
    ///
    /// # Why the label is not serialized
    ///
    /// Expectations come from `RuntimeVerdictLabel::as_str`, not from
    /// `serde_json::to_string` of the label. `aa-core`'s `Serialize` impl sits
    /// behind that crate's `serde` feature, which `aa-api` does not enable; a
    /// test written against it would need a `#[cfg(feature = ...)]` and would
    /// then not run under a plain `cargo nextest run --workspace`, which passes
    /// no `--all-features`. `ALL` and `as_str` carry no feature gate, so this
    /// runs in the default profile.
    #[test]
    fn runtime_verdict_serializes_to_exactly_aa_cores_label_vocabulary() {
        // Checked before zipping, because `zip` silently truncates to the
        // shorter of the two and would turn a dropped label into a pass.
        assert_eq!(
            VERDICTS_IN_ADR_0018_ORDER.len(),
            RuntimeVerdictLabel::ALL.len(),
            "aa-api defines {} runtime verdicts but aa-core mirrors {} labels",
            VERDICTS_IN_ADR_0018_ORDER.len(),
            RuntimeVerdictLabel::ALL.len(),
        );

        for (position, (verdict, label)) in VERDICTS_IN_ADR_0018_ORDER
            .iter()
            .zip(RuntimeVerdictLabel::ALL)
            .enumerate()
        {
            assert_eq!(
                variant_index(*verdict),
                position,
                "VERDICTS_IN_ADR_0018_ORDER is itself out of ADR 0018 order at index {position}",
            );

            let json = serde_json::to_string(verdict).unwrap();
            let wire: String = serde_json::from_str(&json).expect("a RuntimeVerdict serializes as a JSON string");

            assert_eq!(
                wire,
                label.as_str(),
                "aa-api serializes {verdict:?} as {wire:?} but aa-core's \
                 RuntimeVerdictLabel::ALL[{position}] is {:?}",
                label.as_str(),
            );

            // The failure this whole contract guards: a stored
            // SensitiveDataDecisionEvent that aa-core can no longer read back.
            assert_eq!(
                RuntimeVerdictLabel::from_wire(&wire),
                Some(*label),
                "aa-core cannot resolve the label aa-api writes for {verdict:?}",
            );
        }
    }
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
