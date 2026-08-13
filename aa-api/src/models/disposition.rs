//! The additive `sensitive_data_disposition` vocabulary (AAASM-5356, ADR 0032 §10 D-2).
//!
//! # Why this is a second field and not five more verdicts
//!
//! ADR 0018 froze [`RuntimeVerdict`] at five variants and shipped it with zero
//! new OpenAPI paths. ADR 0024 establishes that **adding an enum variant is not
//! additive on the wire** — a reader that does not know the new spelling refuses
//! the payload — so extending `RuntimeVerdict` to say *how* a payload was
//! transformed would break a contract that was frozen on purpose. ADR 0032 D-2
//! therefore puts the finer vocabulary in a separate, optional field, and this
//! module is that field's type.
//!
//! # The three rules this module has to keep
//!
//! **1. Absence must keep meaning exactly what it means today.** The field is
//! `Option<SensitiveDataDisposition>` and is `skip_serializing_if`-omitted when
//! absent, so a response carrying no disposition is byte-identical to what the
//! same response was before this type existed. A client that has never heard of
//! the field reads the same object it read yesterday.
//!
//! **2. A `RuntimeVerdict`-only reader must still be right, just coarser.**
//! [`SensitiveDataDisposition::implied_verdict`] is the full eight-value mapping
//! from ADR 0032 §10 D-2, written as a wildcard-free `match` so neither
//! vocabulary can grow a value whose coarse meaning nobody chose.
//!
//! **3. It is not a second authorisation channel.** See below — this one is
//! structural, not a promise.
//!
//! # How "never an authorisation input" is enforced rather than asserted
//!
//! Three independent mechanisms, none of which is a comment:
//!
//! - **The crates that decide cannot name the type.** `aa-api` depends on
//!   `aa-gateway` and `aa-runtime`; the dependency does not run the other way
//!   (ADR 0018 put `RuntimeVerdict` here for the same reason — so it could carry
//!   a `utoipa::ToSchema` derive). For the policy engine or the enforcement
//!   pipeline to consult a `SensitiveDataDisposition` it would have to depend on
//!   `aa-api`, which is a dependency cycle `cargo` refuses to build. The
//!   authorisation decision is made in crates that structurally cannot see this
//!   enum.
//! - **It is never an input.** The type appears only in response bodies, never
//!   in a request body or a query parameter, so no caller can supply one for the
//!   server to act on. `the_disposition_is_never_a_request_input` in
//!   `aa-api/tests/sensitive_data_disposition_contract.rs` asserts that against
//!   the *generated* `openapi/v1.yaml`, which is the artifact clients build
//!   from.
//! - **It exposes no permission-shaped API.** There is no `is_allowed`, no
//!   `From<SensitiveDataDisposition> for Decision`, and deliberately no
//!   `PartialOrd`/`Ord` — an ordering is exactly the hook someone would reach
//!   for to write "at least as permissive as", which is an authorisation
//!   question. The one method that produces a verdict returns it for *reporting*
//!   and is documented as such.
//!
//! # Shadow reporting: `shadow_decision` owns it, this field does not
//!
//! The proto audit event already has a `shadow_decision` string (`audit.proto`
//! field 31) carrying **what the policy engine would have decided** had the
//! agent not been in observe/dry-run mode, alongside the rule id that produced
//! it. That field keeps sole ownership of shadow *decision* reporting; nothing
//! here duplicates it, and nothing may populate
//! [`ShadowOnly`](SensitiveDataDisposition::ShadowOnly) by copying it.
//!
//! `ShadowOnly` answers a different question — *what happened to the payload* —
//! with the answer "nothing: the sensitive-data pipeline observed and reported
//! only". That it cannot become a second copy of `shadow_decision` is
//! structural rather than a rule to remember: it is a **unit variant**, with
//! nowhere to put a would-be verdict. The two fields are read together, not
//! instead of each other.
//!
//! # Precedence: one action, one disposition
//!
//! The field is single-valued, but an action can be both redacted *and*
//! approval-granted. [`SensitiveDataDisposition::reported`] resolves that, and
//! the rule is derived rather than invented: **the disposition whose implied
//! verdict is more restrictive wins**, so collapsing to one value can never
//! under-report to a `RuntimeVerdict`-only reader. Redacted-and-approved
//! reports `redact` (verdict `scrub`), not `approval_granted` (verdict
//! `allow`) — the outcome ADR 0032 §10 calls for.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::models::verdict::RuntimeVerdict;

/// What the sensitive-data pipeline did to an action's payload and to the
/// approval of the action, at a granularity the 5-way runtime verdict
/// deliberately does not carry (ADR 0032 §10 D-2).
///
/// A **record of** a decision the gateway already made, never an input to one:
/// the runtime verdict remains the authoritative outcome, and every disposition
/// but `none` maps onto one, so a client that reads only the verdict still
/// reaches a correct if coarser conclusion.
///
/// These eight values are a closed vocabulary. Adding a ninth is the same
/// category of breaking wire change ADR 0024 forbids for the runtime verdict.
///
/// This doc comment is published as the schema description in `openapi/v1.yaml`;
/// the implementation rationale — including how "never an authorisation input"
/// is enforced rather than promised — is in the module documentation, which is
/// not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveDataDisposition {
    /// Findings were removed from the payload and the scrubbed bytes were
    /// forwarded. A redacted action is a *transformed transmission*, never a
    /// prevented one.
    Redact,
    /// Findings were replaced with a fixed-shape placeholder that preserves the
    /// field's format, and the masked bytes were forwarded.
    Mask,
    /// Findings were replaced with a reversible token and the tokenized bytes
    /// were forwarded.
    Tokenize,
    /// The action was held for a human approval decision that had not been made
    /// when this record was written.
    RequireApproval,
    /// A human approved the action and it proceeded.
    ApprovalGranted,
    /// A human refused the action and it was blocked.
    ApprovalDenied,
    /// The sensitive-data pipeline observed and reported only; the payload was
    /// neither transformed nor held. Distinct from
    /// [`None`](Self::None) — this records that inspection ran in
    /// observe-only mode, not that nothing was recorded.
    ShadowOnly,
    /// No sensitive-data disposition applies. Semantically identical to the
    /// field being absent, which is what ADR 0032 §10 D-2 requires: the
    /// [`RuntimeVerdict`] carries the whole meaning of the record.
    None,
}

impl SensitiveDataDisposition {
    /// The coarse [`RuntimeVerdict`] this disposition implies — ADR 0032 §10
    /// D-2's mapping table, in code.
    ///
    /// | disposition | verdict |
    /// |---|---|
    /// | `redact` / `mask` / `tokenize` | `scrub` |
    /// | `require_approval` | `pending` |
    /// | `approval_granted` | `allow` |
    /// | `approval_denied` | `deny` |
    /// | `shadow_only` | `allow` |
    /// | `none` | `None` — the verdict carries the whole meaning |
    ///
    /// # This is reporting, not authorisation
    ///
    /// It answers "what would a client that only understands `RuntimeVerdict`
    /// conclude from this record?". It must not be called to decide whether an
    /// action is permitted — that decision is `aa-gateway`'s and was made before
    /// any disposition existed. See the module documentation for why the crates
    /// that make it cannot reach this method at all.
    ///
    /// # Why `Option`
    ///
    /// [`None`](Self::None) maps to no verdict rather than to
    /// [`RuntimeVerdict::Allow`], because it is not a claim that the action was
    /// allowed — it is the statement that this field adds nothing and the
    /// record's own verdict stands. Returning `Allow` here would let a
    /// `none` disposition contradict a `deny` verdict.
    ///
    /// The arms are spelled out one per value with no `_` fallback, so a ninth
    /// disposition cannot be added without someone choosing its coarse meaning.
    pub fn implied_verdict(self) -> Option<RuntimeVerdict> {
        match self {
            Self::Redact => Some(RuntimeVerdict::Scrub),
            Self::Mask => Some(RuntimeVerdict::Scrub),
            Self::Tokenize => Some(RuntimeVerdict::Scrub),
            Self::RequireApproval => Some(RuntimeVerdict::Pending),
            Self::ApprovalGranted => Some(RuntimeVerdict::Allow),
            Self::ApprovalDenied => Some(RuntimeVerdict::Deny),
            Self::ShadowOnly => Some(RuntimeVerdict::Allow),
            Self::None => Option::None,
        }
    }

    /// Reporting rank: when several dispositions applied to one action, the
    /// highest rank is the one the single-valued field carries.
    ///
    /// The ranks are not arbitrary — they ascend with the restrictiveness of
    /// [`implied_verdict`](Self::implied_verdict), which is what makes
    /// collapsing to one value safe for a `RuntimeVerdict`-only reader: the
    /// surviving disposition never implies a *less* restrictive verdict than one
    /// it displaced. `precedence_never_under_reports_the_verdict` proves that
    /// over every pair rather than trusting the numbers below.
    ///
    /// Values sharing an implied verdict (the three transformations; the two
    /// `allow`-implying values) are ordered by declaration. The tie-break is
    /// arbitrary *and harmless*: either winner yields the same verdict, so no
    /// coarse reader can tell which was picked.
    ///
    /// # `require_approval` outranking `approval_granted`
    ///
    /// Taken on its own that pair looks like the mistake this module avoids
    /// elsewhere: reporting `pending` for an action that completed is as wrong
    /// as mapping `none` to `allow`. It is defused by the two values being
    /// mutually exclusive on one record rather than by the ranking — a record
    /// says the action was *held awaiting* a decision or that a human *made*
    /// one, never both, because the second supersedes the first on the same
    /// action. If a caller ever does hold both, the ordering here is the
    /// deliberate one: `pending` over-reports restrictiveness, and
    /// over-reporting is the safe direction for a reporting field.
    fn precedence(self) -> u8 {
        match self {
            // Adds nothing, so it loses to everything that does.
            Self::None => 0,
            Self::ShadowOnly => 1,
            Self::ApprovalGranted => 2,
            Self::Redact => 3,
            Self::Mask => 4,
            Self::Tokenize => 5,
            Self::RequireApproval => 6,
            // The action did not happen; nothing said about the payload can
            // outrank that.
            Self::ApprovalDenied => 7,
        }
    }

    /// The single disposition to report for an action that had several.
    ///
    /// Returns [`None`](Self::None) for an empty iterator, which is the same
    /// statement as the field being absent.
    ///
    /// This resolves a *presentation* ambiguity — which of several true
    /// statements to record in a one-valued field — and decides nothing about
    /// whether the action was permitted.
    ///
    /// The worked case ADR 0032 §10 names — an action both redacted and
    /// approval-granted reports `redact`, so a coarse reader still sees `scrub`
    /// rather than being told the payload passed clean — is asserted by
    /// `a_transformation_outranks_an_approval_grant` below. It is deliberately
    /// *not* written as a doctest: CI runs `cargo test --doc` for `aa-gateway`
    /// only (AAASM-5354), so an example here would document a property nothing
    /// executes.
    pub fn reported(dispositions: impl IntoIterator<Item = Self>) -> Self {
        dispositions.into_iter().fold(Self::None, |winner, candidate| {
            if candidate.precedence() > winner.precedence() {
                candidate
            } else {
                winner
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every disposition ADR 0032 §10 D-2 defines, in the order it lists them.
    ///
    /// Spelled out because Rust has no variant reflection. On its own this array
    /// is exactly the trap AAASM-5384 documented — a ninth variant would simply
    /// not be *mentioned* here, the list would still be eight long, and every
    /// assertion below would still pass. [`variant_index`] is what stops that.
    const DISPOSITIONS_IN_ADR_0032_ORDER: [SensitiveDataDisposition; 8] = [
        SensitiveDataDisposition::Redact,
        SensitiveDataDisposition::Mask,
        SensitiveDataDisposition::Tokenize,
        SensitiveDataDisposition::RequireApproval,
        SensitiveDataDisposition::ApprovalGranted,
        SensitiveDataDisposition::ApprovalDenied,
        SensitiveDataDisposition::ShadowOnly,
        SensitiveDataDisposition::None,
    ];

    /// The wire spellings ADR 0032 §10 D-2 fixes, positionally aligned with
    /// [`DISPOSITIONS_IN_ADR_0032_ORDER`].
    ///
    /// Written as literals rather than derived from the enum, so a `rename_all`
    /// change or a variant rename is a test failure and not a silent respelling
    /// of a published contract.
    const WIRE_SPELLINGS_IN_ADR_0032_ORDER: [&str; 8] = [
        "redact",
        "mask",
        "tokenize",
        "require_approval",
        "approval_granted",
        "approval_denied",
        "shadow_only",
        "none",
    ];

    /// The position ADR 0032 §10 D-2 assigns each disposition.
    ///
    /// This exists for its `match`, not its return value. The arms are
    /// exhaustive with no `_` fallback, so **adding** a variant stops this file
    /// compiling, and **removing** one leaves both this match and
    /// [`DISPOSITIONS_IN_ADR_0032_ORDER`] naming a variant that no longer
    /// exists. It is the same mechanism `aa_core_label_contract` uses to keep
    /// `RuntimeVerdict` honest, for the same reason.
    fn variant_index(disposition: SensitiveDataDisposition) -> usize {
        match disposition {
            SensitiveDataDisposition::Redact => 0,
            SensitiveDataDisposition::Mask => 1,
            SensitiveDataDisposition::Tokenize => 2,
            SensitiveDataDisposition::RequireApproval => 3,
            SensitiveDataDisposition::ApprovalGranted => 4,
            SensitiveDataDisposition::ApprovalDenied => 5,
            SensitiveDataDisposition::ShadowOnly => 6,
            SensitiveDataDisposition::None => 7,
        }
    }

    /// How restrictive a coarse verdict is, with "no verdict at all" below
    /// `allow`.
    ///
    /// # This ranking is AAASM-5356's, not ADR 0018's
    ///
    /// ADR 0018 *lists* the five variants and calls them ordered
    /// least-to-most restrictive, but it states no ranking this test could
    /// inherit, and its declaration order carries no serialized meaning. The
    /// numbers below are a judgment made here, and the debatable one is
    /// `pending` (4) above `scrub` (3): a held action has not happened yet,
    /// whereas a scrubbed one was carried out with a transformed payload, so
    /// `pending` is treated as the more restrictive outcome.
    ///
    /// Nothing outside this test depends on it. It exists to check that
    /// [`precedence`](SensitiveDataDisposition::precedence) is monotone in
    /// restrictiveness — if the ranking here were wrong, the failure mode is a
    /// property test that is too strict or too lax, never a wrong wire value.
    ///
    /// Wildcard-free on purpose: this is a second place a sixth `RuntimeVerdict`
    /// variant would stop the build, which matters because the disposition
    /// mapping is only sound if every verdict has a known restrictiveness.
    fn restrictiveness(verdict: Option<RuntimeVerdict>) -> u8 {
        match verdict {
            Option::None => 0,
            Some(RuntimeVerdict::Allow) => 1,
            Some(RuntimeVerdict::Narrow) => 2,
            Some(RuntimeVerdict::Scrub) => 3,
            Some(RuntimeVerdict::Pending) => 4,
            Some(RuntimeVerdict::Deny) => 5,
        }
    }

    /// The vocabulary is exactly ADR 0032 §10 D-2's eight values, with exactly
    /// those spellings, in that order.
    ///
    /// Catches a removed value (the arrays stop being eight long, and the
    /// removed variant stops existing), a renamed value (the literal no longer
    /// matches what serde emits), and a reordered one (the comparison is
    /// positional).
    #[test]
    fn the_vocabulary_is_exactly_adr_0032s_eight_values() {
        assert_eq!(
            DISPOSITIONS_IN_ADR_0032_ORDER.len(),
            8,
            "ADR 0032 §10 D-2 fixes eight dispositions",
        );
        // Checked before zipping, because `zip` truncates to the shorter side
        // and would turn a dropped spelling into a pass.
        assert_eq!(
            DISPOSITIONS_IN_ADR_0032_ORDER.len(),
            WIRE_SPELLINGS_IN_ADR_0032_ORDER.len(),
        );

        for (position, (disposition, expected)) in DISPOSITIONS_IN_ADR_0032_ORDER
            .iter()
            .zip(WIRE_SPELLINGS_IN_ADR_0032_ORDER)
            .enumerate()
        {
            assert_eq!(
                variant_index(*disposition),
                position,
                "DISPOSITIONS_IN_ADR_0032_ORDER is itself out of order at index {position}",
            );

            let json = serde_json::to_string(disposition).unwrap();
            assert_eq!(
                json,
                format!("\"{expected}\""),
                "{disposition:?} serializes as {json} but ADR 0032 §10 D-2 spells it {expected:?}",
            );
        }
    }

    /// Each spelling reads back as the value that wrote it.
    #[test]
    fn every_disposition_round_trips_through_its_wire_spelling() {
        for disposition in DISPOSITIONS_IN_ADR_0032_ORDER {
            let json = serde_json::to_string(&disposition).unwrap();
            let restored: SensitiveDataDisposition = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, disposition);
        }
    }

    /// `Deserialize` refuses an unrecognised spelling rather than defaulting to
    /// `none` — a fallback would turn a read error into a record that looks
    /// like it had nothing to report.
    ///
    /// # What this does *not* say about the shipped read path
    ///
    /// This is a property of the impl, not of every caller. The audit-log
    /// reader in `routes::agents::entry_to_decision_row` deliberately swallows
    /// the error with `.ok()` and records the disposition as **absent**, so
    /// after AAASM-5356 "absent" means *nothing was recorded* **or** *this
    /// build could not parse what was*. That cost is bounded — the verdict is
    /// parsed independently and stays authoritative — and it is pinned by
    /// `an_unparseable_disposition_reads_as_absent_rather_than_failing_the_row`
    /// rather than left to this test to imply.
    #[test]
    fn an_unknown_spelling_is_refused_by_deserialize() {
        assert!(serde_json::from_str::<SensitiveDataDisposition>(r#""quarantine""#).is_err());
        assert!(serde_json::from_str::<SensitiveDataDisposition>(r#""Redact""#).is_err());
        assert!(serde_json::from_str::<SensitiveDataDisposition>(r#""requireApproval""#).is_err());
        assert!(serde_json::from_str::<SensitiveDataDisposition>(r#""""#).is_err());
    }

    /// ADR 0032 §10 D-2's mapping table, value by value.
    ///
    /// Written as eight explicit expectations rather than a loop over
    /// [`implied_verdict`](SensitiveDataDisposition::implied_verdict), so that
    /// changing one arm of that match fails here — a loop that re-derived the
    /// expectation from the same match would pass whatever it was changed to.
    #[test]
    fn the_mapping_is_exactly_adr_0032s_table() {
        use RuntimeVerdict::{Allow, Deny, Pending, Scrub};
        use SensitiveDataDisposition as D;

        assert_eq!(D::Redact.implied_verdict(), Some(Scrub));
        assert_eq!(D::Mask.implied_verdict(), Some(Scrub));
        assert_eq!(D::Tokenize.implied_verdict(), Some(Scrub));
        assert_eq!(D::RequireApproval.implied_verdict(), Some(Pending));
        assert_eq!(D::ApprovalGranted.implied_verdict(), Some(Allow));
        assert_eq!(D::ApprovalDenied.implied_verdict(), Some(Deny));
        assert_eq!(D::ShadowOnly.implied_verdict(), Some(Allow));
        // Not `Allow`: `none` adds nothing and must not contradict the record's
        // own verdict.
        assert_eq!(D::None.implied_verdict(), Option::None);
    }

    /// Every disposition except `none` maps onto a verdict, so a coarse reader
    /// always reaches a conclusion.
    ///
    /// The exhaustive `match` in [`variant_index`] is what keeps this from being
    /// vacuous against a ninth value.
    #[test]
    fn only_none_declines_to_imply_a_verdict() {
        for disposition in DISPOSITIONS_IN_ADR_0032_ORDER {
            let implied = disposition.implied_verdict();
            if disposition == SensitiveDataDisposition::None {
                assert_eq!(implied, Option::None);
            } else {
                assert!(implied.is_some(), "{disposition:?} implies no verdict");
            }
        }
    }

    /// Precedence never lets the surviving disposition imply a *less*
    /// restrictive verdict than one it displaced.
    ///
    /// This is the property that makes a single-valued field safe: collapsing
    /// several true dispositions into one cannot under-report to a
    /// `RuntimeVerdict`-only reader. Checked over all 64 ordered pairs rather
    /// than by reading the rank literals.
    #[test]
    fn precedence_never_under_reports_the_verdict() {
        for higher in DISPOSITIONS_IN_ADR_0032_ORDER {
            for lower in DISPOSITIONS_IN_ADR_0032_ORDER {
                if higher.precedence() <= lower.precedence() {
                    continue;
                }
                assert!(
                    restrictiveness(higher.implied_verdict()) >= restrictiveness(lower.implied_verdict()),
                    "{higher:?} outranks {lower:?} but implies the less restrictive verdict \
                     {:?} < {:?}",
                    higher.implied_verdict(),
                    lower.implied_verdict(),
                );
            }
        }
    }

    /// No two dispositions share a rank, so [`SensitiveDataDisposition::reported`]
    /// is deterministic regardless of the order the candidates arrive in.
    #[test]
    fn precedence_is_a_total_order() {
        for (position, disposition) in DISPOSITIONS_IN_ADR_0032_ORDER.iter().enumerate() {
            for other in &DISPOSITIONS_IN_ADR_0032_ORDER[position + 1..] {
                assert_ne!(
                    disposition.precedence(),
                    other.precedence(),
                    "{disposition:?} and {other:?} share a precedence rank",
                );
            }
        }
    }

    /// The case ADR 0032 §10 names: an action that was both redacted and
    /// approval-granted reports `redact`, so the verdict stays `scrub` instead
    /// of under-reporting as `allow`.
    #[test]
    fn a_transformation_outranks_an_approval_grant() {
        use SensitiveDataDisposition as D;

        assert_eq!(D::reported([D::ApprovalGranted, D::Redact]), D::Redact);
        // Order of arrival must not change the answer.
        assert_eq!(D::reported([D::Redact, D::ApprovalGranted]), D::Redact);
        assert_eq!(
            D::reported([D::ApprovalGranted, D::Redact]).implied_verdict(),
            Some(RuntimeVerdict::Scrub),
        );
    }

    /// A refusal outranks a transformation: an action that was blocked did not
    /// happen, whatever was done to its payload first.
    #[test]
    fn a_refusal_outranks_a_transformation() {
        use SensitiveDataDisposition as D;

        assert_eq!(D::reported([D::Redact, D::ApprovalDenied]), D::ApprovalDenied);
        assert_eq!(
            D::reported([D::Redact, D::ApprovalDenied]).implied_verdict(),
            Some(RuntimeVerdict::Deny),
        );
    }

    /// `none` loses to every other value, and an empty set of dispositions
    /// resolves to `none` — the same statement as the field being absent.
    #[test]
    fn none_is_the_identity_of_the_precedence_fold() {
        use SensitiveDataDisposition as D;

        assert_eq!(D::reported([]), D::None);
        assert_eq!(D::reported([D::None]), D::None);
        for disposition in DISPOSITIONS_IN_ADR_0032_ORDER {
            assert_eq!(
                D::reported([D::None, disposition]),
                disposition,
                "`none` displaced {disposition:?}",
            );
        }
    }

    /// `shadow_only` carries no would-be verdict, which is what keeps it from
    /// becoming a second representation of the audit event's `shadow_decision`.
    ///
    /// A unit variant has nowhere to put one. This test is the statement of that
    /// ownership split in executable form: if someone ever gives `ShadowOnly` a
    /// payload, the pattern below stops compiling.
    #[test]
    fn shadow_only_is_a_unit_variant_and_holds_no_shadow_decision() {
        let disposition = SensitiveDataDisposition::ShadowOnly;
        assert!(matches!(disposition, SensitiveDataDisposition::ShadowOnly));
        // It reports only that inspection was observe-only; what the policy
        // *would* have decided stays in the audit event's `shadow_decision`.
        assert_eq!(disposition.implied_verdict(), Some(RuntimeVerdict::Allow));
    }
}
