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
