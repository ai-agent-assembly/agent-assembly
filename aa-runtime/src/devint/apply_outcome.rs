//! Whether an apply modified anything — the authoritative answer, and the
//! reasons there might not be one (AAASM-5674).
//!
//! # The question, and why it needs its own field
//!
//! `aasm integrations install` is idempotent: applying a plan whose target
//! already matches leaves the host exactly as it was. That is a success and a
//! no-op, and a caller deciding "do I tell someone something happened?" needs
//! the two apart. AAASM-5499 ratified the vocabulary — `changed | unchanged |
//! refused | failed` — and delivered it for `repair` and `remove`, but left
//! `install` out: [`aa_core::integration::ApplyOutcome::mutated`] exists, and
//! the wire had nowhere to put it.
//!
//! Every way of re-deriving it on the client was checked and each is unsound:
//!
//! | Candidate | Why it fails |
//! | --- | --- |
//! | `receipt_id` | **Reused** when the plan id matches, whether or not anything mutated |
//! | `applied_at_unix_secs` | A cross-process, second-granularity clock compare; false-reports `changed` in a tight loop |
//! | a pre-read `StatusView` | Carries neither `receipt_id` nor `plan_id`, so it cannot match "the exact desired managed state" — a policy-profile swap at the same `planned_level` reads as a false `unchanged` |
//! | exit status | Answers *did the command succeed?*, which is the orthogonal axis |
//!
//! So the answer is stated by the authority that knows it, and this module is
//! the vocabulary both ends speak.
//!
//! # Why a `bool` is forbidden
//!
//! proto3 gives a scalar no presence. A `bool mutated` field would decode to
//! `false` for every peer that never sent it, `false` reads as "nothing was
//! modified", and "nothing was modified" is a **success claim** — so every
//! runtime older than the field would silently announce `unchanged` for every
//! install it ever performed. That is AAASM-5628's defect (an absent identity
//! read as a matching one) reproduced one field over.
//!
//! [`ApplyMutation`] therefore has five states, and the two non-answers are
//! *states* rather than the absence of one:
//!
//! | State | Means |
//! | --- | --- |
//! | [`ApplyMutation::Changed`] | the end state was reached, and something was modified |
//! | [`ApplyMutation::Unchanged`] | the end state already held; nothing was modified |
//! | [`ApplyMutation::Failed`] | the apply ran and did not reach the end state |
//! | [`ApplyMutation::Unsupported`] | this peer cannot determine it, and will not be able to |
//! | [`ApplyMutation::Unknown`] | it was not established here — including because the peer was never asked |
//!
//! [`MutationUnknown`] then says *why* there is no answer, which is the
//! difference between "update the runtime" and "look at the runtime".
//!
//! # Two gates, and the order matters
//!
//! [`ApplyMutation::from_view`] checks the **negotiated version first** and the
//! field's presence second. Both are required and neither subsumes the other:
//!
//! - The version gate answers *may this client consume the field at all?* A
//!   peer that negotiated v4 never promised it, so a v5-shaped block arriving
//!   on a v4 connection is not an answer this client is entitled to read —
//!   whether it got there through a bug, a proxy, or a peer that is not this
//!   build.
//! - The presence gate answers *did this peer state one?* A v5 peer that omits
//!   the block has said nothing, and nothing is not `Unchanged`.
//!
//! Removing either produces a false success claim on some peer. That is
//! demonstrated rather than asserted — see `apply_outcome_falsification`.

use aa_proto::assembly::devint::v1 as wire;

use super::negotiate::DI_API_APPLY_OUTCOME_SINCE;

/// Whether an apply modified anything.
///
/// The same value on both ends of the wire: the runtime states one, the client
/// decodes one. What differs is which variants each side can produce — this
/// build's runtime states only [`Changed`](Self::Changed) and
/// [`Unchanged`](Self::Unchanged), because its engine always knows, while a
/// client must handle all five because the DI-API is a public contract and the
/// peer answering it need not be this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyMutation {
    /// The requested end state was reached, and something was modified.
    Changed,
    /// The requested end state already held; nothing was modified. A success,
    /// and the one answer that must never be produced by guessing.
    Unchanged,
    /// The apply ran and did not reach the requested end state.
    Failed {
        /// What the peer said about it. May be empty.
        detail: String,
    },
    /// This peer cannot determine whether the apply modified anything.
    ///
    /// A *standing* inability, distinct from [`Self::Unknown`]: a client can
    /// stop asking this peer. Never a success.
    Unsupported {
        /// Why, in the peer's words. May be empty.
        detail: String,
    },
    /// No outcome was established. Never a success, on any surface.
    Unknown(MutationUnknown),
}

/// Why no apply outcome was established.
///
/// Kept as distinct variants rather than one string because they call for
/// different actions: a version gap is fixed by updating the runtime, an
/// omitted or unrecognised value is a fact about the peer that answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationUnknown {
    /// The connection negotiated a version that predates the field, so the peer
    /// was never asked. **Not** "nothing changed" — the peer *cannot say*.
    NotReportedAtVersion {
        /// The version this connection negotiated.
        negotiated_version: u32,
        /// The version the field arrived in.
        since: u32,
    },
    /// The negotiated version carries the field and the peer sent no block.
    ///
    /// Distinct from [`Self::NotReportedAtVersion`]: this peer promised an
    /// answer and did not give one, which is a fact about the runtime rather
    /// than about its age.
    Omitted {
        /// The version this connection negotiated.
        negotiated_version: u32,
    },
    /// The peer sent a block and stated it could not classify the apply.
    Unspecified {
        /// The peer's reason. May be empty.
        detail: String,
    },
    /// The peer sent an enum value this build has no name for.
    ///
    /// Reported as unknown rather than mapped onto the nearest known value: a
    /// future `APPLY_MUTATION_…` this client cannot read is exactly the case
    /// where guessing produces a confident wrong answer.
    Unrecognised {
        /// The value that arrived.
        value: i32,
    },
}

impl MutationUnknown {
    /// A sentence naming what could not be established, and why.
    pub fn detail(&self) -> String {
        match self {
            MutationUnknown::NotReportedAtVersion {
                negotiated_version,
                since,
            } => format!(
                "this runtime speaks DI-API v{negotiated_version}; the apply outcome arrived in v{since}, \
                 so it could not be asked whether anything changed"
            ),
            MutationUnknown::Omitted { negotiated_version } => format!(
                "this runtime negotiated DI-API v{negotiated_version}, which carries the apply outcome, \
                 but it sent none"
            ),
            MutationUnknown::Unspecified { detail } if detail.is_empty() => {
                "this runtime could not establish whether the apply changed anything".to_string()
            }
            MutationUnknown::Unspecified { detail } => {
                format!("this runtime could not establish whether the apply changed anything: {detail}")
            }
            MutationUnknown::Unrecognised { value } => format!(
                "this runtime reported apply outcome {value}, which this build has no name for; \
                 update the client to one that speaks it"
            ),
        }
    }
}

impl ApplyMutation {
    /// A stable snake_case token for logs and for the audit trail.
    ///
    /// Disjoint from the CLI's `ChangeOutcome` tokens on purpose only where it
    /// has to be: `changed` and `unchanged` are deliberately the same words,
    /// because they are the same claim, and a surface that renamed them would
    /// make one contract read as two.
    pub const fn as_str(&self) -> &'static str {
        match self {
            ApplyMutation::Changed => "changed",
            ApplyMutation::Unchanged => "unchanged",
            ApplyMutation::Failed { .. } => "failed",
            ApplyMutation::Unsupported { .. } => "unsupported",
            ApplyMutation::Unknown(_) => "unknown",
        }
    }

    /// Whether this is an outcome the peer actually stated.
    ///
    /// The single predicate every caller branches on before making a claim.
    /// `false` for [`Self::Unknown`] **and** for [`Self::Unsupported`]: a
    /// standing inability is still an absence of an answer, and neither may be
    /// rendered as a success.
    pub const fn is_authoritative(&self) -> bool {
        matches!(
            self,
            ApplyMutation::Changed | ApplyMutation::Unchanged | ApplyMutation::Failed { .. }
        )
    }

    /// Whether this outcome asserts the apply modified the host.
    ///
    /// Only [`Self::Changed`] does. Every other variant — including both
    /// non-answers — is `false`, and a caller must **not** read `false` as
    /// `unchanged`: that inversion is the whole defect this type exists to
    /// prevent, which is why [`Self::is_authoritative`] has to be consulted
    /// first.
    pub const fn modified_the_host(&self) -> bool {
        matches!(self, ApplyMutation::Changed)
    }

    /// Operator-facing detail, when there is any.
    pub fn detail(&self) -> String {
        match self {
            ApplyMutation::Changed | ApplyMutation::Unchanged => String::new(),
            ApplyMutation::Failed { detail } | ApplyMutation::Unsupported { detail } => detail.clone(),
            ApplyMutation::Unknown(reason) => reason.detail(),
        }
    }

    /// Render this outcome as the block a v5 peer sends.
    ///
    /// Every variant maps onto a value; there is no arm that omits the block,
    /// because a runtime serving v5 promised an answer and "I could not
    /// establish one" is an answer.
    pub fn to_wire(&self) -> wire::ApplyOutcomeView {
        let (mutation, detail) = match self {
            ApplyMutation::Changed => (wire::ApplyMutation::Changed, String::new()),
            ApplyMutation::Unchanged => (wire::ApplyMutation::Unchanged, String::new()),
            ApplyMutation::Failed { detail } => (wire::ApplyMutation::Failed, detail.clone()),
            ApplyMutation::Unsupported { detail } => (wire::ApplyMutation::Unsupported, detail.clone()),
            // A runtime states its own words; the composed sentences the other
            // reasons carry are *client-side* readings of an absence and would
            // be a peer quoting a conclusion back at itself.
            ApplyMutation::Unknown(MutationUnknown::Unspecified { detail }) => {
                (wire::ApplyMutation::Unspecified, detail.clone())
            }
            ApplyMutation::Unknown(reason) => (wire::ApplyMutation::Unspecified, reason.detail()),
        };
        wire::ApplyOutcomeView {
            mutation: mutation as i32,
            detail,
        }
    }

    /// Decode what the peer said, given what this connection negotiated.
    ///
    /// The **only** entry point a client may use. Both gates are here and both
    /// are load-bearing:
    ///
    /// 1. `negotiated_version < DI_API_APPLY_OUTCOME_SINCE` ⇒
    ///    [`MutationUnknown::NotReportedAtVersion`], *before* the field is even
    ///    looked at. A peer that did not promise the field has not answered,
    ///    and whatever occupies its place is not evidence.
    /// 2. no block on a version that carries it ⇒ [`MutationUnknown::Omitted`].
    ///
    /// Neither path can produce [`ApplyMutation::Unchanged`]. That is the
    /// property the falsification suite pins: the only way to reach `Unchanged`
    /// is for a peer that promised an answer to have stated one.
    pub fn from_view(outcome: Option<&wire::ApplyOutcomeView>, negotiated_version: u32) -> Self {
        if negotiated_version < DI_API_APPLY_OUTCOME_SINCE {
            return ApplyMutation::Unknown(MutationUnknown::NotReportedAtVersion {
                negotiated_version,
                since: DI_API_APPLY_OUTCOME_SINCE,
            });
        }
        let Some(view) = outcome else {
            return ApplyMutation::Unknown(MutationUnknown::Omitted { negotiated_version });
        };
        match wire::ApplyMutation::try_from(view.mutation) {
            Ok(wire::ApplyMutation::Changed) => ApplyMutation::Changed,
            Ok(wire::ApplyMutation::Unchanged) => ApplyMutation::Unchanged,
            Ok(wire::ApplyMutation::Failed) => ApplyMutation::Failed {
                detail: view.detail.clone(),
            },
            Ok(wire::ApplyMutation::Unsupported) => ApplyMutation::Unsupported {
                detail: view.detail.clone(),
            },
            // The proto3 default. A block whose enum was never set says nothing,
            // and is reported as saying nothing.
            Ok(wire::ApplyMutation::Unspecified) => ApplyMutation::Unknown(MutationUnknown::Unspecified {
                detail: view.detail.clone(),
            }),
            Err(_) => ApplyMutation::Unknown(MutationUnknown::Unrecognised { value: view.mutation }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every state survives a round trip at a version that carries the field.
    ///
    /// The determinate half of "every supported outcome is tested": a mapping
    /// that lost a variant on the way out or collapsed two on the way in would
    /// be invisible to a test that only exercised `changed`.
    #[test]
    fn every_outcome_round_trips_at_the_carrying_version() {
        for original in [
            ApplyMutation::Changed,
            ApplyMutation::Unchanged,
            ApplyMutation::Failed {
                detail: "step settings-write did not land".to_string(),
            },
            ApplyMutation::Unsupported {
                detail: "this executor cannot compare canonical forms".to_string(),
            },
            ApplyMutation::Unknown(MutationUnknown::Unspecified {
                detail: "the engine was interrupted".to_string(),
            }),
        ] {
            let view = original.to_wire();
            let decoded = ApplyMutation::from_view(Some(&view), DI_API_APPLY_OUTCOME_SINCE);
            assert_eq!(decoded, original, "{original:?} did not survive the wire");
        }
    }

    /// The five tokens are distinct, and `changed`/`unchanged` are the ratified
    /// words rather than synonyms of them.
    #[test]
    fn the_tokens_are_the_ratified_vocabulary() {
        assert_eq!(ApplyMutation::Changed.as_str(), "changed");
        assert_eq!(ApplyMutation::Unchanged.as_str(), "unchanged");
        assert_eq!(ApplyMutation::Failed { detail: String::new() }.as_str(), "failed");
        assert_eq!(
            ApplyMutation::Unsupported { detail: String::new() }.as_str(),
            "unsupported"
        );
        assert_eq!(
            ApplyMutation::Unknown(MutationUnknown::Omitted { negotiated_version: 5 }).as_str(),
            "unknown"
        );
    }

    /// Only a stated `changed`, `unchanged` or `failed` is an answer.
    ///
    /// `Unsupported` is deliberately on the non-authoritative side: it is a
    /// peer saying it will never know, which is not a result to record.
    #[test]
    fn only_stated_outcomes_are_authoritative() {
        assert!(ApplyMutation::Changed.is_authoritative());
        assert!(ApplyMutation::Unchanged.is_authoritative());
        assert!(ApplyMutation::Failed { detail: String::new() }.is_authoritative());
        assert!(!ApplyMutation::Unsupported { detail: String::new() }.is_authoritative());
        for reason in [
            MutationUnknown::NotReportedAtVersion {
                negotiated_version: 4,
                since: 5,
            },
            MutationUnknown::Omitted { negotiated_version: 5 },
            MutationUnknown::Unspecified { detail: String::new() },
            MutationUnknown::Unrecognised { value: 99 },
        ] {
            let outcome = ApplyMutation::Unknown(reason.clone());
            assert!(!outcome.is_authoritative(), "{reason:?} must not be authoritative");
            assert!(!outcome.modified_the_host());
        }
    }

    /// `modified_the_host` is `true` for exactly one variant, and its `false`
    /// is not a claim of `unchanged`.
    #[test]
    fn only_changed_asserts_a_mutation() {
        assert!(ApplyMutation::Changed.modified_the_host());
        for other in [
            ApplyMutation::Unchanged,
            ApplyMutation::Failed { detail: String::new() },
            ApplyMutation::Unsupported { detail: String::new() },
            ApplyMutation::Unknown(MutationUnknown::Omitted { negotiated_version: 5 }),
        ] {
            assert!(!other.modified_the_host(), "{other:?}");
        }
    }

    /// A connection below the carrying version never reads an outcome — *even
    /// when a block is present*.
    ///
    /// The version gate is not a convenience for peers that omit the field: it
    /// is a refusal to consume one the negotiated version did not promise. A
    /// `CHANGED` block on a v4 connection is still not an answer.
    #[test]
    fn a_version_below_the_floor_reads_nothing_even_when_a_block_arrives() {
        let stated = ApplyMutation::Unchanged.to_wire();
        for version in 1..DI_API_APPLY_OUTCOME_SINCE {
            for present in [None, Some(&stated)] {
                let decoded = ApplyMutation::from_view(present, version);
                assert_eq!(
                    decoded,
                    ApplyMutation::Unknown(MutationUnknown::NotReportedAtVersion {
                        negotiated_version: version,
                        since: DI_API_APPLY_OUTCOME_SINCE,
                    }),
                    "v{version} consumed a field its version did not promise"
                );
                assert!(!decoded.is_authoritative());
                assert!(
                    decoded.detail().contains(&format!("v{version}")),
                    "the reason must name the version that could not say: {}",
                    decoded.detail()
                );
            }
        }
    }

    /// A missing block on a carrying version is `Omitted`, never `Unchanged`.
    #[test]
    fn a_missing_block_on_a_carrying_version_is_not_unchanged() {
        let decoded = ApplyMutation::from_view(None, DI_API_APPLY_OUTCOME_SINCE);
        assert_eq!(
            decoded,
            ApplyMutation::Unknown(MutationUnknown::Omitted {
                negotiated_version: DI_API_APPLY_OUTCOME_SINCE
            })
        );
        assert_ne!(decoded, ApplyMutation::Unchanged);
        assert!(!decoded.is_authoritative());
    }

    /// A default-constructed block — the shape a defaulted or zero-valued field
    /// takes — states nothing.
    ///
    /// The property that makes the enum's zero value the safe one: even a
    /// client that forgets the presence check cannot turn a defaulted block
    /// into a success claim.
    #[test]
    fn a_defaulted_block_states_nothing() {
        let defaulted = wire::ApplyOutcomeView::default();
        assert_eq!(defaulted.mutation, wire::ApplyMutation::Unspecified as i32);
        let decoded = ApplyMutation::from_view(Some(&defaulted), DI_API_APPLY_OUTCOME_SINCE);
        assert_eq!(
            decoded,
            ApplyMutation::Unknown(MutationUnknown::Unspecified { detail: String::new() })
        );
        assert!(!decoded.is_authoritative());
    }

    /// A value from a future version is named, not mapped onto a neighbour.
    #[test]
    fn an_unrecognised_value_is_reported_as_unknown() {
        let view = wire::ApplyOutcomeView {
            mutation: 4242,
            detail: String::new(),
        };
        let decoded = ApplyMutation::from_view(Some(&view), DI_API_APPLY_OUTCOME_SINCE);
        assert_eq!(
            decoded,
            ApplyMutation::Unknown(MutationUnknown::Unrecognised { value: 4242 })
        );
        assert!(decoded.detail().contains("4242"));
    }

    /// Every reason states what could not be established and what to do.
    #[test]
    fn every_unknown_reason_is_actionable() {
        for reason in [
            MutationUnknown::NotReportedAtVersion {
                negotiated_version: 4,
                since: 5,
            },
            MutationUnknown::Omitted { negotiated_version: 5 },
            MutationUnknown::Unspecified { detail: String::new() },
            MutationUnknown::Unspecified {
                detail: "the engine was interrupted".to_string(),
            },
            MutationUnknown::Unrecognised { value: 9 },
        ] {
            let detail = reason.detail();
            assert!(!detail.is_empty(), "{reason:?} has nothing to say");
            assert!(
                !detail.contains("unchanged"),
                "a non-answer must not use the word that names a success: {detail}"
            );
        }
    }
}
