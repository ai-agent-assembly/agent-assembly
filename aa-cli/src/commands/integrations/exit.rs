//! The exit-code vocabulary for `aasm integrations` (AAASM-5280).
//!
//! # Why these are distinct
//!
//! A script that wraps `aasm integrations` has to decide what to do next, and
//! the four things it might reasonably do are different: retry later, upgrade
//! something, repair something, or stop and page a human. Collapsing them all
//! into `1` forces every caller to parse English prose out of stderr, which
//! breaks the moment the wording improves. Each variant below therefore names an
//! outcome a caller can *act* on differently, and nothing else gets a code.
//!
//! `2` is deliberately skipped: `clap` uses it for usage errors, so reusing it
//! would make "you typed the command wrong" indistinguishable from a real
//! outcome.
//!
//! # Two axes, not one (AAASM-5499)
//!
//! [`Outcome`] answers *did the command succeed?* — that is what an exit code
//! is for. [`ChangeOutcome`] answers *did the world change?*, and the two are
//! orthogonal: a `remove` of an integration that is already absent succeeded
//! and modified nothing. Overloading the exit code with both collapses them,
//! which is how `aasm integrations repair X && echo repaired` came to announce
//! a repair of a tool that had never been installed (AAASM-5455).
//!
//! So no code is minted for a no-op. A legitimate no-op is a successful
//! idempotent outcome and exits `0`, and the distinction rides on the reported
//! [`ChangeOutcome`], which appears both in the table rendering and in
//! `--output json`. The half of the vocabulary that *is* pinned to the exit
//! code is the sign: `changed` and `unchanged` only ever accompany `0`,
//! `refused` and `failed` only ever accompany a non-zero code, and
//! [`ChangeOutcome::of`] is the single function that decides it.

use std::process::ExitCode;

use serde::Serialize;

/// What happened, in the vocabulary a caller can branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The command did what it was asked to do.
    Success,
    /// The tool, the mechanism or the verb is not available here — a request
    /// for something that does not exist on this host or in this build.
    /// Nothing is wrong; the answer is no.
    Unsupported,
    /// Two versions do not agree: this client and the running core, or the
    /// detected tool and its adapter's supported range. Something must be
    /// upgraded before the operation can be attempted at all.
    Incompatible,
    /// AASM-owned state no longer matches its receipt. `aasm integrations
    /// repair` is the next step, and it is a *different* next step from either
    /// upgrading or re-verifying.
    Drifted,
    /// The protection test ran and did not establish protection — including the
    /// case where the protected path was never exercised. Distinct from
    /// `InternalError` because the command worked perfectly; the answer is that
    /// you are not protected.
    VerificationFailed,
    /// No runtime is listening and none could be started. Every lifecycle verb
    /// is unavailable until one is, so this is a bootstrap problem rather than
    /// a failure of the requested operation.
    RuntimeUnavailable,
    /// The runtime is there and refused this client: no enrolment, an expired
    /// or out-of-scope token, or a file permission that makes the token
    /// unusable. Actionable, and not something a retry fixes.
    Denied,
    /// The user declined, or a mutating command needed a confirmation it could
    /// not obtain (no terminal and no `--yes`). Nothing was changed. Distinct
    /// from every failure above because there is nothing to fix.
    Aborted,
    /// A runtime answered and was shown **not** to be usable as the build this
    /// `aasm` belongs to — a different checkout, a deleted executable, or more
    /// than one of them listening at once (AAASM-5628).
    ///
    /// A *positive finding* about the peer, which is what separates it from
    /// [`Outcome::RuntimeUnverifiable`]: something is demonstrably wrong, and
    /// every command refuses, read-only included. Distinct from
    /// [`Outcome::Incompatible`] because nothing needs upgrading, and from
    /// [`Outcome::RuntimeUnavailable`] because a runtime *is* listening. The
    /// next step is neither: stop the wrong process. It is also a code a QA
    /// harness must refuse to record a result under — evidence gathered from a
    /// refuted runtime proves nothing about the build it was attributed to.
    RuntimeUnverified,
    /// A runtime answered and its identity could be neither confirmed nor
    /// refuted — one or both sides carry no authoritative build identity, or
    /// the peer is too old to state one (AAASM-5628).
    ///
    /// An *absence*, not a finding. Absence of provenance on both peers proves
    /// only that both are unknown, never that they are the same build, so this
    /// can never be reported as verified. Read-only surfaces still answer and
    /// label the result `unverifiable`; privileged writes, mutating operations,
    /// `Host Enforced` claims and manual enforcement evidence refuse with this
    /// code, because each of those asserts something about *this* build that an
    /// unidentified runtime cannot support.
    RuntimeUnverifiable,
    /// Anything else — a transport fault, a lifecycle failure, a bug.
    InternalError,
}

impl Outcome {
    /// The process exit code for this outcome.
    pub const fn code(self) -> u8 {
        match self {
            Outcome::Success => 0,
            // 1 stays the generic failure a shell expects for "it did not work"
            // and is reserved for `InternalError`; 2 belongs to clap.
            Outcome::InternalError => 1,
            Outcome::Unsupported => 3,
            Outcome::Incompatible => 4,
            Outcome::Drifted => 5,
            Outcome::VerificationFailed => 6,
            Outcome::RuntimeUnavailable => 7,
            Outcome::Denied => 8,
            Outcome::Aborted => 9,
            Outcome::RuntimeUnverified => 10,
            Outcome::RuntimeUnverifiable => 11,
        }
    }

    /// The token used in JSON output and in `--help`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Unsupported => "unsupported",
            Outcome::Incompatible => "incompatible",
            Outcome::Drifted => "drifted",
            Outcome::VerificationFailed => "verification_failed",
            Outcome::RuntimeUnavailable => "runtime_unavailable",
            Outcome::Denied => "denied",
            Outcome::Aborted => "aborted",
            Outcome::RuntimeUnverified => "runtime_unverified",
            Outcome::RuntimeUnverifiable => "runtime_unverifiable",
            Outcome::InternalError => "internal_error",
        }
    }

    /// Every outcome, for the help text and for the tests that pin them.
    pub const ALL: [Outcome; 11] = [
        Outcome::Success,
        Outcome::InternalError,
        Outcome::Unsupported,
        Outcome::Incompatible,
        Outcome::Drifted,
        Outcome::VerificationFailed,
        Outcome::RuntimeUnavailable,
        Outcome::Denied,
        Outcome::Aborted,
        Outcome::RuntimeUnverified,
        Outcome::RuntimeUnverifiable,
    ];
}

impl From<Outcome> for ExitCode {
    fn from(outcome: Outcome) -> Self {
        ExitCode::from(outcome.code())
    }
}

/// Whether the world changed — the question the exit code cannot answer.
///
/// The ratified public contract for `aasm integrations` (AAASM-5499). A caller
/// that has to decide "do I need to tell someone something happened?" is asking
/// this, not "did the command work?", and the two answers differ on exactly the
/// case that matters: a second `remove`, a `repair` of state that is already
/// correct, an `install` of a managed state that already exists. Each of those
/// succeeded and each of those modified nothing.
///
/// Every variant is reported explicitly on both surfaces, so `0` never leaves a
/// no-op indistinguishable from a mutation. Nothing here is inferred from the
/// absence of an optional block or from the emptiness of a list: those are what
/// a reader had to guess from before, and guessing is what the contract exists
/// to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeOutcome {
    /// The requested end state was reached, and something was modified.
    Changed,
    /// The requested end state already held; nothing was modified. A success,
    /// and the reason no no-op needs an exit code of its own.
    Unchanged,
    /// The command declined to act — authorization, policy, consent or invalid
    /// input. Nothing was modified, but unlike [`Self::Unchanged`] the end state
    /// was *not* reached, so the exit code is non-zero.
    Refused,
    /// The command tried and did not reach the requested end state.
    Failed,
}

impl ChangeOutcome {
    /// The token used in `--output json`, in the table rendering and in
    /// `--help`.
    ///
    /// Stable: a script branches on this string. The set is disjoint from
    /// [`Outcome::as_str`]'s, so a caller reading one surface can never mistake
    /// it for the other.
    pub const fn as_str(self) -> &'static str {
        match self {
            ChangeOutcome::Changed => "changed",
            ChangeOutcome::Unchanged => "unchanged",
            ChangeOutcome::Refused => "refused",
            ChangeOutcome::Failed => "failed",
        }
    }

    /// Every change outcome, for the help text and for the tests that pin them.
    pub const ALL: [ChangeOutcome; 4] = [
        ChangeOutcome::Changed,
        ChangeOutcome::Unchanged,
        ChangeOutcome::Refused,
        ChangeOutcome::Failed,
    ];

    /// Classify a completed run from its exit outcome and whether it modified
    /// anything.
    ///
    /// The **single** place the two axes meet, so the invariant "`changed` and
    /// `unchanged` mean exit `0`, everything else means non-zero" is a property
    /// of one function rather than a convention every command has to remember.
    /// `mutated` is consulted only for [`Outcome::Success`]: a run that did not
    /// reach the end state is neither a mutation nor a no-op, whatever it
    /// touched on the way.
    ///
    /// The split between [`Self::Refused`] and [`Self::Failed`] follows the
    /// exit outcome's own meaning: a refusal is a decision not to act — the
    /// host lacks the thing, the versions disagree, the user declined, the peer
    /// is not this build — and a failure is an attempt that did not land.
    pub const fn of(outcome: Outcome, mutated: bool) -> Self {
        match outcome {
            Outcome::Success => {
                if mutated {
                    ChangeOutcome::Changed
                } else {
                    ChangeOutcome::Unchanged
                }
            }
            Outcome::Unsupported
            | Outcome::Incompatible
            | Outcome::Denied
            | Outcome::Aborted
            | Outcome::RuntimeUnverified
            | Outcome::RuntimeUnverifiable => ChangeOutcome::Refused,
            Outcome::Drifted | Outcome::VerificationFailed | Outcome::RuntimeUnavailable | Outcome::InternalError => {
                ChangeOutcome::Failed
            }
        }
    }

    /// Whether this outcome accompanies exit code `0`.
    pub const fn is_success(self) -> bool {
        matches!(self, ChangeOutcome::Changed | ChangeOutcome::Unchanged)
    }
}

/// Serialized from [`ChangeOutcome::as_str`], **not** derived.
///
/// A derived `rename_all` implementation would give the JSON surface its own
/// copy of the four tokens, and two copies of one contract are two things that
/// can disagree — a build could then print `changed` to a person while telling
/// a script `unchanged`, with no single edit able to reveal it. Routing both
/// through one function makes that skew unrepresentable rather than merely
/// tested for.
impl Serialize for ChangeOutcome {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

const fn describe_change(outcome: ChangeOutcome) -> &'static str {
    match outcome {
        ChangeOutcome::Changed => "the end state was reached, and something was modified",
        ChangeOutcome::Unchanged => "the end state already held; nothing was modified",
        ChangeOutcome::Refused => "the command declined to act — nothing was modified",
        ChangeOutcome::Failed => "the command tried and did not reach the end state",
    }
}

/// The change-outcome table, rendered for `--help`.
///
/// Lives next to the vocabulary for the same reason [`help_table`] does: a new
/// outcome cannot be added without the help text moving with it.
pub fn change_help_table() -> String {
    let mut out = String::from("OUTCOMES (reported in the result, not in the exit code):\n");
    for outcome in ChangeOutcome::ALL {
        out.push_str(&format!(
            "    {:<10} exit {:<9} {}\n",
            outcome.as_str(),
            if outcome.is_success() { "0" } else { "non-zero" },
            describe_change(outcome)
        ));
    }
    out.push_str(
        "\n    A no-op is a success and exits 0. Which of the two happened is carried by\n    \
         the outcome above — on the result's first line and as `outcome` in --output json —\n    \
         never by the exit code.\n",
    );
    out
}

/// The exit-code table, rendered for `--help`.
///
/// Lives next to the codes so a new outcome cannot be added without the help
/// text moving with it.
pub fn help_table() -> String {
    let mut out = String::from("EXIT CODES:\n");
    for outcome in Outcome::ALL {
        out.push_str(&format!(
            "    {:<3} {:<20} {}\n",
            outcome.code(),
            outcome.as_str(),
            describe(outcome)
        ));
    }
    out
}

const fn describe(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Success => "the operation completed",
        Outcome::InternalError => "a transport or lifecycle failure",
        Outcome::Unsupported => "the tool, mechanism or verb is not available here",
        Outcome::Incompatible => "this client, the core or the tool version do not agree",
        Outcome::Drifted => "AASM-owned state no longer matches its receipt — run repair",
        Outcome::VerificationFailed => "the protection test did not establish protection",
        Outcome::RuntimeUnavailable => "no runtime is listening and none could be started",
        Outcome::Denied => "the runtime refused this client — re-enrol or fix permissions",
        Outcome::Aborted => "nothing was changed — declined, or no confirmation was possible",
        Outcome::RuntimeUnverified => "the runtime that answered is not this build — stop it and re-run",
        Outcome::RuntimeUnverifiable => {
            "the runtime that answered carries no build identity — read-only commands still work and say so"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole reason this module exists. If two outcomes ever share a code,
    /// a caller that branches on the code silently starts doing the wrong thing
    /// for one of them.
    #[test]
    fn every_outcome_has_its_own_code() {
        for (i, a) in Outcome::ALL.iter().enumerate() {
            for b in Outcome::ALL.iter().skip(i + 1) {
                assert_ne!(a.code(), b.code(), "{a:?} and {b:?} share exit code {}", a.code());
            }
        }
    }

    /// The ticket's minimum vocabulary, transcribed. A rename that dropped one
    /// of these would be a user-visible break in a scripted caller.
    #[test]
    fn the_required_outcomes_are_all_present() {
        let names: Vec<&str> = Outcome::ALL.iter().map(|o| o.as_str()).collect();
        for required in [
            "success",
            "unsupported",
            "incompatible",
            "drifted",
            "verification_failed",
            "runtime_unverified",
            "runtime_unverifiable",
            "internal_error",
        ] {
            assert!(names.contains(&required), "{required} is missing from the vocabulary");
        }
    }

    /// clap exits 2 for a usage error, so no outcome may claim it.
    #[test]
    fn no_outcome_claims_claps_usage_code() {
        assert!(Outcome::ALL.iter().all(|o| o.code() != 2));
    }

    #[test]
    fn only_success_is_zero() {
        for outcome in Outcome::ALL {
            assert_eq!(outcome.code() == 0, outcome == Outcome::Success, "{outcome:?}");
        }
    }

    #[test]
    fn the_help_table_lists_every_outcome() {
        let table = help_table();
        for outcome in Outcome::ALL {
            assert!(
                table.contains(outcome.as_str()),
                "{} is not documented",
                outcome.as_str()
            );
            assert!(table.contains(&outcome.code().to_string()));
        }
    }

    // ── the change-outcome axis (AAASM-5499) ────────────────────────────────

    /// The load-bearing half of the ratified contract: the *sign* of the exit
    /// code is a function of the change outcome, in both directions and for
    /// every exit outcome this build knows. A future `Outcome` variant wired
    /// into the wrong arm of `ChangeOutcome::of` fails here.
    #[test]
    fn changed_and_unchanged_are_exactly_the_zero_exit_outcomes() {
        for outcome in Outcome::ALL {
            for mutated in [true, false] {
                let change = ChangeOutcome::of(outcome, mutated);
                assert_eq!(
                    change.is_success(),
                    outcome.code() == 0,
                    "{outcome:?} exits {} but reports {}",
                    outcome.code(),
                    change.as_str()
                );
            }
        }
    }

    /// `mutated` decides between the two success outcomes and is ignored
    /// everywhere else. A run that did not reach the end state is neither a
    /// mutation nor a no-op, whatever it touched on the way.
    #[test]
    fn the_mutation_bit_only_moves_the_successful_outcomes() {
        assert_eq!(ChangeOutcome::of(Outcome::Success, true), ChangeOutcome::Changed);
        assert_eq!(ChangeOutcome::of(Outcome::Success, false), ChangeOutcome::Unchanged);
        for outcome in Outcome::ALL.into_iter().filter(|o| *o != Outcome::Success) {
            assert_eq!(
                ChangeOutcome::of(outcome, true),
                ChangeOutcome::of(outcome, false),
                "{outcome:?} let the mutation bit change a non-success outcome"
            );
        }
    }

    /// A refusal declined to act; a failure tried and missed. Transcribed from
    /// the ratified table so a re-classification is a deliberate edit here.
    #[test]
    fn refusals_and_failures_are_classified_as_ratified() {
        for outcome in [
            Outcome::Unsupported,
            Outcome::Incompatible,
            Outcome::Denied,
            Outcome::Aborted,
            Outcome::RuntimeUnverified,
            Outcome::RuntimeUnverifiable,
        ] {
            assert_eq!(ChangeOutcome::of(outcome, false), ChangeOutcome::Refused, "{outcome:?}");
        }
        for outcome in [
            Outcome::Drifted,
            Outcome::VerificationFailed,
            Outcome::RuntimeUnavailable,
            Outcome::InternalError,
        ] {
            assert_eq!(ChangeOutcome::of(outcome, false), ChangeOutcome::Failed, "{outcome:?}");
        }
    }

    /// The two vocabularies appear on the same surfaces, so a token that meant
    /// one thing in `outcome` and another in the exit table would be a trap for
    /// exactly the scripted caller both exist to serve.
    #[test]
    fn the_two_vocabularies_share_no_token() {
        for change in ChangeOutcome::ALL {
            for exit in Outcome::ALL {
                assert_ne!(change.as_str(), exit.as_str(), "{} is used by both", change.as_str());
            }
        }
    }

    /// The JSON token and the rendered token are the same string. They are read
    /// off different surfaces by the same script.
    #[test]
    fn the_json_token_matches_the_rendered_token() {
        for outcome in ChangeOutcome::ALL {
            let json = serde_json::to_string(&outcome).expect("serialize");
            assert_eq!(json, format!("\"{}\"", outcome.as_str()));
        }
    }

    #[test]
    fn every_change_outcome_has_its_own_token() {
        for (i, a) in ChangeOutcome::ALL.iter().enumerate() {
            for b in ChangeOutcome::ALL.iter().skip(i + 1) {
                assert_ne!(a.as_str(), b.as_str(), "{a:?} and {b:?} share a token");
            }
        }
    }

    #[test]
    fn the_change_help_table_lists_every_outcome() {
        let table = change_help_table();
        for outcome in ChangeOutcome::ALL {
            assert!(
                table.contains(outcome.as_str()),
                "{} is not documented",
                outcome.as_str()
            );
        }
        assert!(
            table.contains("exits 0"),
            "the help does not state that a no-op is a success: {table}"
        );
    }
}
