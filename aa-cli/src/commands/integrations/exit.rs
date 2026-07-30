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

use std::process::ExitCode;

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
            Outcome::InternalError => "internal_error",
        }
    }

    /// Every outcome, for the help text and for the tests that pin them.
    pub const ALL: [Outcome; 9] = [
        Outcome::Success,
        Outcome::InternalError,
        Outcome::Unsupported,
        Outcome::Incompatible,
        Outcome::Drifted,
        Outcome::VerificationFailed,
        Outcome::RuntimeUnavailable,
        Outcome::Denied,
        Outcome::Aborted,
    ];
}

impl From<Outcome> for ExitCode {
    fn from(outcome: Outcome) -> Self {
        ExitCode::from(outcome.code())
    }
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
}
