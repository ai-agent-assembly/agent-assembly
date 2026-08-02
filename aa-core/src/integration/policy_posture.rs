//! Which policy a governed launch would run under, as a reportable fact.
//!
//! # Why this lives here and carries no policy types (AAASM-5349)
//!
//! `status` and `verify` must be able to say which of the four policy states a
//! launch resolves to, and ADR 0030 forbidden design 10 requires the *service*
//! to compute that — a client that derived it would be making a claim wearing a
//! measurement's clothes. The resolver itself is `aa_policy::resolve`, which
//! depends on this crate, so the reportable shape has to sit below it: this is
//! plain data, and the service maps its resolution onto it.
//!
//! # Why absence is a variant rather than an `Option`
//!
//! A peer speaking an older DI-API cannot answer this question at all, and
//! "unknown" is a different fact from any of the four states — particularly
//! from `Unconfigured`, which is itself a refusal. Collapsing them would let a
//! version mismatch read as a policy finding.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The state a policy resolution landed in, using the tokens `aasm run` already
/// prints and exports as `AA_POLICY_STATE`.
///
/// Two of these refuse a governed launch. They are kept apart because the
/// operator's next step differs: a typo in their own file sends them to that
/// file, an absent policy sends them to the concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PolicyState {
    /// A document loaded and carries at least one tool rule.
    Enforced,
    /// An explicit allow-all artifact — nothing is restricted, and the operator
    /// wrote that down rather than arriving at it by omission.
    Permissive,
    /// Nothing was found at any searched location, or a document parsed cleanly
    /// and declares no tool rule. **Refuses.**
    Unconfigured,
    /// An artifact was selected but could not be turned into a policy.
    /// **Refuses.**
    LoadFailed,
}

impl PolicyState {
    /// The stable token, identical to `AA_POLICY_STATE` and the `policy=`
    /// banner, so a log scraper and a `status` reader agree without translation.
    pub fn token(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Permissive => "permissive",
            Self::Unconfigured => "unconfigured",
            Self::LoadFailed => "load_failed",
        }
    }

    /// Whether a governed launch is refused in this state.
    pub fn refuses_launch(self) -> bool {
        matches!(self, Self::Unconfigured | Self::LoadFailed)
    }
}

/// What the service can say about the policy a launch would run under.
///
/// `Unknown` is not a fifth policy state — it records that this reading could
/// not establish one, which is the honest answer when the peer speaks a DI-API
/// version that predates the field.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum PolicyPosture {
    /// The service resolved a policy and reports which state it landed in.
    Resolved {
        /// Which of the four states the resolution landed in.
        state: PolicyState,
        /// The artifact the state came from. `None` when nothing was found —
        /// there is no file to name, and naming a searched location would imply
        /// one exists.
        source: Option<String>,
        /// Operator-facing detail: the rule count, the reason it failed to
        /// load, or why it counts as permissive.
        detail: String,
    },
    /// This reading cannot establish a policy state. Carries why, so it is not
    /// mistaken for a finding about the policy.
    Unknown {
        /// Why no state could be established — a version mismatch, a shim with
        /// no service behind it, an adapter that does not resolve policy.
        reason: String,
    },
}

impl PolicyPosture {
    /// The reported state, or `None` when the posture is [`Self::Unknown`].
    ///
    /// Deliberately not defaulted to a state: a caller that wants to render
    /// something must decide what "unknown" looks like rather than inheriting a
    /// state nobody measured.
    pub fn state(&self) -> Option<PolicyState> {
        match self {
            Self::Resolved { state, .. } => Some(*state),
            Self::Unknown { .. } => None,
        }
    }

    /// The token for display: the four state tokens, or `unknown`.
    pub fn token(&self) -> &'static str {
        self.state().map_or("unknown", PolicyState::token)
    }

    /// Whether a governed launch would be refused.
    ///
    /// `None` for [`Self::Unknown`] — an unanswerable question is not a "no",
    /// and a caller that treats it as one would report a refusal that was never
    /// measured.
    pub fn refuses_launch(&self) -> Option<bool> {
        self.state().map(PolicyState::refuses_launch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tokens are a wire contract shared with `AA_POLICY_STATE`, the
    /// `policy=` banner and the `--dry-run` receipt. Renaming one silently
    /// would desynchronise surfaces that are supposed to agree by construction.
    #[test]
    fn state_tokens_are_the_documented_ones() {
        assert_eq!(PolicyState::Enforced.token(), "enforced");
        assert_eq!(PolicyState::Permissive.token(), "permissive");
        assert_eq!(PolicyState::Unconfigured.token(), "unconfigured");
        assert_eq!(PolicyState::LoadFailed.token(), "load_failed");
    }

    /// The two refusing states are the reason this is reportable at all.
    #[test]
    fn exactly_the_two_refusing_states_refuse() {
        assert!(!PolicyState::Enforced.refuses_launch());
        assert!(!PolicyState::Permissive.refuses_launch());
        assert!(PolicyState::Unconfigured.refuses_launch());
        assert!(PolicyState::LoadFailed.refuses_launch());
    }

    /// Unknown must not resolve to a state, and must not answer the refusal
    /// question — that is the whole reason it is a variant rather than an
    /// `Option<PolicyState>` defaulted somewhere.
    #[test]
    fn unknown_reports_neither_a_state_nor_a_refusal() {
        let unknown = PolicyPosture::Unknown {
            reason: "peer speaks DI-API 2".to_string(),
        };
        assert_eq!(unknown.state(), None);
        assert_eq!(unknown.refuses_launch(), None);
        assert_eq!(unknown.token(), "unknown");
    }

    /// `unknown` must never collide with a real state token, or a reader cannot
    /// tell "nobody could say" from "nothing is configured".
    #[test]
    fn unknown_token_is_not_a_policy_state_token() {
        let states = [
            PolicyState::Enforced,
            PolicyState::Permissive,
            PolicyState::Unconfigured,
            PolicyState::LoadFailed,
        ];
        assert!(!states.iter().any(|s| s.token() == "unknown"));
    }

    #[test]
    fn resolved_reports_its_state_and_refusal() {
        let p = PolicyPosture::Resolved {
            state: PolicyState::Unconfigured,
            source: None,
            detail: "no policy artifact found".to_string(),
        };
        assert_eq!(p.state(), Some(PolicyState::Unconfigured));
        assert_eq!(p.refuses_launch(), Some(true));
        assert_eq!(p.token(), "unconfigured");
    }
}
