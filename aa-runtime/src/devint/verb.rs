//! The closed verb space of the Developer Integration API (ADR 0030 §5.6.1).
//!
//! # Why this is an enum and not a string
//!
//! The single most important structural property of the DI-API is that a
//! compromised thin client **cannot request an operation that does not exist**.
//! Every request names its operation through [`DiVerb`], which is decoded from
//! the wire by [`DiVerb::from_wire`]; an unrecognised discriminant is rejected
//! before any handler runs. There is no method string, no resource path, no
//! filter or predicate passthrough, and no opaque forwarded envelope — so there
//! is no crafting of a request that reaches something else.
//!
//! In particular there is **no policy-decision verb and no approval-*decision*
//! verb**. Agent decisions travel SDK → `aa-sdk-client` → runtime/gateway
//! (ADR 0004), on a different socket with a different verb space. Adding a
//! `check`-like verb here would reopen ADR 0004 *and* ADR 0030 (forbidden
//! design 6), so [`DiVerb::ALL`] is pinned by a unit test against the ADR's
//! list: widening the boundary fails the build instead of passing review.
//!
//! [`DiVerb::ApprovalRelay`] is the one verb that touches approvals, and it
//! relays a *human's* input to the decision authority (ADR 0030 matrix row 12).
//! It cannot return, influence or shortcut a decision — [`DiVerb::decides_policy`]
//! is `false` for every variant, and that is asserted exhaustively.

use aa_proto::assembly::devint::v1 as wire;

/// Every operation the DI-API will ever serve at this major version.
///
/// Deliberately **not** `#[non_exhaustive]`: exhaustive matching by every
/// consumer is the mechanism that makes adding a verb a visible, reviewable
/// change rather than a silent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiVerb {
    /// Enumerate the tools the linked adapters can see, and what each can do.
    ListTools,
    /// Author a reviewable dry run. Mutates nothing.
    Plan,
    /// Execute a previously authored plan.
    Apply,
    /// Read the derived protection state and the evidence behind it.
    Status,
    /// Run the protection test and adjudicate it server-side.
    Verify,
    /// Restore AASM-owned keys that drifted.
    Repair,
    /// Author and execute the reversal.
    Remove,
    /// Read an integration-scoped, already-redacted event projection.
    ScopedEvents,
    /// Relay a human's approval input to the core, which decides.
    ApprovalRelay,
}

impl DiVerb {
    /// Every variant, in the order ADR 0030 §5.6.1 lists them.
    pub const ALL: [DiVerb; 9] = [
        DiVerb::ListTools,
        DiVerb::Plan,
        DiVerb::Apply,
        DiVerb::Status,
        DiVerb::Verify,
        DiVerb::Repair,
        DiVerb::Remove,
        DiVerb::ScopedEvents,
        DiVerb::ApprovalRelay,
    ];

    /// The stable snake_case name used in scopes, audit events and the
    /// `unavailable_verbs` list of a degraded `HelloAck`.
    pub const fn as_str(self) -> &'static str {
        match self {
            DiVerb::ListTools => "list_tools",
            DiVerb::Plan => "plan",
            DiVerb::Apply => "apply",
            DiVerb::Status => "status",
            DiVerb::Verify => "verify",
            DiVerb::Repair => "repair",
            DiVerb::Remove => "remove",
            DiVerb::ScopedEvents => "scoped_events",
            DiVerb::ApprovalRelay => "approval_relay",
        }
    }

    /// Parse a scope entry or configuration string back into a verb.
    ///
    /// Returns `None` for anything outside the closed set, so an enrolment
    /// record naming a verb that does not exist cannot silently grant one that
    /// does.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == name)
    }

    /// Decode the wire discriminant.
    ///
    /// `VERB_UNSPECIFIED` and any unknown discriminant map to `None` — an
    /// absent verb is never defaulted into a real one.
    pub fn from_wire(value: i32) -> Option<Self> {
        match wire::Verb::try_from(value).ok()? {
            wire::Verb::Unspecified => None,
            wire::Verb::ListTools => Some(DiVerb::ListTools),
            wire::Verb::Plan => Some(DiVerb::Plan),
            wire::Verb::Apply => Some(DiVerb::Apply),
            wire::Verb::Status => Some(DiVerb::Status),
            wire::Verb::Verify => Some(DiVerb::Verify),
            wire::Verb::Repair => Some(DiVerb::Repair),
            wire::Verb::Remove => Some(DiVerb::Remove),
            wire::Verb::ScopedEvents => Some(DiVerb::ScopedEvents),
            wire::Verb::ApprovalRelay => Some(DiVerb::ApprovalRelay),
        }
    }

    /// The wire discriminant.
    pub const fn to_wire(self) -> wire::Verb {
        match self {
            DiVerb::ListTools => wire::Verb::ListTools,
            DiVerb::Plan => wire::Verb::Plan,
            DiVerb::Apply => wire::Verb::Apply,
            DiVerb::Status => wire::Verb::Status,
            DiVerb::Verify => wire::Verb::Verify,
            DiVerb::Repair => wire::Verb::Repair,
            DiVerb::Remove => wire::Verb::Remove,
            DiVerb::ScopedEvents => wire::Verb::ScopedEvents,
            DiVerb::ApprovalRelay => wire::Verb::ApprovalRelay,
        }
    }

    /// Whether this verb mutates integration state, and therefore must be
    /// audited as a lifecycle mutation.
    pub const fn is_mutation(self) -> bool {
        match self {
            DiVerb::Apply | DiVerb::Repair | DiVerb::Remove => true,
            // `Verify` runs a protection test: it exercises probe traffic and
            // records evidence, but it does not change the integration.
            DiVerb::ListTools
            | DiVerb::Plan
            | DiVerb::Status
            | DiVerb::Verify
            | DiVerb::ScopedEvents
            | DiVerb::ApprovalRelay => false,
        }
    }

    /// Whether the verb names a single tool. Only [`DiVerb::ListTools`] does
    /// not, which is why it is the only verb a tool-scoped token may invoke
    /// without a tool-scope check.
    pub const fn is_tool_scoped(self) -> bool {
        !matches!(self, DiVerb::ListTools)
    }

    /// Whether this verb obtains, shortcuts or influences a policy decision.
    ///
    /// Constantly `false`, and asserted exhaustively by a unit test. It exists
    /// so that a future variant must be classified explicitly — a new verb that
    /// answers "may this agent do X?" would have to return `true` here and fail
    /// the test, rather than slipping in as one more lifecycle call.
    pub const fn decides_policy(self) -> bool {
        match self {
            DiVerb::ListTools
            | DiVerb::Plan
            | DiVerb::Apply
            | DiVerb::Status
            | DiVerb::Verify
            | DiVerb::Repair
            | DiVerb::Remove
            | DiVerb::ScopedEvents
            // Relays a human's input *to* the authority; the authority answers.
            | DiVerb::ApprovalRelay => false,
        }
    }
}

impl std::fmt::Display for DiVerb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR 0030 §1.2 / §5.6.1, transcribed. If this list and `DiVerb::ALL`
    /// disagree, either the ADR moved or someone widened the boundary; both
    /// require a decision, not a green build.
    const ADR_0030_VERB_SPACE: [&str; 9] = [
        "list_tools",
        "plan",
        "apply",
        "status",
        "verify",
        "repair",
        "remove",
        "scoped_events",
        "approval_relay",
    ];

    #[test]
    fn verb_space_matches_the_adr_closed_list() {
        let actual: Vec<&str> = DiVerb::ALL.iter().map(|v| v.as_str()).collect();
        assert_eq!(actual, ADR_0030_VERB_SPACE.to_vec());
    }

    #[test]
    fn no_verb_decides_policy() {
        for verb in DiVerb::ALL {
            assert!(!verb.decides_policy(), "{verb} must not carry a policy decision");
        }
    }

    #[test]
    fn no_verb_is_named_like_a_policy_check() {
        // A cheap tripwire for the shape of mistake ADR 0030 forbids: a verb
        // called `check`, `evaluate`, `decide`, `allow` or `deny` would be a
        // second route to a decision even if its handler started out benign.
        for verb in DiVerb::ALL {
            let name = verb.as_str();
            for forbidden in ["check", "evaluate", "decide", "allow", "deny", "authorize"] {
                assert!(
                    !name.contains(forbidden),
                    "verb {name} looks like a policy-decision verb (contains {forbidden})"
                );
            }
        }
    }

    #[test]
    fn wire_round_trips_for_every_verb() {
        for verb in DiVerb::ALL {
            assert_eq!(DiVerb::from_wire(verb.to_wire() as i32), Some(verb));
        }
    }

    #[test]
    fn unspecified_and_unknown_wire_values_are_not_verbs() {
        assert_eq!(DiVerb::from_wire(0), None);
        assert_eq!(DiVerb::from_wire(9999), None);
        assert_eq!(DiVerb::from_wire(-1), None);
    }

    #[test]
    fn parse_rejects_names_outside_the_closed_set() {
        assert_eq!(DiVerb::parse("plan"), Some(DiVerb::Plan));
        assert_eq!(DiVerb::parse("check_action"), None);
        assert_eq!(DiVerb::parse(""), None);
    }

    #[test]
    fn only_lifecycle_mutations_are_flagged_as_mutations() {
        let mutations: Vec<&str> = DiVerb::ALL
            .iter()
            .filter(|v| v.is_mutation())
            .map(|v| v.as_str())
            .collect();
        assert_eq!(mutations, vec!["apply", "repair", "remove"]);
    }

    #[test]
    fn list_tools_is_the_only_verb_that_names_no_tool() {
        let unscoped: Vec<&str> = DiVerb::ALL
            .iter()
            .filter(|v| !v.is_tool_scoped())
            .map(|v| v.as_str())
            .collect();
        assert_eq!(unscoped, vec!["list_tools"]);
    }
}
