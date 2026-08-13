//! How much is known about the agent identity attached to a governance check.
//!
//! A check request carries an `agentId` supplied by the caller. That string is
//! a *claim*: the SDK asserts which agent subject the action belongs to. It is
//! not, by itself, an authentication of that subject. This module gives the
//! difference a name so it can be recorded in evidence rather than described in
//! prose (AAASM-5665).
//!
//! Three assurance states are distinguished, and nothing else is representable:
//!
//! | State | Meaning |
//! | --- | --- |
//! | [`AgentIdentityAssurance::Unattributed`] | No `agentId` on the request. No identity — not a default one |
//! | [`AgentIdentityAssurance::Asserted`] | An `agentId` was claimed; no authoritative identity was available to check it against |
//! | [`AgentIdentityAssurance::Bound`] | The claimed `agentId` matched the authoritative identity the receiver resolved independently of the claim |
//!
//! [`AgentIdentityAttribution::resolve`] is the only constructor that consults
//! an authoritative identity, and it **never** returns `Bound` for a claim that
//! disagrees with one. A disagreeing claim resolves to `Asserted`, so no
//! evidence record can describe a mismatched claim as bound identity, and a
//! caller reading the assurance cannot mistake the claim for a verified subject.

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

/// The three-valued assurance level of an agent identity attached to a check.
///
/// Ordered from least to most known. Serialised lowercase (`"unattributed"` /
/// `"asserted"` / `"bound"`) by [`AgentIdentityAssurance::as_str`], which is
/// the form written into evidence payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AgentIdentityAssurance {
    /// The request carried no agent identity at all.
    ///
    /// The default, deliberately: a record that was never told which agent
    /// acted must read as *unattributed*, never as some placeholder subject.
    #[default]
    Unattributed,
    /// The request claimed an agent identity, and the receiver had no
    /// authoritative identity of its own to check the claim against.
    ///
    /// The claim is carried and attributed. It is not authenticated.
    Asserted,
    /// The claimed identity equals the authoritative identity the receiver
    /// resolved without reference to the claim.
    ///
    /// The strength of this state is exactly the strength of whatever produced
    /// the authoritative identity; see the caller that supplies it.
    ///
    /// A corroboration, **not** a verification — never render it as "identity
    /// verified". In the gateway the authoritative identity comes from
    /// possession of a UUID-v4 bearer registration token, so a replayed token
    /// yields `Bound` while proving nothing about the caller being that agent's
    /// process. It is not the Ed25519 / `did:key` machinery.
    Bound,
}

impl AgentIdentityAssurance {
    /// Lowercase wire/evidence spelling of the assurance level.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unattributed => "unattributed",
            Self::Asserted => "asserted",
            Self::Bound => "bound",
        }
    }

    /// Whether the claim agreed with an identity the receiver resolved
    /// independently of it.
    ///
    /// True only for [`Self::Bound`]. Exists so callers asking "is this
    /// identity corroborated?" test this rather than `!= Unattributed`, which
    /// would silently promote an asserted claim.
    ///
    /// **This is not a test for authenticated identity, and `Bound` must never
    /// be rendered as *verified*.** Its strength is only that of whatever
    /// produced the authoritative identity, which this type does not know and
    /// cannot bound. For the gateway that is possession of a UUID-v4 bearer
    /// registration token: a replayed token yields `Bound` while proving
    /// nothing about the caller being that agent's process. A surface that
    /// renders `Bound` as "identity verified" overstates every deployment whose
    /// authoritative identity is a bearer credential.
    #[must_use]
    pub const fn is_bound(self) -> bool {
        matches!(self, Self::Bound)
    }
}

/// An agent identity attached to a check, together with what is known about it.
///
/// Construct with [`AgentIdentityAttribution::resolve`]. The claimed identity is
/// retained in every state that has one, so evidence can name the subject the
/// caller asserted even when that claim was not bound.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "assurance", rename_all = "snake_case"))]
pub enum AgentIdentityAttribution {
    /// No agent identity was supplied.
    #[default]
    Unattributed,
    /// An identity was claimed but not bound to an authoritative identity.
    Asserted {
        /// The identity the request claimed.
        claimed: String,
    },
    /// The claimed identity matched the authoritative identity.
    Bound {
        /// The agreed identity — claimed and authoritative are equal here.
        agent_id: String,
    },
}

#[cfg(feature = "alloc")]
impl AgentIdentityAttribution {
    /// Resolve the attribution for one check.
    ///
    /// * `claimed` — the `agentId` carried by the request. `None`, or an empty
    ///   string, means the request supplied no identity.
    /// * `authoritative` — an identity the receiver resolved **independently of
    ///   the claim** (for the gateway: the registered owner of the presented
    ///   credential token). `None` when the receiver has no such identity for
    ///   this request.
    ///
    /// A claim that disagrees with an authoritative identity resolves to
    /// [`Self::Asserted`], never [`Self::Bound`]. Deciding *what to do* about
    /// that disagreement — reject it, or evaluate it under the authoritative
    /// identity — belongs to the caller; this function only refuses to describe
    /// it as bound.
    #[must_use]
    pub fn resolve(claimed: Option<&str>, authoritative: Option<&str>) -> Self {
        let agreement = authoritative.map(|a| Some(a) == claimed.filter(|c| !c.is_empty()));
        Self::from_claim(claimed, agreement)
    }

    /// Resolve the attribution when the receiver's authoritative identity is
    /// not a string and so cannot be compared here.
    ///
    /// * `claimed` — as [`Self::resolve`].
    /// * `agreement` — `None` when the receiver has no authoritative identity
    ///   for this request; `Some(true)` when it resolved one **and already
    ///   compared it** to the claim and they agree; `Some(false)` when they
    ///   disagree.
    ///
    /// The gateway needs this because its authoritative identity is a
    /// registry key derived from the `{org, team, agent}` triple, while the
    /// claim travelling in evidence is the wire `agentId` string — the
    /// comparison happens over keys, the record keeps the string.
    ///
    /// `Some(false)` yields [`Self::Asserted`], never [`Self::Bound`]. So does
    /// every value of `agreement` when there is no claim.
    #[must_use]
    pub fn from_claim(claimed: Option<&str>, agreement: Option<bool>) -> Self {
        let claimed = match claimed {
            Some(c) if !c.is_empty() => c,
            _ => return Self::Unattributed,
        };
        if agreement == Some(true) {
            Self::Bound {
                agent_id: claimed.to_string(),
            }
        } else {
            Self::Asserted {
                claimed: claimed.to_string(),
            }
        }
    }

    /// The three-valued assurance level of this attribution.
    #[must_use]
    pub const fn assurance(&self) -> AgentIdentityAssurance {
        match self {
            Self::Unattributed => AgentIdentityAssurance::Unattributed,
            Self::Asserted { .. } => AgentIdentityAssurance::Asserted,
            Self::Bound { .. } => AgentIdentityAssurance::Bound,
        }
    }

    /// The identity the request claimed, if it claimed one.
    ///
    /// Present for both [`Self::Asserted`] and [`Self::Bound`] — the claim is
    /// what a reviewer searches evidence by, whether or not it was bound.
    #[must_use]
    pub fn claimed_id(&self) -> Option<&str> {
        match self {
            Self::Unattributed => None,
            Self::Asserted { claimed } => Some(claimed),
            Self::Bound { agent_id } => Some(agent_id),
        }
    }

    /// The identity that may be relied on, i.e. `Some` only when bound.
    ///
    /// Use this — not [`Self::claimed_id`] — anywhere the identity would grant
    /// something.
    #[must_use]
    pub fn bound_id(&self) -> Option<&str> {
        match self {
            Self::Bound { agent_id } => Some(agent_id),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn absent_claim_is_unattributed() {
        let a = AgentIdentityAttribution::resolve(None, None);
        assert_eq!(a, AgentIdentityAttribution::Unattributed);
        assert_eq!(a.assurance(), AgentIdentityAssurance::Unattributed);
        assert_eq!(a.claimed_id(), None);
        assert_eq!(a.bound_id(), None);
    }

    #[test]
    fn empty_claim_is_unattributed_not_an_empty_identity() {
        // The failure mode this guards: `""` hashing to a stable value that a
        // policy rule or a registry entry could match. An empty claim is the
        // absence of a claim.
        let a = AgentIdentityAttribution::resolve(Some(""), None);
        assert_eq!(a, AgentIdentityAttribution::Unattributed);
        assert_eq!(a.claimed_id(), None);
    }

    #[test]
    fn an_absent_claim_stays_unattributed_even_with_an_authoritative_identity() {
        // A credentialed request that names no agent must not silently acquire
        // the token owner's identity as if it had claimed it.
        let a = AgentIdentityAttribution::resolve(None, Some("agent-owner"));
        assert_eq!(a, AgentIdentityAttribution::Unattributed);
        assert_eq!(a.bound_id(), None);
    }

    #[test]
    fn claim_without_an_authoritative_identity_is_asserted() {
        let a = AgentIdentityAttribution::resolve(Some("agent-a"), None);
        assert_eq!(
            a,
            AgentIdentityAttribution::Asserted {
                claimed: "agent-a".into()
            }
        );
        assert_eq!(a.assurance(), AgentIdentityAssurance::Asserted);
        assert_eq!(a.claimed_id(), Some("agent-a"));
        // Asserted is not relied on.
        assert_eq!(a.bound_id(), None);
        assert!(!a.assurance().is_bound());
    }

    #[test]
    fn matching_claim_is_bound() {
        let a = AgentIdentityAttribution::resolve(Some("agent-a"), Some("agent-a"));
        assert_eq!(
            a,
            AgentIdentityAttribution::Bound {
                agent_id: "agent-a".into()
            }
        );
        assert_eq!(a.assurance(), AgentIdentityAssurance::Bound);
        assert_eq!(a.bound_id(), Some("agent-a"));
        assert!(a.assurance().is_bound());
    }

    #[test]
    fn mismatched_claim_is_asserted_never_bound() {
        // The load-bearing case: agent-a presents a credential that belongs to
        // agent-b. The claim is retained for evidence, but no part of this type
        // will report it as bound identity.
        let a = AgentIdentityAttribution::resolve(Some("agent-a"), Some("agent-b"));
        assert_eq!(a.assurance(), AgentIdentityAssurance::Asserted);
        assert_eq!(a.claimed_id(), Some("agent-a"));
        assert_eq!(a.bound_id(), None);
        assert!(!a.assurance().is_bound());
    }

    #[test]
    fn from_claim_agrees_with_resolve_on_every_combination() {
        // `resolve` is a thin string-comparing wrapper over `from_claim`; if the
        // two ever diverge, one caller's evidence would disagree with another's.
        for claimed in [None, Some(""), Some("agent-a")] {
            for authoritative in [None, Some("agent-a"), Some("agent-b")] {
                let via_resolve = AgentIdentityAttribution::resolve(claimed, authoritative);
                let agreement = authoritative.map(|a| Some(a) == claimed.filter(|c| !c.is_empty()));
                let via_from_claim = AgentIdentityAttribution::from_claim(claimed, agreement);
                assert_eq!(
                    via_resolve, via_from_claim,
                    "claimed={claimed:?} auth={authoritative:?}"
                );
            }
        }
    }

    #[test]
    fn from_claim_with_disagreement_is_asserted() {
        let a = AgentIdentityAttribution::from_claim(Some("agent-a"), Some(false));
        assert_eq!(a.assurance(), AgentIdentityAssurance::Asserted);
        assert_eq!(a.claimed_id(), Some("agent-a"));
        assert_eq!(a.bound_id(), None);
    }

    #[test]
    fn from_claim_without_a_claim_is_unattributed_whatever_the_agreement() {
        for agreement in [None, Some(true), Some(false)] {
            assert_eq!(
                AgentIdentityAttribution::from_claim(None, agreement),
                AgentIdentityAttribution::Unattributed,
                "agreement={agreement:?}"
            );
        }
    }

    #[test]
    fn assurance_wire_spellings_are_distinct_and_stable() {
        assert_eq!(AgentIdentityAssurance::Unattributed.as_str(), "unattributed");
        assert_eq!(AgentIdentityAssurance::Asserted.as_str(), "asserted");
        assert_eq!(AgentIdentityAssurance::Bound.as_str(), "bound");
    }

    #[test]
    fn default_assurance_is_unattributed() {
        assert_eq!(AgentIdentityAssurance::default(), AgentIdentityAssurance::Unattributed);
        assert_eq!(
            AgentIdentityAttribution::default().assurance(),
            AgentIdentityAssurance::Unattributed
        );
    }
}
