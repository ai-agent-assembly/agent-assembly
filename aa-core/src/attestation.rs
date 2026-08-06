//! Protection attestation — what a governance component may truthfully claim,
//! and the evidence that lets it claim it (AAASM-5535, ADR 0033 §6 and §7).
//!
//! # Why this exists
//!
//! ADR 0033 §7 records three signals in the current implementation that *look*
//! like coverage and are not: an environment variable that replaces a probe
//! result outright, a probe satisfied by a binary merely existing on `$PATH`,
//! and a layer asserted unconditionally by construction. Each of them reaches a
//! wire surface as an "active layer", which is a protection claim the system
//! cannot substantiate.
//!
//! The defect is structural, not textual. A `bool` — or a bitflag — has nowhere
//! to record *how* it came to be true, so every caller downstream is forced to
//! read "present" as "protecting". This module makes the basis of a claim part
//! of the claim, so that a basis which is not evidence cannot produce a term
//! that asserts coverage.
//!
//! # The three axes the ticket requires kept apart
//!
//! * [`SelectedMode`] — what configuration *asked for*. Intent. Never evidence.
//! * [`AttestationBasis`] — how the component's state was established.
//! * [`ClaimTerm`] — what may therefore be said, drawn from ADR 0033 §6.
//!
//! [`LayerAttestation::verified_state_at`] is the derivation between them, and
//! it is one-directional: `selected_mode` can only *lower* or hold the verified
//! state, never raise it. Asking for a control does not deliver one.
//!
//! # Relationship to ADR 0030's ladder
//!
//! [`ProtectionLevel`](crate::integration::ProtectionLevel) is the *developer
//! integration* ladder: it answers "how well is this tool integrated", keyed by
//! [`IntegrationCapability`](crate::integration::IntegrationCapability) and
//! backed by receipts. This module is deliberately **not** a second copy of it.
//! It answers a different question — "what can this enforcement component claim
//! about actions right now" — for components that have no receipt and no tool:
//! the proxy, the host-level mechanism, the in-process SDK path. The two meet
//! only in discipline: missing evidence resolves downward in both.

use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The ADR 0033 §6 claim vocabulary.
///
/// This is a *vocabulary*, not a ladder: the variants are not ordered and must
/// not be compared. A governance claim is incomplete without its decision
/// timing and its failure posture, so downstream material picks one of these
/// terms rather than an undifferentiated verb like "protects", "enforces" or
/// "catches".
///
/// The split that matters for safety is
/// [`asserts_coverage`](Self::asserts_coverage): six terms say *something
/// happened for this action*, and five say nothing did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ClaimTerm {
    /// An event reached the evidence pipeline.
    Observed,
    /// A pattern of interest was found in observed material.
    Detected,
    /// The control plane produced a decision for this action.
    Evaluated,
    /// The action did not take effect, and the decision preceded the effect.
    ///
    /// The only term that claims prevention. It requires a refusal by a
    /// component sitting *before* the effect; an asynchronous kill after the
    /// syscall has run is [`Detected`](Self::Detected), not this.
    DeniedBeforeExecution,
    /// The action proceeded with content removed.
    Redacted,
    /// The action was held pending a human decision.
    ApprovalRequired,
    /// A planned control is configured but unavailable, so the achieved level
    /// is below the planned level.
    Degraded,
    /// No control inspected this action or payload; nothing is known about it.
    ///
    /// Scoped deliberately: a connection-level observation may still exist for
    /// the same traffic, so *Unmeasured* about a payload does not imply
    /// *unobserved* about its connection.
    Unmeasured,
    /// Implemented but not validated for production use.
    Experimental,
    /// Decided but not implemented.
    Planned,
    /// Not available on this platform or configuration, with no plan asserted.
    Unsupported,
}

impl ClaimTerm {
    /// Whether this term asserts that a control acted on the action.
    ///
    /// This is the load-bearing predicate of the module: a basis that is not
    /// evidence must never yield a term for which this returns `true`. The six
    /// terms that assert coverage each require a durable artifact naming the
    /// component that produced them; the other five are the honest answers when
    /// no such artifact exists.
    pub fn asserts_coverage(self) -> bool {
        matches!(
            self,
            Self::Observed
                | Self::Detected
                | Self::Evaluated
                | Self::DeniedBeforeExecution
                | Self::Redacted
                | Self::ApprovalRequired
        )
    }

    /// Whether this term claims the action was stopped before it took effect.
    ///
    /// Distinct from [`asserts_coverage`](Self::asserts_coverage): observing,
    /// detecting and evaluating are all coverage and none of them are
    /// prevention. Treating observation as prevention is the single failure
    /// this vocabulary exists to prevent.
    pub fn is_prevention(self) -> bool {
        matches!(self, Self::DeniedBeforeExecution)
    }

    /// The lowercase wire name, matching the `serde` representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Detected => "detected",
            Self::Evaluated => "evaluated",
            Self::DeniedBeforeExecution => "denied_before_execution",
            Self::Redacted => "redacted",
            Self::ApprovalRequired => "approval_required",
            Self::Degraded => "degraded",
            Self::Unmeasured => "unmeasured",
            Self::Experimental => "experimental",
            Self::Planned => "planned",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for ClaimTerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
