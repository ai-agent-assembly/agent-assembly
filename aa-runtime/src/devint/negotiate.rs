//! DI-API version negotiation — explicit, deterministic, never a silent
//! downgrade (ADR 0030 §5.4).
//!
//! The first exchange on every connection is `Hello` → `HelloAck` |
//! `Incompatible`. No lifecycle verb is accepted before it, and the negotiated
//! version is fixed for the connection's lifetime — a second `Hello` is a
//! protocol violation, not a renegotiation, because a mid-connection downgrade
//! is exactly the move an attacker would use to reach behaviour the current
//! version removed.
//!
//! # Three outcomes, and they are the only three
//!
//! | Outcome | When | What the client gets |
//! | --- | --- | --- |
//! | [`Negotiation::Supported`] | the highest shared version exposes every verb | the whole verb space |
//! | [`Negotiation::Degraded`] | a shared version exists but exposes a subset | the subset, plus the *named* missing verbs and remediation |
//! | [`Negotiation::Incompatible`] | no shared version, or the client's best is below the floor | a reason, remediation, and a closed connection |
//!
//! `Degraded` is an outcome the client must surface, never an implicit
//! fallback. Silently serving an older behaviour is the failure mode this
//! design exists to prevent: a client that believes it has approval relay and
//! silently does not will show a human a prompt no one is waiting on.
//!
//! Lifecycle schema compatibility is negotiated in the same breath. The service
//! speaks exactly [`aa_core::integration::LIFECYCLE_SCHEMA_VERSION`]; a client
//! that cannot read it is incompatible rather than served a plan it will
//! misparse.

use aa_core::integration::{core_version, LIFECYCLE_SCHEMA_VERSION};
use aa_proto::assembly::devint::v1 as wire;

use super::verb::DiVerb;

/// The oldest DI-API version this runtime will serve.
///
/// Versions below the floor are refused with remediation rather than emulated:
/// an emulation is a second behaviour to defend, and the whole point of a
/// closed verb space is having one.
pub const DI_API_MIN_SUPPORTED: u32 = 1;

/// The newest DI-API version this runtime speaks.
///
/// **v3 adds no verbs.** It records that `status` and `verify` carry a
/// [`PolicyView`](aa_proto::assembly::devint::v1::PolicyView) — which policy a
/// governed launch would run under (AAASM-5349). A v2 peer is therefore *not*
/// [`Negotiation::Degraded`]: it has every verb, and `unavailable_verbs` stays
/// empty, because nothing became unavailable.
///
/// The version exists for what a client can *say* rather than what it can call.
/// Protobuf message presence already makes the field's absence unambiguous, so
/// behaviour is correct without consulting the version at all; knowing the peer
/// speaks 2 lets the client name the reason — "this runtime speaks DI-API 2;
/// policy posture arrived in 3" — instead of the vaguer "the field is missing".
pub const DI_API_MAX_SUPPORTED: u32 = 3;

/// The first DI-API version whose `status` and `verify` carry a policy posture.
///
/// Below this, absence of the field means the peer cannot answer — never that
/// the policy is unconfigured. `unconfigured` is itself a refusal, so reading
/// one as the other would turn a version mismatch into a governance finding.
pub const DI_API_POLICY_POSTURE_SINCE: u32 = 3;

/// Verbs that did not exist at DI-API v1.
///
/// A v1 client is [`Negotiation::Degraded`]: it gets the lifecycle verbs and is
/// told, by name, which UX verbs it does not have.
pub const VERBS_ADDED_IN_V2: [DiVerb; 2] = [DiVerb::ScopedEvents, DiVerb::ApprovalRelay];

/// Whether `verb` exists at DI-API version `version`.
pub fn verb_available_at(verb: DiVerb, version: u32) -> bool {
    if version >= 2 {
        return true;
    }
    !VERBS_ADDED_IN_V2.contains(&verb)
}

/// The lowest DI-API version at which `verb` exists.
///
/// Remediation names this rather than [`DI_API_MAX_SUPPORTED`]: they were the
/// same number until v3, so "reconnect at the maximum" read as precise advice
/// while only accidentally being so. Telling a v1 client to reach v3 when v2
/// carries the verb asks for an upgrade the gate does not require.
pub fn verb_available_since(verb: DiVerb) -> u32 {
    if VERBS_ADDED_IN_V2.contains(&verb) {
        2
    } else {
        DI_API_MIN_SUPPORTED
    }
}

/// Why a `Hello` could not be honoured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationError {
    /// The client offered no DI-API version at all. Treated as incompatible,
    /// never as "assume the oldest" — an unstated version is unknown, and an
    /// unknown must not be resolved in the permissive direction.
    NoVersionOffered,
    /// Every version the client offered is below [`DI_API_MIN_SUPPORTED`].
    BelowFloor {
        /// The best the client could do.
        client_best: u32,
    },
    /// The client speaks only versions newer than this runtime.
    AboveCeiling {
        /// The lowest version the client offered.
        client_lowest: u32,
    },
    /// The offered versions straddle the window without intersecting it.
    NoOverlap,
    /// The client cannot read the lifecycle schema this core writes.
    LifecycleSchemaMismatch {
        /// What the service speaks.
        service: u32,
    },
}

impl NegotiationError {
    /// A short statement of what is wrong, for `Incompatible.reason`.
    pub fn reason(&self) -> String {
        match self {
            NegotiationError::NoVersionOffered => "the client offered no DI-API version".to_string(),
            NegotiationError::BelowFloor { client_best } => format!(
                "the client's newest DI-API version ({client_best}) is below the supported floor ({DI_API_MIN_SUPPORTED})"
            ),
            NegotiationError::AboveCeiling { client_lowest } => format!(
                "the client's oldest DI-API version ({client_lowest}) is newer than this runtime serves ({DI_API_MAX_SUPPORTED})"
            ),
            NegotiationError::NoOverlap => format!(
                "no DI-API version is shared; this runtime serves {DI_API_MIN_SUPPORTED}–{DI_API_MAX_SUPPORTED}"
            ),
            NegotiationError::LifecycleSchemaMismatch { service } => {
                format!("the client cannot read lifecycle schema version {service}")
            }
        }
    }

    /// What the user should actually do about it. Never "try again".
    pub fn remediation(&self) -> String {
        match self {
            NegotiationError::NoVersionOffered | NegotiationError::NoOverlap => {
                format!("update the client to one speaking DI-API {DI_API_MIN_SUPPORTED}–{DI_API_MAX_SUPPORTED}")
            }
            NegotiationError::BelowFloor { .. } => {
                format!("update the client to DI-API {DI_API_MIN_SUPPORTED} or newer")
            }
            NegotiationError::AboveCeiling { .. } => {
                "update the AASM runtime — the client is newer than the installed core".to_string()
            }
            NegotiationError::LifecycleSchemaMismatch { service } => {
                format!("update the client to one that reads lifecycle schema version {service}")
            }
        }
    }
}

/// The outcome of one `Hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiation {
    /// Every verb is available at `version`.
    Supported {
        /// The agreed DI-API version.
        version: u32,
    },
    /// `version` was agreed, but it does not expose every verb.
    Degraded {
        /// The agreed DI-API version.
        version: u32,
        /// The verbs that do not exist at it, named so the client can disable
        /// the corresponding UI rather than discovering it at first use.
        unavailable: Vec<DiVerb>,
        /// Why, in words a user can act on.
        reason: String,
        /// What to do about it.
        remediation: String,
    },
    /// Nothing was agreed. The connection is closed after the reply.
    Incompatible(NegotiationError),
}

impl Negotiation {
    /// The agreed version, when one was agreed.
    pub fn version(&self) -> Option<u32> {
        match self {
            Negotiation::Supported { version } | Negotiation::Degraded { version, .. } => Some(*version),
            Negotiation::Incompatible(_) => None,
        }
    }

    /// Whether the connection may proceed to serve verbs.
    pub fn is_usable(&self) -> bool {
        self.version().is_some()
    }

    /// A stable snake_case outcome name for the audit trail.
    pub const fn outcome(&self) -> &'static str {
        match self {
            Negotiation::Supported { .. } => "supported",
            Negotiation::Degraded { .. } => "degraded",
            Negotiation::Incompatible(_) => "incompatible",
        }
    }
}

/// Decide what a `Hello` gets.
///
/// The rule is "highest version both sides offer", evaluated over the client's
/// *offered set* rather than a claimed range, so a client cannot widen its
/// reach by asserting a range it does not implement.
pub fn negotiate(hello: &wire::Hello) -> Negotiation {
    if hello.di_api_versions.is_empty() {
        return Negotiation::Incompatible(NegotiationError::NoVersionOffered);
    }

    let shared = hello
        .di_api_versions
        .iter()
        .copied()
        .filter(|v| (DI_API_MIN_SUPPORTED..=DI_API_MAX_SUPPORTED).contains(v))
        .max();

    let Some(version) = shared else {
        let client_best = hello.di_api_versions.iter().copied().max().unwrap_or(0);
        let client_lowest = hello.di_api_versions.iter().copied().min().unwrap_or(0);
        let error = if client_best < DI_API_MIN_SUPPORTED {
            NegotiationError::BelowFloor { client_best }
        } else if client_lowest > DI_API_MAX_SUPPORTED {
            NegotiationError::AboveCeiling { client_lowest }
        } else {
            NegotiationError::NoOverlap
        };
        return Negotiation::Incompatible(error);
    };

    // The lifecycle schema is not negotiable down: the service writes exactly
    // one schema, and a client that cannot read it would misparse a plan rather
    // than fail loudly.
    if !hello.lifecycle_schema_versions.contains(&LIFECYCLE_SCHEMA_VERSION) {
        return Negotiation::Incompatible(NegotiationError::LifecycleSchemaMismatch {
            service: LIFECYCLE_SCHEMA_VERSION,
        });
    }

    let unavailable: Vec<DiVerb> = DiVerb::ALL
        .into_iter()
        .filter(|v| !verb_available_at(*v, version))
        .collect();

    if unavailable.is_empty() {
        Negotiation::Supported { version }
    } else {
        let names: Vec<&str> = unavailable.iter().map(|v| v.as_str()).collect();
        Negotiation::Degraded {
            version,
            unavailable,
            reason: format!(
                "DI-API v{version} does not expose {}; this runtime also speaks v{DI_API_MAX_SUPPORTED}",
                names.join(", ")
            ),
            remediation: format!("update the client to speak DI-API v{DI_API_MAX_SUPPORTED} to enable them"),
        }
    }
}

/// Render a negotiation outcome as the frame the client receives.
///
/// `Ok` carries a `HelloAck` (supported or degraded); `Err` carries an
/// `Incompatible` whose reason and remediation are both populated — an
/// incompatible answer without remediation is a dead end, not an outcome.
pub fn to_wire(negotiation: &Negotiation) -> Result<wire::HelloAck, wire::Incompatible> {
    match negotiation {
        Negotiation::Supported { version } => Ok(wire::HelloAck {
            outcome: wire::NegotiationOutcome::Supported as i32,
            di_api_version: *version,
            core_version: core_version().to_string(),
            lifecycle_schema_version: LIFECYCLE_SCHEMA_VERSION,
            min_supported: DI_API_MIN_SUPPORTED,
            max_supported: DI_API_MAX_SUPPORTED,
            unavailable_verbs: Vec::new(),
            degraded_reason: String::new(),
            remediation: String::new(),
        }),
        Negotiation::Degraded {
            version,
            unavailable,
            reason,
            remediation,
        } => Ok(wire::HelloAck {
            outcome: wire::NegotiationOutcome::Degraded as i32,
            di_api_version: *version,
            core_version: core_version().to_string(),
            lifecycle_schema_version: LIFECYCLE_SCHEMA_VERSION,
            min_supported: DI_API_MIN_SUPPORTED,
            max_supported: DI_API_MAX_SUPPORTED,
            unavailable_verbs: unavailable.iter().map(|v| v.as_str().to_string()).collect(),
            degraded_reason: reason.clone(),
            remediation: remediation.clone(),
        }),
        Negotiation::Incompatible(error) => Err(wire::Incompatible {
            reason: error.reason(),
            remediation: error.remediation(),
            min_supported: DI_API_MIN_SUPPORTED,
            max_supported: DI_API_MAX_SUPPORTED,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(di_versions: &[u32]) -> wire::Hello {
        wire::Hello {
            client_name: "test-client".to_string(),
            client_version: "1.0.0".to_string(),
            di_api_versions: di_versions.to_vec(),
            lifecycle_schema_versions: vec![LIFECYCLE_SCHEMA_VERSION],
        }
    }

    #[test]
    fn the_highest_shared_version_wins() {
        // Highest *shared*, not this runtime's maximum. The two were the same
        // number until v3 added the policy posture, and asserting the maximum
        // silently asserted the wrong thing: a client offering only [1, 2] must
        // negotiate 2, or it would be told it speaks a version it does not.
        assert_eq!(negotiate(&hello(&[1, 2])), Negotiation::Supported { version: 2 });
        assert_eq!(
            negotiate(&hello(&[1, 2, 3])),
            Negotiation::Supported {
                version: DI_API_MAX_SUPPORTED
            }
        );
    }

    #[test]
    fn a_version_missing_verbs_is_degraded_not_silently_downgraded() {
        let outcome = negotiate(&hello(&[1]));
        match &outcome {
            Negotiation::Degraded {
                version,
                unavailable,
                reason,
                remediation,
            } => {
                assert_eq!(*version, 1);
                assert_eq!(unavailable, &VERBS_ADDED_IN_V2.to_vec());
                assert!(reason.contains("scoped_events"));
                assert!(!remediation.is_empty(), "a degraded outcome must be actionable");
            }
            other => panic!("expected Degraded, got {other:?}"),
        }
        // Degraded is still usable — but it is *named*, which is the property
        // that distinguishes it from a silent downgrade.
        assert!(outcome.is_usable());
        assert_eq!(outcome.outcome(), "degraded");
    }

    #[test]
    fn a_client_below_the_floor_is_incompatible_with_remediation() {
        let outcome = negotiate(&hello(&[0]));
        let Negotiation::Incompatible(error) = &outcome else {
            panic!("expected Incompatible, got {outcome:?}");
        };
        assert_eq!(*error, NegotiationError::BelowFloor { client_best: 0 });
        assert!(!outcome.is_usable());
        let incompatible = to_wire(&outcome).expect_err("must not produce a HelloAck");
        assert!(!incompatible.reason.is_empty());
        assert!(incompatible.remediation.contains("update the client"));
    }

    #[test]
    fn a_client_newer_than_the_runtime_is_told_to_update_the_runtime() {
        let outcome = negotiate(&hello(&[7, 8]));
        let Negotiation::Incompatible(error) = &outcome else {
            panic!("expected Incompatible, got {outcome:?}");
        };
        assert_eq!(*error, NegotiationError::AboveCeiling { client_lowest: 7 });
        let incompatible = to_wire(&outcome).expect_err("incompatible");
        assert!(incompatible.remediation.contains("runtime"));
    }

    #[test]
    fn offering_no_version_is_incompatible_not_assumed_oldest() {
        assert_eq!(
            negotiate(&hello(&[])),
            Negotiation::Incompatible(NegotiationError::NoVersionOffered)
        );
    }

    #[test]
    fn a_straddling_offer_that_misses_the_window_is_incompatible() {
        // Only meaningful once the window has a gap around it; asserts the
        // classifier does not fall through to a permissive branch.
        let outcome = negotiate(&wire::Hello {
            di_api_versions: vec![0, 9],
            ..hello(&[])
        });
        assert_eq!(outcome, Negotiation::Incompatible(NegotiationError::NoOverlap));
    }

    #[test]
    fn an_unreadable_lifecycle_schema_is_incompatible() {
        let outcome = negotiate(&wire::Hello {
            lifecycle_schema_versions: vec![LIFECYCLE_SCHEMA_VERSION + 99],
            ..hello(&[2])
        });
        assert_eq!(
            outcome,
            Negotiation::Incompatible(NegotiationError::LifecycleSchemaMismatch {
                service: LIFECYCLE_SCHEMA_VERSION
            })
        );
    }

    #[test]
    fn the_supported_ack_names_the_core_and_the_window() {
        let ack = to_wire(&negotiate(&hello(&[2]))).expect("supported");
        assert_eq!(ack.outcome, wire::NegotiationOutcome::Supported as i32);
        // The negotiated version is what the client can actually speak; the
        // window it is told about is this runtime's. Conflating them hid the
        // difference while the two numbers happened to be equal.
        assert_eq!(ack.di_api_version, 2);
        assert_eq!(ack.min_supported, DI_API_MIN_SUPPORTED);
        assert_eq!(ack.max_supported, DI_API_MAX_SUPPORTED);
        assert_eq!(ack.lifecycle_schema_version, LIFECYCLE_SCHEMA_VERSION);
        assert!(!ack.core_version.is_empty());
        assert!(ack.unavailable_verbs.is_empty());
    }

    #[test]
    fn negotiation_is_deterministic_for_a_repeated_hello() {
        let request = hello(&[2, 1]);
        let first = negotiate(&request);
        for _ in 0..8 {
            assert_eq!(negotiate(&request), first);
        }
    }

    #[test]
    fn every_verb_exists_at_the_newest_version() {
        for verb in DiVerb::ALL {
            assert!(verb_available_at(verb, DI_API_MAX_SUPPORTED), "{verb} missing at max");
        }
    }
}
