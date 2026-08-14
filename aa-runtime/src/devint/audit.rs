//! The DI-API's audit obligation (ADR 0030 §5.3, and ADR 0015's rule
//! transferred).
//!
//! Two classes of event are recorded, and they are the two the ticket names:
//!
//! * **Client authentication and authorization failures** — every absent,
//!   malformed, unknown, expired or out-of-scope token, and every rejected
//!   peer, unknown verb and failed negotiation. A resolution failure that is
//!   not audit-visible is a resolution failure nobody will ever learn about.
//! * **Lifecycle mutations** — every apply, repair and remove, with its
//!   outcome.
//!
//! # What an event may carry, and what it may never
//!
//! An event names the **token id**, the client, the verb, the tool and the
//! outcome. It never carries:
//!
//! * the token value — §5.3 is explicit: "the token *id* and the outcome —
//!   never the token value";
//! * *why it almost matched* — there is no field for a partial-match hint,
//!   because an audit trail that narrows a secret is an oracle;
//! * protected content — no prompt, no tool output, no settings body, no
//!   policy document. [`DevIntAuditEvent`] has no field one could occupy, which
//!   is the same enforcement-by-shape the response types use.
//!
//! [`TracingAuditSink`] is the default: structured `tracing` records, which is
//! where the rest of the runtime's security-relevant events already go. The
//! sink is a trait so AAASM-5278's service can route the same events into the
//! durable audit trail without this module growing a second event store
//! (ADR 0030 matrix row 13).

use std::sync::{Arc, Mutex};

use super::token::{TokenDenial, TokenId};
use super::verb::DiVerb;

/// What happened, in the vocabulary the audit trail records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevIntAuditKind {
    /// A peer was rejected before any DI-API frame was read.
    PeerRejected {
        /// Why: `uid_mismatch` or `peercred_unavailable`.
        reason: &'static str,
    },
    /// Version negotiation concluded.
    Negotiated {
        /// `supported`, `degraded` or `incompatible`.
        outcome: &'static str,
        /// The agreed version, when one was agreed.
        version: Option<u32>,
    },
    /// A request was refused at the token layer.
    AuthFailure {
        /// The coarse outcome name, e.g. `token_expired`.
        outcome: &'static str,
        /// The enrolment involved, when one was reached. `None` for absent,
        /// malformed and unknown tokens — there is genuinely no id to record,
        /// and inventing one would imply a match that did not happen.
        token_id: Option<TokenId>,
    },
    /// A request was refused for a reason other than the token.
    ProtocolFailure {
        /// `unknown_verb`, `renegotiation_attempted`, `unavailable_at_version`,
        /// `malformed_frame` or `frame_too_large`.
        reason: &'static str,
    },
    /// A verb ran to completion.
    VerbServed {
        /// Whether the lifecycle service succeeded.
        succeeded: bool,
    },
}

impl DevIntAuditKind {
    /// A stable snake_case event name.
    pub const fn name(&self) -> &'static str {
        match self {
            DevIntAuditKind::PeerRejected { .. } => "devint.peer_rejected",
            DevIntAuditKind::Negotiated { .. } => "devint.negotiated",
            DevIntAuditKind::AuthFailure { .. } => "devint.auth_failure",
            DevIntAuditKind::ProtocolFailure { .. } => "devint.protocol_failure",
            DevIntAuditKind::VerbServed { .. } => "devint.verb_served",
        }
    }
}

/// One DI-API audit record.
///
/// Every field is an identifier, a name or an outcome. There is deliberately no
/// free-form payload field: a `details: String` would be exactly the place a
/// future contributor pastes a settings body or a token into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevIntAuditEvent {
    /// When, seconds since the Unix epoch.
    pub at_unix_secs: u64,
    /// What happened.
    pub kind: DevIntAuditKind,
    /// The connection this happened on, so a sequence can be reconstructed.
    pub connection_id: u64,
    /// The client name from `Hello`. Display only — it is self-asserted and is
    /// never an authentication factor, which is why it is recorded next to the
    /// token id rather than instead of it.
    pub client_name: Option<String>,
    /// The verb, when the event concerns one.
    pub verb: Option<DiVerb>,
    /// The tool the verb named, when it named one.
    pub tool_id: Option<String>,
}

impl DevIntAuditEvent {
    /// Build an event.
    pub fn new(at_unix_secs: u64, connection_id: u64, kind: DevIntAuditKind) -> Self {
        Self {
            at_unix_secs,
            kind,
            connection_id,
            client_name: None,
            verb: None,
            tool_id: None,
        }
    }

    /// Attach the self-asserted client name.
    #[must_use]
    pub fn with_client(mut self, client_name: Option<String>) -> Self {
        self.client_name = client_name;
        self
    }

    /// Attach the verb and tool the event concerns.
    #[must_use]
    pub fn with_target(mut self, verb: DiVerb, tool_id: impl Into<String>) -> Self {
        self.verb = Some(verb);
        let tool_id = tool_id.into();
        self.tool_id = if tool_id.is_empty() { None } else { Some(tool_id) };
        self
    }

    /// Build an auth-failure event from a [`TokenDenial`].
    ///
    /// The denial's coarse outcome and the enrolment id are carried across;
    /// nothing else about the denial is, which is why this constructor exists
    /// rather than each call site deciding what to log.
    pub fn from_denial(at_unix_secs: u64, connection_id: u64, denial: &TokenDenial) -> Self {
        Self::new(
            at_unix_secs,
            connection_id,
            DevIntAuditKind::AuthFailure {
                outcome: denial.outcome(),
                token_id: denial.token_id().cloned(),
            },
        )
    }
}

/// Where DI-API audit events go.
pub trait DevIntAuditSink: Send + Sync {
    /// Record one event. Must not block the connection it came from for long;
    /// the caller is on a per-connection task, not the accept loop.
    fn record(&self, event: DevIntAuditEvent);
}

/// The default sink: structured `tracing` records at INFO (mutations,
/// negotiation) and WARN (failures).
#[derive(Debug, Default, Clone)]
pub struct TracingAuditSink;

impl DevIntAuditSink for TracingAuditSink {
    fn record(&self, event: DevIntAuditEvent) {
        let name = event.kind.name();
        let verb = event.verb.map(|v| v.as_str()).unwrap_or("-");
        let tool = event.tool_id.as_deref().unwrap_or("-");
        let client = event.client_name.as_deref().unwrap_or("-");
        match &event.kind {
            DevIntAuditKind::PeerRejected { reason } => {
                tracing::warn!(
                    event = name,
                    connection_id = event.connection_id,
                    reason,
                    "DI-API peer rejected"
                );
            }
            DevIntAuditKind::Negotiated { outcome, version } => {
                tracing::info!(
                    event = name,
                    connection_id = event.connection_id,
                    client,
                    outcome,
                    version = version.unwrap_or(0),
                    "DI-API version negotiated"
                );
            }
            DevIntAuditKind::AuthFailure { outcome, token_id } => {
                tracing::warn!(
                    event = name,
                    connection_id = event.connection_id,
                    client,
                    verb,
                    tool,
                    outcome,
                    // The id, never the value.
                    token_id = token_id.as_ref().map(TokenId::as_str).unwrap_or("-"),
                    "DI-API request denied"
                );
            }
            DevIntAuditKind::ProtocolFailure { reason } => {
                tracing::warn!(
                    event = name,
                    connection_id = event.connection_id,
                    client,
                    verb,
                    reason,
                    "DI-API protocol failure"
                );
            }
            DevIntAuditKind::VerbServed { succeeded } => {
                tracing::info!(
                    event = name,
                    connection_id = event.connection_id,
                    client,
                    verb,
                    tool,
                    succeeded,
                    "DI-API verb served"
                );
            }
        }
    }
}

/// An in-memory sink for tests and for asserting the audit obligation.
#[derive(Debug, Default, Clone)]
pub struct RecordingAuditSink {
    events: Arc<Mutex<Vec<DevIntAuditEvent>>>,
}

impl RecordingAuditSink {
    /// A new, empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every event recorded so far, in order.
    pub fn events(&self) -> Vec<DevIntAuditEvent> {
        self.events.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether any recorded event is an auth failure with `outcome`.
    pub fn has_auth_failure(&self, outcome: &str) -> bool {
        self.events()
            .iter()
            .any(|e| matches!(&e.kind, DevIntAuditKind::AuthFailure { outcome: recorded, .. } if *recorded == outcome))
    }
}

impl DevIntAuditSink for RecordingAuditSink {
    fn record(&self, event: DevIntAuditEvent) {
        self.events.lock().unwrap_or_else(|e| e.into_inner()).push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denial_becomes_an_event_naming_the_id_and_not_the_value() {
        let denial = TokenDenial::OutOfScope {
            token_id: TokenId::generate(),
            verb: DiVerb::Apply,
        };
        let event = DevIntAuditEvent::from_denial(1_700_000_000, 7, &denial).with_target(DiVerb::Apply, "codex");
        match &event.kind {
            DevIntAuditKind::AuthFailure { outcome, token_id } => {
                assert_eq!(*outcome, "out_of_scope");
                assert_eq!(token_id.as_ref(), denial.token_id());
            }
            other => panic!("expected AuthFailure, got {other:?}"),
        }
        assert_eq!(event.tool_id.as_deref(), Some("codex"));
    }

    #[test]
    fn denials_that_reached_no_record_carry_no_id() {
        for denial in [TokenDenial::Absent, TokenDenial::Malformed, TokenDenial::Unknown] {
            let event = DevIntAuditEvent::from_denial(0, 1, &denial);
            let DevIntAuditKind::AuthFailure { token_id, .. } = &event.kind else {
                panic!("expected AuthFailure");
            };
            assert!(
                token_id.is_none(),
                "an unreached record has no id; inventing one implies a match"
            );
        }
    }

    #[test]
    fn the_event_type_has_no_field_that_could_hold_content() {
        // Enforcement by shape: the only strings on the event are a
        // self-asserted client name and a tool id, both of which the client
        // supplied and neither of which is protected content. A `{:?}` of a
        // fully-populated event is therefore safe to log.
        let event = DevIntAuditEvent::new(1, 2, DevIntAuditKind::VerbServed { succeeded: true })
            .with_client(Some("vscode-aasm".to_string()))
            .with_target(DiVerb::Status, "claude-code");
        let rendered = format!("{event:?}");
        assert!(rendered.contains("vscode-aasm"));
        assert!(rendered.contains("claude-code"));
        assert!(rendered.contains("VerbServed"));
    }

    #[test]
    fn an_empty_tool_id_is_recorded_as_absent_not_as_an_empty_string() {
        let event = DevIntAuditEvent::new(1, 2, DevIntAuditKind::VerbServed { succeeded: true })
            .with_target(DiVerb::ListTools, "");
        assert_eq!(event.tool_id, None);
    }

    #[test]
    fn the_recording_sink_preserves_order() {
        let sink = RecordingAuditSink::new();
        sink.record(DevIntAuditEvent::from_denial(1, 1, &TokenDenial::Absent));
        sink.record(DevIntAuditEvent::new(
            2,
            1,
            DevIntAuditKind::VerbServed { succeeded: true },
        ));
        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind.name(), "devint.auth_failure");
        assert_eq!(events[1].kind.name(), "devint.verb_served");
        assert!(sink.has_auth_failure("token_absent"));
        assert!(!sink.has_auth_failure("token_expired"));
    }

    #[test]
    fn every_kind_has_a_stable_name() {
        let kinds = [
            DevIntAuditKind::PeerRejected { reason: "uid_mismatch" },
            DevIntAuditKind::Negotiated {
                outcome: "supported",
                version: Some(2),
            },
            DevIntAuditKind::AuthFailure {
                outcome: "token_absent",
                token_id: None,
            },
            DevIntAuditKind::ProtocolFailure { reason: "unknown_verb" },
            DevIntAuditKind::VerbServed { succeeded: false },
        ];
        let names: Vec<&str> = kinds.iter().map(DevIntAuditKind::name).collect();
        assert_eq!(
            names,
            vec![
                "devint.peer_rejected",
                "devint.negotiated",
                "devint.auth_failure",
                "devint.protocol_failure",
                "devint.verb_served",
            ]
        );
    }
}
