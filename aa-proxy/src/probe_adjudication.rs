//! Telling a protection probe what this proxy did with the probe's own request.
//!
//! # Why the proxy has to be the one to answer
//!
//! A protection probe sits on the **near** side of the MitM. It can observe that
//! its request went out and that nothing obviously failed, and neither fact is
//! evidence: reporting protection from them is the vacuous pass the evidence
//! model exists to prevent (ADR 0030 §4.1). The component that *does* know is
//! this proxy — it runs [`Interceptor::intercept_request`](crate::intercept::Interceptor::intercept_request),
//! it decides whether to block, redact or forward, and it constructs the exact
//! bytes that would leave the machine. So the adjudication is reported from
//! here, on the probe's own connection.
//!
//! # Why the reply, and not a queryable store
//!
//! A probe must learn the verdict for **its** request and gain nothing else. A
//! store keyed by correlation id would need a read endpoint, a retention policy
//! and an authorisation story, and would hand the probe a general-purpose audit
//! read it has no business having. Answering in the response to the very request
//! that was adjudicated makes "only its own verdict" structural: there is no
//! surface to ask a second question through.
//!
//! # Why a probe request is never forwarded upstream
//!
//! A probe request carries a synthetic credential on purpose. Under a
//! non-enforcing policy (`alert_only`, or a disabled scanner) the ordinary data
//! path would forward that body to the real provider — measuring the deployment
//! by leaking to it. Recognising the correlation header therefore *terminates*
//! the request here: it is adjudicated exactly as a real request would be, and
//! then answered instead of relayed. That can only ever withhold traffic, so an
//! attacker who guesses the header buys themselves a refusal, not a bypass.
//!
//! # What the reply may carry
//!
//! An opaque correlation id the caller minted, the decision token, the number of
//! findings, and a re-inspection verdict for the bytes the proxy resolved to
//! forward. No body, no target, no host, no finding value — nothing a reader
//! could use to recover the payload.

use serde::{Deserialize, Serialize};

use crate::intercept::{InterceptVerdict, VerdictDecision};

/// Request header a protection probe marks its own traffic with.
///
/// The value is the probe's correlation id; see [`ProbeCorrelation`].
pub const PROBE_CORRELATION_HEADER: &str = "x-agent-assembly-probe";

/// Schema tag on the reply, so a probe can tell an adjudication from any other
/// JSON a server might answer with.
pub const PROBE_ADJUDICATION_SCHEMA: &str = "agent-assembly.probe-adjudication/1";

/// An opaque, caller-minted correlation identifier.
///
/// Exactly 32 lowercase hex characters — the `simple` form of a v4 UUID, which
/// is what the shipped probe mints. The grammar is enforced rather than assumed
/// so a caller cannot smuggle arbitrary bytes into the reply (or the logs)
/// through this field, and so a value that is *derived from the payload* is not
/// silently accepted: a content hash is 64 hex characters and is rejected here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCorrelation(String);

impl ProbeCorrelation {
    /// Parse a header value, returning `None` when it is not the fixed grammar.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.len() == 32
            && trimmed
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Some(Self(trimmed.to_owned()))
        } else {
            None
        }
    }

    /// The identifier, as it will be echoed.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the proxy did with an adjudicated probe request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeDecision {
    /// Refused: upstream was never dialled.
    Blocked,
    /// Findings replaced with redaction markers; the redacted bytes are what
    /// would have been forwarded.
    ForwardedRedacted,
    /// Findings recorded and the body would have gone upstream unmodified
    /// (`alert_only`).
    AlertedAndForwarded,
    /// No findings: the body would have gone upstream unmodified.
    Forwarded,
}

/// A re-inspection of the exact bytes the proxy resolved to forward.
///
/// This is the half a near-side client cannot produce for itself, and it is
/// deliberately about *bytes*, not about the decision: a proxy that decided to
/// redact but produced a payload still carrying a credential must not read as
/// protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedPayload {
    /// There were no bytes to inspect — the request was refused.
    NotForwarded,
    /// Re-inspected and carrying no credential.
    Clean,
    /// Re-inspected and still carrying a credential.
    CarriesCredential,
    /// This proxy has no scanner configured, so it cannot say what the payload
    /// carries. Never protective.
    NotInspected,
}

/// The reply a probe request is answered with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeAdjudication {
    /// Always [`PROBE_ADJUDICATION_SCHEMA`].
    pub schema: String,
    /// The caller's correlation id, echoed verbatim.
    pub correlation_id: String,
    /// What the proxy did.
    pub decision: ProbeDecision,
    /// How many credential findings the scanner produced. A count, never a value.
    pub findings: usize,
    /// Re-inspection of the bytes that would have been forwarded.
    pub forwarded_payload: ForwardedPayload,
}

impl ProbeAdjudication {
    /// Adjudicate one probe request.
    ///
    /// `forwarded` is the payload re-inspection: `None` when the proxy has no
    /// scanner and therefore cannot say. It is supplied by the caller because
    /// only the data path knows which bytes it resolved to forward.
    pub fn new(correlation: &ProbeCorrelation, verdict: &InterceptVerdict, forwarded: Option<bool>) -> Self {
        let (decision, forwarded_payload) = match verdict.decision {
            VerdictDecision::Block => (ProbeDecision::Blocked, ForwardedPayload::NotForwarded),
            VerdictDecision::ForwardRedacted => (ProbeDecision::ForwardedRedacted, payload(forwarded)),
            VerdictDecision::AlertAndForward => (ProbeDecision::AlertedAndForwarded, payload(forwarded)),
            VerdictDecision::Forward => (ProbeDecision::Forwarded, payload(forwarded)),
        };
        Self {
            schema: PROBE_ADJUDICATION_SCHEMA.to_owned(),
            correlation_id: correlation.as_str().to_owned(),
            decision,
            findings: verdict.findings.len(),
            forwarded_payload,
        }
    }

    /// The complete HTTP/1.1 response carrying this adjudication.
    ///
    /// `Connection: close` because the probe request is terminated here: nothing
    /// further may be pipelined onto a connection whose request never reached
    /// upstream.
    pub fn http_response(&self) -> Vec<u8> {
        // Serialising a struct of owned `String`/enum/`usize` cannot fail; the
        // fallback keeps the data path infallible rather than asserting it.
        let body = serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned());
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{PROBE_CORRELATION_HEADER}: {}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.correlation_id,
            body.len(),
        )
        .into_bytes()
    }
}

fn payload(forwarded_is_clean: Option<bool>) -> ForwardedPayload {
    match forwarded_is_clean {
        Some(true) => ForwardedPayload::Clean,
        Some(false) => ForwardedPayload::CarriesCredential,
        None => ForwardedPayload::NotInspected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aa_security::CredentialScanner;
    use bytes::Bytes;

    /// A synthetic Anthropic-shaped key. Not a real credential.
    const SECRET: &str = "sk-ant-api03-AAASM5300SYNTHETICDONOTUSE0000000000000000000000000000000000AA";

    fn verdict(decision: VerdictDecision, findings: usize) -> InterceptVerdict {
        let body = format!("carrying {SECRET} here");
        let scan = CredentialScanner::new().scan(&body);
        assert!(!scan.findings.is_empty(), "fixture invariant: the scanner matches");
        InterceptVerdict {
            decision,
            findings: scan.findings.into_iter().take(findings).collect(),
            redacted_body: Some(Bytes::from("redacted")),
        }
    }

    fn correlation() -> ProbeCorrelation {
        ProbeCorrelation::parse("0123456789abcdef0123456789abcdef").expect("valid id")
    }

    #[test]
    fn a_correlation_id_must_be_thirty_two_lowercase_hex_characters() {
        assert!(ProbeCorrelation::parse("0123456789abcdef0123456789abcdef").is_some());
        assert!(
            ProbeCorrelation::parse("0123456789ABCDEF0123456789ABCDEF").is_none(),
            "uppercase"
        );
        assert!(
            ProbeCorrelation::parse("0123456789abcdef0123456789abcde").is_none(),
            "too short"
        );
        assert!(
            ProbeCorrelation::parse("../../etc/passwd\r\nX-Evil: 1").is_none(),
            "not hex"
        );
        assert!(ProbeCorrelation::parse("").is_none(), "empty");
    }

    /// A content hash is the correlation value the design forbids: it is derived
    /// from the payload, so holding it is holding a fingerprint of the secret.
    /// SHA-256 hex is 64 characters, and the grammar rejects it.
    #[test]
    fn a_payload_derived_hash_is_not_a_valid_correlation_id() {
        let hex = "a".repeat(64);
        assert!(
            ProbeCorrelation::parse(&hex).is_none(),
            "a 64-character digest must not be accepted as a correlation id"
        );
    }

    #[test]
    fn a_block_reports_nothing_forwarded() {
        let a = ProbeAdjudication::new(&correlation(), &verdict(VerdictDecision::Block, 1), None);
        assert_eq!(a.decision, ProbeDecision::Blocked);
        assert_eq!(a.forwarded_payload, ForwardedPayload::NotForwarded);
    }

    #[test]
    fn a_redaction_reports_the_reinspection_of_the_forwarded_bytes() {
        let clean = ProbeAdjudication::new(
            &correlation(),
            &verdict(VerdictDecision::ForwardRedacted, 1),
            Some(true),
        );
        assert_eq!(clean.decision, ProbeDecision::ForwardedRedacted);
        assert_eq!(clean.forwarded_payload, ForwardedPayload::Clean);

        let dirty = ProbeAdjudication::new(
            &correlation(),
            &verdict(VerdictDecision::ForwardRedacted, 1),
            Some(false),
        );
        assert_eq!(dirty.forwarded_payload, ForwardedPayload::CarriesCredential);
    }

    #[test]
    fn a_proxy_without_a_scanner_says_it_did_not_inspect() {
        let a = ProbeAdjudication::new(&correlation(), &verdict(VerdictDecision::Forward, 0), None);
        assert_eq!(a.decision, ProbeDecision::Forwarded);
        assert_eq!(
            a.forwarded_payload,
            ForwardedPayload::NotInspected,
            "an uninspected payload must never read as clean"
        );
    }

    /// The security invariant of the whole correlation path: the reply is an
    /// outcome vocabulary and an opaque id, and carries no protected content —
    /// not the secret, not the body, not the target it was addressed to.
    #[test]
    fn the_reply_carries_no_protected_content() {
        let a = ProbeAdjudication::new(
            &correlation(),
            &verdict(VerdictDecision::ForwardRedacted, 1),
            Some(true),
        );
        let wire = String::from_utf8(a.http_response()).expect("utf-8 response");
        assert!(!wire.contains(SECRET), "SECURITY INVARIANT VIOLATED: {wire}");
        assert!(!wire.contains("sk-ant-"), "no credential prefix may appear: {wire}");
        assert!(
            !wire.contains("/v1/messages"),
            "the reply must not echo the target: {wire}"
        );
        assert!(wire.contains(PROBE_ADJUDICATION_SCHEMA));
        assert!(wire.contains("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn the_reply_round_trips_through_json() {
        let a = ProbeAdjudication::new(
            &correlation(),
            &verdict(VerdictDecision::AlertAndForward, 1),
            Some(false),
        );
        let wire = String::from_utf8(a.http_response()).expect("utf-8");
        let body = wire.split_once("\r\n\r\n").expect("headers then body").1;
        let back: ProbeAdjudication = serde_json::from_str(body).expect("parses");
        assert_eq!(back, a);
        assert_eq!(back.decision, ProbeDecision::AlertedAndForwarded);
    }
}
