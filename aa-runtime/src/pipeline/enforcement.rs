//! Authoritative scan / redact / normalize enforcement stage (AAASM-2568).
//!
//! `aa-runtime` is the mandatory chokepoint on the SDK fast-path
//! (`SDK → UDS → runtime → gateway`). The SDK is untrusted, so the runtime
//! re-scans **every** event unconditionally before it is forwarded or audited.
//! Nothing the SDK asserts can shorten this work: there is no
//! `clean` / `already_scanned` marker on the wire, and none is honoured.
//!
//! This module is the standalone enforcement primitive. Wiring it into the
//! pipeline `run()` loop lands in AAASM-2586.
//!
//! The scanner / redaction primitives are sourced from the dedicated
//! [`aa_security`] leaf crate (extracted out of `aa-core` under AAASM-2567).

use std::time::{Duration, Instant};

use aa_proto::assembly::audit::v1::audit_event::Detail;
use aa_security::{CredentialFinding, CredentialScanner};

use super::event::EnrichedEvent;
use crate::config::RuntimeConfig;

/// Reserved `labels` keys that assert a *trust grant* — values the runtime must
/// compute itself, never the SDK (AAASM-3630).
///
/// The SDK controls the `labels` map, so any of these keys arriving on the wire
/// is a forgery attempt: an agent trying to shorten enforcement by claiming the
/// event was already trusted / scanned / allowed. The runtime strips them
/// unconditionally and counts the attempt — it never honours them. This is the
/// concrete realization of the AAASM-2569 "no SDK-supplied trust marker" threat.
///
/// `aa.sdk_version` is deliberately **not** in this set: it is a *claim to be
/// verified* (read in AAASM-3625), not a trust grant, so it is preserved.
pub const TRUST_MARKER_LABELS: &[&str] = &["aa.trusted", "aa.scanned", "aa.allow", "aa.bypass"];

/// Default upper bound, in bytes, on a single secret-bearing field handed to
/// the scanner. Fields larger than this are handled per [`OversizedPolicy`].
///
/// 64 KiB comfortably covers realistic tool-call argument payloads while
/// bounding the per-event scan cost.
pub const DEFAULT_MAX_FIELD_BYTES: usize = 64 * 1024;

/// Replacement written into a field that exceeded the configured size cap.
pub const OVERSIZED_MARKER: &str = "[REDACTED:OVERSIZED]";

/// Replacement written into a `bytes` field that carries a finding but cannot be
/// decoded as UTF-8, so no faithful per-finding splice exists (AAASM-5346).
///
/// Distinct from [`OVERSIZED_MARKER`] because the reason differs and operators
/// need to tell them apart: oversized means *not fully scanned*, undecodable
/// means *scanned, found dirty, but not precisely repairable*.
pub const UNDECODABLE_MARKER: &str = "[REDACTED:UNDECODABLE]";

/// Behaviour when a secret-bearing field exceeds [`EnforcementConfig::max_field_bytes`].
///
/// The runtime is a security gate, so the policy is **fail-closed**: an
/// oversized field cannot be scanned in full, therefore it must never be
/// forwarded in raw form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OversizedPolicy {
    /// Replace the entire field with [`OVERSIZED_MARKER`] and flag it. The
    /// unscanned tail might contain secrets, so the whole field is dropped
    /// rather than partially scanned and forwarded. This is the default.
    #[default]
    RedactWhole,
}

/// Configuration for the runtime enforcement stage.
#[derive(Debug, Clone)]
pub struct EnforcementConfig {
    /// Maximum bytes of any single field passed to the scanner.
    pub max_field_bytes: usize,
    /// What to do with a field that exceeds `max_field_bytes`.
    pub oversized_policy: OversizedPolicy,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            max_field_bytes: DEFAULT_MAX_FIELD_BYTES,
            oversized_policy: OversizedPolicy::default(),
        }
    }
}

impl EnforcementConfig {
    /// Build an [`EnforcementConfig`] from a [`RuntimeConfig`].
    ///
    /// Maps the operator-tunable per-field size cap
    /// ([`RuntimeConfig::enforcement_max_field_bytes`]). `oversized_policy`
    /// keeps its fail-closed [`OversizedPolicy::RedactWhole`] default — the
    /// sole variant today — so an oversized field is never forwarded raw.
    pub fn from_runtime_config(c: &RuntimeConfig) -> Self {
        Self {
            max_field_bytes: c.enforcement_max_field_bytes,
            oversized_policy: OversizedPolicy::default(),
        }
    }
}

/// Summary of the work performed by a single [`RuntimeScanner::enforce`] call.
///
/// Carries only finding metadata (kind + offset + redacted label) — never a
/// raw secret. Consumed by the metrics layer (AAASM-2585) and the verification
/// suite (AAASM-2587).
///
/// `#[non_exhaustive]` because this struct records *what enforcement did*, and
/// that vocabulary keeps growing — `undecodable_fields` (AAASM-5346) is the
/// latest, and the ADR 0032 `sensitive_data_disposition` work will add more.
/// Without it every such addition is a semver break for any out-of-crate struct
/// literal. Construct it with [`Default`] and functional-update syntax
/// (`..Default::default()`); field *reads* are unaffected (AAASM-5346).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnforcementOutcome {
    /// Every credential finding across all scanned fields of the event.
    pub findings: Vec<CredentialFinding>,
    /// Number of fields that hit the size cap and were redacted whole.
    pub oversized_fields: usize,
    /// Number of `bytes` fields that carried a finding but could not be decoded
    /// as UTF-8, and so were redacted whole rather than spliced (AAASM-5346).
    ///
    /// Records the payload as *inspected but not precisely transformable*. It is
    /// a counter on this internal outcome, **not** a verdict: decision D-2
    /// (ADR 0032 §10) freezes [`RuntimeVerdict`], and the finer disposition
    /// vocabulary belongs to the future additive `sensitive_data_disposition`
    /// field, which this counter is intended to feed.
    ///
    /// [`RuntimeVerdict`]: https://github.com/ai-agent-assembly/agent-assembly/blob/main/docs/src/adr/0018-canonical-runtime-verdict-and-enriched-decision-record.md
    pub undecodable_fields: usize,
    /// Total **input** bytes inspected across all fields.
    ///
    /// Counted from the field as it arrived, never from a decoded form of it:
    /// `String::from_utf8_lossy` expands every invalid byte into a 3-byte
    /// U+FFFD, so counting the decoded length would inflate this figure — and
    /// the `aa_runtime_scan_payload_bytes` histogram it feeds — by up to 3x for
    /// a binary payload (AAASM-5346).
    pub scanned_bytes: usize,
    /// Number of SDK-supplied trust-marker labels (see [`TRUST_MARKER_LABELS`])
    /// that were stripped from the event — i.e. forgery attempts the runtime
    /// refused to honour (AAASM-3630). Read by the tamper audit / metric layer.
    pub forged_trust_markers: usize,
}

impl EnforcementOutcome {
    /// `true` when nothing was redacted: no findings and no oversized fields.
    ///
    /// Forged trust markers do **not** affect this: they are a distinct tamper
    /// signal (see [`has_forged_trust_markers`](Self::has_forged_trust_markers)),
    /// not a payload redaction. Stripping a forged `aa.trusted` label from an
    /// otherwise-clean event still leaves it clean.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty() && self.oversized_fields == 0
    }

    /// Total number of redactions applied (findings + oversized fields).
    ///
    /// `undecodable_fields` is deliberately **not** added: such a field is only
    /// counted when it produced at least one finding, so it is already included
    /// via `findings.len()`. Adding it here would double-count (AAASM-5346).
    pub fn redaction_count(&self) -> usize {
        self.findings.len() + self.oversized_fields
    }

    /// `true` when at least one field was scanned dirty but could not be decoded
    /// well enough to splice, and was therefore dropped whole.
    pub fn has_undecodable_fields(&self) -> bool {
        self.undecodable_fields > 0
    }

    /// `true` when at least one forged SDK trust-marker label was stripped.
    pub fn has_forged_trust_markers(&self) -> bool {
        self.forged_trust_markers > 0
    }
}

/// Authoritative, reusable scan / redact / normalize stage.
///
/// Holds **one** precompiled [`CredentialScanner`]: construct it once at
/// pipeline start (see AAASM-2586) and call [`enforce`](Self::enforce) per
/// event. The scanner is never rebuilt per event.
pub struct RuntimeScanner {
    scanner: CredentialScanner,
    config: EnforcementConfig,
}

impl Default for RuntimeScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeScanner {
    /// Build with the default [`EnforcementConfig`] and a freshly compiled scanner.
    pub fn new() -> Self {
        Self::with_config(EnforcementConfig::default())
    }

    /// Build with explicit configuration.
    pub fn with_config(config: EnforcementConfig) -> Self {
        Self {
            scanner: CredentialScanner::new(),
            config,
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &EnforcementConfig {
        &self.config
    }

    /// Scan, redact, and normalize every secret-bearing field of `event`,
    /// mutating it in place, and return an [`EnforcementOutcome`].
    ///
    /// Runs **unconditionally** — no field of the event can request that
    /// scanning be skipped, and there is no SDK trust marker on the wire. Only
    /// the allowlisted secret-bearing fields are scanned; opaque numeric and
    /// enumeration fields are left untouched. Any SDK-supplied trust-marker
    /// labels are stripped and counted (AAASM-3630) before the scan so a forged
    /// marker can never shorten the work below.
    pub fn enforce(&self, event: &mut EnrichedEvent) -> EnforcementOutcome {
        let started = Instant::now();
        let mut outcome = EnforcementOutcome::default();
        strip_trust_markers(&mut event.inner.labels, &mut outcome);
        self.scan_labels(&mut event.inner.labels, &mut outcome);
        if let Some(detail) = event.inner.detail.as_mut() {
            self.scan_detail(detail, &mut outcome);
        }
        emit_metrics(&outcome, started.elapsed());
        outcome
    }

    /// Scan and redact every surviving label *key and value* in place
    /// (AAASM-4744, extended by AAASM-4793).
    ///
    /// `labels` is an SDK-supplied map, so a secret can ride in a label key
    /// exactly as easily as in a label value — nothing on the wire prevents an
    /// agent from smuggling a credential into the map's key instead of its
    /// value. Trust-marker keys are already stripped by [`strip_trust_markers`]
    /// before this runs; every remaining key and value is passed through the
    /// same [`scan_string`](Self::scan_string) path (size cap, credential scan,
    /// and redaction) so a leaked secret is redacted, not forwarded, regardless
    /// of which side of the map it rode in on. The map is rebuilt because
    /// `HashMap` keys cannot be mutated in place.
    fn scan_labels(&self, labels: &mut std::collections::HashMap<String, String>, outcome: &mut EnforcementOutcome) {
        let scanned: Vec<(String, String)> = std::mem::take(labels)
            .into_iter()
            .map(|(mut key, mut value)| {
                self.scan_string(&mut key, outcome);
                self.scan_string(&mut value, outcome);
                (key, value)
            })
            .collect();
        // Two *distinct* original keys can redact to the **same** marker — e.g.
        // two keys each wholly a same-kind secret both become
        // "[REDACTED:AwsAccessKey]". A plain `extend` would let the second
        // silently overwrite the first, dropping a distinct (forged/secret-
        // bearing) label pair from the forwarded and audited event. That is an
        // audit-completeness gap, not a leak (both are fully redacted), so on a
        // key collision append a positional suffix to keep every pair
        // (AAASM-4813). Non-colliding keys insert unchanged.
        for (key, value) in scanned {
            if labels.contains_key(&key) {
                let mut suffix = 2;
                let mut candidate = format!("{key}#{suffix}");
                while labels.contains_key(&candidate) {
                    suffix += 1;
                    candidate = format!("{key}#{suffix}");
                }
                labels.insert(candidate, value);
            } else {
                labels.insert(key, value);
            }
        }
    }

    /// Scan and redact the allowlisted secret-bearing fields of `detail`.
    fn scan_detail(&self, detail: &mut Detail, outcome: &mut EnforcementOutcome) {
        match detail {
            Detail::ToolCall(tc) => {
                self.scan_bytes(&mut tc.args_json, outcome);
                self.scan_string(&mut tc.error_message, outcome);
            }
            Detail::FileOp(f) => {
                self.scan_string(&mut f.path, outcome);
            }
            Detail::Process(p) => {
                self.scan_string(&mut p.command, outcome);
                for arg in p.args.iter_mut() {
                    self.scan_string(arg, outcome);
                }
            }
            // No free-text secret-bearing fields: LlmCall / Network / Violation
            // / Approval carry only identifiers, enums, and counters. Matched
            // explicitly (no wildcard) so a new detail variant fails to compile
            // until its secret-bearing fields are triaged here.
            Detail::LlmCall(_) | Detail::Network(_) | Detail::Violation(_) | Detail::Approval(_) => {}
        }
    }

    /// Scan and redact a UTF-8 string field in place.
    fn scan_string(&self, field: &mut String, outcome: &mut EnforcementOutcome) {
        if field.is_empty() {
            return;
        }
        if field.len() > self.config.max_field_bytes {
            self.apply_oversized_str(field, outcome);
            return;
        }
        outcome.scanned_bytes += field.len();
        let result = self.scanner.scan(field);
        if !result.is_clean() {
            *field = result.redact(field);
            outcome.findings.extend(result.findings);
        }
    }

    /// Scan a `bytes` field and redact it in place without ever corrupting it
    /// (AAASM-5346).
    ///
    /// Every payload is scanned — an undecodable one is *never* waved through,
    /// because skipping the write-back must never mean skipping the decision.
    /// What differs is how a dirty payload is repaired:
    ///
    /// * **Valid UTF-8** — finding offsets are byte offsets into `field` itself,
    ///   so [`ScanResult::redact`] splices exactly the flagged spans and every
    ///   other byte survives verbatim.
    /// * **Not valid UTF-8** (binary body, or a multi-byte character cut by a
    ///   chunk boundary) — the scan runs against a lossy decoding, in which each
    ///   invalid byte has become a 3-byte U+FFFD. Those offsets do not map back
    ///   onto `field`, so no faithful splice exists. Writing the decoded text
    ///   back would replace the caller's bytes with replacement characters —
    ///   silent corruption, and the bug this method was rewritten to fix.
    ///
    ///   ADR 0015 §1 already decides this case ("caller text ≠ scanned text"):
    ///   redaction degrades to an opaque whole-value replacement rather than
    ///   passing the original through. Leaving the payload alone would forward a
    ///   detected secret in the clear — a fail-open — so the field is dropped
    ///   whole into [`UNDECODABLE_MARKER`] and counted in
    ///   [`EnforcementOutcome::undecodable_fields`], mirroring the
    ///   [`OversizedPolicy::RedactWhole`] precedent.
    ///
    /// A clean payload is left byte-identical in both branches.
    fn scan_bytes(&self, field: &mut Vec<u8>, outcome: &mut EnforcementOutcome) {
        if field.is_empty() {
            return;
        }
        if field.len() > self.config.max_field_bytes {
            self.apply_oversized_bytes(field, outcome);
            return;
        }
        // Count the payload as it arrived. Lossy decoding can expand it (each
        // invalid byte becomes a 3-byte U+FFFD), and the accounting must
        // describe the payload, not an artefact of decoding it.
        outcome.scanned_bytes += field.len();

        // Computed inside the match so the immutable borrow of `field` taken by
        // the decode ends before the write-back below.
        let replacement: Option<Vec<u8>> = match std::str::from_utf8(field) {
            Ok(text) => {
                let result = self.scanner.scan(text);
                if result.is_clean() {
                    None
                } else {
                    let redacted = result.redact(text).into_bytes();
                    outcome.findings.extend(result.findings);
                    Some(redacted)
                }
            }
            Err(_) => {
                let text = String::from_utf8_lossy(field);
                let result = self.scanner.scan(&text);
                if result.is_clean() {
                    None
                } else {
                    // These findings are **kind-only**. Their `offset` / `end`
                    // index the lossy decoding, so they match neither the input
                    // bytes nor the marker that replaces them. Nothing consumes
                    // the spans today (the metrics layer reads `kind`, and
                    // redaction already happened above), but a future consumer
                    // must not treat them as positions in the payload. They are
                    // kept rather than dropped because *what kind* of secret was
                    // found is the audit-relevant fact.
                    outcome.findings.extend(result.findings);
                    outcome.undecodable_fields += 1;
                    Some(UNDECODABLE_MARKER.as_bytes().to_vec())
                }
            }
        };
        if let Some(bytes) = replacement {
            *field = bytes;
        }
    }

    fn apply_oversized_str(&self, field: &mut String, outcome: &mut EnforcementOutcome) {
        match self.config.oversized_policy {
            OversizedPolicy::RedactWhole => {
                *field = OVERSIZED_MARKER.to_string();
                outcome.oversized_fields += 1;
            }
        }
    }

    fn apply_oversized_bytes(&self, field: &mut Vec<u8>, outcome: &mut EnforcementOutcome) {
        match self.config.oversized_policy {
            OversizedPolicy::RedactWhole => {
                *field = OVERSIZED_MARKER.as_bytes().to_vec();
                outcome.oversized_fields += 1;
            }
        }
    }
}

/// Strip every reserved SDK trust-marker label (see [`TRUST_MARKER_LABELS`])
/// from `labels` in place, counting each removal into
/// [`EnforcementOutcome::forged_trust_markers`].
///
/// The runtime computes trust itself; an SDK-supplied trust grant is a forgery
/// attempt that is dropped and flagged, never honoured. `aa.sdk_version` (a
/// claim, not a grant) is intentionally not in the marker set and is preserved.
fn strip_trust_markers(labels: &mut std::collections::HashMap<String, String>, outcome: &mut EnforcementOutcome) {
    for key in TRUST_MARKER_LABELS {
        if labels.remove(*key).is_some() {
            outcome.forged_trust_markers += 1;
        }
    }
}

/// Emit scan observability metrics for one [`RuntimeScanner::enforce`] call.
///
/// Latency is measured around the scan + redact work only. The finding
/// counter is labelled by [`aa_security::CredentialKind`] and never carries the
/// raw secret. Emitted on every call, including clean and no-detail events.
fn emit_metrics(outcome: &EnforcementOutcome, elapsed: Duration) {
    ::metrics::histogram!("aa_runtime_scan_latency_seconds").record(elapsed.as_secs_f64());
    ::metrics::histogram!("aa_runtime_scan_payload_bytes").record(outcome.scanned_bytes as f64);
    if outcome.oversized_fields > 0 {
        ::metrics::counter!("aa_runtime_scan_oversized_total").increment(outcome.oversized_fields as u64);
    }
    // A payload dropped whole because it could not be decoded is a *coarser*
    // redaction than the operator asked for, so it must be visible rather than
    // hidden inside the generic finding counter (AAASM-5346).
    if outcome.undecodable_fields > 0 {
        ::metrics::counter!("aa_runtime_scan_undecodable_total").increment(outcome.undecodable_fields as u64);
    }
    for finding in &outcome.findings {
        ::metrics::counter!("aa_runtime_scan_findings_total", "kind" => finding.kind.as_str()).increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::event::EventSource;
    use aa_proto::assembly::audit::v1::{
        AuditEvent, FileOpDetail, NetworkCallDetail, ProcessExecDetail, ToolCallDetail,
    };
    use metrics_exporter_prometheus::PrometheusBuilder;

    /// An AWS access-key id — detected via the `AKIA` literal pattern.
    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    /// A GitHub PAT — detected via the `ghp_` literal pattern.
    const GH_PAT: &str = "ghp_0123456789abcdefABCDEF0123456789abcd";

    /// UTF-8 encoding of U+FFFD, the character `from_utf8_lossy` substitutes for
    /// every byte it cannot decode. Its presence in an output payload is the
    /// signature of the AAASM-5346 corruption bug.
    const REPLACEMENT_CHAR: &[u8] = "\u{FFFD}".as_bytes();

    /// Traditional-Chinese sample: eight 3-byte characters, so every character
    /// boundary is a candidate chunk-split point.
    const CJK: &str = "台北市政府資訊局";

    /// [`CJK`] with its first and last bytes shaved off, so a 3-byte character is
    /// cut in half at **both** ends — exactly what a stream chunk boundary does
    /// to multi-byte text. Invalid UTF-8 in isolation, valid in aggregate.
    fn chunk_split_cjk() -> Vec<u8> {
        let bytes = CJK.as_bytes();
        assert!(
            std::str::from_utf8(&bytes[1..bytes.len() - 1]).is_err(),
            "fixture must be invalid UTF-8 or it does not exercise the split path"
        );
        bytes[1..bytes.len() - 1].to_vec()
    }

    /// Byte-level substring search — the AAASM-5346 assertions must run over raw
    /// `Vec<u8>`, never a lossy `String` view of it, or they would compare the
    /// very decoding that causes the bug and pass either way.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// A genuinely binary payload wrapping a synthetic secret: a PNG signature,
    /// a `0xFF 0xFE` pair no UTF-8 decoder accepts, and a truncated 2-byte
    /// sequence plus a lone continuation byte at the tail.
    fn binary_payload_with_secret() -> Vec<u8> {
        let mut payload = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xFE];
        payload.extend_from_slice(AWS_KEY.as_bytes());
        payload.extend_from_slice(&[0x00, 0xC3, 0x28, 0x80]);
        payload
    }

    /// Extract the `args_json` payload from an event whose detail is a ToolCall.
    fn args_json_of(event: EnrichedEvent) -> Vec<u8> {
        let Some(Detail::ToolCall(tc)) = event.inner.detail else {
            unreachable!("detail was a ToolCall");
        };
        tc.args_json
    }

    /// Build an [`EnrichedEvent`] wrapping `detail` with throwaway metadata.
    fn event_with(detail: Detail) -> EnrichedEvent {
        EnrichedEvent {
            inner: AuditEvent {
                detail: Some(detail),
                ..Default::default()
            },
            received_at_ms: 0,
            source: EventSource::Sdk,
            agent_id: "test-agent".to_string(),
            connection_id: 0,
            sequence_number: 0,
            observed_sdk_identity: Default::default(),
            tamper: None,
        }
    }

    #[test]
    fn tool_call_args_json_secret_is_redacted_in_place() {
        let scanner = RuntimeScanner::new();
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: format!(r#"{{"api_key": "{AWS_KEY}"}}"#).into_bytes(),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let Some(Detail::ToolCall(tc)) = event.inner.detail else {
            unreachable!("detail was a ToolCall");
        };
        let scanned = String::from_utf8(tc.args_json).expect("redacted text is utf-8");
        assert!(!scanned.contains(AWS_KEY), "raw secret must not survive");
        assert!(scanned.contains("[REDACTED:"), "redaction marker present");
        assert_eq!(outcome.findings.len(), 1);
        assert!(!outcome.is_clean());
    }

    /// AAASM-3870: the runtime shares the credential scanner, so a hex-encoded
    /// secret (which evaded the old entropy gate) must now be redacted on the
    /// authoritative enforcement path too.
    #[test]
    fn tool_call_hex_secret_is_redacted_via_runtime() {
        // 64-char lowercase hex — a hex-encoded 256-bit key.
        const HEX_SECRET: &str = "deadbeefcafebabe0123456789abcdef0123456789abcdeffedcba9876543210";
        let scanner = RuntimeScanner::new();
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: format!(r#"{{"api_token": "{HEX_SECRET}"}}"#).into_bytes(),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let Some(Detail::ToolCall(tc)) = event.inner.detail else {
            unreachable!("detail was a ToolCall");
        };
        let scanned = String::from_utf8(tc.args_json).expect("redacted text is utf-8");
        assert!(!scanned.contains(HEX_SECRET), "raw hex secret must not survive");
        assert!(scanned.contains("[REDACTED:"), "redaction marker present");
        assert!(!outcome.is_clean());
    }

    #[test]
    fn tool_call_error_message_secret_is_redacted() {
        let scanner = RuntimeScanner::new();
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            succeeded: false,
            error_message: format!("upstream auth failed using {AWS_KEY}"),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let Some(Detail::ToolCall(tc)) = event.inner.detail else {
            unreachable!("detail was a ToolCall");
        };
        assert!(!tc.error_message.contains(AWS_KEY));
        assert!(tc.error_message.contains("[REDACTED:"));
        assert_eq!(outcome.findings.len(), 1);
    }

    #[test]
    fn file_op_path_secret_is_redacted() {
        let scanner = RuntimeScanner::new();
        let mut event = event_with(Detail::FileOp(FileOpDetail {
            operation: "read".to_string(),
            path: format!("/var/secrets/{GH_PAT}.pem"),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let Some(Detail::FileOp(f)) = event.inner.detail else {
            unreachable!("detail was a FileOp");
        };
        assert!(!f.path.contains(GH_PAT));
        assert!(f.path.contains("[REDACTED:"));
        // A 40-char PAT can match both the `ghp_` literal and the
        // high-entropy detector; assert presence, not an exact count.
        assert!(!outcome.findings.is_empty());
    }

    #[test]
    fn process_command_and_args_secrets_are_redacted() {
        let scanner = RuntimeScanner::new();
        let mut event = event_with(Detail::Process(ProcessExecDetail {
            command: format!("aws-cli --access-key {AWS_KEY}"),
            args: vec!["--auth".to_string(), format!("token={GH_PAT}")],
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let Some(Detail::Process(p)) = event.inner.detail else {
            unreachable!("detail was a Process");
        };
        assert!(!p.command.contains(AWS_KEY));
        assert!(p.command.contains("[REDACTED:"));
        assert!(!p.args.iter().any(|a| a.contains(GH_PAT)));
        assert!(p.args.iter().any(|a| a.contains("[REDACTED:")));
        assert!(!outcome.is_clean());
    }

    #[test]
    fn clean_payload_is_left_untouched() {
        let scanner = RuntimeScanner::new();
        let original = br#"{"city": "Taipei", "limit": 42}"#.to_vec();
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: original.clone(),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let Some(Detail::ToolCall(tc)) = event.inner.detail else {
            unreachable!("detail was a ToolCall");
        };
        assert_eq!(tc.args_json, original, "clean bytes preserved verbatim");
        assert!(outcome.is_clean());
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.scanned_bytes, original.len());
    }

    /// AAASM-5346: the write-back used to splice a lossy decoding over the
    /// caller's bytes, so a binary payload carrying a secret came back riddled
    /// with U+FFFD. It must now be dropped whole instead — fail-closed, and
    /// never a half-rewritten buffer the caller cannot detect.
    #[test]
    fn binary_payload_with_secret_is_dropped_whole_never_corrupted() {
        let scanner = RuntimeScanner::new();
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: binary_payload_with_secret(),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let out = args_json_of(event);
        assert!(!contains(&out, AWS_KEY.as_bytes()), "raw secret must not survive");
        assert!(
            !contains(&out, REPLACEMENT_CHAR),
            "payload was corrupted: U+FFFD spliced into the output"
        );
        assert_eq!(
            out,
            UNDECODABLE_MARKER.as_bytes(),
            "an undecodable dirty payload is replaced whole, not partially rewritten"
        );
        assert_eq!(outcome.undecodable_fields, 1, "the coarse redaction is recorded");
        assert!(outcome.has_undecodable_fields());
        assert!(!outcome.findings.is_empty(), "the decision was made, not skipped");
        assert!(
            !outcome.is_clean(),
            "fail-closed: never reported as a clean pass-through"
        );
    }

    /// AAASM-5346: a multi-byte character cut by a chunk boundary makes the
    /// payload invalid UTF-8. With no finding present nothing may be written
    /// back, so the bytes must survive exactly — compared as `Vec<u8>`, never as
    /// a lossy `String`.
    #[test]
    fn chunk_split_multibyte_clean_payload_round_trips_byte_identically() {
        let scanner = RuntimeScanner::new();
        let original = chunk_split_cjk();
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: original.clone(),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        assert_eq!(
            args_json_of(event),
            original,
            "a clean split payload must round-trip byte-identically"
        );
        assert!(outcome.is_clean());
        assert_eq!(
            outcome.undecodable_fields, 0,
            "a clean payload is not a coarse redaction"
        );
    }

    /// AAASM-5346: the same split payload *with* a synthetic secret. Pre-fix the
    /// surviving CJK bytes came back as U+FFFD; the flagged payload must now be
    /// handled without any replacement character reaching the output.
    #[test]
    fn chunk_split_multibyte_payload_with_secret_introduces_no_replacement_char() {
        let scanner = RuntimeScanner::new();
        let mut payload = chunk_split_cjk();
        payload.extend_from_slice(format!(" key={AWS_KEY} ").as_bytes());
        payload.extend_from_slice(&chunk_split_cjk());
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: payload,
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let out = args_json_of(event);
        assert!(!contains(&out, AWS_KEY.as_bytes()), "raw secret must not survive");
        assert!(
            !contains(&out, REPLACEMENT_CHAR),
            "surviving bytes must not carry U+FFFD"
        );
        // Pin the actual disposition. The U+FFFD assertion above is necessary
        // but not sufficient: once the field is dropped whole, *nothing*
        // survives, so that check alone would pass trivially and would keep
        // passing if the branch silently changed to emit something else.
        assert_eq!(
            out,
            UNDECODABLE_MARKER.as_bytes(),
            "the split payload is replaced whole, exactly as the binary case is"
        );
        assert_eq!(outcome.undecodable_fields, 1);
        assert!(!outcome.is_clean());
    }

    /// AAASM-5346: `scanned_bytes` counted the *lossy* decoding, which expands
    /// each invalid byte into a 3-byte U+FFFD — over-reporting a binary payload
    /// by up to 3x in the `aa_runtime_scan_payload_bytes` histogram.
    #[test]
    fn scanned_bytes_counts_input_bytes_not_the_lossy_expansion() {
        let scanner = RuntimeScanner::new();
        let original = chunk_split_cjk();
        let lossy_len = String::from_utf8_lossy(&original).len();
        assert!(
            lossy_len > original.len(),
            "fixture must actually expand under lossy decoding, else it proves nothing"
        );
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: original.clone(),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        assert_eq!(
            outcome.scanned_bytes,
            original.len(),
            "scanned_bytes must describe the payload, not its decoding"
        );
    }

    /// AAASM-5346 guard on the *unchanged* path: a payload that is valid UTF-8
    /// still gets a precise per-finding splice, so multi-byte text around the
    /// secret survives byte-for-byte rather than being dropped whole.
    #[test]
    fn valid_utf8_multibyte_payload_keeps_surrounding_bytes_on_redaction() {
        let scanner = RuntimeScanner::new();
        let payload = format!("{CJK} key={AWS_KEY} {CJK}");
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: payload.into_bytes(),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let out = args_json_of(event);
        assert!(!contains(&out, AWS_KEY.as_bytes()), "raw secret must not survive");
        assert!(
            !contains(&out, REPLACEMENT_CHAR),
            "no lossy substitution on a valid payload"
        );
        assert!(
            contains(&out, CJK.as_bytes()),
            "CJK bytes either side of the secret must survive verbatim"
        );
        assert!(
            contains(&out, b"[REDACTED:"),
            "a precise splice, not a whole-field drop"
        );
        assert_eq!(
            outcome.undecodable_fields, 0,
            "a decodable payload is repaired precisely, not coarsely"
        );
        assert!(!outcome.is_clean());
    }

    #[test]
    fn oversized_field_is_redacted_whole_fail_closed() {
        let scanner = RuntimeScanner::with_config(EnforcementConfig {
            max_field_bytes: 16,
            ..Default::default()
        });
        // The secret sits past the 16-byte cap: it must never be scanned and
        // forwarded raw. The whole field is dropped instead.
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: format!("padding-padding-{AWS_KEY}").into_bytes(),
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let Some(Detail::ToolCall(tc)) = event.inner.detail else {
            unreachable!("detail was a ToolCall");
        };
        let body = String::from_utf8(tc.args_json).expect("marker is utf-8");
        assert_eq!(body, OVERSIZED_MARKER);
        assert!(!body.contains(AWS_KEY), "raw secret must not survive");
        assert_eq!(outcome.oversized_fields, 1);
        assert!(!outcome.is_clean());
    }

    #[test]
    fn non_allowlisted_detail_is_not_scanned() {
        let scanner = RuntimeScanner::new();
        // NetworkCallDetail carries only host/port/status — no free-text field
        // is on the allowlist, so the stage skips it entirely.
        let mut event = event_with(Detail::Network(NetworkCallDetail {
            host: "api.example.com".to_string(),
            port: 443,
            ..Default::default()
        }));

        let outcome = scanner.enforce(&mut event);

        let Some(Detail::Network(n)) = event.inner.detail else {
            unreachable!("detail was a Network");
        };
        assert_eq!(n.host, "api.example.com", "non-allowlisted field untouched");
        assert!(outcome.is_clean());
        assert_eq!(outcome.scanned_bytes, 0);
    }

    #[test]
    fn event_without_detail_is_a_noop() {
        let scanner = RuntimeScanner::new();
        let mut event = EnrichedEvent {
            inner: AuditEvent::default(),
            received_at_ms: 0,
            source: EventSource::Sdk,
            agent_id: "test-agent".to_string(),
            connection_id: 0,
            sequence_number: 0,
            observed_sdk_identity: Default::default(),
            tamper: None,
        };

        let outcome = scanner.enforce(&mut event);

        assert!(event.inner.detail.is_none());
        assert!(outcome.is_clean());
        assert_eq!(outcome.scanned_bytes, 0);
    }

    #[test]
    fn one_scanner_redacts_across_multiple_events() {
        // The single precompiled scanner is reused for every event.
        let scanner = RuntimeScanner::new();
        for _ in 0..3 {
            let mut event = event_with(Detail::ToolCall(ToolCallDetail {
                args_json: format!(r#"{{"key": "{AWS_KEY}"}}"#).into_bytes(),
                ..Default::default()
            }));

            let outcome = scanner.enforce(&mut event);

            let Some(Detail::ToolCall(tc)) = event.inner.detail else {
                unreachable!("detail was a ToolCall");
            };
            let contains_secret = tc.args_json.windows(AWS_KEY.len()).any(|w| w == AWS_KEY.as_bytes());
            assert!(!contains_secret, "raw secret must not survive any iteration");
            assert!(!outcome.is_clean());
        }
    }

    #[test]
    fn enforce_emits_scan_metrics() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, || {
            let scanner = RuntimeScanner::new();
            let mut event = event_with(Detail::ToolCall(ToolCallDetail {
                args_json: format!(r#"{{"key": "{AWS_KEY}"}}"#).into_bytes(),
                ..Default::default()
            }));
            scanner.enforce(&mut event);
        });

        let rendered = handle.render();
        assert!(rendered.contains("aa_runtime_scan_latency_seconds"));
        assert!(rendered.contains("aa_runtime_scan_payload_bytes"));
        assert!(rendered.contains("aa_runtime_scan_findings_total"));
        // The finding metric is labelled by kind; the raw secret never appears.
        assert!(!rendered.contains(AWS_KEY));
    }

    /// AAASM-5346: dropping a payload whole because it could not be decoded is a
    /// coarser redaction than configured, so operators get a dedicated counter
    /// rather than having it disappear into the generic finding metric.
    #[test]
    fn enforce_emits_undecodable_metric() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, || {
            let scanner = RuntimeScanner::new();
            let mut event = event_with(Detail::ToolCall(ToolCallDetail {
                args_json: binary_payload_with_secret(),
                ..Default::default()
            }));
            scanner.enforce(&mut event);
        });

        let rendered = handle.render();
        assert!(rendered.contains("aa_runtime_scan_undecodable_total"));
        assert!(!rendered.contains(AWS_KEY), "the raw secret never reaches a metric");
    }

    #[test]
    fn from_runtime_config_maps_size_cap_and_keeps_fail_closed_policy() {
        let rc = RuntimeConfig {
            agent_id: "test".to_string(),
            agent_team_id: String::new(),
            agent_org_id: String::new(),
            worker_threads: 0,
            shutdown_timeout_secs: 30,
            ipc_max_connections: 64,
            pipeline_input_buffer: 10_000,
            pipeline_batch_size: 100,
            pipeline_flush_interval_ms: 100,
            pipeline_broadcast_capacity: 1_024,
            metrics_addr: "0.0.0.0:8080".to_string(),
            policy_path: None,
            gateway_endpoint: None,
            gateway_credential_token: None,
            gateway_agent_id: None,
            correlation_window_ms: 5_000,
            correlation_interval_ms: 1_000,
            nats_config_path: None,
            audit_buffer_path: std::path::PathBuf::from("/tmp/aa-audit-buffer-test.db"),
            enforcement_max_field_bytes: 4096,
            gateway_fail_closed: true,
            gateway_timeout_ms: crate::config::DEFAULT_GATEWAY_TIMEOUT_MS,
            devint_enabled: false,
        };

        let config = EnforcementConfig::from_runtime_config(&rc);

        assert_eq!(config.max_field_bytes, 4096, "size cap is threaded from RuntimeConfig");
        assert_eq!(
            config.oversized_policy,
            OversizedPolicy::RedactWhole,
            "oversized policy stays fail-closed"
        );
    }

    /// Build a label-bearing event with no secret-bearing detail.
    fn event_with_labels(labels: &[(&str, &str)]) -> EnrichedEvent {
        let mut event = EnrichedEvent {
            inner: AuditEvent::default(),
            received_at_ms: 0,
            source: EventSource::Sdk,
            agent_id: "test-agent".to_string(),
            connection_id: 0,
            sequence_number: 0,
            observed_sdk_identity: Default::default(),
            tamper: None,
        };
        for (k, v) in labels {
            event.inner.labels.insert((*k).to_string(), (*v).to_string());
        }
        event
    }

    #[test]
    fn forged_trust_marker_is_stripped_and_counted() {
        let scanner = RuntimeScanner::new();
        let mut event = event_with_labels(&[("aa.trusted", "true")]);

        let outcome = scanner.enforce(&mut event);

        assert!(
            !event.inner.labels.contains_key("aa.trusted"),
            "forged trust marker must be stripped"
        );
        assert_eq!(outcome.forged_trust_markers, 1);
        assert!(outcome.has_forged_trust_markers());
    }

    #[test]
    fn every_reserved_trust_marker_is_stripped() {
        let scanner = RuntimeScanner::new();
        let labels: Vec<(&str, &str)> = TRUST_MARKER_LABELS.iter().map(|k| (*k, "1")).collect();
        let mut event = event_with_labels(&labels);

        let outcome = scanner.enforce(&mut event);

        for key in TRUST_MARKER_LABELS {
            assert!(!event.inner.labels.contains_key(*key), "{key} must be stripped");
        }
        assert_eq!(outcome.forged_trust_markers, TRUST_MARKER_LABELS.len());
    }

    #[test]
    fn sdk_version_label_is_preserved_not_a_trust_marker() {
        let scanner = RuntimeScanner::new();
        let mut event = event_with_labels(&[("aa.sdk_version", "1.2.3"), ("aa.bypass", "1")]);

        let outcome = scanner.enforce(&mut event);

        assert_eq!(
            event.inner.labels.get("aa.sdk_version").map(String::as_str),
            Some("1.2.3"),
            "the version claim is preserved for the classifier, not stripped"
        );
        assert!(!event.inner.labels.contains_key("aa.bypass"));
        assert_eq!(outcome.forged_trust_markers, 1);
    }

    #[test]
    fn stripping_a_marker_does_not_make_a_clean_event_dirty() {
        // Forged markers are a distinct signal; they don't count as a redaction.
        let scanner = RuntimeScanner::new();
        let mut event = event_with_labels(&[("aa.trusted", "true")]);

        let outcome = scanner.enforce(&mut event);

        assert!(outcome.is_clean(), "no findings / oversized → still clean");
        assert!(outcome.has_forged_trust_markers());
    }

    #[test]
    fn forged_clean_marker_does_not_suppress_scanning() {
        // The AAASM-2569 threat: an agent forges aa.scanned hoping the runtime
        // skips the scan. The secret must still be redacted.
        let scanner = RuntimeScanner::new();
        let mut event = event_with(Detail::ToolCall(ToolCallDetail {
            args_json: format!(r#"{{"key": "{AWS_KEY}"}}"#).into_bytes(),
            ..Default::default()
        }));
        event.inner.labels.insert("aa.scanned".to_string(), "true".to_string());

        let outcome = scanner.enforce(&mut event);

        let Some(Detail::ToolCall(tc)) = event.inner.detail else {
            unreachable!("detail was a ToolCall");
        };
        let body = String::from_utf8(tc.args_json).expect("utf-8");
        assert!(
            !body.contains(AWS_KEY),
            "raw secret must not survive a forged scanned marker"
        );
        assert!(!event.inner.labels.contains_key("aa.scanned"), "forged marker stripped");
        assert_eq!(outcome.forged_trust_markers, 1);
        assert!(!outcome.is_clean(), "the secret was still found and redacted");
    }

    #[test]
    fn secret_in_label_value_is_redacted() {
        // AAASM-4744: a secret smuggled into a label value must be redacted,
        // just like one in a detail field — the SDK controls the label map.
        let scanner = RuntimeScanner::new();
        let mut event = event_with_labels(&[("team", "payments"), ("note", &format!("key={AWS_KEY}"))]);

        let outcome = scanner.enforce(&mut event);

        let note = event.inner.labels.get("note").expect("note label present");
        assert!(!note.contains(AWS_KEY), "raw secret must not survive in a label value");
        assert!(note.contains("[REDACTED:"), "label value carries the redaction marker");
        assert_eq!(
            event.inner.labels.get("team").map(String::as_str),
            Some("payments"),
            "a clean label value is left untouched"
        );
        assert!(!outcome.is_clean());
        assert_eq!(outcome.findings.len(), 1);
    }

    #[test]
    fn secret_in_label_key_is_redacted() {
        // AAASM-4793: the SDK controls the whole labels map, key and value
        // alike, so a secret smuggled into a label *key* must be redacted just
        // like one riding in the value.
        let scanner = RuntimeScanner::new();
        let poisoned_key = format!("note-{AWS_KEY}");
        let mut event = event_with_labels(&[(poisoned_key.as_str(), "some-value")]);

        let outcome = scanner.enforce(&mut event);

        assert!(
            !event.inner.labels.keys().any(|k| k.contains(AWS_KEY)),
            "raw secret must not survive in a label key"
        );
        assert!(
            event.inner.labels.keys().any(|k| k.contains("[REDACTED:")),
            "redacted label key carries the redaction marker"
        );
        assert!(!outcome.is_clean());
        assert_eq!(outcome.findings.len(), 1);
    }

    #[test]
    fn no_trust_markers_leaves_outcome_unflagged() {
        let scanner = RuntimeScanner::new();
        let mut event = event_with_labels(&[("team", "payments")]);

        let outcome = scanner.enforce(&mut event);

        assert_eq!(
            event.inner.labels.get("team").map(String::as_str),
            Some("payments"),
            "ordinary labels are untouched"
        );
        assert_eq!(outcome.forged_trust_markers, 0);
        assert!(!outcome.has_forged_trust_markers());
    }

    #[test]
    fn two_distinct_secret_keys_of_same_kind_both_survive_redaction() {
        // AAASM-4813: two *distinct* label keys that each wholly consist of a
        // same-kind secret both redact to the identical marker
        // "[REDACTED:AwsAccessKey]". Rebuilding the map must not let the second
        // overwrite the first — a distinct label pair would silently vanish
        // from the forwarded/audited event (an audit-completeness gap). Both
        // pairs must survive.
        let scanner = RuntimeScanner::new();
        // Two valid, distinct AWS access-key ids (differ in the final char);
        // each is wholly the secret, so each redacts to the same marker.
        const AWS_KEY_A: &str = "AKIAIOSFODNN7EXAMPLE";
        const AWS_KEY_B: &str = "AKIAIOSFODNN7EXAMPLF";
        let mut event = event_with_labels(&[(AWS_KEY_A, "value-a"), (AWS_KEY_B, "value-b")]);

        let outcome = scanner.enforce(&mut event);

        assert_eq!(
            event.inner.labels.len(),
            2,
            "both label pairs must survive the collision"
        );
        assert!(
            !event
                .inner
                .labels
                .keys()
                .any(|k| k.contains(AWS_KEY_A) || k.contains(AWS_KEY_B)),
            "no raw secret may survive in a label key"
        );
        assert!(
            event.inner.labels.keys().all(|k| k.contains("[REDACTED:AwsAccessKey]")),
            "both keys carry the redaction marker"
        );
        let mut values: Vec<&str> = event.inner.labels.values().map(String::as_str).collect();
        values.sort_unstable();
        assert_eq!(values, vec!["value-a", "value-b"], "neither value was dropped");
        assert!(!outcome.is_clean());
    }
}
