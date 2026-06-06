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

/// Default upper bound, in bytes, on a single secret-bearing field handed to
/// the scanner. Fields larger than this are handled per [`OversizedPolicy`].
///
/// 64 KiB comfortably covers realistic tool-call argument payloads while
/// bounding the per-event scan cost.
pub const DEFAULT_MAX_FIELD_BYTES: usize = 64 * 1024;

/// Replacement written into a field that exceeded the configured size cap.
pub const OVERSIZED_MARKER: &str = "[REDACTED:OVERSIZED]";

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
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EnforcementOutcome {
    /// Every credential finding across all scanned fields of the event.
    pub findings: Vec<CredentialFinding>,
    /// Number of fields that hit the size cap and were redacted whole.
    pub oversized_fields: usize,
    /// Total bytes actually handed to the scanner across all fields.
    pub scanned_bytes: usize,
}

impl EnforcementOutcome {
    /// `true` when nothing was redacted: no findings and no oversized fields.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty() && self.oversized_fields == 0
    }

    /// Total number of redactions applied (findings + oversized fields).
    pub fn redaction_count(&self) -> usize {
        self.findings.len() + self.oversized_fields
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
    /// enumeration fields are left untouched.
    pub fn enforce(&self, event: &mut EnrichedEvent) -> EnforcementOutcome {
        let started = Instant::now();
        let mut outcome = EnforcementOutcome::default();
        if let Some(detail) = event.inner.detail.as_mut() {
            self.scan_detail(detail, &mut outcome);
        }
        emit_metrics(&outcome, started.elapsed());
        outcome
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

    /// Normalize a `bytes` field to UTF-8, then scan and redact it in place.
    ///
    /// The original bytes are left untouched when the field is clean; they are
    /// rewritten (from the normalized, redacted text) only when a finding is
    /// present.
    fn scan_bytes(&self, field: &mut Vec<u8>, outcome: &mut EnforcementOutcome) {
        if field.is_empty() {
            return;
        }
        if field.len() > self.config.max_field_bytes {
            self.apply_oversized_bytes(field, outcome);
            return;
        }
        // Normalize: a `bytes` payload is scanned as lossy UTF-8 text.
        let text = String::from_utf8_lossy(field);
        outcome.scanned_bytes += text.len();
        let result = self.scanner.scan(&text);
        if !result.is_clean() {
            let redacted = result.redact(&text);
            *field = redacted.into_bytes();
            outcome.findings.extend(result.findings);
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

    #[test]
    fn from_runtime_config_maps_size_cap_and_keeps_fail_closed_policy() {
        let rc = RuntimeConfig {
            agent_id: "test".to_string(),
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
            correlation_window_ms: 5_000,
            correlation_interval_ms: 1_000,
            nats_config_path: None,
            audit_buffer_path: std::path::PathBuf::from("/tmp/aa-audit-buffer-test.db"),
            enforcement_max_field_bytes: 4096,
        };

        let config = EnforcementConfig::from_runtime_config(&rc);

        assert_eq!(config.max_field_bytes, 4096, "size cap is threaded from RuntimeConfig");
        assert_eq!(
            config.oversized_policy,
            OversizedPolicy::RedactWhole,
            "oversized policy stays fail-closed"
        );
    }
}
