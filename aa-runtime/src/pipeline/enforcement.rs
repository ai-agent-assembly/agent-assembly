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
//! The scanner / redaction primitives are sourced from [`aa_core`] today; they
//! move to `aa-security` under AAASM-2567, which is an import-only change here.

use aa_core::{CredentialFinding, CredentialScanner};
use aa_proto::assembly::audit::v1::audit_event::Detail;

use super::event::EnrichedEvent;

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
        let mut outcome = EnforcementOutcome::default();
        let Some(detail) = event.inner.detail.as_mut() else {
            return outcome;
        };
        match detail {
            Detail::ToolCall(tc) => {
                self.scan_bytes(&mut tc.args_json, &mut outcome);
                self.scan_string(&mut tc.error_message, &mut outcome);
            }
            Detail::FileOp(f) => {
                self.scan_string(&mut f.path, &mut outcome);
            }
            Detail::Process(p) => {
                self.scan_string(&mut p.command, &mut outcome);
                for arg in p.args.iter_mut() {
                    self.scan_string(arg, &mut outcome);
                }
            }
            // No free-text secret-bearing fields: LlmCall / Network / Violation
            // / Approval carry only identifiers, enums, and counters. Matched
            // explicitly (no wildcard) so a new detail variant fails to compile
            // until its secret-bearing fields are triaged here.
            Detail::LlmCall(_) | Detail::Network(_) | Detail::Violation(_) | Detail::Approval(_) => {}
        }
        outcome
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
