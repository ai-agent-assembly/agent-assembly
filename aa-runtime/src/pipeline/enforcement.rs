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

use aa_core::CredentialFinding;

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
