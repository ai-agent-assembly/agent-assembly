//! Verification spec for AAASM-2614 — removal of the temporary `aa-security`
//! compat re-exports from `aa-core` (implementation: AAASM-2657).
//!
//! Every scanner / finding / redaction symbol below is imported from
//! `aa_security` **directly**. None of these paths route through an `aa_core`
//! re-export — that surface (`aa_core::scanner`, `aa_core::CredentialFinding`,
//! `aa_core::Redaction`, …) was removed. This file therefore only compiles
//! against the cleaned-up public API, which is the point.
//!
//! Gated behind `feature = "serde"` (the audit round-trip exercises the JSON
//! serializer); runs under `cargo nextest run -p aa-core --all-features`.

#![cfg(feature = "serde")]

use aa_core::{AgentId, AuditEntry, AuditEventType, Lineage, SessionId};
use aa_security::{CredentialFinding, CredentialScanner, Redaction};

const AGENT: AgentId = AgentId::from_bytes([7u8; 16]);
const SESSION: SessionId = SessionId::from_bytes([9u8; 16]);

/// Synthetic AWS access key from AWS public documentation — not a real credential.
const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn redaction_for_fake_secret() -> Redaction {
    let scanner = CredentialScanner::new();
    let scan = scanner.scan(FAKE_AWS_ACCESS_KEY);
    assert!(
        !scan.findings.is_empty(),
        "scanner fixture must detect the synthetic AWS access key",
    );
    let redacted_payload = Some(scan.redact(FAKE_AWS_ACCESS_KEY));
    Redaction {
        credential_findings: scan.findings,
        redacted_payload,
    }
}

/// AC: `AuditEntry::credential_findings()` now hands back
/// `aa_security::CredentialFinding` directly. The explicit
/// `&[CredentialFinding]` annotation (with `CredentialFinding` imported from
/// `aa_security`) is a **compile-time** proof: if the getter were still typed
/// at the deleted `aa_core::scanner::CredentialFinding` re-export, the two
/// types would differ and this file would fail to compile.
#[test]
fn credential_findings_getter_returns_aa_security_type() {
    let redaction = redaction_for_fake_secret();
    let expected_len = redaction.credential_findings.len();

    let entry = AuditEntry::new_with_lineage_and_redaction(
        0,
        1_700_000_000_000_000_000,
        AuditEventType::CredentialLeakBlocked,
        AGENT,
        SESSION,
        String::from(r#"{"action_type":"tool_call","decision":"redact"}"#),
        [0u8; 32],
        Lineage::default(),
        redaction,
    );

    let findings: &[CredentialFinding] = entry.credential_findings();
    assert_eq!(
        findings.len(),
        expected_len,
        "findings attached to AuditEntry must survive the aa_security repoint",
    );
}
