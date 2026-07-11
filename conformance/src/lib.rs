//! Conformance test suite for the Agent Assembly protocol.
//!
//! This crate provides:
//! - JSON test vectors in `conformance/vectors/` (language-neutral)
//! - Rust test helpers that drive the vectors against `aa-core` and `aa-proto`
//! - A Python runner in `conformance/runner/` for SDK-level conformance
//!
//! # Test categories
//! 1. `ipc_framing`     — prost varint length-delimited encode/decode
//! 2. `message_serial`  — proto message wire-format golden bytes
//! 3. `policy_query`    — CheckActionRequest / CheckActionResponse round-trips
//! 4. `cred_detection`  — CredentialScanner::scan() + ScanResult::redact()
//! 5. `session_lifecycle` — agent Register → Heartbeat → Deregister → ControlStream
//! 6. `integration_surface_contract` — the SDK-relied-on network surface is
//!    actually present on the server(s) the CLI starts (AAASM-4454)

/// Source-introspection helpers for the integration-surface contract tests.
pub mod surface;

use serde::de::DeserializeOwned;
use std::path::Path;

// ── Vector types ─────────────────────────────────────────────────────────────

/// A single IPC framing test vector.
///
/// `input_hex` is the hex-encoded proto bytes of a serialized message.
/// `expected_framed_hex` is the expected output of `encode_length_delimited`:
/// a prost varint-encoded length prefix followed by the same bytes.
#[derive(Debug, serde::Deserialize)]
pub struct FramingVector {
    pub description: String,
    pub message_type: String,
    pub input_hex: String,
    pub expected_framed_hex: String,
}

/// A single credential-detection test vector.
///
/// `expected_findings` lists `{kind, offset}` pairs in offset order.
/// `expected_redacted` is the full text after `ScanResult::redact()`.
#[derive(Debug, serde::Deserialize)]
pub struct ScanVector {
    pub description: String,
    pub input_text: String,
    pub expected_findings: Vec<FindingSpec>,
    pub expected_redacted: String,
}

/// One expected finding within a `ScanVector`.
#[derive(Debug, serde::Deserialize)]
pub struct FindingSpec {
    pub kind: String,
    pub offset: usize,
}

/// A single session lifecycle test vector.
///
/// `message_type` names the proto message under test (e.g. `"RegisterRequest"`).
/// `fields` carries the representative field values in language-neutral JSON.
/// The Rust test in `tests/session_lifecycle.rs` matches on `message_type`,
/// constructs the proto message from `fields`, round-trips through prost, and
/// verifies the specified fields survive encoding / decoding.
#[derive(Debug, serde::Deserialize)]
pub struct SessionLifecycleVector {
    pub description: String,
    pub message_type: String,
    pub fields: serde_json::Value,
}

// ── VectorLoader ─────────────────────────────────────────────────────────────

/// Loads all JSON test vectors from a directory.
///
/// Reads every `*.json` file in `dir` in sorted filename order and
/// deserialises each into `T`. Panics with a descriptive message on any
/// file-read or parse error so test failures are easy to diagnose.
pub fn load_vectors<T: DeserializeOwned>(dir: &str) -> Vec<T> {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    let mut entries: Vec<_> = std::fs::read_dir(&base)
        .unwrap_or_else(|e| panic!("cannot open vector dir {}: {}", base.display(), e))
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    entries
        .iter()
        .map(|entry| {
            let path = entry.path();
            let raw =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("cannot parse {}: {}", path.display(), e))
        })
        .collect()
}

/// Loads a golden binary file from `conformance/vectors/proto/<name>.bin`.
///
/// Returns the raw bytes. Panics if the file cannot be read.
pub fn load_golden_bin(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors/proto")
        .join(format!("{name}.bin"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read golden file {}: {}", path.display(), e))
}

/// Decodes a lowercase hex string into bytes.
///
/// Panics if the string has odd length or contains non-hex characters.
pub fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string has odd length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| panic!("invalid hex at {i}: {}", &s[i..i + 2]))
        })
        .collect()
}
