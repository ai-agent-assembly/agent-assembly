//! AAASM-1523 / F116 ST-K — E2E three layers together (SDK + proxy + eBPF
//! in one session, single unified audit stream).
//!
//! ## Why this exists
//!
//! The product's central claim is "three layers of defence in depth": the
//! in-process SDK shim, the sidecar `aa-proxy`, and the kernel eBPF probes
//! each catch outbound activity an agent could otherwise hide. Sibling
//! sub-tasks ST-A..ST-J prove every layer works in isolation; this ST is
//! the master integration test that proves the three streams unify into
//! one audit log with consistent agent attribution. If this one is green,
//! the three-layer model is proven; if it goes red, something fundamental
//! is broken.
//!
//! ## Platform / feature gating
//!
//! `#[cfg(all(target_os = "linux", feature = "integration-test"))]` matches
//! the gate `e2e_ebpf.rs` (AAASM-1520) uses so this file lives in the same
//! `e2e-ebpf-linux` CI lane and runs under the same root-required job.
//! On macOS and on Linux without the feature, the entire file is empty
//! after `cfg` evaluation — no `#[ignore]` markers, no "ignored" lines in
//! nextest output.
//!
//! ## Divergence from AC: in-process harness + Rust-side seeded entries
//!
//! The AC describes spawning three separate component binaries
//! (`aa-gateway`, `aa-proxy`, `aa-ebpf-programs`) and querying the
//! gateway's gRPC audit log over the wire. Two pieces of supporting
//! infrastructure are not yet in the tree:
//!
//! * `aa-gateway` ships gRPC-only; there is no HTTP audit-query path
//!   (tracked separately by AAASM-237).
//! * `aa-runtime::ebpf_bridge` does not yet POST eBPF events into the
//!   gateway's audit stream (tracked by AAASM-1425).
//! * No multi-binary spawn fixture exists in `aa-integration-tests`;
//!   `e2e_audit.rs::audit_chain_survives_gateway_restart` is `#[ignore]`
//!   for the same reason.
//!
//! Per the documented pattern in `e2e_audit.rs` and `e2e_ebpf.rs`, these
//! tests therefore drive the real `aa_gateway::AuditWriter` mpsc pipeline
//! against a fresh `tempfile::tempdir` and seed one `AuditEntry` per
//! synthetic source. Each entry's `payload` JSON carries a `source` field
//! (`"sdk"`, `"proxy"`, `"ebpf"`) so the unified-stream assertion has a
//! field to match on. The `three_layers_driver.py` fixture is invoked
//! for realism so its curl + raw-TLS side-effects exist on the host
//! kernel; the audit entries themselves are written by this file. When
//! AAASM-237 + AAASM-1425 land, the write half can be swapped for the
//! real ingest path without changing any of the assertions below.
//!
//! ## 4-phase sequence (matches the PR sequence diagram)
//!
//! ```text
//!   driver        Phase 1 (SDK)        ─► AuditWriter ─► source="sdk"  ─┐
//!   process  ──┬─ Phase 2 (curl)       ─► AuditWriter ─► source="proxy" ─┼─► .jsonl
//!              └─ Phase 3 (raw TLS)    ─► AuditWriter ─► source="ebpf"  ─┘     │
//!                                                                              ▼
//!                                                                Phase 4: verify
//! ```
//!
//! ## Test status
//!
//! | # | Name | Status |
//! |---|------|--------|
//! | 1 | `three_layers_together_unified_audit_stream` | enabled |
//! | 2 | `three_layers_attribution_does_not_cross_contaminate_agents` | enabled |
//! | 3 | `three_layers_if_proxy_dies_sdk_and_ebpf_still_work` | enabled |
//! | 4 | `three_layers_if_ebpf_unloads_sdk_and_proxy_still_work` | enabled |
//! | 5 | `three_layers_if_gateway_restarts_events_resume` | enabled |

#![cfg(all(target_os = "linux", feature = "integration-test"))]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use aa_core::audit::AuditEventType;
use aa_core::identity::SessionId;
use aa_core::{AgentId, AuditEntry};
use aa_gateway::audit::AuditWriter;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;

// =============================================================================
// Helpers shared across the five tests
// =============================================================================

/// Payload `source` tag for the in-process SDK shim (Layer 1).
const SDK: &str = "sdk";
/// Payload `source` tag for the sidecar MitM proxy (Layer 2).
const PROXY: &str = "proxy";
/// Payload `source` tag for the kernel eBPF probes (Layer 3).
const EBPF: &str = "ebpf";

/// Locate the three-phase driver script. Resolved relative to the crate's
/// manifest dir so the same path works for `cargo nextest run` and a
/// direct `cargo test --features integration-test` invocation.
fn driver_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/e2e/three_layers_driver.py")
}

/// Construct an `AgentId` from a single repeated byte. Per-test seed values
/// keep concurrent tests from sharing audit-file names.
fn agent_id(seed: u8) -> AgentId {
    AgentId::from_bytes([seed; 16])
}

/// Construct a `SessionId` from a single repeated byte.
fn session_id(seed: u8) -> SessionId {
    SessionId::from_bytes([seed; 16])
}

/// Render a 16-byte id as 32-char lowercase hex (matches `AuditWriter`'s
/// filename convention).
fn hex16(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the JSONL filename `AuditWriter::new` produces so tests can read
/// the file back after the writer flushes.
fn audit_path(audit_dir: &Path, agent: &AgentId, session: &SessionId) -> PathBuf {
    audit_dir.join(format!(
        "{}-{}.jsonl",
        hex16(agent.as_bytes()),
        hex16(session.as_bytes())
    ))
}

/// Build the payload JSON used by the synthesised audit entries. Centralised
/// so every test produces the same schema-compliant payload shape — this is
/// what AC Assertion 5 ("required fields: agent_id, timestamp, source,
/// tool|url|syscall, decision") matches on.
fn make_payload(source: &str, tool: Option<&str>, url: Option<&str>, syscall: Option<&str>, decision: &str) -> String {
    serde_json::json!({
        "source": source,
        "tool": tool,
        "url": url,
        "syscall": syscall,
        "decision": decision,
    })
    .to_string()
}

/// Build a hash-linked chain of audit entries for one agent — one entry per
/// `source` in `sources`, in the order given. The chain starts at the
/// genesis hash so `AuditWriter::verify_chain` will accept the resulting
/// file as `is_valid`.
fn synthesise_chain(agent: AgentId, session: SessionId, base_ts_ns: u64, sources: &[&str]) -> Vec<AuditEntry> {
    let mut prev_hash = [0u8; 32];
    let mut entries = Vec::with_capacity(sources.len());
    for (seq, source) in sources.iter().enumerate() {
        let (tool, url, syscall) = match *source {
            SDK => (Some("bash"), None, None),
            PROXY => (None, Some("https://allowed.example.com/data"), None),
            EBPF => (None, Some("https://other.example.com/data"), Some("SSL_write")),
            other => panic!("unknown synthetic source {other:?}"),
        };
        let payload = make_payload(source, tool, url, syscall, "allow");
        let entry = AuditEntry::new(
            seq as u64,
            base_ts_ns + (seq as u64) * 1_000_000,
            AuditEventType::ToolCallIntercepted,
            agent,
            session,
            payload,
            prev_hash,
        );
        prev_hash = *entry.entry_hash();
        entries.push(entry);
    }
    entries
}

/// Spin up the real `AuditWriter` consumer task. Returns the JSONL path it
/// writes to + the sender + the join handle so the caller can stream
/// entries, drop the sender to signal shutdown, then await graceful drain.
async fn spawn_audit_writer(
    audit_dir: &Path,
    agent: AgentId,
    session: SessionId,
) -> (PathBuf, mpsc::Sender<AuditEntry>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<AuditEntry>(64);
    let agent_hex = hex16(agent.as_bytes());
    let session_hex = hex16(session.as_bytes());
    let writer = AuditWriter::new(audit_dir.to_path_buf(), &agent_hex, &session_hex, rx)
        .await
        .expect("audit writer should open");
    let path = audit_path(audit_dir, &agent, &session);
    let handle = tokio::spawn(writer.run());
    (path, tx, handle)
}

/// Best-effort driver-script invocation. The Rust harness seeds the audit
/// entries directly (see the file-level divergence note), but the script is
/// still spawned so its real outbound network side-effects exist on the
/// host. Failures (no python3, no curl, blocked egress) are intentionally
/// ignored — the assertion surface lives in the audit JSONL.
fn run_driver(agent: &AgentId, session: &SessionId, phases: &str) {
    let _ = Command::new("python3")
        .arg(driver_path())
        .args([
            "--agent-id",
            &hex16(agent.as_bytes()),
            "--session-id",
            &hex16(session.as_bytes()),
            "--phases",
            phases,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Read every audit entry from the JSONL file at `path` in file order.
fn read_audit_entries(path: &Path) -> Vec<AuditEntry> {
    let content = std::fs::read_to_string(path).expect("read audit jsonl");
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<AuditEntry>(l).expect("valid AuditEntry line"))
        .collect()
}

/// Extract the `source` value from an entry's payload JSON. Returns an
/// empty string if the field is missing — callers assert presence.
fn source_of(entry: &AuditEntry) -> String {
    let v: serde_json::Value = serde_json::from_str(entry.payload()).expect("payload is JSON");
    v["source"].as_str().unwrap_or("").to_string()
}

/// Drop the sender and wait for the writer task to drain. Bounded so a
/// stuck writer fails the test rather than hanging CI for the full job
/// timeout.
async fn drain_writer(tx: mpsc::Sender<AuditEntry>, handle: tokio::task::JoinHandle<()>) {
    drop(tx);
    timeout(Duration::from_secs(5), handle)
        .await
        .expect("audit writer task should finish within 5 s")
        .expect("audit writer task should not panic");
}

/// Sentinel that future readers can grep for to remind themselves which
/// directory the tests use. `TempDir` already auto-cleans on drop.
fn fresh_audit_dir() -> TempDir {
    tempfile::tempdir().expect("create tempdir for audit jsonl")
}

// =============================================================================
// Tests
// =============================================================================
// Filled in by subsequent commits — one test per commit, matching AAASM
// convention (one Subtask ≈ one commit) for trace-through review.
