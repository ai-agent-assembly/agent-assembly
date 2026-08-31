//! End-to-end regression for AAASM-6020: the local-mode audit JSONL file
//! must `verify_chain` as `Verified` (not `Tampered`) once more than one
//! entry has been written by more than one producer.
//!
//! Drives the real production handlers (`suspend_agent`,
//! `dispatch_tool`/the WASM-sandbox branch) against a real
//! `AppState::local_hardened` — the same `AuditChain` + `AuditWriter` the
//! shipped `aa-api-server` binary wires — rather than a hand-built chain, so
//! this exercises the exact bug the ticket fixes: before AAASM-6020, the
//! WASM-sandbox loop alone produced two entries per single request with
//! `seq=idx`/`previous_hash=[0u8; 32]` each, which made `verify_chain`
//! report `Tampered` starting from the *second* entry of the *first*
//! request — i.e. this reproduces with exactly one dispatch call.

mod common;

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use aa_api::auth::{AuthenticatedCaller, Tenant};
use aa_api::routes::agents::{suspend_agent, SuspendRequest};
use aa_api::routes::dispatch::{dispatch_tool, DispatchToolRequest};
use aa_api::state::{AppState, LocalAuth};
use aa_gateway::audit::VerifyOutcome;
use aa_gateway::registry::{AgentRecord, AgentStatus};
use aa_sandbox::registry::ToolKind;
use axum::extract::{Extension, Path};
use axum::Json;

/// Hand-assembled minimal WASM module equivalent to
/// `(module (func (export "_start")))` — mirrors `aa-sandbox`'s own
/// `NOOP_WAT` fixture (`aa_sandbox::wasm_dispatch::tests::NOOP_WAT`), spelled
/// out as raw bytes instead of pulling in the `wat` crate as a new
/// aa-api dev-dependency for one test.
const NOOP_WASM_MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: () -> ()
    0x03, 0x02, 0x01, 0x00, // function section: 1 function, type 0
    0x07, 0x0a, 0x01, 0x06, b'_', b's', b't', b'a', b'r', b't', 0x00, 0x00, // export "_start"
    0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // code section: empty body
];

/// A write-scoped, admin caller — enough to pass every authz check the two
/// handlers under test perform (tenant/scope checks are not what this test
/// is about; the audit-chain linkage across producers is).
fn admin_caller() -> AuthenticatedCaller {
    AuthenticatedCaller {
        key_id: "aaasm-6020-test-operator".to_string(),
        scopes: vec![aa_api::auth::scope::Scope::Admin, aa_api::auth::scope::Scope::Write],
        tenant: Tenant {
            org_id: None,
            team_id: None,
        },
    }
}

fn agent_record(id: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: id,
        name: "aaasm-6020-agent".to_string(),
        framework: "test".to_string(),
        version: "0".to_string(),
        risk_tier: 1,
        tool_names: Vec::new(),
        public_key: String::new(),
        credential_token: String::new(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        active_sessions: Vec::new(),
        recent_events: VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some(id),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        enforcement_mode_expires_at: None,
        org_id: None,
    }
}

#[tokio::test]
async fn local_mode_audit_file_verifies_across_two_producers() {
    let state = AppState::local_hardened(LocalAuth::Off)
        .await
        .expect("local_hardened state builds");

    let agent_id = [0x42u8; 16];
    let hex_id = agent_id.iter().map(|b| format!("{b:02x}")).collect::<String>();
    state
        .agent_registry
        .register(agent_record(agent_id))
        .expect("register test agent");

    // Register a real (trivial) WASM tool so the sandbox-dispatch branch
    // routes through `dispatch_wasm` instead of the native/secret-injection
    // path — this is the branch that previously emitted a broken chain from
    // its *second* entry onward within a single request.
    state.tool_registry.register(
        "noop_wasm_tool",
        ToolKind::Wasm {
            module_bytes: NOOP_WASM_MODULE.to_vec(),
            config: Default::default(),
        },
    );

    // ── Producer 1: governance-mutation audit (agents::suspend_agent) ──
    let suspend_resp = suspend_agent(
        aa_api::auth::scope::RequireWrite(admin_caller()),
        Extension(state.clone()),
        Path(hex_id),
        Json(SuspendRequest {
            reason: "AAASM-6020 regression coverage".to_string(),
        }),
    )
    .await
    .expect("suspend succeeds");
    assert_eq!(suspend_resp.0, axum::http::StatusCode::OK);

    // ── Producer 2: WASM-sandbox dispatch (dispatch::dispatch_tool) ──
    // A single call emits *two* audit entries (SandboxStarted +
    // SandboxTerminated) — the exact case that broke before AAASM-6020.
    let dispatch_resp = dispatch_tool(
        Extension(state.clone()),
        aa_api::auth::scope::RequireWrite(admin_caller()),
        Json(DispatchToolRequest {
            tool: "noop_wasm_tool".to_string(),
            args: serde_json::json!({}),
        }),
    )
    .await
    .expect("wasm dispatch succeeds");
    assert!(dispatch_resp.0.sandbox.is_some(), "sandbox branch must have run");

    // ── Locate the file the writer actually persisted to. ──
    // `local_hardened_at` builds the writer as
    // `AuditWriter::new(audit_jsonl_dir, "local", "local", ...)`, so the
    // filename is `local-local.jsonl` per `AuditWriter::new`'s
    // `<agent_id>-<session_id>.jsonl` convention.
    let path = state.audit_reader.dir().join("local-local.jsonl");

    // The `AuditWriter` runs in a detached `tokio::spawn` with no completion
    // signal, so poll `verify_chain` with a bounded retry instead of reading
    // once and racing the writer's flush.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut last = None;
    loop {
        match aa_gateway::audit::AuditWriter::verify_chain(&path).await {
            Ok(result) if result.entries_checked >= 3 => {
                last = Some(result);
                break;
            }
            Ok(result) => last = Some(result),
            Err(_) => {} // file may not exist yet on the very first poll
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let result = last.expect("verify_chain ran at least once");

    // Negative control: if this were still 1 entry (or 0), `Verified` would
    // be a vacuous pass — a single-entry file trivially verifies even with
    // the old per-producer-zeroed-seq bug, since there is no link to break.
    assert!(
        result.entries_checked > 1,
        "need more than one entry for this test to actually exercise chain linkage, got {}",
        result.entries_checked
    );
    assert_eq!(
        result.entries_checked, 3,
        "expected 1 governance-mutation + 2 sandbox lifecycle entries"
    );
    assert_eq!(
        result.outcome,
        VerifyOutcome::Verified,
        "local-mode audit file must verify cleanly across producers, got {:?} (missing_seq_ranges={:?})",
        result.outcome,
        result.missing_seq_ranges,
    );
}
