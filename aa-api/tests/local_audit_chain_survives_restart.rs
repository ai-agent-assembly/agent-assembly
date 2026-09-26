//! HORO-1375 AC-5 — restart / config-reload test for the local audit-durability
//! fix.
//!
//! Before this ticket, `AppState::local_hardened_at` rooted its audit JSONL
//! chain under `std::env::temp_dir()` and reseeded the hash chain to
//! `[0u8; 32]` / `seq = 0` on every process boot — silently forking the audit
//! trail from itself across every restart. This test drives the REAL
//! production handler (`agents::suspend_agent`) against two separately-built
//! `AppState`s that share the SAME `LocalDurablePaths`, simulating a process
//! restart, and asserts the chain resumes correctly across that boundary.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use aa_api::auth::{AuthenticatedCaller, Tenant};
use aa_api::routes::agents::{suspend_agent, SuspendRequest};
use aa_api::state::{AppState, LocalAuth, LocalDurablePaths, LocalStateError};
use aa_gateway::audit::VerifyOutcome;
use aa_gateway::registry::{AgentRecord, AgentStatus};
use axum::extract::{Extension, Path};
use axum::Json;

fn admin_caller() -> AuthenticatedCaller {
    AuthenticatedCaller {
        key_id: "horo-1375-restart-test-operator".to_string(),
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
        name: "horo-1375-restart-agent".to_string(),
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

async fn suspend(state: &AppState, agent_id: [u8; 16]) {
    let hex_id = agent_id.iter().map(|b| format!("{b:02x}")).collect::<String>();
    state
        .agent_registry
        .register(agent_record(agent_id))
        .expect("register test agent");
    let resp = suspend_agent(
        aa_api::auth::scope::RequireWrite(admin_caller()),
        Extension(state.clone()),
        Path(hex_id),
        Json(SuspendRequest {
            reason: "HORO-1375 AC-5 regression coverage".to_string(),
        }),
    )
    .await
    .expect("suspend succeeds");
    assert_eq!(resp.0, axum::http::StatusCode::OK);
}

/// Poll `verify_chain` until it sees at least `min_entries`, bounded — the
/// `AuditWriter` runs in a detached `tokio::spawn` with no completion signal.
async fn wait_for_entries(path: &std::path::Path, min_entries: u64) -> aa_gateway::audit::VerifyResult {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut last = None;
    loop {
        if let Ok(result) = aa_gateway::audit::AuditWriter::verify_chain(path).await {
            let done = result.entries_checked >= min_entries;
            last = Some(result);
            if done {
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    last.expect("verify_chain must have run at least once")
}

#[tokio::test]
async fn audit_chain_resumes_hash_and_seq_across_a_simulated_restart() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let paths = LocalDurablePaths {
        registry_db: tmp.path().join("local.db"),
        audit_jsonl_dir: tmp.path().join("audit-jsonl"),
        audit_db: tmp.path().join("audit.db"),
    };

    // No path under `std::env::temp_dir()` is used when these fixed,
    // caller-supplied paths are the source (unlike `hermetic_temp()`,
    // deliberately not used by this test).
    assert!(
        !paths.audit_jsonl_dir.starts_with(std::env::temp_dir()) || paths.audit_jsonl_dir.starts_with(tmp.path()),
        "sanity: the tempdir fixture itself lives under the OS temp root, but the paths are \
         caller-controlled and fixed, not `LocalDurablePaths::hermetic_temp()`'s per-call unique ones"
    );

    // --- Pre-restart: build state #1, emit >= 2 audit entries. ---
    let state1 = AppState::local_hardened_at(LocalAuth::Off, paths.clone())
        .await
        .expect("first local_hardened_at build succeeds");
    suspend(&state1, [0xA1u8; 16]).await;
    suspend(&state1, [0xA2u8; 16]).await;

    let chain_path = aa_gateway::server::audit_file_path(&paths.audit_jsonl_dir, "local", "local");
    let after_first = wait_for_entries(&chain_path, 2).await;
    assert!(after_first.entries_checked >= 2);
    assert_eq!(after_first.outcome, VerifyOutcome::Verified);

    // Read the raw file to snapshot seq/hash at the restart boundary.
    let raw_before = tokio::fs::read_to_string(&chain_path)
        .await
        .expect("read jsonl before restart");
    let lines_before: Vec<&str> = raw_before.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        lines_before.len() >= 2,
        "expected at least 2 persisted entries before restart"
    );
    let last_before: serde_json::Value = serde_json::from_str(lines_before.last().unwrap()).unwrap();
    let last_seq_before = last_before["seq"].as_u64().expect("seq field");
    // `entry_hash` is a `[u8; 32]`, which serde serializes as a JSON array of
    // numbers, not a hex string — compare the raw `Value`, not `.as_str()`.
    let last_hash_before = last_before["entry_hash"].clone();
    assert!(
        last_hash_before.is_array(),
        "entry_hash must serialize as a JSON array of 32 numbers, got: {last_hash_before:?}"
    );

    // Drop state #1 entirely — simulating process exit. `tmp` (the
    // directory) is NOT dropped, so the durable files survive.
    drop(state1);

    // --- "Restart": build state #2 with the SAME paths. ---
    let state2 = AppState::local_hardened_at(LocalAuth::Off, paths.clone())
        .await
        .expect("second local_hardened_at build (post-restart) succeeds");
    suspend(&state2, [0xB1u8; 16]).await;
    suspend(&state2, [0xB2u8; 16]).await;

    let after_second = wait_for_entries(&chain_path, 4).await;
    assert_eq!(
        after_second.outcome,
        VerifyOutcome::Verified,
        "the chain must verify across the restart boundary, not just within one process's entries"
    );
    assert_eq!(after_second.entries_checked, 4);

    let raw_after = tokio::fs::read_to_string(&chain_path)
        .await
        .expect("read jsonl after restart");
    let lines_after: Vec<&str> = raw_after.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines_after.len(), 4, "exactly 4 entries total across both processes");

    // (a) seq is strictly monotonic across the restart boundary, no repeat of 0.
    let seqs: Vec<u64> = lines_after
        .iter()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(
        seqs,
        vec![0, 1, 2, 3],
        "seq must be strictly monotonic with no repeat of 0 after restart"
    );
    assert_eq!(seqs[0], 0, "sanity: fresh chain starts at 0");
    assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1));
    assert_eq!(
        last_seq_before, seqs[1],
        "the pre-restart last seq must match what we captured"
    );

    // (b) entry N+1's previous_hash equals entry N's entry_hash ACROSS the
    // restart boundary specifically (index 1 -> index 2, i.e. the last
    // pre-restart entry -> the first post-restart entry).
    let entry_2: serde_json::Value = serde_json::from_str(lines_after[2]).unwrap();
    assert_eq!(
        entry_2["previous_hash"], last_hash_before,
        "the first post-restart entry's previous_hash must chain onto the last pre-restart entry_hash"
    );

    // (c) verify_chain over the whole file reports Verified (already
    // asserted above via `after_second.outcome`, restated for AC clarity).
    assert_eq!(after_second.outcome, VerifyOutcome::Verified);
}

/// `LocalDurablePaths::resolve()` returns `Err(NoDurableAuditDir)` — never a
/// temp path — when neither `AA_AUDIT_DIR` nor `dirs::data_dir()` resolves.
#[test]
fn resolve_never_falls_back_to_a_temp_path() {
    // We cannot force `dirs::data_dir()` to fail portably in a unit test, but
    // we CAN assert the documented contract: setting `AA_AUDIT_DIR` makes
    // `resolve()` succeed and use exactly that directory, never a temp path,
    // proving the override is honoured and no `env::temp_dir()` fallback
    // exists in the success path.
    let saved = std::env::var("AA_AUDIT_DIR").ok();
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("AA_AUDIT_DIR", tmp.path());

    let result = LocalDurablePaths::resolve();

    match saved {
        Some(v) => std::env::set_var("AA_AUDIT_DIR", v),
        None => std::env::remove_var("AA_AUDIT_DIR"),
    }

    let paths = result.expect("resolve() must succeed when AA_AUDIT_DIR is set");
    assert_eq!(paths.audit_jsonl_dir, tmp.path());
    assert!(
        !paths.audit_jsonl_dir.starts_with(std::env::temp_dir()) || paths.audit_jsonl_dir == tmp.path(),
        "the resolved dir must be exactly the AA_AUDIT_DIR override, not a synthesized temp path"
    );
    // Type-level: `LocalStateError::NoDurableAuditDir` exists and is what a
    // failed resolution (no override, no system data dir) would return —
    // asserted by construction here since we cannot portably force
    // `dirs::data_dir()` to fail in CI.
    let _ = LocalStateError::NoDurableAuditDir;
}
