//! AAASM-2033 / F116 ST-W data-path E2E — `POST /api/v1/dispatch_tool`
//! with a WASM-marked tool registered.
//!
//! Boots [`TopologyTestEnv::start_with_audit_sink`] — an in-process Axum
//! server with an `mpsc::Receiver<AuditEntry>` wired to
//! `AppState::audit_sender`. Each test registers a `ToolKind::Wasm`
//! entry in the shared `tool_registry` for one of the AAASM-2020 WAT
//! fixtures, drives the HTTP route, and asserts **both** the
//! `DispatchToolResponse.sandbox` payload shape AND the exact
//! lifecycle audit-event sequence drained from the audit-sink receiver.
//!
//! Four tests:
//!
//! * `dispatch_tool_wasm_routes_filesystem_blocked` — exercises the
//!   AAASM-2017 filesystem-isolation half end-to-end through the HTTP
//!   surface; asserts `sandbox.error == "FilesystemBlocked"` + audit
//!   sequence `[SandboxStarted, SandboxFilesystemBlocked]`.
//! * `dispatch_tool_wasm_routes_cpu_timeout` — exercises the AAASM-2018
//!   CPU-timeout half; asserts `sandbox.error == "CpuTimeout"` + audit
//!   `[SandboxStarted, SandboxCpuTimeout]`.
//! * `dispatch_tool_wasm_routes_memory_exhausted` — exercises the
//!   AAASM-2018 memory-exhaustion half; asserts
//!   `sandbox.error == "MemoryExhausted"` + audit
//!   `[SandboxStarted, SandboxOomKilled]`.
//! * `dispatch_tool_unknown_tool_falls_through_to_secret_injection` —
//!   regression guard that the AAASM-1920 secret-injection path is
//!   untouched when the registry has no entry; asserts the native path
//!   emits a single `ToolDispatched` audit entry.

#[path = "common/mod.rs"]
mod common;

use std::time::Duration;

use aa_core::audit::{AuditEntry, AuditEventType};
use aa_sandbox::policy::{SandboxConfig, SandboxLimits};
use aa_sandbox::registry::ToolKind;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use common::TopologyTestEnv;

const FS_PROBE_WAT: &str = include_str!("../fixtures/wasm/fs_probe.wat");
const RUNAWAY_WAT: &str = include_str!("../fixtures/wasm/runaway.wat");
const MEM_BOMB_WAT: &str = include_str!("../fixtures/wasm/mem_bomb.wat");

/// POST `body` to `/api/v1/dispatch_tool` on `env`'s loopback server
/// and return the parsed response.
async fn post_dispatch_tool(env: &TopologyTestEnv, body: Value) -> Value {
    let client = reqwest::Client::new();
    let url = format!("http://{}/api/v1/dispatch_tool", env.addr);
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("HTTP POST must succeed");
    assert_eq!(resp.status(), 200, "expected 200 OK, got {}", resp.status());
    resp.json::<Value>().await.expect("response must be valid JSON")
}

/// Drain `expected` audit entries from `receiver`, each with a 500 ms
/// timeout. Returns the entries in the order they were emitted. Panics
/// if `expected` entries don't arrive — the handler emits via
/// `try_send` synchronously before returning the HTTP response, so any
/// drop indicates a real bug, not a timing flake.
async fn drain_audit_entries(receiver: &mut mpsc::Receiver<AuditEntry>, expected: usize) -> Vec<AuditEntry> {
    let mut entries = Vec::with_capacity(expected);
    for i in 0..expected {
        match tokio::time::timeout(Duration::from_millis(500), receiver.recv()).await {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => panic!("audit-sink channel closed before {expected} entries (got {i})"),
            Err(_) => panic!("timeout waiting for audit entry #{i} of {expected}"),
        }
    }
    entries
}

/// Convenience: extract just the `event_type` discriminants from a
/// drained entry list.
fn event_types(entries: &[AuditEntry]) -> Vec<AuditEventType> {
    entries.iter().map(|e| e.event_type()).collect()
}

#[tokio::test]
async fn dispatch_tool_wasm_routes_filesystem_blocked() {
    let (env, mut audit_rx) = TopologyTestEnv::start_with_audit_sink()
        .await
        .expect("topology env must boot");
    let module_bytes = wat::parse_str(FS_PROBE_WAT).expect("fs_probe.wat must parse");
    env.tool_registry.register(
        "fs_probe",
        ToolKind::Wasm {
            module_bytes,
            config: SandboxConfig::default(),
        },
    );

    let resp = post_dispatch_tool(&env, json!({ "tool": "fs_probe", "args": {} })).await;

    let sandbox = resp
        .get("sandbox")
        .cloned()
        .expect("WASM-routed dispatch must populate `sandbox`");
    assert_eq!(
        sandbox["ok"],
        json!(false),
        "FilesystemBlocked must surface as ok=false"
    );
    assert_eq!(
        sandbox["error"],
        json!("FilesystemBlocked"),
        "error discriminant must round-trip"
    );
    assert!(
        sandbox["errno"].as_u64().filter(|n| *n != 0).is_some(),
        "errno must be a non-zero WASI errno, got {:?}",
        sandbox["errno"],
    );
    assert!(resp["resolved_args"].is_null());
    assert_eq!(resp["names_substituted"], json!([]));

    // Drain the audit sink — the handler must have emitted the
    // lifecycle sequence to the live sender during the HTTP request.
    let entries = drain_audit_entries(&mut audit_rx, 2).await;
    assert_eq!(
        event_types(&entries),
        vec![AuditEventType::SandboxStarted, AuditEventType::SandboxFilesystemBlocked],
        "audit sink must receive [SandboxStarted, SandboxFilesystemBlocked]",
    );
}

#[tokio::test]
async fn dispatch_tool_wasm_routes_cpu_timeout() {
    let (env, mut audit_rx) = TopologyTestEnv::start_with_audit_sink()
        .await
        .expect("topology env must boot");
    let module_bytes = wat::parse_str(RUNAWAY_WAT).expect("runaway.wat must parse");
    // Tight 1 000-unit fuel budget so the loop trips OutOfFuel within
    // microseconds. Memory + wall-clock budgets kept at the safe-by-default
    // values — fuel exhausts first on this pure-CPU runaway.
    env.tool_registry.register(
        "runaway",
        ToolKind::Wasm {
            module_bytes,
            config: SandboxConfig {
                limits: SandboxLimits {
                    fuel: 1_000,
                    ..Default::default()
                },
                ..Default::default()
            },
        },
    );

    let resp = post_dispatch_tool(&env, json!({ "tool": "runaway", "args": {} })).await;

    let sandbox = resp.get("sandbox").cloned().expect("`sandbox` must be present");
    assert_eq!(sandbox["ok"], json!(false));
    assert_eq!(sandbox["error"], json!("CpuTimeout"));

    let entries = drain_audit_entries(&mut audit_rx, 2).await;
    assert_eq!(
        event_types(&entries),
        vec![AuditEventType::SandboxStarted, AuditEventType::SandboxCpuTimeout],
    );
}

#[tokio::test]
async fn dispatch_tool_wasm_routes_memory_exhausted() {
    let (env, mut audit_rx) = TopologyTestEnv::start_with_audit_sink()
        .await
        .expect("topology env must boot");
    let module_bytes = wat::parse_str(MEM_BOMB_WAT).expect("mem_bomb.wat must parse");
    env.tool_registry.register(
        "mem_bomb",
        ToolKind::Wasm {
            module_bytes,
            config: SandboxConfig::default(),
        },
    );

    let resp = post_dispatch_tool(&env, json!({ "tool": "mem_bomb", "args": {} })).await;

    let sandbox = resp.get("sandbox").cloned().expect("`sandbox` must be present");
    assert_eq!(sandbox["ok"], json!(false));
    assert_eq!(sandbox["error"], json!("MemoryExhausted"));

    let entries = drain_audit_entries(&mut audit_rx, 2).await;
    assert_eq!(
        event_types(&entries),
        vec![AuditEventType::SandboxStarted, AuditEventType::SandboxOomKilled],
    );
}

#[tokio::test]
async fn dispatch_tool_unknown_tool_falls_through_to_secret_injection() {
    // Regression guard: when the registry has no entry for the tool name
    // (the default state of the `TopologyTestEnv` `tool_registry`), the
    // handler must fall through to the AAASM-1920 secret-injection
    // path — `sandbox` field absent / null, `resolved_args` populated,
    // a single `ToolDispatched` audit entry emitted.
    let (env, mut audit_rx) = TopologyTestEnv::start_with_audit_sink()
        .await
        .expect("topology env must boot");

    let resp = post_dispatch_tool(
        &env,
        json!({ "tool": "not_in_registry", "args": { "k": "literal-value-no-placeholder" } }),
    )
    .await;

    assert!(
        resp.get("sandbox").is_none_or(Value::is_null),
        "native-path response must not populate `sandbox`, got {:?}",
        resp.get("sandbox"),
    );
    assert_eq!(
        resp["resolved_args"],
        json!({ "k": "literal-value-no-placeholder" }),
        "no-placeholder args must round-trip verbatim",
    );
    assert_eq!(resp["names_substituted"], json!([]));

    // The native path emits exactly one `ToolDispatched` audit entry
    // (AAASM-1920) — confirms our fall-through preserves the existing
    // emission shape.
    let entries = drain_audit_entries(&mut audit_rx, 1).await;
    assert_eq!(
        event_types(&entries),
        vec![AuditEventType::ToolDispatched],
        "native fall-through must emit exactly one ToolDispatched entry",
    );
}
