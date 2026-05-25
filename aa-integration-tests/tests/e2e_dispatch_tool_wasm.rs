//! AAASM-2033 / F116 ST-W data-path E2E — `POST /api/v1/dispatch_tool`
//! with a WASM-marked tool registered.
//!
//! Boots the `TopologyTestEnv` (in-process Axum server), registers a
//! `ToolKind::Wasm` entry in the shared `tool_registry` for each of the
//! three sandbox scenarios from AAASM-2020's WAT fixtures, drives the
//! HTTP route, and asserts the `DispatchToolResponse.sandbox` payload
//! shape.
//!
//! Three tests:
//!
//! * `dispatch_tool_wasm_routes_filesystem_blocked` — exercises the
//!   AAASM-2017 filesystem-isolation half end-to-end through the HTTP
//!   surface; asserts `sandbox.error == "FilesystemBlocked"`.
//! * `dispatch_tool_wasm_routes_cpu_timeout` — exercises the AAASM-2018
//!   CPU-timeout half; asserts `sandbox.error == "CpuTimeout"`.
//! * `dispatch_tool_wasm_routes_memory_exhausted` — exercises the
//!   AAASM-2018 memory-exhaustion half; asserts
//!   `sandbox.error == "MemoryExhausted"`.
//!
//! ## Scope note
//!
//! The AAASM-2033 acceptance criterion mentions "persistence to the
//! production audit sink" — the dispatch handler emits audit entries
//! via `state.audit_sender.try_send()` for every `audit_events` element
//! returned by `dispatch_wasm_tool`. The `TopologyTestEnv` test harness
//! constructs `AppState` with `audit_sender: None` (no on-disk JSONL
//! writer wired), so the emission is exercised but its persisted
//! readback is verified at two adjacent layers instead:
//!
//! * `aa_sandbox::wasm_dispatch` unit tests assert the dispatch helper
//!   returns the exact `[SandboxStarted, <outcome>]` `Vec`.
//! * `aa-api/src/routes/dispatch.rs` emits each entry via
//!   `audit_sender.try_send()` — code-reviewable, exercised here as a
//!   no-op when `audit_sender` is `None`.
//!
//! End-to-end JSONL persistence belongs to the binary that hosts
//! `aa-api` (boots the audit writer); follow-up scope.

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use aa_sandbox::policy::{SandboxConfig, SandboxLimits};
use aa_sandbox::registry::ToolKind;
use serde_json::{json, Value};

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

#[tokio::test]
async fn dispatch_tool_wasm_routes_filesystem_blocked() {
    let env = TopologyTestEnv::start().await.expect("topology env must boot");
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
    // Native-path fields are empty/null for WASM dispatches.
    assert!(
        resp["resolved_args"].is_null(),
        "resolved_args must be null on WASM path"
    );
    assert_eq!(
        resp["names_substituted"],
        json!([]),
        "names_substituted must be empty on WASM path",
    );
}

#[tokio::test]
async fn dispatch_tool_wasm_routes_cpu_timeout() {
    let env = TopologyTestEnv::start().await.expect("topology env must boot");
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
}

#[tokio::test]
async fn dispatch_tool_wasm_routes_memory_exhausted() {
    let env = TopologyTestEnv::start().await.expect("topology env must boot");
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
}

#[tokio::test]
async fn dispatch_tool_unknown_tool_falls_through_to_secret_injection() {
    // Regression guard: when the registry has no entry for the tool name
    // (the default state of the `TopologyTestEnv` `tool_registry`), the
    // handler must fall through to the AAASM-1920 secret-injection
    // path — `sandbox` field absent / null, `resolved_args` populated.
    let env = TopologyTestEnv::start().await.expect("topology env must boot");

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

    // Keep `env` alive until the test exits so the server task stays
    // running for the HTTP request above. (The `Arc<>` field on the
    // struct keeps the underlying server alive even after `env` is
    // dropped, but holding the binding explicit is clearer.)
    let _keep_alive: Arc<()> = Arc::new(());
    drop(_keep_alive);
    drop(env);
}
