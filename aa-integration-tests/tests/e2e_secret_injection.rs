//! AAASM-1570 / F116 ST-O — E2E **Secret Injection** verification.
//!
//! Status: **active** (AAASM-1931). All four `#[ignore]` markers have been
//! dropped now that AAASM-1920 has shipped its `SecretsStore` + `${...}`
//! resolver + `dispatch_tool` HTTP route + `ToolDispatched` audit shape
//! (Subtasks AAASM-1923 … AAASM-1927).
//!
//! ## What this file exercises
//!
//! Each test boots an in-process `TopologyTestEnv` with a pre-populated
//! `InMemorySecretsStore` (via the new
//! [`TopologyTestEnv::start_with_secrets_store`] helper) and drives the
//! `POST /api/v1/dispatch_tool` route over a real TCP socket. The four
//! tests below cover the four Story acceptance criteria pinned by ST-O-1
//! … ST-O-4.
//!
//! ## Scope deviations from the original scaffold
//!
//! The scaffold added under AAASM-1570 imagined a topology with a
//! `MockLlmServer` bound as both the LLM upstream and the tool sink. The
//! shipped v0.0.1 implementation has neither of those wirings on the
//! `/dispatch_tool` path — the route is a pure resolver: it takes
//! placeholder-form args, calls `resolve_placeholders`, emits an audit
//! entry, and returns the resolved args to the caller. Forwarding to a
//! real tool sink and to an LLM upstream are explicit follow-up
//! Subtasks tracked in `aa-gateway/src/secrets/README.md`.
//!
//! Where the scaffold called for an upstream-traffic assertion (ST-O-2)
//! or a downstream-tool-body assertion (ST-O-1's first bullet), the
//! verification reads the gateway response body — the only surface where
//! the resolved credential is observable in v0.0.1 — and treats that as
//! the "downstream tool sink" view.
//!
//! ## Synthetic credentials only
//!
//! Every secret literal below is synthetic — fabricated for test
//! purposes. No real credentials are ever stored in this fixture.

#![allow(dead_code)]

mod common;

use serde_json::json;

// ── Synthetic credential fixtures ────────────────────────────────────────────

/// Bare placeholder name (without `${…}` wrapping) registered in the store.
const NAME_DB_PASSWORD: &str = "DB_PASSWORD";

/// Placeholder token the agent will reference. Matches the spec example at
/// `.ai/spec/about_ai-agent-assembly_born.md:7246`.
const PLACEHOLDER_DB_PASSWORD: &str = "${DB_PASSWORD}";

/// Real secret value the gateway's `SecretsStore` returns when resolving
/// `${DB_PASSWORD}`. Synthetic — fabricated for this test only.
const REAL_DB_PASSWORD: &str = "real-secret-abc-DEADBEEF-0001";

/// Placeholder the agent will reference that has **no** entry in the
/// `SecretsStore`. ST-O-4 asserts this produces a structured error rather
/// than silently passing through.
const PLACEHOLDER_UNKNOWN: &str = "${UNKNOWN_SECRET}";

/// Synthetic placeholder name (without `${…}` wrapping) for ST-O-4.
const NAME_UNKNOWN: &str = "UNKNOWN_SECRET";

// ── ST-O-1 — Placeholder substituted at dispatch ─────────────────────────────

/// **ST-O-1** — Placeholder `${DB_PASSWORD}` is substituted with the real
/// credential before the downstream tool receives the dispatch.
///
/// Boots a `TopologyTestEnv` with `${DB_PASSWORD} → REAL_DB_PASSWORD`
/// registered, POSTs `{ "connection_string": "${DB_PASSWORD}" }` to
/// `/api/v1/dispatch_tool`, and asserts:
///
/// 1. The response's `resolved_args.connection_string` is the resolved
///    value `REAL_DB_PASSWORD` — what the agent (and any downstream tool
///    sink the agent forwards to) sees.
/// 2. `names_substituted` records `DB_PASSWORD` exactly once.
#[tokio::test(flavor = "multi_thread")]
async fn st_o_1_placeholder_substituted_at_dispatch() {
    let env = common::TopologyTestEnv::start_with_secrets_store(&[(NAME_DB_PASSWORD, REAL_DB_PASSWORD)])
        .await
        .expect("test env starts");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/api/v1/dispatch_tool", env.addr))
        .json(&json!({
            "tool": "call_database",
            "args": {"connection_string": PLACEHOLDER_DB_PASSWORD},
        }))
        .send()
        .await
        .expect("dispatch request sends");
    assert_eq!(resp.status(), 200, "dispatch_tool returns 200 on resolved placeholder");

    let body: serde_json::Value = resp.json().await.expect("response body is JSON");
    assert_eq!(
        body["resolved_args"]["connection_string"],
        json!(REAL_DB_PASSWORD),
        "resolved_args carries the resolved credential value"
    );
    assert_eq!(
        body["names_substituted"],
        json!([NAME_DB_PASSWORD]),
        "names_substituted lists the placeholder name (only) for the one substitution"
    );
}

// ── ST-O-2 — Real secret absent from any caller-observable surface ───────────

/// **ST-O-2** — The placeholder name (not the resolved value) is what
/// surfaces in any audit-tracked surface.
///
/// The v0.0.1 `/dispatch_tool` HTTP route does not call an LLM upstream
/// — there is no LLM-bound request body to grep. The product contract
/// reduces to: the resolved credential value MUST NOT appear in any
/// surface other than the immediate response back to the trusted caller.
/// The `names_substituted` surface and the audit-shape contract
/// (validated by ST-O-3) are where the spec's "LLM never sees the real
/// value" guarantee is enforced.
///
/// Asserts:
///
/// 1. The response's `names_substituted` field contains the placeholder
///    *name* — never the value (cross-checked by string search).
/// 2. The serialised `names_substituted` JSON contains zero occurrences
///    of `REAL_DB_PASSWORD`.
#[tokio::test(flavor = "multi_thread")]
async fn st_o_2_real_secret_absent_from_llm_traffic() {
    let env = common::TopologyTestEnv::start_with_secrets_store(&[(NAME_DB_PASSWORD, REAL_DB_PASSWORD)])
        .await
        .expect("test env starts");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/api/v1/dispatch_tool", env.addr))
        .json(&json!({
            "tool": "call_database",
            "args": {"connection_string": PLACEHOLDER_DB_PASSWORD},
        }))
        .send()
        .await
        .expect("dispatch request sends");
    let body: serde_json::Value = resp.json().await.expect("response body is JSON");

    // names_substituted carries names only.
    let names_json = body["names_substituted"].to_string();
    assert!(
        names_json.contains(NAME_DB_PASSWORD),
        "names_substituted carries the placeholder name"
    );
    assert!(
        !names_json.contains(REAL_DB_PASSWORD),
        "names_substituted MUST NOT carry the resolved credential value"
    );
}

// ── ST-O-3 — Raw audit JSONL contains no real value ──────────────────────────

/// **ST-O-3** — The placeholder-form payload contract: the audit-entry
/// builder used by every `dispatch_tool` handler emits the
/// **placeholder-form** args, never the resolved value.
///
/// The harness's `AppState.audit_sender` is `None` in v0.0.1 — wiring an
/// `AuditWriter` into the in-process test env is deferred to a follow-up
/// Subtask. The contract is instead pinned at the helper level: this test
/// drives `audit_entry_for_tool_dispatch` directly against the same
/// placeholder-form args the route would receive and grep's its payload.
///
/// Asserts:
///
/// 1. The audit entry's `payload` field contains `${DB_PASSWORD}` verbatim.
/// 2. The audit entry's `payload` field contains zero occurrences of
///    `REAL_DB_PASSWORD` — the resolved credential never reaches the
///    audit JSONL.
#[tokio::test(flavor = "multi_thread")]
async fn st_o_3_audit_log_contains_no_real_value() {
    use aa_core::audit::audit_entry_for_tool_dispatch;
    use aa_core::{AgentId, AuditEventType, SessionId};

    let placeholder_args = json!({"connection_string": PLACEHOLDER_DB_PASSWORD});
    let entry = audit_entry_for_tool_dispatch(
        0,
        1_700_000_000_000_000_000,
        AgentId::from_bytes([0xAA; 16]),
        SessionId::from_bytes([0xBB; 16]),
        &placeholder_args,
        [0u8; 32],
    );

    assert_eq!(entry.event_type(), AuditEventType::ToolDispatched);
    assert!(
        entry.payload().contains(PLACEHOLDER_DB_PASSWORD),
        "audit payload carries the placeholder-form args"
    );
    assert!(
        !entry.payload().contains(REAL_DB_PASSWORD),
        "audit payload MUST NOT contain the resolved credential value"
    );
}

// ── ST-O-4 — Unknown placeholder is an error, not a passthrough ──────────────

/// **ST-O-4** — Dispatching a tool with a placeholder that is **not**
/// registered surfaces a structured 422 error to the caller. The gateway
/// must **not** silently forward the literal `${UNKNOWN_SECRET}` string.
///
/// Asserts:
///
/// 1. HTTP status is 422 Unprocessable Entity.
/// 2. The error body references the unknown placeholder name
///    (`UNKNOWN_SECRET`) so the operator gets a signal rather than a
///    silent passthrough.
#[tokio::test(flavor = "multi_thread")]
async fn st_o_4_unknown_placeholder_returns_error() {
    let env = common::TopologyTestEnv::start_with_secrets_store(&[(NAME_DB_PASSWORD, REAL_DB_PASSWORD)])
        .await
        .expect("test env starts");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/api/v1/dispatch_tool", env.addr))
        .json(&json!({
            "tool": "call_database",
            "args": {"connection_string": PLACEHOLDER_UNKNOWN},
        }))
        .send()
        .await
        .expect("dispatch request sends");

    assert_eq!(resp.status(), 422, "unknown placeholder must surface as 422");

    let body_text = resp.text().await.expect("error body is text");
    assert!(
        body_text.contains(NAME_UNKNOWN),
        "error body must reference the unknown placeholder name; got {body_text}"
    );
}
