//! AAASM-1570 / F116 ST-O — E2E **Secret Injection** scaffold.
//!
//! ## What this file is — and is NOT
//!
//! Secret Injection is the capability described at
//! `.ai/spec/about_ai-agent-assembly_born.md:7246`:
//!
//! > "Secret value 不暴露給 LLM 這個點非常重要，這其實是一個獨立的核心功能叫做
//! > **Secret Injection** ——agent 只拿到 placeholder，Assembly 在 tool dispatch
//! > 時才注入真實 credential，LLM 的 context window 裡永遠看不到真實 secret。"
//!
//! It is **distinct** from Secret Detection (ST-I / ST-N, already shipped):
//!
//! | Capability | Trigger | What Assembly does |
//! |---|---|---|
//! | Secret Detection (ST-I / ST-N) | Agent *accidentally* leaks a real secret | Redact the value in flight |
//! | Secret Injection (this file)   | Agent *intentionally* holds a placeholder `${NAME}` | Substitute the real value at tool-dispatch time |
//!
//! ## Why all tests are `#[ignore]`
//!
//! Secret Injection has **no implementation in the workspace today** — no
//! `SecretsStore`, no `${...}` resolver, no `dispatch_tool` route. The four
//! tests below pin the spec contract (ST-O-1…4 acceptance criteria from
//! AAASM-1570) so that they become runnable assertions the moment the feature
//! lands. They are tracked under **AAASM-1920** ("Implement Secret Injection
//! — gateway secrets store + dispatch-time substitution + audit shape"),
//! which is linked as a *Blocks* relationship on AAASM-1570.
//!
//! ## Test status
//!
//! | # | Name | Status |
//! |---|------|--------|
//! | 1 | `st_o_1_placeholder_substituted_at_dispatch` | `#[ignore]` — blocked on AAASM-1920 |
//! | 2 | `st_o_2_real_secret_absent_from_llm_traffic` | `#[ignore]` — blocked on AAASM-1920 |
//! | 3 | `st_o_3_audit_log_contains_no_real_value`    | `#[ignore]` — blocked on AAASM-1920 |
//! | 4 | `st_o_4_unknown_placeholder_returns_error`   | `#[ignore]` — blocked on AAASM-1920 |
//!
//! ## How to un-ignore
//!
//! When AAASM-1920 ships its `SecretsStore` + `dispatch_tool` + audit shape:
//!
//! 1. Wire `TopologyTestEnv::start_with_secrets_store([...])` (or equivalent
//!    helper added by AAASM-1920) and a `MockLlmServer` for upstream capture.
//! 2. Replace each `todo!(...)` with the real assertions described in the
//!    function-body comments.
//! 3. Drop the `#[ignore]` attribute on each test that the feature satisfies.
//! 4. Verify under `cargo nextest run -p aa-integration-tests --test
//!    e2e_secret_injection`.
//!
//! ## Synthetic credentials only
//!
//! Every secret literal below is synthetic — fabricated for test purposes.
//! No real credentials are ever stored in this fixture.

#![allow(dead_code)]

mod common;

// ── Synthetic credential fixtures ────────────────────────────────────────────

/// Placeholder name the agent will reference. Matches the spec example at
/// `.ai/spec/about_ai-agent-assembly_born.md:7246`.
const PLACEHOLDER_DB_PASSWORD: &str = "${DB_PASSWORD}";

/// Real secret value the gateway's `SecretsStore` will return when resolving
/// `${DB_PASSWORD}`. Synthetic — fabricated for this test only.
const REAL_DB_PASSWORD: &str = "real-secret-abc-DEADBEEF-0001";

/// Placeholder the agent will reference that has **no** entry in the
/// `SecretsStore`. ST-O-4 asserts this produces a structured error rather
/// than silently passing through.
const PLACEHOLDER_UNKNOWN: &str = "${UNKNOWN_SECRET}";

// ── ST-O-1 — Placeholder substituted at dispatch ─────────────────────────────

/// **ST-O-1** — Placeholder `${DB_PASSWORD}` is substituted with the real
/// credential before the downstream tool receives the dispatch.
///
/// Setup (once AAASM-1920 ships):
///   * Start `TopologyTestEnv` with a `SecretsStore` mapping
///     `${DB_PASSWORD}` → `REAL_DB_PASSWORD`.
///   * Register agent `secret-injection-test-agent`.
///   * Stand up a `MockLlmServer` (AAASM-1547) as the tool sink so we can
///     observe what the downstream tool actually received.
///
/// Action:
///   * Agent dispatches `call_database` with
///     `{ "connection_string": "${DB_PASSWORD}" }` via the new
///     `dispatch_tool` route on `aa-api` / `aa-gateway`.
///
/// Assertions:
///   1. The downstream tool sees `REAL_DB_PASSWORD` substituted in for
///      `${DB_PASSWORD}` — `mock.last_body()` contains `REAL_DB_PASSWORD`.
///   2. The audit entry for this dispatch records the **placeholder name**
///      (`${DB_PASSWORD}`), not the resolved value.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "blocked on AAASM-1920: Secret Injection feature (SecretsStore + dispatch_tool + audit shape) not yet implemented"]
async fn st_o_1_placeholder_substituted_at_dispatch() {
    todo!(
        "Wire TopologyTestEnv::start_with_secrets_store + dispatch_tool + AuditWriter once AAASM-1920 lands. \
         Assertions: (1) downstream tool body contains REAL_DB_PASSWORD; \
         (2) audit entry args field contains PLACEHOLDER_DB_PASSWORD, not REAL_DB_PASSWORD."
    );
}

// ── ST-O-2 — Real secret absent from any LLM-facing traffic ──────────────────

/// **ST-O-2** — Across every LLM-bound request the agent makes during the
/// scenario, the real secret value `REAL_DB_PASSWORD` appears **zero** times.
/// The LLM only ever sees the placeholder `${DB_PASSWORD}` or a redacted form
/// — never the resolved credential.
///
/// This is the central product guarantee of Secret Injection (`.ai/spec/
/// about_ai-agent-assembly_born.md:7246`): the LLM's context window is
/// provably free of the real credential, even though tool dispatches succeed
/// against the real value.
///
/// Setup (once AAASM-1920 ships):
///   * Same `TopologyTestEnv` + `SecretsStore` as ST-O-1.
///   * A `MockLlmServer` (AAASM-1547, Done) bound as the LLM upstream so
///     every LLM-bound request body is captured for inspection.
///
/// Action:
///   * Agent runs a short scenario: a prompt round-trip to the LLM, then a
///     `dispatch_tool` call that references `${DB_PASSWORD}`.
///
/// Assertions:
///   1. `mock_llm.history()` is non-empty (the LLM was actually exercised).
///   2. For every `RecordedRequest` in `mock_llm.history()`, the request body
///      contains zero occurrences of `REAL_DB_PASSWORD`.
///   3. At least one request body contains either `PLACEHOLDER_DB_PASSWORD`
///      verbatim or a `[REDACTED:*]` marker — confirming the placeholder
///      form (or its redaction) is what the LLM saw.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "blocked on AAASM-1920: Secret Injection feature (SecretsStore + dispatch_tool + audit shape) not yet implemented"]
async fn st_o_2_real_secret_absent_from_llm_traffic() {
    todo!(
        "Wire TopologyTestEnv + SecretsStore + MockLlmServer once AAASM-1920 lands. \
         Assertions: for every recorded LLM request body, REAL_DB_PASSWORD count == 0; \
         at least one body carries PLACEHOLDER_DB_PASSWORD or a [REDACTED:*] marker."
    );
}
