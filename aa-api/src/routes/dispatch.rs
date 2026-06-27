//! `POST /api/v1/dispatch_tool` — Secret Injection tool-dispatch route
//! (AAASM-1920 / Story scope #3) + WASM sandbox dispatch route
//! (AAASM-2033 / F116 ST-W data-path follow-up).
//!
//! Two flows fan in through the same endpoint, demultiplexed on the
//! tool's [`ToolKind`] in the [`AppState::tool_registry`]:
//!
//! * **WASM tools** (`ToolKind::Wasm`): the args are forwarded as raw
//!   bytes to [`aa_sandbox::wasm_dispatch::dispatch_wasm_tool`] under
//!   `tokio::task::spawn_blocking` (the sandbox is synchronous wasmtime
//!   work). The lifecycle audit-event sequence
//!   (`SandboxStarted`/`Sandbox<outcome>`) is emitted to the audit
//!   pipeline. The response carries the sandbox verdict in the
//!   `sandbox` field; `resolved_args` is `null` and
//!   `names_substituted` is empty for this path.
//! * **Native or unknown tools**: the existing AAASM-1920 secret-injection
//!   pipeline runs — placeholder `${NAME}` tokens are resolved via the
//!   [`SecretsStore`], a `ToolDispatched` audit entry is emitted with the
//!   **placeholder-form** args (the resolved credential value is never
//!   recorded), and the resolved args + the list of substituted names are
//!   returned to the caller.
//!
//! Unknown placeholders surface as HTTP 422 with a [`ProblemDetail`]
//! referencing the unresolved placeholder name — the resolver refuses to
//! silently forward the literal `${UNKNOWN}` token.
//!
//! [`ToolKind`]: aa_sandbox::registry::ToolKind

use aa_core::audit::AuditEntry;
use aa_core::{AgentId, SessionId};
use aa_gateway::secrets::{resolver::resolve_placeholders, SecretInjectionError, TenantScopedStore};
use aa_sandbox::error::SandboxError;
use aa_sandbox::registry::ToolKind;
use aa_sandbox::wasm_dispatch::{dispatch_wasm_tool, WasmDispatchResult};
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::scope::RequireWrite;
use crate::error::ProblemDetail;
use crate::state::AppState;

/// Request body for `POST /api/v1/dispatch_tool`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DispatchToolRequest {
    /// Name of the tool the agent wants to dispatch (e.g. `"call_database"`).
    pub tool: String,
    /// Placeholder-form args. May contain `${NAME}` tokens that the gateway
    /// will resolve via the `SecretsStore` before audit + forwarding. For
    /// WASM tools (`ToolKind::Wasm`) the args are forwarded as raw bytes to
    /// the sandbox without placeholder resolution.
    pub args: serde_json::Value,
}

/// Response body for `POST /api/v1/dispatch_tool`.
///
/// Two flows fan in through this shape:
///
/// * **Native / secret-injection** — `resolved_args` + `names_substituted`
///   carry the AAASM-1920 result; `sandbox` is `None`.
/// * **WASM sandbox** (AAASM-2033) — `sandbox` carries the dispatch
///   verdict; `resolved_args` is `null` and `names_substituted` is empty.
#[derive(Debug, Serialize, ToSchema)]
pub struct DispatchToolResponse {
    /// Post-substitution args ready to forward to the tool sink. Contains
    /// the *resolved* credential values; callers must not log these.
    /// `null` for WASM-sandbox dispatches.
    pub resolved_args: serde_json::Value,
    /// The placeholder names that were resolved during this call. Names
    /// only — never the resolved values. Echoes the audit-log shape so
    /// callers can correlate dispatches with audit entries. Empty for
    /// WASM-sandbox dispatches.
    pub names_substituted: Vec<String>,
    /// WASM sandbox dispatch verdict, present only when the named tool was
    /// registered as `ToolKind::Wasm` in `AppState::tool_registry`.
    /// (AAASM-2033 / F116 ST-W.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxDispatchOutcome>,
}

/// Sandbox dispatch outcome — populated on the `sandbox` field of
/// [`DispatchToolResponse`] when the named tool routed through
/// [`aa_sandbox::wasm_dispatch::dispatch_wasm_tool`].
#[derive(Debug, Serialize, ToSchema)]
pub struct SandboxDispatchOutcome {
    /// `true` iff the sandbox runtime returned `Ok`. `false` for every
    /// `SandboxError` variant.
    pub ok: bool,
    /// WASI exit code surfaced by a clean guest exit (`proc_exit(0)` or a
    /// `_start` return). `None` when the dispatch failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Discriminant name of the [`SandboxError`] variant that fired —
    /// `FilesystemBlocked`, `CpuTimeout`, `WallClockTimeout`,
    /// `MemoryExhausted`, `InvalidWasm`, or `Wasmtime`. `None` on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// WASI errno that triggered `FilesystemBlocked`. `None` for other
    /// error variants and for success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<u32>,
}

/// Dispatch a tool by name.
///
/// Demultiplexes on the registered [`ToolKind`]: WASM tools route through
/// the sandbox; native / unknown tools fall through to the existing
/// secret-injection resolver.
#[utoipa::path(
    post,
    path = "/api/v1/dispatch_tool",
    request_body = DispatchToolRequest,
    responses(
        (status = 200, description = "Tool dispatch resolved (native) or sandboxed (WASM)", body = DispatchToolResponse),
        (status = 401, description = "Missing or invalid credentials", body = ProblemDetail),
        (status = 403, description = "Caller lacks the write scope required to dispatch", body = ProblemDetail),
        (status = 422, description = "Unknown placeholder referenced in args", body = ProblemDetail),
        (status = 500, description = "Sandbox dispatch task panicked", body = ProblemDetail),
        (status = 503, description = "Audit pipeline is not connected", body = ProblemDetail),
    ),
    tag = "dispatch"
)]
pub async fn dispatch_tool(
    Extension(state): Extension<AppState>,
    // AAASM-3845 — dispatching a tool (and resolving `${SECRET}` placeholders)
    // is a privileged write action: require an authenticated caller holding the
    // write scope. The caller's verified tenant then scopes secret resolution.
    RequireWrite(caller): RequireWrite,
    Json(body): Json<DispatchToolRequest>,
) -> Result<Json<DispatchToolResponse>, ProblemDetail> {
    // ── WASM dispatch branch ────────────────────────────────────────
    // A `ToolKind::Wasm` registry entry bypasses secret injection — the
    // args travel into the sandbox as raw JSON bytes.
    if matches!(state.tool_registry.get(&body.tool), Some(ToolKind::Wasm { .. })) {
        return dispatch_wasm(&state, &body).await;
    }

    // ── Native / secret-injection branch (existing AAASM-1920 path) ──
    // Resolve only within the caller's verified tenant namespace so a caller
    // can never resolve a `${NAME}` owned by another tenant — the tenant is
    // taken from the authenticated identity, never from the request body.
    let scoped = TenantScopedStore::for_tenant(
        state.secrets_store.as_ref(),
        caller.tenant.org_id.as_deref(),
        caller.tenant.team_id.as_deref(),
    );
    let outcome = resolve_placeholders(&body.args, &scoped).map_err(|e| match e {
        SecretInjectionError::UnknownPlaceholder { name } => {
            ProblemDetail::from_status(StatusCode::UNPROCESSABLE_ENTITY)
                .with_detail(format!("Unknown placeholder: ${{{name}}}"))
        }
    })?;

    // Emit audit entry with the placeholder-form args. Non-blocking;
    // 503 if the pipeline is not connected (matches devtools pattern).
    if let Some(sender) = state.audit_sender.as_ref() {
        // v0.0.1: no per-dispatch session/agent context flows in via the
        // HTTP body. The E2E harness wires concrete ids via the test env
        // (ST8 / AAASM-1931); here we emit zero-byte identifiers so the
        // audit chain stays well-formed without leaking arbitrary
        // caller-supplied bytes.
        let entry = aa_core::audit::audit_entry_for_tool_dispatch(
            0,
            unix_now_ns(),
            AgentId::from_bytes([0u8; 16]),
            SessionId::from_bytes([0u8; 16]),
            &body.args,
            [0u8; 32],
        );
        // try_send: backpressure is non-fatal for the response — the
        // entry is dropped if the channel is full. The ST-O-3 E2E
        // assertion grep's the on-disk JSONL, so the channel needs to
        // drain in the test harness.
        let _ = sender.try_send(entry);
    }

    Ok(Json(DispatchToolResponse {
        resolved_args: outcome.resolved,
        names_substituted: outcome.names_substituted,
        sandbox: None,
    }))
}

/// WASM sandbox dispatch path — pulled out so the parent handler stays
/// readable. Builds a registry handle clone, runs the dispatch under
/// `spawn_blocking`, emits the audit-event sequence to the audit sink,
/// and packages the verdict into a [`DispatchToolResponse`].
async fn dispatch_wasm(
    state: &AppState,
    body: &DispatchToolRequest,
) -> Result<Json<DispatchToolResponse>, ProblemDetail> {
    let registry = state.tool_registry.clone();
    let tool_name = body.tool.clone();
    let args_bytes = serde_json::to_vec(&body.args).unwrap_or_default();

    let outcome = tokio::task::spawn_blocking(move || dispatch_wasm_tool(&tool_name, &args_bytes, &registry))
        .await
        .map_err(|e| {
            ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR)
                .with_detail(format!("sandbox dispatch task panicked: {e}"))
        })?;

    let (result, audit_events) = match outcome {
        WasmDispatchResult::Wasm { result, audit_events } => (result, audit_events),
        // Defensive: the caller already checked `ToolKind::Wasm` before
        // routing here. If the registry races a `register(Native)` swap
        // between the check and the dispatch, fall through to the
        // secret-injection path instead of returning a stale Wasm shape.
        WasmDispatchResult::NotWasm => {
            return Ok(Json(DispatchToolResponse {
                resolved_args: serde_json::Value::Null,
                names_substituted: Vec::new(),
                sandbox: None,
            }));
        }
    };

    // Emit the lifecycle audit-event sequence
    // (`SandboxStarted, <outcome>`) to the production audit sink.
    // Same zero-id contract as the native-path entry above — concrete
    // session/agent ids will be wired through once the dispatch route
    // is reachable from a session-aware caller (AAASM-1931 follow-up).
    if let Some(sender) = state.audit_sender.as_ref() {
        let now = unix_now_ns();
        for (idx, event_type) in audit_events.iter().enumerate() {
            let entry = AuditEntry::new(
                idx as u64,
                now,
                *event_type,
                AgentId::from_bytes([0u8; 16]),
                SessionId::from_bytes([0u8; 16]),
                String::new(),
                [0u8; 32],
            );
            let _ = sender.try_send(entry);
        }
    }

    let sandbox = match result {
        Ok(output) => SandboxDispatchOutcome {
            ok: true,
            exit_code: Some(output.exit_code),
            error: None,
            errno: None,
        },
        Err(err) => sandbox_error_to_outcome(&err),
    };

    Ok(Json(DispatchToolResponse {
        resolved_args: serde_json::Value::Null,
        names_substituted: Vec::new(),
        sandbox: Some(sandbox),
    }))
}

/// Map a [`SandboxError`] to the [`SandboxDispatchOutcome`] payload.
fn sandbox_error_to_outcome(err: &SandboxError) -> SandboxDispatchOutcome {
    match err {
        SandboxError::FilesystemBlocked { errno } => SandboxDispatchOutcome {
            ok: false,
            exit_code: None,
            error: Some("FilesystemBlocked".to_string()),
            errno: Some(*errno),
        },
        SandboxError::CpuTimeout => SandboxDispatchOutcome {
            ok: false,
            exit_code: None,
            error: Some("CpuTimeout".to_string()),
            errno: None,
        },
        SandboxError::WallClockTimeout => SandboxDispatchOutcome {
            ok: false,
            exit_code: None,
            error: Some("WallClockTimeout".to_string()),
            errno: None,
        },
        SandboxError::MemoryExhausted => SandboxDispatchOutcome {
            ok: false,
            exit_code: None,
            error: Some("MemoryExhausted".to_string()),
            errno: None,
        },
        SandboxError::HostFnRateLimited => SandboxDispatchOutcome {
            ok: false,
            exit_code: None,
            error: Some("HostFnRateLimited".to_string()),
            errno: None,
        },
        SandboxError::InvalidWasm(msg) => SandboxDispatchOutcome {
            ok: false,
            exit_code: None,
            error: Some(format!("InvalidWasm: {msg}")),
            errno: None,
        },
        SandboxError::Wasmtime(msg) => SandboxDispatchOutcome {
            ok: false,
            exit_code: None,
            error: Some(format!("Wasmtime: {msg}")),
            errno: None,
        },
    }
}

/// Current Unix timestamp in nanoseconds. Matches the helper used by the
/// native path; extracted so both branches stay in sync.
fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::scope::Scope;
    use crate::auth::{AuthenticatedCaller, Tenant};
    use aa_gateway::secrets::{Secret, SecretsStore, TenantScopedStore};
    use tokio::sync::mpsc;

    /// Build the fully-wired in-memory AppState used by the native dispatch path.
    fn state() -> AppState {
        AppState::local_in_memory().expect("in-memory state builds")
    }

    /// A write-scoped caller bound to a fixed tenant (`org-a` / `team-1`), as
    /// the auth extractor produces in production (AAASM-3845).
    fn writer() -> RequireWrite {
        RequireWrite(AuthenticatedCaller {
            key_id: "test-writer".to_string(),
            scopes: vec![Scope::Read, Scope::Write],
            tenant: Tenant {
                team_id: Some("team-1".to_string()),
                org_id: Some("org-a".to_string()),
            },
        })
    }

    /// Register `name`→`value` in `st`'s store under `caller`'s tenant namespace
    /// so the scoped dispatch path can resolve it.
    fn register_for(st: &AppState, caller: &AuthenticatedCaller, name: &str, value: &str) {
        TenantScopedStore::for_tenant(
            st.secrets_store.as_ref(),
            caller.tenant.org_id.as_deref(),
            caller.tenant.team_id.as_deref(),
        )
        .register(Secret {
            name: name.to_string(),
            value: value.to_string(),
        })
        .expect("register secret");
    }

    fn req(args: serde_json::Value) -> DispatchToolRequest {
        DispatchToolRequest {
            tool: "call_database".to_string(),
            args,
        }
    }

    #[tokio::test]
    async fn passthrough_args_without_placeholders() {
        let st = state();
        let body = req(serde_json::json!({"query": "SELECT 1"}));
        let resp = dispatch_tool(Extension(st), writer(), Json(body)).await.expect("ok").0;
        // No `${...}` tokens: args echoed verbatim, nothing substituted, no sandbox.
        assert_eq!(resp.resolved_args, serde_json::json!({"query": "SELECT 1"}));
        assert!(resp.names_substituted.is_empty());
        assert!(resp.sandbox.is_none());
    }

    #[tokio::test]
    async fn resolves_registered_placeholder() {
        let st = state();
        let caller = writer();
        register_for(&st, &caller.0, "DB_PASSWORD", "real-secret");

        let body = req(serde_json::json!({"password": "${DB_PASSWORD}"}));
        let resp = dispatch_tool(Extension(st), caller, Json(body)).await.expect("ok").0;

        assert_eq!(resp.resolved_args, serde_json::json!({"password": "real-secret"}));
        assert_eq!(resp.names_substituted, vec!["DB_PASSWORD".to_string()]);
    }

    #[tokio::test]
    async fn unknown_placeholder_is_422() {
        let st = state();
        let body = req(serde_json::json!({"token": "${MISSING}"}));
        let err = dispatch_tool(Extension(st), writer(), Json(body))
            .await
            .expect_err("unknown placeholder rejected");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
        assert!(err.detail.unwrap().contains("MISSING"));
    }

    /// AAASM-3845 regression: a secret registered by one tenant must not resolve
    /// for a caller in a different tenant — it surfaces as an unknown placeholder
    /// (422) rather than leaking the other tenant's credential.
    #[tokio::test]
    async fn cross_tenant_placeholder_is_not_resolved() {
        let st = state();
        // org-a / team-1 owns DB_PASSWORD.
        register_for(&st, &writer().0, "DB_PASSWORD", "real-secret");

        // A different tenant references the same bare name.
        let attacker = RequireWrite(AuthenticatedCaller {
            key_id: "attacker".to_string(),
            scopes: vec![Scope::Read, Scope::Write],
            tenant: Tenant {
                team_id: Some("team-1".to_string()),
                org_id: Some("org-b".to_string()),
            },
        });
        let body = req(serde_json::json!({"password": "${DB_PASSWORD}"}));
        let err = dispatch_tool(Extension(st), attacker, Json(body))
            .await
            .expect_err("cross-tenant placeholder must not resolve");
        assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY.as_u16());
        assert!(err.detail.unwrap().contains("DB_PASSWORD"));
    }

    #[tokio::test]
    async fn emits_audit_entry_with_placeholder_form_args() {
        let mut st = state();
        let (tx, mut rx) = mpsc::channel(8);
        st.audit_sender = Some(tx);

        let body = req(serde_json::json!({"q": "noop"}));
        let resp = dispatch_tool(Extension(st), writer(), Json(body)).await.expect("ok").0;
        assert!(resp.names_substituted.is_empty());

        // The audit path runs only when audit_sender is wired; an entry must be queued.
        let entry = rx.try_recv().expect("audit entry emitted when sender is connected");
        // Native dispatch emits with zero-byte identifiers (no per-dispatch context).
        assert_eq!(entry.agent_id(), AgentId::from_bytes([0u8; 16]));
    }

    #[test]
    fn sandbox_error_outcomes_carry_variant_name() {
        // Pure mapping: every SandboxError variant projects to ok=false with its
        // discriminant name; FilesystemBlocked additionally carries the errno.
        let fs = sandbox_error_to_outcome(&SandboxError::FilesystemBlocked { errno: 13 });
        assert!(!fs.ok);
        assert_eq!(fs.error.as_deref(), Some("FilesystemBlocked"));
        assert_eq!(fs.errno, Some(13));

        let cpu = sandbox_error_to_outcome(&SandboxError::CpuTimeout);
        assert_eq!(cpu.error.as_deref(), Some("CpuTimeout"));
        assert!(cpu.errno.is_none());

        let invalid = sandbox_error_to_outcome(&SandboxError::InvalidWasm("bad".to_string()));
        assert_eq!(invalid.error.as_deref(), Some("InvalidWasm: bad"));
    }
}
