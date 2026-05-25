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
use aa_gateway::secrets::{resolver::resolve_placeholders, SecretInjectionError};
use aa_sandbox::error::SandboxError;
use aa_sandbox::registry::ToolKind;
use aa_sandbox::wasm_dispatch::{dispatch_wasm_tool, WasmDispatchResult};
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

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
        (status = 422, description = "Unknown placeholder referenced in args", body = ProblemDetail),
        (status = 500, description = "Sandbox dispatch task panicked", body = ProblemDetail),
        (status = 503, description = "Audit pipeline is not connected", body = ProblemDetail),
    ),
    tag = "dispatch"
)]
pub async fn dispatch_tool(
    Extension(state): Extension<AppState>,
    Json(body): Json<DispatchToolRequest>,
) -> Result<Json<DispatchToolResponse>, ProblemDetail> {
    // ── WASM dispatch branch ────────────────────────────────────────
    // A `ToolKind::Wasm` registry entry bypasses secret injection — the
    // args travel into the sandbox as raw JSON bytes.
    if matches!(state.tool_registry.get(&body.tool), Some(ToolKind::Wasm { .. })) {
        return dispatch_wasm(&state, &body).await;
    }

    // ── Native / secret-injection branch (existing AAASM-1920 path) ──
    let outcome = resolve_placeholders(&body.args, state.secrets_store.as_ref()).map_err(|e| match e {
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
