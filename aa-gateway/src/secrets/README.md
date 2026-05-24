# Secret Injection — threat model

This document describes the **Secret Injection** capability shipped under
[AAASM-1920](https://lightning-dust-mite.atlassian.net/browse/AAASM-1920)
and tracks what is *not* covered in v0.0.1.

## Why this is not Secret Detection

Agent Assembly ships two distinct credential guards. They look superficially
similar but serve different threat models and the operator picks *both*, not
one-or-the-other.

| Capability        | Trigger                                                | Assembly's response                                                    |
| ----------------- | ------------------------------------------------------ | ---------------------------------------------------------------------- |
| Secret *Detection*<br/>(AAASM-1521 / 1549, shipped)   | Agent **accidentally** includes a real secret value in tool args, prompt, or output. | Detect the secret in flight and redact it. The leak is logged. |
| Secret *Injection*<br/>(AAASM-1920, this module)      | Agent **intentionally** holds a placeholder `${NAME}`; never sees the real value.    | Substitute the placeholder with the real credential at tool-dispatch time. |

Detection is a *save-them-from-themselves* guard. Injection is a positive
product feature: it lets agents reference credentials by name and *guarantees*
the LLM never sees the resolved value.

## Guarantees

For every `dispatch_tool` call where the args carry a `${NAME}` token and the
store has a registered entry for `NAME`:

1. The **LLM** never observes the resolved credential. Agent code holds the
   placeholder; Assembly substitutes the value after the args have left the
   model.
2. The **on-disk audit JSONL** never contains the resolved credential. The
   `AuditEntry.payload` field for an `AuditEventType::ToolDispatched` entry
   carries the **placeholder-form** args
   (`{"connection_string": "${DB_PASSWORD}"}`) — never the resolved form.
3. The **`names_substituted`** field in the dispatch response, and the
   placeholder-form payload in audit, both record names only — the resolved
   value never appears in either surface.

These three points are pinned by `aa-integration-tests/tests/e2e_secret_injection.rs`
(ST-O-1 … ST-O-4 under [AAASM-1570](https://lightning-dust-mite.atlassian.net/browse/AAASM-1570)).

## Data flow

```text
                  ┌─────────────────────────┐
                  │      Agent code         │
                  │   ctx.dispatch_tool(    │
                  │     "call_database",    │
                  │     { "conn":           │
                  │        "${DB_PASSWORD}"})│
                  └────────────┬────────────┘
                               │ placeholder-form args
                               ▼
        ┌──────────────────────────────────────────┐
        │   aa-api  /api/v1/dispatch_tool handler  │
        │                                          │
        │   1. resolve_placeholders(args, store)   │
        │   2. emit AuditEntry { event_type:       │
        │        ToolDispatched, payload:          │
        │        <placeholder-form JSON> }         │
        │   3. forward resolved_args to tool sink  │
        └────────────┬────────────────┬────────────┘
                     │                │
       resolved form │                │ placeholder form
                     ▼                ▼
              ┌────────────┐    ┌────────────────┐
              │ Tool sink  │    │ Audit JSONL    │
              │ (real DB)  │    │ (read-only,    │
              │            │    │ append-only)   │
              └────────────┘    └────────────────┘
```

The split between the two destinations is the entire point: the tool sink
needs the resolved value to do its job; the audit log must never see it.

## Audit-shape contract

For every `AuditEventType::ToolDispatched` entry the `payload` field is
`serde_json::to_string(&placeholder_form_args)`. The helper
`aa_core::audit::audit_entry_for_tool_dispatch` is the single chokepoint that
constructs these entries — both the HTTP handler (`aa-api`) and the future
gRPC handler (`aa-gateway`) call into it.

Verification: `tool_dispatch_helper_emits_placeholder_form_payload` in
`aa-core/src/audit.rs` and the E2E `st_o_3_audit_log_contains_no_real_value`
grep over the on-disk JSONL files.

## Unknown placeholder = error, never passthrough

If a `${NAME}` token references a name that has no entry in the
`SecretsStore`, `resolve_placeholders` short-circuits with
`SecretInjectionError::UnknownPlaceholder { name }`. Handlers map this to:

* HTTP: `422 Unprocessable Entity` with a `ProblemDetail` referencing the
  placeholder name.
* gRPC: `tonic::Status::failed_precondition` referencing the placeholder
  name (AAASM-1927 wires this).

The resolver **never** silently passes the literal `${UNKNOWN}` token through
to the tool sink. A typo like `${DB_PASWORD}` would otherwise be forwarded as
an arbitrary string and trigger downstream parser errors with no signal that
the secret never resolved.

## What is out of scope for v0.0.1

These are tracked in the Story comment thread and will land as follow-ups:

* **Persistence.** The in-memory store loses state across gateway restarts.
  A persisted backend (sqlite / k/v store) is a follow-up Subtask.
* **Per-agent / per-team scoping.** v0.0.1 uses a single global namespace;
  any agent in the gateway can resolve any registered placeholder. Tenant
  isolation is a follow-up.
* **Rotation.** No graceful re-key path. Operators today delete + re-register
  the placeholder; v0.0.1 makes no guarantee about in-flight dispatches when
  that happens.
* **Audit of register / delete calls.** v0.0.1 audits *dispatch*, not the
  store-management mutations. Adding `SecretRegistered` /
  `SecretDeleted` audit events is a follow-up.

If you need any of the above before they ship, raise a Subtask under
AAASM-1920 (or its successor follow-up Epic) — these are explicit non-goals,
not unknowns.
