# AAASM-2594 — Verification: AuditPublisher startup wiring

Verifies parent Story **AAASM-2547** (wire `AuditPublisher` into `aa-runtime`
startup), implemented in **AAASM-2593** (PR #937).

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| Startup loads `[gateway.nats]` (`NatsConfig::from_toml_str`) and builds `NatsAuditSink` + `EventBuffer` + `AuditPublisher` when configured | ✅ Pass | `build_audit_publisher` (aa-runtime); config unit tests for `AA_NATS_CONFIG_PATH` / `AA_AUDIT_BUFFER_PATH` |
| Approval `AuditEntry` stream (`ApprovalQueue::with_audit`) drained into `AuditPublisher::publish` | ✅ Pass | e2e `governance_decision_produces_nats_audit_message` |
| `spawn_reconnect_flush_loop` started + aborted on shutdown; pending events flush on graceful shutdown | ✅ Pass | `run()` wiring (start → abort → `flush_pending`); buffer/replay covered by `aa-runtime` `audit_publisher_nats::buffers_during_outage_and_replays_all_on_reconnect` |
| NATS-less / unconfigured deployment fully functional (publisher disabled, no startup failure) | ✅ Pass | `build_audit_publisher_disabled_when_unconfigured_or_unreadable`; `nats_config_path` unset ⇒ `None` |
| e2e: a governance decision produces a message on `assembly.audit.<tenant>.<agent>` | ✅ Pass | e2e test (below) |

## How verified

| # | Method |
|---|--------|
| 1 | `cargo nextest run -p aa-runtime` — config parsing + `build_audit_publisher` disabled-when-unconfigured unit tests (256 passed) |
| 2 | `cargo nextest run -p aa-integration-tests --features audit-publisher --test audit_publisher_startup_verify` — Docker-backed e2e |

### e2e detail

`tests/audit_publisher_startup_verify.rs` brings up a real NATS container and
composes the exact pieces `runtime::run` wires together:
`ApprovalQueue::with_audit` → `mpsc::Receiver<AuditEntry>` drain task →
`AuditPublisher` (`NatsAuditSink` + `EventBuffer`). It then submits an approval
(a governance decision, which emits an `ApprovalRequested` `AuditEntry`) and
asserts a message arrives on `assembly.audit.<tenant>.<agent>` carrying the
governance action. **Result:** message received in < 1s; subject and payload
asserted. ✅

## Outcome

All acceptance criteria pass. The producer side of the Epic AAASM-2350 pipeline
(publisher → NATS → consumer → Postgres) is now wired end-to-end:
governance audit events flow from the runtime to NATS in production, and an
unconfigured deployment is unaffected.
