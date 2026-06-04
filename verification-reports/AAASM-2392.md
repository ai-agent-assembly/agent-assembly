# AAASM-2392 — AuditPublisher + SQLite-buffer fallback acceptance verification

**Story:** AAASM-2387 — *As an Assembly runtime, I want to publish audit events to NATS so the agent critical path doesn't wait on the gateway*
**Epic:** AAASM-2350 — *Async event production + Gateway NATS consumer (Phase 1)*
**Implementation:** AAASM-2391 (PR #902)
**Verified against:** `aa-runtime` @ branch `v0.0.1/AAASM-2392/test/verify_audit_publisher` (stacked on the AAASM-2391 branch)

## Scope note

The Story description names crate `aa-assembly`; no such crate exists in the
workspace. The Assembly runtime is **`aa-runtime`**, so the publisher lives at
`aa-runtime/src/audit_publisher/` and is verified with `-p aa-runtime`. The
ticket's `aasm metrics` check is covered by the metric-snapshot unit test.

## Acceptance criteria

| # | Criterion (AAASM-2387 / 2392) | Status | Evidence |
|---|---|---|---|
| 1 | `AuditPublisher` wraps the `async-nats` client; subject `assembly.audit.<tenant>.<agent>` | ✅ | `NatsAuditSink` wraps `async_nats::Client`; `subject::subject_for` builds the subject. Unit tests `audit_publisher::subject::tests::*` (default tenant + agent UUID, org priority + sanitization, team fallback). Live subjects observed by the integration test's `assembly.audit.>` subscriber. |
| 2 | TLS + token auth configurable via `[gateway.nats]` in `agent-assembly.toml` | ✅ | `NatsConfig`/`NatsTlsConfig` + `from_toml_str`; `connect_options` applies `token`, `require_tls`, root + client certs. Unit tests `config::tests::parses_full_gateway_nats_table` (url + token + tls.{ca,cert,key} + max_inflight) and `falls_back_to_defaults_when_table_absent`. |
| 3 | NATS down → events go to the SQLite buffer; never blocks the agent | ✅ | `AuditPublisher::publish` is fire-and-forget and returns `()`; on sink error it `buffer.enqueue`s. Unit test `publisher::tests::buffers_when_sink_down`; integration test buffers 100 events during a real server outage (`buffered_len() == 100`). |
| 4 | On reconnect, the buffer flushes in FIFO order | ✅ | `flush_pending` → `EventBuffer::drain_and_send`; `spawn_reconnect_flush_loop` runs it on an interval. Unit test `publisher::tests::reconnect_drains_buffer_in_fifo_order`; integration test replays the 100 buffered events as `seq 1000..1100` **in order** after a same-port restart. |
| 5 | Metrics `aa_audit_published_total`, `aa_audit_publish_errors_total`, `aa_audit_buffered_total` (+ `aa_audit_flushed_total`) | ✅ | Constants in `audit_publisher/mod.rs`; emitted in `publish`/`flush_pending`. Unit test `publisher::tests::records_all_four_audit_metrics` asserts all four names present via a scoped `DebuggingRecorder`. |

## How it was run

### Unit + doc tests
```
cargo nextest run -p aa-runtime          # 239 passed, 2 skipped
cargo test -p aa-runtime --doc           # 1 passed (NatsConfig example)
cargo clippy -p aa-runtime --all-targets --all-features -- -D warnings   # clean
cargo deny check                         # advisories/bans/licenses/sources ok
```

### Reconnect integration test (Docker required)
```
cargo test -p aa-runtime --test audit_publisher_nats -- --nocapture
# test result: ok. 1 passed; finished in 227.30s
```

`tests/audit_publisher_nats.rs::buffers_during_outage_and_replays_all_on_reconnect`
exercises the end-to-end path against a real `nats:2.10` container:

1. **Up** — publish 1000 events; a `assembly.audit.>` subscriber receives all 1000; buffer empty.
2. **Down** — stop the container; the publisher observes the disconnect; publish 100 more → all 100 land in the SQLite buffer (publish never errors).
3. **Restart** — start NATS again on the **same mapped host port**; the client auto-reconnects; `flush_pending` drains all 100; a fresh subscriber receives them as `seq 1000..1100` in FIFO order.
4. **Total** — 1000 + 100 = **1100** events delivered across the restart; zero acked events lost.

## Result

**All five acceptance criteria pass.** No bugs found; no Bug Subtask filed.
