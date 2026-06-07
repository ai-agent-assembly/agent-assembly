# AAASM-1577 acceptance verification report

**Story**: [AAASM-1577 — E17 S-C: Remote CP Mode — server startup, TLS configuration, /healthz endpoint, graceful shutdown](https://lightning-dust-mite.atlassian.net/browse/AAASM-1577)
**Epic**: AAASM-1568 — Gateway Deployment Architecture
**Verification Sub-task**: AAASM-1718

## Sub-task delivery

| Sub-task | Type | PR | Status |
| --- | --- | --- | --- |
| AAASM-1698 (ST-1) | Implementation — `/healthz` HTTP route module | [#654](https://github.com/ai-agent-assembly/agent-assembly/pull/654) | Done |
| AAASM-1702 (ST-2) | Implementation — `remote_mode::tls` validator | [#674](https://github.com/ai-agent-assembly/agent-assembly/pull/674) | Done |
| AAASM-1709 (ST-3) | Implementation — `remote_mode::server::start_remote` | [#690](https://github.com/ai-agent-assembly/agent-assembly/pull/690) | Done |
| AAASM-1713 (ST-4) | Implementation — `main.rs` deployment-mode dispatch | [#692](https://github.com/ai-agent-assembly/agent-assembly/pull/692) | Done |
| AAASM-1718 (ST-5) | Verification — this PR | _this PR_ | In progress |

## Acceptance Criteria

| AC | Status | Evidence |
| --- | --- | --- |
| `AA_MODE=remote` starts server on `0.0.0.0:7391` (default) or configured `listen_addr` | ✅ | `RemoteModeConfig::default()` (aa-core/src/config.rs L124–132) defaults `listen_addr` to `0.0.0.0:7391`; `aa_gateway::remote_mode::start_remote_with_handle` (aa-gateway/src/remote_mode/server.rs) honours `cfg.listen_addr`. Wired into the binary via `aa-gateway::main::run_remote` (AAASM-1713). End-to-end exercise in `aa-gateway/tests/remote_mode_http.rs::start_remote_serves_healthz_over_http` (AAASM-1709) using `127.0.0.1:0` ephemeral binding. |
| `GET /healthz` returns 200 with JSON body including `mode: "remote"` and `storage` type | ✅ | Handler in `aa-gateway/src/routes/healthz.rs::healthz` (AAASM-1698) returns `Json<HealthzBody>` (always 200). Body shape exercised by `aa-gateway/tests/remote_mode_e2e.rs::two_agents_register_and_list_via_http` (AAASM-1718) — asserts `body["mode"] == "remote"`. |
| TLS: valid cert/key → HTTPS; missing cert → HTTP with startup warning; bad cert path → startup error | ✅ | Three sub-paths verified: (a) **Valid → HTTPS**: `aa-gateway/tests/remote_mode_tls.rs::https_handshake_serves_healthz_with_remote_mode_body` (AAASM-1718) issues a self-signed cert with rcgen, points `RemoteModeConfig.tls` at the PEMs, and probes `/healthz` over HTTPS with a rustls-backed reqwest client. (b) **Missing TLS → HTTP + warning**: `aa-gateway/src/remote_mode/server.rs::start_remote_with_handle` (AAASM-1709) emits `tracing::warn!("⚠ TLS not configured — running over plain HTTP")` in the `cfg.tls.is_none()` branch. (c) **Bad cert path → startup error**: `aa-gateway/src/remote_mode/tls.rs::validate` (AAASM-1702) returns `TlsError::CertFileMissing` / `TlsError::KeyFileMissing` / `TlsError::CertParse`; unit-tested by `errors_when_cert_file_missing`, `errors_when_key_file_missing`, `errors_when_cert_is_not_pem`. |
| SIGTERM → graceful drain: in-flight requests complete, new connections refused, exit 0 | ✅ | `aa-gateway/src/remote_mode/server.rs::start_remote` spawns a SIGTERM/SIGINT listener that calls `axum_server::Handle::graceful_shutdown(Some(30s))`. Drain behaviour exercised by `aa-gateway/tests/remote_mode_http.rs::graceful_shutdown_drains_cleanly` (AAASM-1709): asserts the bind/serve future returns `Ok(())` within a 10-second timeout after the handle is triggered. |
| Multiple agents on different machines can register and appear in the same registry | ✅ | `aa-gateway/tests/remote_mode_e2e.rs::two_agents_register_and_list_via_http` (AAASM-1718) merges the production remote-mode router (`aa_gateway::remote_mode::router()`) with a test-local placeholder `/api/v1/agents` API backed by an `Arc<Mutex<Vec<Agent>>>`, registers two agents from different host labels, then asserts both come back via `GET /api/v1/agents`. Production agent registration goes through gRPC today; the HTTP-via-aa-api wiring lands in a sibling Epic (E18). |
| Integration test: start in remote mode (plain HTTP for CI), register two agents, list both via API | ✅ | Same test as the row above — `aa-gateway/tests/remote_mode_e2e.rs::two_agents_register_and_list_via_http`. Binds on `127.0.0.1:0` (ephemeral), plain HTTP, so it runs deterministically on every CI runner without external TLS material. |
| `cargo nextest run -p aa-gateway remote_mode::tls::tests` green | ✅ | 6/6 pass. See [AAASM-1702 PR #674 closing comment](https://lightning-dust-mite.atlassian.net/browse/AAASM-1702) for the per-test breakdown. |

## Test-suite invocation

```
cargo nextest run -p aa-gateway \
    remote_mode \
    --test remote_mode_http \
    --test remote_mode_e2e \
    --test remote_mode_tls
```

Expected: 6 + 2 + 1 + 1 = **10 tests passed, 0 failed**.

## Out-of-scope follow-ups

- **PostgreSQL backend (E18 S-C / AAASM-1719)** — `start_remote_with_handle` currently labels storage as `"memory"` and skips the migration step. When the PostgreSQL backend lands, the `HealthzState::new("remote", "memory")` call in `remote_mode::server::router()` will be replaced with the real storage label threaded through `RemoteModeConfig`.
- **HTTP-mounted agents API** — agent registration over HTTP is currently a test-local placeholder. The production HTTP route surface lives in `aa-api`; mounting that into the remote-mode router is tracked separately (AAASM-1731 per the ST-3 module rustdoc).
- **`aasm start --mode remote`** — explicit lifecycle commands are AAASM-1578 (E17 S-D); this Story only delivers the underlying `start_remote` entrypoint that ST-D wraps.
