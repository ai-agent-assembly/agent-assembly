# AAASM-1576 — E17 S-B Local Dev Mode — Acceptance Verification

| | |
| --- | --- |
| **Story** | [AAASM-1576](https://lightning-dust-mite.atlassian.net/browse/AAASM-1576) — E17 S-B: Local Dev Mode — auto-start lightweight control plane at localhost:7391 with SQLite |
| **Epic** | [AAASM-1568](https://lightning-dust-mite.atlassian.net/browse/AAASM-1568) — Epic 17: Gateway Deployment Architecture |
| **Verified against `master` SHA** | `9769abc3` (PR #703 merge — Sub-task 7 / AAASM-1731) |
| **Verification date** | 2026-05-22 |
| **Verification sub-task** | [AAASM-1737](https://lightning-dust-mite.atlassian.net/browse/AAASM-1737) |
| **Conclusion** | ✅ Ready for Done — all 9 ACs verified |

---

## Sub-tasks landed (in dependency order)

| # | Key | PR | Title |
| --- | --- | --- | --- |
| 1 | [AAASM-1701](https://lightning-dust-mite.atlassian.net/browse/AAASM-1701) | [#655](https://github.com/AI-agent-assembly/agent-assembly/pull/655) | local_mode module scaffold — handle, healthz response, error types |
| 2 | [AAASM-1705](https://lightning-dust-mite.atlassian.net/browse/AAASM-1705) | [#670](https://github.com/AI-agent-assembly/agent-assembly/pull/670) | Mount /healthz in local_mode router via routes::healthz |
| 3 | [AAASM-1710](https://lightning-dust-mite.atlassian.net/browse/AAASM-1710) | [#687](https://github.com/AI-agent-assembly/agent-assembly/pull/687) | SQLite open + parent-dir mkdir helpers |
| 4 | [AAASM-1715](https://lightning-dust-mite.atlassian.net/browse/AAASM-1715) | [#693](https://github.com/AI-agent-assembly/agent-assembly/pull/693) | Idempotent healthz pre-flight probe |
| 5 | [AAASM-1725](https://lightning-dust-mite.atlassian.net/browse/AAASM-1725) | [#696](https://github.com/AI-agent-assembly/agent-assembly/pull/696) | start_local() orchestrator + 127.0.0.1 bind + PID file |
| 6 | [AAASM-1728](https://lightning-dust-mite.atlassian.net/browse/AAASM-1728) | [#701](https://github.com/AI-agent-assembly/agent-assembly/pull/701) | Graceful shutdown + PID/DB cleanup |
| 7 | [AAASM-1731](https://lightning-dust-mite.atlassian.net/browse/AAASM-1731) | [#703](https://github.com/AI-agent-assembly/agent-assembly/pull/703) | Wire DeploymentMode dispatch — AA_MODE=local boots local CP |

---

## Acceptance Criteria walkthrough

### AC #1 — `AA_MODE=local` starts a control plane at `http://localhost:7391`

✅ **Verified** via `aa-integration-tests::local_mode_main_dispatch::aa_mode_local_serves_healthz_and_exits_cleanly_on_sigterm`. The test spawns the real `aa-gateway` binary with `AA_MODE=local` + `AAASM_GATEWAY_PORT=<ephemeral>` + `HOME=<tempdir>`, then asserts `GET /healthz` returns 200 with a body carrying `mode == "local"` and `storage == "sqlite"`.

```text
$ cargo nextest run -p aa-integration-tests --test local_mode_main_dispatch
Starting 1 test across 1 binary
    PASS [   1.428s] (1/1) aa-integration-tests::local_mode_main_dispatch aa_mode_local_serves_healthz_and_exits_cleanly_on_sigterm
Summary [   1.429s] 1 test run: 1 passed, 0 skipped
```

### AC #2 — Auto-start is skipped when the port is already serving a gateway (idempotent)

✅ **Verified** via `aa-gateway::local_mode::tests::start_local_skips_when_probe_returns_true`. The test calls `start_local_with_pid_path()` twice against the same `LocalModeConfig`; the second call must return Ok (would have returned `LocalModeError::Bind` if it had tried to re-bind) and must NOT write a fresh PID file (proof the probe short-circuit fired before the PID-write step).

Probe behaviour itself is exercised by three further tests forming the full truth table:

* `probe_running_returns_false_on_connection_refused`
* `probe_running_returns_true_against_local_mode_router`
* `probe_running_returns_false_on_body_shape_mismatch` — guards against foreign HTTP servers on the port

### AC #3 — SQLite file created at `~/.aasm/local.db` on first start

✅ **Verified** via `aa-gateway::local_mode::tests::open_storage_creates_sqlite_file_in_fresh_tempdir`. The test calls `open_storage(&db_path)` with a path inside a fresh nested directory tree (neither parent nor file exists), then asserts `db_path.is_file()` and `!pool.is_closed()`.

The end-to-end binary test additionally exercises the production `~/.aasm/local.db` path via `HOME=<tempdir>` redirect: `dirs::home_dir()` resolves to the tempdir, so `LocalModeConfig::storage_path` (`~/.aasm/local.db`) is created at `<tempdir>/.aasm/local.db`.

Supporting unit test: `ensure_storage_parent_creates_nested_directories` — confirms the parent directory chain is materialised before sqlx tries to create the database file.

### AC #4 — `GET /healthz` returns `{"mode":"local","storage":"sqlite","version":"<v>"}`

✅ **Verified** via `aa-gateway::local_mode::tests::router_serves_healthz_with_local_mode_json` and the integration test.

The router test drives `router()` through `tower::ServiceExt::oneshot` and asserts: HTTP 200, `Content-Type: application/json`, body `mode == "local"`, `storage == "sqlite"`, `version == env!("CARGO_PKG_VERSION")`, and `uptime_secs` is present as `u64` (guards against a regression dropping the field from `HealthzBody`).

The implementation reuses the shared `routes::healthz::HealthzBody` wire contract from AAASM-1698 (scope adjustment documented in AAASM-1705); the response includes the three AC-required fields plus `uptime_secs` from the stable shape.

### AC #5 — Startup completes in under 500 ms on a developer laptop

✅ **Verified** via `aa-gateway::local_mode::tests::start_local_healthz_round_trip_completes_within_500ms`. Measures `Instant::elapsed()` across `start_local_with_pid_path` + `reqwest::get(/healthz)` + JSON parse. Asserts `elapsed < 500 ms`. Locally observed wall-clock ≈ 40 ms on the verification run (single-digit ms for `start_local` itself; the rest is reqwest connection + JSON parse latency).

### AC #6 — Gateway binds to `127.0.0.1` only, never `0.0.0.0`

✅ **Verified** via `aa-gateway::local_mode::tests::start_local_binds_127_0_0_1_and_serves_healthz`. Asserts `handle.local_addr.ip() == Ipv4Addr::LOCALHOST` after `start_local`. Implementation uses an explicit `SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port)` — there is no code path in `local_mode::start_local_with_pid_path` that binds to `0.0.0.0`.

### AC #7 — PID file written to `~/.aasm/gateway.pid`

✅ **Verified** via `aa-gateway::local_mode::tests::start_local_writes_pid_file_with_running_pid`. The test reads the written file, parses as `u32`, and asserts `== std::process::id()`. The production location `~/.aasm/gateway.pid` is computed by `pid_file_path()` via `dirs::home_dir().join(".aasm/gateway.pid")`; the test exercises this via the `pub(crate)` `start_local_with_pid_path()` testability split so it points at `tempdir/gateway.pid` rather than polluting the real `~/.aasm/`.

The end-to-end binary test additionally exercises the production path with `HOME=<tempdir>` redirect and asserts `tempdir/.aasm/gateway.pid` exists while the spawned process is running.

### AC #8 — Clean shutdown (Ctrl+C or SIGTERM) removes PID file and closes DB connection

✅ **Verified** via three unit tests covering the full cleanup truth table:

| Invariant | Test |
| --- | --- |
| Server stops accepting connections | `handle_shutdown_stops_the_server_within_100ms` — asserts `elapsed < 500 ms` and post-shutdown GET `/healthz` does not return a successful response |
| PID file removed (`!pid_path.exists()`) | `handle_shutdown_removes_the_pid_file` |
| `SqlitePool::is_closed()` returns `true` | `handle_shutdown_closes_the_sqlite_pool` — cloned-pool view pattern, since `SqlitePool` is internally `Arc`-based |

End-to-end via the integration test: the spawned binary receives `libc::kill(pid, SIGTERM)`, the test waits up to 5 s for clean exit, then asserts `exit_status.success()` and `!pid_path.exists()`.

`SIGINT` parity is structural — `wait_for_shutdown_signal()` uses `tokio::select!` over both `tokio::signal::ctrl_c()` and `tokio::signal::unix::signal(SignalKind::terminate())`. Whichever wakes up first feeds into the same `handle.shutdown()` path.

### AC #9 — `cargo nextest run -p aa-gateway local_mode::tests` green

✅ **Verified** locally against master `9769abc3`:

```text
$ cargo nextest run -p aa-gateway -E 'test(/^local_mode::/)'
Starting 13 tests across 41 binaries (920 tests skipped)
    PASS [   0.036s] ( 1/13) aa-gateway local_mode::tests::ensure_storage_parent_creates_nested_directories
    PASS [   0.036s] ( 2/13) aa-gateway local_mode::tests::probe_running_returns_false_on_connection_refused
    PASS [   0.037s] ( 3/13) aa-gateway local_mode::tests::router_serves_healthz_with_local_mode_json
    PASS [   0.039s] ( 4/13) aa-gateway local_mode::tests::probe_running_returns_false_on_body_shape_mismatch
    PASS [   0.038s] ( 5/13) aa-gateway local_mode::tests::probe_running_returns_true_against_local_mode_router
    PASS [   0.040s] ( 6/13) aa-gateway local_mode::tests::open_storage_creates_sqlite_file_in_fresh_tempdir
    PASS [   0.040s] ( 7/13) aa-gateway local_mode::tests::start_local_writes_pid_file_with_running_pid
    PASS [   0.040s] ( 8/13) aa-gateway local_mode::tests::handle_shutdown_closes_the_sqlite_pool
    PASS [   0.040s] ( 9/13) aa-gateway local_mode::tests::handle_shutdown_removes_the_pid_file
    PASS [  0.040s] (10/13) aa-gateway local_mode::tests::start_local_binds_127_0_0_1_and_serves_healthz
    PASS [  0.040s] (11/13) aa-gateway local_mode::tests::start_local_healthz_round_trip_completes_within_500ms
    PASS [  0.040s] (12/13) aa-gateway local_mode::tests::start_local_skips_when_probe_returns_true
    PASS [  0.041s] (13/13) aa-gateway local_mode::tests::handle_shutdown_stops_the_server_within_100ms
Summary [   0.042s] 13 tests run: 13 passed, 920 skipped
```

13/13 — every AC has at least one passing test.

---

## Scope adjustments documented during implementation

The seven implementation Sub-tasks each carried scope adjustments vs the original AAASM-1576 description. They are recorded in the Sub-task closing comments and summarised here for the Story-level record:

| Sub-task | Adjustment |
| --- | --- |
| AAASM-1705 | Original plan added a `HealthzResponse` type; reused the shared `routes::healthz::HealthzBody` wire contract from AAASM-1698 instead. Single source of truth across local + remote modes. |
| AAASM-1710 | Original plan added a `resolve_storage_path` helper for `~` expansion; that logic already lives in `aa-core::config::GatewayConfig::expand_paths()` from AAASM-1691. This Sub-task shipped only the on-disk pieces (mkdir + SqlitePool open). |
| AAASM-1715 | Probe parses `serde_json::Value` rather than a strongly-typed shape — avoids adding `Deserialize` to the stable `HealthzBody` wire contract. The body-shape check (require `mode`, `storage`, `version` as strings) rejects foreign servers on port 7391. |
| AAASM-1725 | `LocalGatewayHandle` was extended in AAASM-1728 with `Option<JoinHandle>`, `Option<SqlitePool>`, `Option<PathBuf>` so `shutdown()` could drive cleanup explicitly. The Option pattern correctly captures that the probe-short-circuit "shell handle" has nothing to clean up. |
| AAASM-1728 | `run_until_shutdown` signature simplified from the originally-planned `(handle, pool)` to `(handle)` — pool now lives on the handle. |
| AAASM-1731 | `aa-gateway/src/main.rs` had already been refactored by AAASM-1577 sibling work (Mode enum, resolve_mode, run_legacy_grpc, run_remote). This Sub-task only had to replace the `Mode::Local => Err(...)` placeholder with `run_local()`. |

None of these adjustments changed observable behaviour or the AC contract.

---

## Conclusion

**Ready for Done.** All 9 AAASM-1576 ACs verified ✅ against master `9769abc3`. 13/13 `aa-gateway local_mode::tests` green; 1/1 `aa-integration-tests local_mode_main_dispatch` green. No bugs uncovered during verification; no follow-up Sub-tasks filed.
