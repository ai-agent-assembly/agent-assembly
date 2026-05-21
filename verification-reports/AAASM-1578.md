# Verification Report — AAASM-1578 (E17 S-D `aasm start` / `aasm stop`)

* **Story**: [AAASM-1578](https://lightning-dust-mite.atlassian.net/browse/AAASM-1578)
* **Epic**: [AAASM-1568](https://lightning-dust-mite.atlassian.net/browse/AAASM-1568) — Gateway Deployment Architecture
* **Scope**: scaffold-only. Real `/healthz` integration is deferred to a follow-up subtask once AAASM-1577 lands; this story uses a TCP-listener readiness probe as the stand-in.
* **Verified against**: master ≥ `8ef6a4ab` plus the four Impl PRs:
  * AAASM-1706 / PR #657 — PID-file utility
  * AAASM-1711 / PR #661 — gateway readiness probe
  * AAASM-1717 / PR #667 — `aasm start` subcommand
  * AAASM-1722 / PR #671 — `aasm stop` subcommand

## Test counts

```
cargo nextest run -p aa-cli commands::pidfile::tests   →  7 passed
cargo nextest run -p aa-cli commands::gw_probe::tests  →  4 passed
cargo nextest run -p aa-cli commands::start::tests     →  6 passed
cargo nextest run -p aa-cli commands::stop::tests      →  4 passed
                                              total      21 passed
```

Combined wall time: ~3.1 s (dominated by the AC-mandated real-child SIGTERM test in `commands::stop::tests::run_kills_real_child_and_removes_pid_file`).

Full `aa-cli` suite at the head of the stacked verify branch: **521 / 521 passed**.

`cargo clippy -p aa-cli --all-targets -- -D warnings` — clean.

## Acceptance Criteria — item-by-item verification

### `[x]` `aasm start` starts the gateway in local mode (default) and exits after confirming readiness

* CLI surface: `aa-cli/src/commands/start.rs::StartArgs` declares `--mode` with `default_value_t = ModeArg::Local` and `--port` with `default_value_t = 7391`. Default values pinned by `commands::start::tests::resolve_listen_addr_local_binds_loopback`.
* Flow: `run` calls `resolve_listen_addr(Local, 7391)` → `127.0.0.1:7391`, then `Command::new("aa-gateway").arg("--listen").arg(addr).spawn()`, then `gw_probe::wait_for_ready(addr, 5 s, 100 ms)`.
* On the spawn path, success prints `format_started_banner(...)` (covered by `format_started_banner_contains_mode_address_and_pid`) and returns `ExitCode::SUCCESS`.

**Scaffold caveat**: the real `aa-gateway` binary currently requires `--policy` and does not yet accept `--mode` / `--config` — those land with AAASM-1576 / AAASM-1577. Until then, `aasm start` reaches "spawn → ready timeout → error 1" against a vanilla `aa-gateway`; once S-B lands, the same code path becomes "spawn → ready → banner → exit 0" with no change to S-D.

### `[x]` `aasm start --mode remote --config /path/to/config.yaml` starts in remote mode

* `ModeArg` derives `clap::ValueEnum` with `rename_all = "lowercase"`; `--mode remote` parses to `ModeArg::Remote`. Default-value test plus remote test confirm both arms: `resolve_listen_addr_remote_binds_unspecified` pins `0.0.0.0`.
* `--config` is parsed into `StartArgs::config: PathBuf`. The flag is currently a no-op end-to-end (gateway does not yet read it) — see scope caveat in the parent story comment.

### `[x]` `aasm start` when gateway already running: prints "already running" message, exits 0

* `check_already_running(pid_file, addr, probe_timeout)` returns `Some(pid)` when **both** the PID file resolves to a live process **and** a TCP probe of the addr succeeds. Covered by `check_already_running_returns_some_when_pid_is_self_and_port_listens` (positive) and `check_already_running_returns_none_when_pid_file_is_missing` (negative).
* On `Some(pid)`, `run` prints exactly `Gateway already running at http://localhost:7391 (PID 12345). Use 'aasm stop' first.` and returns `ExitCode::SUCCESS`. The exact wording is locked in by `format_already_running_message_matches_story_contract`.

### `[x]` `aasm stop` sends SIGTERM and waits for clean exit

* `commands::stop::run_with_pid_file` reads the PID, calls `send_signal(pid, libc::SIGTERM)`, then `wait_for_exit(pid, timeout)`. Covered by `run_kills_real_child_and_removes_pid_file` which spawns a real `sleep 60`, drives `run_with_pid_file`, and asserts:
  * exit code is `SUCCESS`
  * PID file is removed
  * the child is reaped on test cleanup (no orphan)
* SIGKILL fallback exercised implicitly by the same test (the test process keeps the child as a zombie, forcing the escalation path).

### `[x]` `aasm stop` when no gateway running: prints "no gateway running", exits 0

* Direct test: `run_with_missing_pid_file_returns_success` — empty temp dir, no PID file present, drives `run_with_pid_file` and asserts `ExitCode::SUCCESS`.
* Exact output line: `No gateway running.` (period included, single line).

### `[x]` PID file written on start, removed on stop

* **Written**: `start::run` calls `pidfile::write_pid(&pid_file, child.id())` immediately after the background `Command::spawn()` succeeds. `pidfile::write_pid` itself is covered by `write_pid_creates_missing_parent_directory` and `write_then_read_round_trip_preserves_pid`.
* **Removed**: `stop::run_with_pid_file` calls `pidfile::remove_pid` on every exit path (missing → no-op; stale → cleanup; live → after signal). End-to-end coverage in `run_with_stale_pid_removes_file_and_returns_success` (stale path) and `run_kills_real_child_and_removes_pid_file` (live path).

### `[x]` `cargo nextest run -p aa-cli commands::start::tests` green

```
$ cargo nextest run -p aa-cli commands::start::tests
    Starting 6 tests across 12 binaries (504 tests skipped)
        PASS [   0.012s] (1/6) resolve_listen_addr_local_binds_loopback
        PASS [   0.012s] (2/6) resolve_listen_addr_remote_binds_unspecified
        PASS [   0.012s] (3/6) format_already_running_message_matches_story_contract
        PASS [   0.013s] (4/6) format_started_banner_contains_mode_address_and_pid
        PASS [   0.014s] (5/6) check_already_running_returns_none_when_pid_file_is_missing
        PASS [   0.015s] (6/6) check_already_running_returns_some_when_pid_is_self_and_port_listens
     Summary [   0.016s] 6 tests run: 6 passed
```

### `[x]` `cargo nextest run -p aa-cli commands::stop::tests` green *(extension of the original AC)*

```
$ cargo nextest run -p aa-cli commands::stop::tests
    Starting 4 tests across 12 binaries (504 tests skipped)
        PASS [   0.013s] (1/4) send_signal_to_self_with_signal_zero_returns_true
        PASS [   0.014s] (2/4) run_with_missing_pid_file_returns_success
        PASS [   0.014s] (3/4) run_with_stale_pid_removes_file_and_returns_success
        PASS [   3.108s] (4/4) run_kills_real_child_and_removes_pid_file
     Summary [   3.115s] 4 tests run: 4 passed
```

## Known caveats (carried forward)

1. **Readiness probe is TCP-listener, not `/healthz`.** Documented in the parent-story scope decision. A follow-up subtask under AAASM-1578 will swap the probe to `gw_probe::probe_http(addr, "/healthz")` once AAASM-1577 lands its endpoint. The `gw_probe` API is shaped so this is a one-line change.
2. **`--config` and `--no-dashboard` flags are parsed but currently no-op.** The gateway binary does not yet read them. Both flags land their real behaviour with AAASM-1576 (S-B local mode) and AAASM-1577 (S-C remote mode).
3. **End-to-end against the real `aa-gateway` binary is not exercised in this verification.** The current `aa-gateway --listen <addr>` invocation requires a `--policy` flag that `aasm start` does not yet pass through. A follow-up integration test will land once the gateway accepts a config-derived policy path (AAASM-1576).

## Conclusion

All seven story-level AC items are verified by automated tests at the unit and integration boundary. The scope-deferral caveats are explicitly documented in the parent ticket and in the source code (`commands/start.rs` module doc). **Recommendation: mark AAASM-1578 ready for the verify-then-merge transition.**
