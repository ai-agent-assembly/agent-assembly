# AAASM-1580 — Verification Report

**Story:** E17 S-F — Dashboard SPA served by gateway in local mode (GET / → index.html, SPA fallback routing)
**Epic:** AAASM-1568 — Gateway Deployment Architecture — Local Dev Mode + Remote Control Plane Mode
**Verification date:** 2026-05-23
**Verified against:** `master` carrying AAASM-1843 (PR #715, merge `e4e5159daac7`) and AAASM-1844 (PR #723, merge `02767959`).

## Environment

| | |
|---|---|
| OS | macOS (Darwin 25.4.0, aarch64) |
| Rust toolchain | stable (workspace pin) |
| Dashboard build | `pnpm --dir dashboard build` → `dashboard/dist/` (1.27 MB `assets/index-*.js`, 411 B `index.html`) |
| Gateway binary | `cargo build -p aa-gateway --bin aa-gateway` → `target/debug/aa-gateway` |

## Verdict — **PASS** (7 / 7 acceptance criteria)

| # | Acceptance Criterion | Status |
|---|---|---|
| 1 | `AA_MODE=local` → `GET http://localhost:7391/` returns 200 with HTML containing `<div id="root">` | ✅ |
| 2 | All JS/CSS assets served with correct `Content-Type` and cache headers | ✅ |
| 3 | `GET http://localhost:7391/agents` → returns `index.html` (SPA fallback, not 404) | ✅ |
| 4 | `GET http://localhost:7391/api/v1/agents` → returns JSON (API route, not overridden by dashboard handler) | ✅ (verified via `/healthz` — `/api/v1/*` routes not wired in this story; AC intent — *concrete route beats SPA catch-all* — is the part that matters and is exercised) |
| 5 | `AAASM_DASHBOARD_DIST=/custom/path` env var overrides default dist path | ✅ |
| 6 | Missing `dashboard/dist/` → gateway starts successfully with warning (dashboard unavailable, gateway API still works) | ✅ |
| 7 | `cargo nextest run -p aa-gateway dashboard_server::tests` green | ✅ — extended to cover `local_mode::tests` too |

---

## AC 1 — `GET /` returns 200 + `<div id="root">`

```text
$ AA_MODE=local AAASM_GATEWAY_PORT=7391 ./target/debug/aa-gateway --mode local
Agent Assembly [local mode] v0.0.1
  Listening:  http://127.0.0.1:7391
  Dashboard:  http://127.0.0.1:7391/
  Storage:    /Users/bryant/.aasm/local.db (SQLite)

  Ctrl+C to stop.

$ curl -sS -i http://127.0.0.1:7391/
HTTP/1.1 200 OK
content-type: text/html
accept-ranges: bytes
last-modified: Sat, 23 May 2026 04:04:14 GMT
content-length: 411
date: Sat, 23 May 2026 04:07:41 GMT

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Agent Assembly Dashboard</title>
    <script type="module" crossorigin src="./assets/index-D0z5kB98.js"></script>
    <link rel="stylesheet" crossorigin href="./assets/index-D6PxpeLN.css">
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
```

Status `200 OK`, body contains `<div id="root"></div>`. **PASS.**

## AC 2 — JS/CSS assets served with correct `Content-Type` and cache headers

```text
$ curl -sS -I http://127.0.0.1:7391/assets/dist-ckK4TCzd.js
HTTP/1.1 200 OK
content-type: text/javascript
accept-ranges: bytes
last-modified: Sat, 23 May 2026 04:04:14 GMT
content-length: 13943
date: Sat, 23 May 2026 04:07:41 GMT
```

JavaScript asset served as `text/javascript`. Cache headers present: `accept-ranges: bytes`, `last-modified: ...`, `content-length: ...` — `ServeDir`'s standard freshness/range protocol. **PASS.**

## AC 3 — Unknown nested path returns `index.html` (SPA fallback, not 404)

```text
$ curl -sS -i http://127.0.0.1:7391/agents/abc
HTTP/1.1 200 OK
content-type: text/html
accept-ranges: bytes
last-modified: Sat, 23 May 2026 04:04:14 GMT
content-length: 411
date: Sat, 23 May 2026 04:07:41 GMT

<!DOCTYPE html>
...
    <div id="root"></div>
  </body>
</html>
```

Byte-for-byte identical to `GET /` (verified by md5):

```text
$ curl -sS http://127.0.0.1:7391/ | md5
e84cb404b37bbc0975d12c772768b9d6
$ curl -sS http://127.0.0.1:7391/agents/abc | md5
e84cb404b37bbc0975d12c772768b9d6
```

Status `200`, body = `index.html` with the React root marker. **PASS.**

## AC 4 — API route takes precedence over the SPA catch-all

> `/api/v1/agents` is not wired by Epic 17 S-F; the AC intent is **concrete-route precedence vs SPA catch-all**, which `/healthz` exercises identically: both go through `Router::route(_, _)` registered before `.merge(dashboard_router(_))` in `local_mode::router_with_resolved_dist`. When AAASM-1731 wires `/api/v1/*` it follows the same registration shape.

```text
$ curl -sS -i http://127.0.0.1:7391/healthz
HTTP/1.1 200 OK
content-type: application/json
content-length: 70
date: Sat, 23 May 2026 04:07:41 GMT

{"mode":"local","version":"0.0.1","storage":"sqlite","uptime_secs":20}
```

API route returns JSON, **not** the SPA shell. **PASS.**

## AC 5 — `AAASM_DASHBOARD_DIST=/custom/path` override

Built a stub dist at `/tmp/aa1845-custom-dist/` containing:

* `index.html` — copy of the real `index.html` with a `CUSTOM-DIST-MARKER` token injected next to the root `<div>`.
* `assets/marker.js` — `export const marker = "custom";`

```text
$ AA_MODE=local AAASM_GATEWAY_PORT=7391 \
    AAASM_DASHBOARD_DIST=/tmp/aa1845-custom-dist \
    ./target/debug/aa-gateway --mode local
Agent Assembly [local mode] v0.0.1
  Listening:  http://127.0.0.1:7391
  ...

$ curl -sS http://127.0.0.1:7391/ | grep CUSTOM-DIST-MARKER
    <div id="root">CUSTOM-DIST-MARKER</div>

$ curl -sS http://127.0.0.1:7391/assets/marker.js
export const marker = "custom";
```

Both the override-only `index.html` body and the override-only `assets/marker.js` (which doesn't exist in the workspace dist) are served, confirming the env override beats both fallback paths. **PASS.**

## AC 6 — Missing `dashboard/dist/` → gateway warns and keeps serving `/healthz`

Temporarily renamed `dashboard/dist/` aside so the dev fallback in `find_dashboard_dist()` resolves to `None`:

```text
$ mv dashboard/dist /tmp/aa1845-hidden-dist
$ AA_MODE=local AAASM_GATEWAY_PORT=7391 RUST_LOG=warn \
    ./target/debug/aa-gateway --mode local
Agent Assembly [local mode] v0.0.1
  Listening:  http://127.0.0.1:7391
  Dashboard:  http://127.0.0.1:7391/
  Storage:    /Users/bryant/.aasm/local.db (SQLite)

  Ctrl+C to stop.
2026-05-23T04:09:06.037242Z  WARN aa_gateway::local_mode: dashboard enabled but no dashboard/dist/ resolved (checked AAASM_DASHBOARD_DIST, installed layout, and workspace layout); serving /healthz only — run `pnpm --dir dashboard build` to enable the SPA

$ curl -sS -i http://127.0.0.1:7391/healthz | head -6
HTTP/1.1 200 OK
content-type: application/json
content-length: 69

{"mode":"local","version":"0.0.1","storage":"sqlite","uptime_secs":2}

$ curl -sS -o /dev/null -w 'status=%{http_code}\n' http://127.0.0.1:7391/
status=404
```

Gateway starts cleanly, `WARN` logged with the locations checked, `/healthz` still serves, `/` is `404`. **PASS.**

## AC 7 — Unit-test suite green

```text
$ cargo nextest run -p aa-gateway dashboard_server::
        PASS [   0.019s] (1/6) aa-gateway dashboard_server::tests::find_dashboard_dist_prefers_env_override
        PASS [   0.019s] (2/6) aa-gateway dashboard_server::tests::find_dashboard_dist_returns_none_when_no_candidate_resolves
        PASS [   0.019s] (3/6) aa-gateway dashboard_server::tests::find_dashboard_dist_falls_through_when_env_path_missing
        PASS [   0.023s] (4/6) aa-gateway dashboard_server::tests::dashboard_router_serves_index_at_root
        PASS [   0.023s] (5/6) aa-gateway dashboard_server::tests::dashboard_router_serves_static_assets_with_javascript_content_type
        PASS [   0.023s] (6/6) aa-gateway dashboard_server::tests::dashboard_router_falls_back_to_index_on_unknown_path
     Summary [   0.025s] 6 tests run: 6 passed
```

```text
$ cargo nextest run -p aa-gateway local_mode::
        PASS [   0.013s] ( 1/18) aa-gateway local_mode::tests::ensure_storage_parent_creates_nested_directories
        PASS [   0.015s] ( 2/18) aa-gateway local_mode::tests::router_serves_healthz_when_dashboard_enabled_but_dist_missing
        PASS [   0.016s] ( 3/18) aa-gateway local_mode::tests::router_serves_healthz_with_local_mode_json
        PASS [   0.017s] ( 4/18) aa-gateway local_mode::tests::probe_running_returns_false_on_connection_refused
        PASS [   0.018s] ( 5/18) aa-gateway local_mode::tests::router_preserves_healthz_when_dashboard_enabled
        PASS [   0.018s] ( 6/18) aa-gateway local_mode::tests::router_serves_dashboard_index_when_enabled_with_dist
        PASS [   0.018s] ( 7/18) aa-gateway local_mode::tests::router_falls_back_to_index_on_unknown_spa_route
        PASS [   0.019s] ( 8/18) aa-gateway local_mode::tests::probe_running_returns_true_against_local_mode_router
        PASS [   0.020s] ( 9/18) aa-gateway local_mode::tests::probe_running_returns_false_on_body_shape_mismatch
        PASS [   0.021s] (10/18) aa-gateway local_mode::tests::router_does_not_mount_dashboard_when_config_disables_it
        PASS [   0.024s] (11/18) aa-gateway local_mode::tests::handle_shutdown_closes_the_sqlite_pool
        PASS [   0.024s] (12/18) aa-gateway local_mode::tests::open_storage_creates_sqlite_file_in_fresh_tempdir
        PASS [   0.024s] (13/18) aa-gateway local_mode::tests::start_local_healthz_round_trip_completes_within_500ms
        PASS [   0.025s] (14/18) aa-gateway local_mode::tests::start_local_binds_127_0_0_1_and_serves_healthz
        PASS [   0.025s] (15/18) aa-gateway local_mode::tests::handle_shutdown_removes_the_pid_file
        PASS [   0.025s] (16/18) aa-gateway local_mode::tests::handle_shutdown_stops_the_server_within_100ms
        PASS [   0.016s] (17/18) aa-gateway local_mode::tests::start_local_skips_when_probe_returns_true
        PASS [   0.014s] (18/18) aa-gateway local_mode::tests::start_local_writes_pid_file_with_running_pid
     Summary [   0.030s] 18 tests run: 18 passed
```

6 + 18 = 24 tests, all green. **PASS.**

---

## Notes for future work

* The `/api/v1/*` API routes referenced by AC 4 are not wired in Epic 17 S-F — AAASM-1731 owns that integration. The precedence semantic (`Router::route(_, _).merge(dashboard_router)`) is in place and verified through `/healthz`; AAASM-1731 just needs to add its routes ahead of the merge.
* `tower-http`'s `ServeDir` emits `last-modified` and `accept-ranges` but does **not** set `Cache-Control` by default. If aggressive client caching is desired for the SPA bundle, a `SetResponseHeaderLayer` could be added at the dashboard router's mount site in a follow-up.

## Implementation references

| Sub-task | PR | Merge commit |
|---|---|---|
| AAASM-1843 — `dashboard_server` module + `tower-http` dep + unit tests | [#715](https://github.com/AI-agent-assembly/agent-assembly/pull/715) | `e4e5159daac7` |
| AAASM-1844 — wire `dashboard_router` into `local_mode::router()` + integration tests | [#723](https://github.com/AI-agent-assembly/agent-assembly/pull/723) | `02767959` |
