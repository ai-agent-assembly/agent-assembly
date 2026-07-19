# AAASM-4861 — WebSocket ticket auth: live browser validation

Validation of the dashboard WebSocket-ticket flow (PR #1583) against a **real running
stack**: `aa-api-server` (AUTH DISABLED / local mode) serving the production dashboard
build (`pnpm build`) + REST + WebSocket on a single origin `http://127.0.0.1:7700`,
driven with the Playwright MCP browser.

## What was verified ✅

| Check | Result |
|---|---|
| Dashboard build (with the ticket changes) serves and authenticates | ✅ logged in as `__bypass__` (no `/login` redirect on `/live`) |
| Browser mints a ticket over REST before connecting | ✅ `POST /api/v1/auth/ws-ticket → 200` observed in the network log |
| Mint endpoint returns an opaque `wst_` ticket (running process) | ✅ `curl` → `{"ticket":"wst_2f39…","expires_at":…,"purpose":"events"}` |
| **No long-lived token in any URL** (the AAASM-4861 defect) | ✅ `performance.getEntries()` → `tokenInAnyUrl: false` |
| Ticket accepted (no reconnect/re-mint storm) | ✅ exactly **one** mint request; the socket stayed up |
| Approvals stream mounts app-wide | ✅ approvals bell present in the shell (top-right chip) |

Backed by the automated suites: **1501** dashboard vitest tests (incl. "URL carries
`ticket=` not `token=`", "reconnect re-mints", "mint auth-failure spins up no socket"),
**16** Rust ticket tests, **6** OpenAPI contract tests.

## Pre-existing issue observed (NOT this PR)

`/live` renders an ErrorBoundary: `(f.data ?? []).map is not a function`. Root cause is
`LiveOpsPage.tsx:99` — `(agentsQuery.data ?? []).map(...)` over a **REST** query
(`useAgentsQuery`) whose **local in-memory backend** returns a paginated envelope, not a
bare array. This file is **not part of PR #1583** (the PR touches only
`useLiveOpsStream.ts` in this area), it consumes REST — not WebSocket — data, and it
reproduces independently of the ticket change. Worth a separate follow-up (local-mode
`/agents` response-shape vs `useAgentsQuery`); out of scope for the WS-auth PR.

## Artifacts

- `aaasm-4861-ws-ticket-live-validation.png` — full-page screenshot of the session
  (shell authenticated; `/live` showing the pre-existing unrelated ErrorBoundary).

## How to reproduce

```bash
cd dashboard && pnpm build && cd ..
cargo build -p aa-api --bin aa-api-server
AASM_API_AUTH=off AASM_DASHBOARD_DIST="$(pwd)/dashboard/dist" AA_API_ADDR=127.0.0.1:7700 \
  ./target/debug/aa-api-server
# browse http://127.0.0.1:7700 ; seed sessionStorage.aa_token from POST /api/v1/auth/token ;
# open /live ; observe POST /api/v1/auth/ws-ticket 200 and no token= in any URL.
```
