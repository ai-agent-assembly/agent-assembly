# AAASM-5347 — Scrub surface wired to the shipped `/api/v1/scrub/*` routes

Captured against a **running gateway**, not a mocked page.

## Harness

```bash
cargo build -p aa-api --bin aa-api-server
pnpm --dir dashboard build

AA_API_ADDR=127.0.0.1:8099 \
AASM_DASHBOARD_DIST=$PWD/dashboard/dist \
AASM_API_KEY=aa_<32 hex> \
  ./target/debug/aa-api-server
```

`aa-api-server` serves the built SPA at `/` **and** the real `/api/v1/*` surface,
so the page and the API share an origin. That matters: `dashboard/index.html`
sets `connect-src 'self'`, so a dev server on `:3000` talking to an API on
another port is blocked by CSP before a request is made. Same-origin is the
production-style path and the only one that exercises the page end to end.

The browser holds the API key in `sessionStorage` under `aa_token`, exactly as a
signed-in operator would; every `/scrub/*` request was confirmed to carry an
`Authorization: Bearer …` header.

## Screenshots

| File | State | Where the data came from |
|---|---|---|
| `01-loading.png` | Loading | Real `/scrub/patterns` response, delayed at the network layer so the skeleton is observable. |
| `02-empty-idle-window.png` | Empty | Fully real. Idle install: 27 detectors served, both aggregation windows genuinely empty. |
| `03-populated.png` | Populated | Catalogue and redaction figure real; the two aggregation responses supplied — see below. |
| `04-error.png` | Error | `/scrub/patterns` forced to `503`; every other request still hit the running gateway. |
| `05-populated-dark.png` | Populated, dark | Same as `03` with the theme toggled (ADR 0027 contrast pass). |

## Why the populated state is not fully live

`secret_detected` alerts are the sole input to `/scrub/pattern-counts` and
`/scrub/posture`. They are written only by the gRPC `PolicyServiceImpl` when the
credential scanner fires (`aa-gateway/src/alerts.rs`), into an **in-memory**
store. `aa-api-server`'s `serve_local` serves the REST surface plus the gRPC
`AgentLifecycleService` only — it does not serve `PolicyService` — so **no HTTP
path on this install can create one**. The two aggregation responses in `03`/`05`
are therefore supplied at the network layer, in the exact shape the handler
emits; the catalogue, the fleet redaction figure, the auth, and the rendering are
all real.

`02` and `04` are the states this install can produce natively, and both are
fully live.

## Checks

- Console on a clean load: **0 errors, 0 warnings**.
- Failed requests: **none**.
- All seven `/api/v1/*` calls returned `200`, including
  `/scrub/patterns`, `/scrub/pattern-counts?range=24h` and
  `/scrub/posture?range=30d`.
