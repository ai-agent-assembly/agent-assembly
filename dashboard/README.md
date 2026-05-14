# Agent Assembly Dashboard

Web-based governance console for the Agent Assembly platform.

Built with Vite + React 19 + TypeScript. Communicates with `aa-api` (port 8080) via the `/api/*` proxy.

## Requirements

- Node.js ≥ 20
- pnpm ≥ 10

## Setup

```bash
pnpm install
```

## Development

```bash
# Start dev server at http://localhost:3000 (proxies /api/* to http://localhost:8080)
# `pnpm start` is an alias for the same command.
pnpm dev

# Type-check without emitting
pnpm type-check

# Lint
pnpm lint
```

## Testing

```bash
# Run unit tests once
pnpm test

# Watch mode
pnpm test:watch

# Coverage report
pnpm test:coverage
```

## Build

```bash
# Type-check + Vite production build → dist/
pnpm build
```

## Serving the built dashboard locally

After `pnpm build` produces `dist/`, you can serve it directly with Vite's preview server:

```bash
# Serve dist/ at http://localhost:3000 (fails loudly if 3000 is taken)
pnpm serve
```

This is the production-build counterpart to `pnpm dev` — useful for smoke-testing the bundle without going through the `aasm` CLI.

## Serving via the embedded aasm CLI

For production-style serving with the `/api/*` proxy baked in, use the `aasm` CLI:

```bash
# Start the embedded SPA server (default port 3000)
aasm dashboard start

# Override the port
aasm dashboard start --port 4000

# Start and open the browser automatically
aasm dashboard start --open

# Port can also be set via environment variable
AASM_DASHBOARD_PORT=4000 aasm dashboard start
```

Other dashboard commands:

```bash
# Open the browser to a running dashboard (reads port from PID file)
aasm dashboard open

# Stop a running dashboard server
aasm dashboard stop
```

Dashboard config can also be set in `~/.aa/config.yaml`:

```yaml
dashboard:
  port: 4000       # default: 3000
  auto_open: true  # default: false
```

The server proxies `/api/*` requests to the configured gateway address
(default `http://localhost:8080`, overridden via `--api-url` or context config).

## API client

The typed client lives in `src/api/client.ts` and is generated from `../openapi/v1.yaml`.
To regenerate after an OpenAPI spec change:

```bash
pnpm generate:api
```

## Authentication

The dashboard reads an API token from `localStorage` key `aa_token` and sends it as
`Authorization: Bearer <token>` on every request. Navigate to `/login` to enter a token.

## Shared empty / error states

Pages that fetch async data must use the shared surfaces in `src/components/states/`
so empty and error UIs stay consistent across the dashboard:

```tsx
import { EmptyState, ErrorState } from '../components/states'

<EmptyState
  title="No policies yet"
  description="Create your first policy to get started."
  action={<Link to="/policies/editor">New policy →</Link>}
/>

<ErrorState
  title="Failed to load policies"
  description="The gateway returned an error."
  onRetry={refetch}
/>
```

Both components consume only design tokens from `src/styles.css`; do not pass
inline color or spacing styles.

## Live Ops page

The Live Ops page (`/live`) renders the realtime governance pipeline in three zones:
the traffic-flow canvas, the `tail -f` event stream, and the pending-approvals pool.
The page subscribes to `GET /api/v1/ws/events?types=violation&token=<jwt>` via
`useLiveOpsStream` (`src/features/liveOps/useLiveOpsStream.ts`), projects each
incoming event into a 100-op ring (most-recent-first), and reconnects with
exponential backoff (250 ms → 8 s cap, 5 attempts) before transitioning to an
`error` state that exposes a manual `reconnect()` escape hatch surfaced as the
`ErrorState`'s retry button. Filtering, freezing the stream (auto-scroll
toggle), inline call-stack expansion, and the per-row action menu are
implemented across `OperationRow`, `FilterBar`, `AutoScrollToggle`,
`PipelineCanvas`, and `ApprovalPool` under `src/features/liveOps/`.

Row actions POST against the following per-op endpoints — wired client-side
through `src/features/liveOps/actions.ts` with an optimistic `OperationOverride`
that is cleared on the next matching WS event or rolled back via a toast on
rejection:

- `POST /api/v1/ops/{id}/pause`     — running → blocked
- `POST /api/v1/ops/{id}/resume`    — blocked → running
- `POST /api/v1/ops/{id}/terminate` — any → completing (gated behind a
  `ConfirmDialog` danger variant)

The gateway-side handlers for those three endpoints are not yet shipped; until
[AAASM-1401](https://lightning-dust-mite.atlassian.net/browse/AAASM-1401)
lands, a real 404 exercises the dashboard rollback path. The page-level
optimistic state machine lives in `LiveOpsPage` and is covered by
`LiveOpsPage.actions.test.tsx`.

Design source: `../design/v1/hi-fi/live-ops.jsx`.

## Design reference

Hi-fi prototypes are in `../design/v1/hi-fi/`. Open `index.html` directly in a browser.
