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

## Design reference

Hi-fi prototypes are in `../design/v1/hi-fi/`. Open `index.html` directly in a browser.
