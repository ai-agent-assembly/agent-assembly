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
