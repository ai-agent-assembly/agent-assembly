# Dashboard

Agent Assembly ships two governance consoles. Both are read/observe surfaces over
the gateway — policy decisions are always made server-side.

| Console | Lives in | Talks to | Use when |
|---|---|---|---|
| **Web dashboard** | [`dashboard/`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/dashboard) | `aa-api` (HTTP, port 8080) | You want a browser UI for fleet health, policies, and audit. |
| **Terminal dashboard (TUI)** | `aasm dashboard` ([`aa-cli`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-cli)) | Gateway API | You want real-time monitoring from the terminal / over SSH. |

## Web dashboard

The community web UI is built with **Vite + React 19 + TypeScript**. It proxies
`/api/*` to `aa-api` on port 8080.

```bash
cd dashboard
pnpm install

# Dev server at http://localhost:3000, proxying /api/* to http://localhost:8080
pnpm dev

pnpm type-check   # type-check without emitting
pnpm lint         # lint
pnpm test         # unit tests (Vitest)
pnpm build        # production build → dist/
```

Requirements: Node.js ≥ 20 and pnpm ≥ 10. Start a gateway + `aa-api` first so
the `/api/*` proxy has a backend (see [CLI](cli.md) and the README quickstart).

## Terminal dashboard (TUI)

```bash
# Interactive TUI against the default context
aasm dashboard

# Against a named connection profile
aasm --context staging dashboard
```

The TUI renders fleet health, agents, approvals, and budget, refreshing in real
time. For a one-shot non-interactive snapshot use [`aasm status`](cli.md).
