# Limited-function self-host — docker-compose example

A sample **limited-function** self-host stack for Agent Assembly. It runs the
open-source enforcement services that ship a real image or build context in this
repository, wired to reflect the sidecar-interception dataflow.

> **Limited function, by design.** Per the owner policy (2026-06-21), self-hosting
> the open-source services is supported, but **complete functionality — the gateway
> brain, persistence, the HTTP/OpenAPI API, the operator dashboard, central agent
> registry, and team budgets — is SaaS-only.** This stack does not (and cannot)
> stand those up; they have no open-source image. See
> [`docs/src/usage-guide/self-hosting.md`](../../docs/src/usage-guide/self-hosting.md)
> for the full story.

## What this stack runs

| Service | Image / build | Profile | Port | Role |
|---|---|---|---|---|
| `aa-runtime` | `ghcr.io/ai-agent-assembly/aa-runtime:latest` | default | `8080` | Authoritative in-process enforcement sidecar |
| `agent-stub` | `alpine:latest` (placeholder) | default | — | Stand-in agent sharing the runtime's IPC socket |
| `aa-proxy` | built from `../../aa-proxy/Dockerfile` | `proxy` | `8899` | Optional egress-interception (MitM HTTPS) proxy |

Services that are **SaaS-only** (`aa-gateway`, `aa-api`, persistence, dashboard)
are intentionally absent — they have no open-source container image.

## Prerequisites

- Docker and Docker Compose v2
- An Agent Assembly API key (`AA_API_KEY`) — used by the agent stub

## Running the example

Default (runtime sidecar path):

```bash
AA_API_KEY=<your-key> docker compose up
```

`aa-runtime` starts, enforces locally from the mounted `../policy.toml`, exposes the
IPC socket at `/tmp/aa-runtime-my-agent-001.sock`, and serves health/metrics at
`http://localhost:8080`.

With the optional egress proxy:

```bash
AA_API_KEY=<your-key> docker compose --profile proxy up
```

This additionally **builds** `aa-proxy` from `../../aa-proxy/Dockerfile` and listens
on `:8899`.

## Local enforcement (no gateway)

In this limited-function stack `aa-runtime` runs with **no central gateway**. It
enforces from the policy file mounted at `/etc/aa/policy.toml` (`../policy.toml`).
To point it at a gateway instead, set `AA_GATEWAY_ENDPOINT` on the `aa-runtime`
service. See `../policy.toml` for the rule format.

## Agent placeholder

> **Python SDK not yet available.** The `agent-stub` service is an `alpine` placeholder.
> Replace it with your agent image once the Python SDK (`aa-sdk`) is published
> (tracked in AAASM-55). The socket mount and `AA_AGENT_ID` env var must be
> preserved in your replacement.

To swap in your own agent:

1. Replace the `agent-stub` service's `image:` with your agent image
   (or use `build: ./your-agent` to build locally).
2. Keep `AA_AGENT_ID` identical in both `aa-runtime` and your agent service.
3. Keep the `aa-runtime-socket` volume mount at `/tmp` — the IPC socket lives at
   `/tmp/aa-runtime-<AA_AGENT_ID>.sock`.

## About the optional `aa-proxy` profile

`aa-proxy` forwards governance decisions to the gateway and **fails closed** when
the gateway is unreachable. Because this stack has no open-source gateway image,
the proxy service sets `AA_PROXY_MCP_FAIL_OPEN=1` so it can start standalone for a
demo of the egress path. Remove that variable and set `AA_PROXY_GATEWAY_ENDPOINT`
to enforce through a (SaaS) gateway.

## Health check

```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
curl http://localhost:8080/metrics
```

## Tear down

```bash
docker compose down            # default profile
docker compose --profile proxy down
```
