# Self-hosting (limited function)

You can self-host Agent Assembly's open-source enforcement services with the
sample Docker Compose stack in [`examples/docker-compose/`](https://github.com/ai-agent-assembly/agent-assembly/tree/master/examples/docker-compose).
This page explains what that stack does, what it deliberately does **not** do, and
how to bring it up.

## Limited function, by design

> **Complete functionality is SaaS-only.** Self-hosting via the open-source images
> is supported for the enforcement *data plane* only. The **control plane** — the
> gateway brain, persistence, the HTTP/OpenAPI API, the operator dashboard, the
> central agent registry, and team budgets — is provided exclusively through the
> hosted (SaaS) product.

What this means in practice:

| Capability | Self-host (this stack) | SaaS-only |
|---|---|---|
| In-process / sidecar enforcement (`aa-runtime`) | ✅ | |
| Local policy-file enforcement | ✅ | |
| Egress-interception proxy (`aa-proxy`, optional) | ✅ (demo) | |
| Gateway brain, central registry, policy evaluation service | | ✅ |
| Persistence (audit history, durable state) | | ✅ |
| HTTP/OpenAPI API + operator dashboard | | ✅ |
| Team budgets and cost tracking | | ✅ |

The control-plane services have **no open-source container image**, so the sample
stack intentionally omits them. It runs only the services this repository ships an
image or build context for.

## What the stack runs

The compose file (`examples/docker-compose/docker-compose.yml`) defines these
services. Values below are taken directly from that file.

| Service | Image / build | Compose profile | Published port | Role |
|---|---|---|---|---|
| `aa-runtime` | `ghcr.io/ai-agent-assembly/aa-runtime:latest` | default | `8080:8080` | Authoritative in-process enforcement sidecar (health + metrics) |
| `agent-stub` | `alpine:latest` (placeholder) | default | — | Stand-in agent sharing the runtime IPC socket |
| `aa-proxy` | built from `../../aa-proxy/Dockerfile` (context = repo root) | `proxy` | `8899:8899` | Optional egress-interception (MitM HTTPS) proxy |

### Volumes

| Volume | Mounted at | Purpose |
|---|---|---|
| `aa-runtime-socket` | `/tmp` (in `aa-runtime` and `agent-stub`) | Shared Unix domain socket — the IPC channel lives at `/tmp/aa-runtime-<AA_AGENT_ID>.sock` |
| `../policy.toml` (bind) | `/etc/aa/policy.toml` (read-only) in `aa-runtime` | Local enforcement policy |

### Environment variables

`aa-runtime`:

| Variable | Value in the stack | Meaning |
|---|---|---|
| `AA_AGENT_ID` | `my-agent-001` | Agent identity; **must match** `agent-stub`. Names the IPC socket. |
| `AA_POLICY_PATH` | `/etc/aa/policy.toml` | Path to the mounted local policy file. |
| `AA_METRICS_ADDR` | `0.0.0.0:8080` (default) | Bind address for the health/metrics HTTP server. |
| `AA_GATEWAY_ENDPOINT` | _(unset)_ | Left unset for standalone, gateway-less enforcement. Set it to call a (SaaS) gateway instead. |

`agent-stub`:

| Variable | Value in the stack | Meaning |
|---|---|---|
| `AA_AGENT_ID` | `my-agent-001` | Must equal the runtime's `AA_AGENT_ID`. |
| `AA_GATEWAY_URL` | `https://api.agentassembly.io` | SaaS gateway URL a real agent SDK would use. |
| `AA_API_KEY` | `${AA_API_KEY}` | Read from your shell environment. |

`aa-proxy` (only under the `proxy` profile):

| Variable | Value in the stack | Meaning |
|---|---|---|
| `AA_PROXY_ADDR` | `0.0.0.0:8899` | Proxy listen address. |
| `AA_PROXY_LLM_ONLY` | `false` | Intercept all egress, not just LLM calls. |
| `AA_PROXY_MCP_FAIL_OPEN` | `1` | **Demo only** — lets the proxy start without a gateway. The proxy normally fails **closed** when its gateway is unreachable. |
| `AA_PROXY_GATEWAY_ENDPOINT` | _(unset)_ | Set to a gateway endpoint (SaaS-only) to enforce through it. |

## Quickstart

From a clone of the repository:

```bash
cd examples/docker-compose

# Runtime sidecar path (default profile: aa-runtime + agent-stub)
AA_API_KEY=dev-local-key docker compose up
```

`aa-runtime` starts, enforces locally from `../policy.toml`, exposes the IPC socket
at `/tmp/aa-runtime-my-agent-001.sock`, and serves health/metrics on `:8080`:

```bash
curl http://localhost:8080/ready
curl http://localhost:8080/health
curl http://localhost:8080/metrics
```

To additionally build and run the optional egress proxy on `:8899`:

```bash
AA_API_KEY=dev-local-key docker compose --profile proxy up
```

Tear down when finished:

```bash
docker compose down
# or, if you started the proxy profile:
docker compose --profile proxy down
```

## Replacing the agent stub

`agent-stub` is an `alpine` placeholder (the Python SDK is not yet published —
tracked in AAASM-55). To run a real agent, replace its `image:` with your agent
image, keep `AA_AGENT_ID` identical to `aa-runtime`, and keep the
`aa-runtime-socket` volume mounted at `/tmp`. See the example's
[README](https://github.com/ai-agent-assembly/agent-assembly/blob/master/examples/docker-compose/README.md)
for details.

## When you need the full product

If you need the control-plane capabilities listed above — durable audit history,
the operator dashboard, central registry, team budgets, the HTTP/OpenAPI surface —
use the hosted (SaaS) product. Those services are not available as self-hostable
open-source images.
