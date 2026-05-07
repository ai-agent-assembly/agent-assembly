# SaaS Coding-Agent Governance Limits

SaaS coding agents (Claude.ai, ChatGPT, Cursor cloud) run in opaque cloud
environments. This imposes hard limits on what Agent Assembly can govern:
in-process enforcement (L2/L3) is structurally impossible at the SaaS boundary.
All SaaS adapters are capped at `L1Observe`.

The table below documents each capability per provider so operators can set
accurate expectations and plan compensating controls where needed.

| Provider | Capability | Status | Reason |
|---|---|---|---|
| Claude.ai | MCP allowlist | ✅ Supported | Workspaces API exposes MCP configuration |
| Claude.ai | System-prompt overlay | ⚠️ Partial | Can prepend governance note; operator must apply manually |
| Claude.ai | Network egress deny | ❌ Unsupported | SaaS boundary; no network-layer hook |
| Claude.ai | L2 enforcement | ❌ Unsupported | SaaS boundary prevents in-process enforcement |
| ChatGPT | MCP allowlist | ❌ Unsupported | Enterprise API does not expose MCP configuration |
| ChatGPT | System-prompt overlay | ⚠️ Partial | Custom GPT system-prompt field; operator applies |
| ChatGPT | Network egress deny | ❌ Unsupported | SaaS boundary; no network-layer hook |
| ChatGPT | L2 enforcement | ❌ Unsupported | SaaS boundary prevents in-process enforcement |
| Cursor cloud | MCP allowlist | ❌ Unsupported | Audit webhook does not expose MCP config |
| Cursor cloud | System-prompt overlay | ❌ Unsupported | No system-prompt surface in audit webhook |
| Cursor cloud | Audit event ingestion | ✅ Supported | Signed audit webhook delivers all agent actions |
| Cursor cloud | L2 enforcement | ❌ Unsupported | SaaS boundary prevents in-process enforcement |

## Compensating controls

For capabilities marked ❌ Unsupported, operators should consider:

- **Network egress deny**: use the sidecar proxy (`aa-proxy`) or eBPF layer on
  the host machine that runs the SaaS agent's browser or desktop client.
- **L2 enforcement**: not possible at the SaaS boundary. Governance relies on
  webhook audit events and operator-applied configuration overlays.
- **MCP allowlist (ChatGPT, Cursor)**: use network-layer controls to restrict
  which MCP servers the agent host can reach.
