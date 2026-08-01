# Claude Code — Governance Capability Matrix

> **Superseded.** The maintained, evidence-cited matrix is
> [L0-L3 Capability Matrix](../../governance/capability-matrix.md). This page
> predates that consolidated matrix and is retained only as legacy detail —
> not, as an earlier revision of this page claimed, because any
> `aa-devtool-saas` source comment references this directory (none do; that
> claim was wrong and has been removed). Where the two disagree, the rendered
> matrix wins.

**Governance level:** L2Enforce  
**Detection:** `which claude` / `~/.claude` directory marker  
**MCP support:** Yes  
**Managed settings:** Yes

| Capability | Status | Reason |
|---|---|---|
| network deny | Yes | Proxy (`aa-proxy`) intercepts and enforces network egress deny rules for the managed launch; Claude Code's managed settings carry no network-restriction keys, only `permissions.*` tool patterns and MCP allow/deny lists (`aa-devtool-claude-code/src/apply.rs`) |
| network allowlist | Yes | Same as network deny — proxy-only; managed settings have no native network-allowlist config |
| file read | Partial — eBPF | Proxy cannot inspect local filesystem operations; eBPF uprobes are the only enforcement path |
| file write | Partial — eBPF | Same as file read — eBPF only |
| process spawn | Partial — eBPF | eBPF tracepoint on `sched_process_exec` is the detection path; no SDK is embedded in Claude Code to govern spawns directly |
| MCP allowlist | Yes | The adapter writes `enabledMcpjsonServers` / `disabledMcpjsonServers` into the managed `settings.json` (`aa-devtool-claude-code/src/apply.rs`) — not a separate `mcp_servers.json` |
| sub-agent lineage | **No (L0)** | Claude Code sub-agents are not registered, get no topology entry and no per-child policy scope — see the [L0-L3 Capability Matrix](../../governance/capability-matrix.md). No SDK is embedded in Claude Code |
| prompt redaction | Yes | Proxy intercepts all outbound API traffic and applies redaction rules |
| response redaction | Yes | Proxy intercepts all inbound API responses |
| budget enforcement | Yes | Gateway tracks spend from proxy-observed request/response pairs for the managed launch — no SDK is embedded to emit cost events directly |
| audit ingestion | Yes | The managed launch injects `AA_AGENT_ID` and the proxy captures every intercepted request for that process (measured: two `/v1/messages` POSTs, an MCP-registry GET and a telemetry POST for one headless run — `AAASM-5276`); there is no SDK-level semantic event stream |

## Notes

Claude Code declares `L2Enforce`, the same static ceiling as the Codex, Copilot
and Windsurf adapters. No adapter declares `L3Native`, and no Agent Assembly SDK
is embedded into Claude Code — governance is applied through managed settings,
the intercepting proxy and (on Linux) eBPF.

`GovernanceLevel` is a static, self-declared ceiling in any case. What is
actually protecting a Claude Code install, and the evidence for it, comes from
the protection ladder reported by `aasm integrations status` — see
[Protection Levels](../protection-levels.md).
