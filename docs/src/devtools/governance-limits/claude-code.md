# Claude Code — Governance Capability Matrix

> **Superseded.** The maintained, evidence-cited matrix is
> `docs/src/governance/capability-matrix.md`, which renders as part of the book.
> This page does not render and is kept only for the `aa-devtool-saas` source
> comments that reference this directory. Where the two disagree, the rendered
> matrix wins.

**Governance level:** L2Enforce  
**Detection:** `which claude` / `~/.claude` directory marker  
**MCP support:** Yes  
**Managed settings:** Yes

| Capability | Status | Reason |
|---|---|---|
| network deny | Yes | Managed settings + proxy both enforce network egress deny rules |
| network allowlist | Yes | Managed settings + proxy both enforce allowlist |
| file read | Partial — eBPF | Proxy cannot inspect local filesystem operations; eBPF uprobes are the only enforcement path |
| file write | Partial — eBPF | Same as file read — eBPF only |
| process spawn | Partial — eBPF | eBPF tracepoint on `sched_process_exec` is the detection path; SDK does not govern spawns directly |
| MCP allowlist | Yes | The adapter writes `enabledMcpjsonServers` / `disabledMcpjsonServers` into the managed `settings.json` (`aa-devtool-claude-code/src/apply.rs`) — not a separate `mcp_servers.json` |
| sub-agent lineage | **No (L0)** | Claude Code sub-agents are not registered, get no topology entry and no per-child policy scope — see `docs/src/governance/capability-matrix.md`. No SDK is embedded in Claude Code |
| prompt redaction | Yes | Proxy intercepts all outbound API traffic and applies redaction rules |
| response redaction | Yes | Proxy intercepts all inbound API responses |
| budget enforcement | Yes | Gateway tracks spend per agent via SDK-emitted cost events |
| audit ingestion | Yes | SDK emits structured events to the gateway at every action boundary |

## Notes

Claude Code declares `L2Enforce`, the same static ceiling as the Codex, Copilot
and Windsurf adapters. No adapter declares `L3Native`, and no Agent Assembly SDK
is embedded into Claude Code — governance is applied through managed settings,
the intercepting proxy and (on Linux) eBPF.

`GovernanceLevel` is a static, self-declared ceiling in any case. What is
actually protecting a Claude Code install, and the evidence for it, comes from
the protection ladder reported by `aasm integrations status` — see
`docs/src/devtools/protection-levels.md`.
