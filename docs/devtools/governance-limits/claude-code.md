# Claude Code — Governance Capability Matrix

**Governance level:** L3Native  
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
| MCP allowlist | Yes | Managed settings surface (`~/.claude/mcp_servers.json`) is governed by the adapter |
| sub-agent lineage | Yes | SDK integration injects `AA_AGENT_ID`; gateway maintains the full lineage tree |
| prompt redaction | Yes | Proxy intercepts all outbound API traffic and applies redaction rules |
| response redaction | Yes | Proxy intercepts all inbound API responses |
| budget enforcement | Yes | Gateway tracks spend per agent via SDK-emitted cost events |
| audit ingestion | Yes | SDK emits structured events to the gateway at every action boundary |

## Notes

Claude Code is the only currently supported tool that reaches L3Native governance
because the Agent Assembly SDK is embedded via the Claude Code managed-settings
integration. All proxy and eBPF layers stack on top of the SDK for defence in depth.
