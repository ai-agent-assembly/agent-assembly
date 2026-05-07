# Codex CLI — Governance Capability Matrix

**Governance level:** L2Enforce  
**Detection:** `which codex` / `~/.npm/bin/codex`  
**MCP support:** No  
**Managed settings:** Yes (`.codex/config.toml`)

| Capability | Status | Reason |
|---|---|---|
| network deny | Yes | Proxy intercepts and blocks outbound connections matching deny rules |
| network allowlist | Yes | Proxy enforces allowlist for all Codex API traffic |
| file read | Partial — eBPF | No SDK integration; eBPF kprobes on `openat` are the only path |
| file write | Partial — eBPF | Same as file read — eBPF only |
| process spawn | Partial — eBPF | eBPF `sched_process_exec` tracepoint detects spawned processes |
| MCP allowlist | No | Codex does not expose MCP server configuration; no governance surface |
| sub-agent lineage | Partial — proxy | No SDK; `AA_AGENT_ID` can be injected as an env var via the wrapper launch command |
| prompt redaction | Yes | Proxy intercepts all outbound Codex API calls and applies redaction |
| response redaction | Yes | Proxy intercepts all inbound responses |
| budget enforcement | Yes | Gateway tracks spend via proxy-observed request/response pairs |
| audit ingestion | Partial — proxy | HTTP-level action events only; no SDK-level semantic events |

## Notes

Codex reaches L2Enforce because the proxy can enforce allow/deny and redaction
without requiring SDK adoption. The `.codex/config.toml` managed-settings surface
lets the adapter push policy without modifying the tool binary. eBPF fills the
file-system and process-spawn gaps that the proxy cannot observe.
