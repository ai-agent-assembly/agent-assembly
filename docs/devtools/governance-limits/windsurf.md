# Windsurf Cascade — Governance Capability Matrix

**Governance level:** L1Observe  
**Detection:** `which windsurf` / `/Applications/Windsurf.app` (macOS) / `~/.local/share/windsurf` (Linux)  
**MCP support:** No  
**Managed settings:** No

| Capability | Status | Reason |
|---|---|---|
| network deny | Partial — proxy | Proxy intercepts outbound Windsurf API traffic when configured as system proxy |
| network allowlist | Partial — proxy | Same as network deny — proxy-only |
| file read | Partial — eBPF | eBPF kprobes on `openat` detect file reads on Linux |
| file write | Partial — eBPF | eBPF kprobes on `write` / `unlink` detect file writes |
| process spawn | Partial — eBPF | eBPF `sched_process_exec` tracepoint detects spawned processes |
| MCP allowlist | No | Windsurf MCP configuration is not accessible to external governance tools |
| sub-agent lineage | Partial — proxy | `AA_AGENT_ID` can be injected via a wrapper launch command; not available for GUI launches |
| prompt redaction | Partial — proxy | Proxy intercepts and redacts when configured |
| response redaction | Partial — proxy | Proxy intercepts and redacts inbound responses |
| budget enforcement | Partial — proxy | Request-level spend tracking via proxy only |
| audit ingestion | Partial — proxy | HTTP-level action events via proxy; no SDK-level semantic events |

## Notes

Windsurf reaches L1Observe. Unlike Copilot, it has a CLI binary that can be
wrapped for governance wiring, enabling lineage injection and proxy routing
for command-line launches. GUI launches from the application bundle bypass
this path. eBPF provides filesystem and process observability on Linux.
Full L2Enforce requires either a CLI wrapper or a managed-settings surface —
neither is currently available in Windsurf (tracked in AAASM-204).
