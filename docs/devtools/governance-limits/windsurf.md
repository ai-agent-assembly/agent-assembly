# Windsurf Cascade — Governance Capability Matrix

> **Superseded.** The maintained, evidence-cited matrix is
> `docs/src/governance/capability-matrix.md`, which renders as part of the book.
> This page does not render and is kept only for the `aa-devtool-saas` source
> comments that reference this directory. Where the two disagree, the rendered
> matrix wins.

**Governance level:** L2Enforce  
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

Windsurf declares `L2Enforce` (`aa-devtool-windsurf/src/lib.rs`), the same
static ceiling as every other in-tree adapter. `GovernanceLevel` is a
self-declared ceiling, not a measurement. Unlike Copilot, Windsurf has a CLI
binary that can be wrapped for governance wiring, enabling lineage injection and
proxy routing for command-line launches. GUI launches from the application
bundle bypass this path. eBPF provides filesystem and process observability on
Linux. A managed-settings surface — the thing that would let the declared
ceiling be substantiated the way Claude Code's is — is still not available in
Windsurf (tracked in AAASM-204).
