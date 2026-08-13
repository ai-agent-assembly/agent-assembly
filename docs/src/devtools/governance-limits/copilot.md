# GitHub Copilot — Governance Capability Matrix

> **Superseded.** The maintained, evidence-cited matrix is
> [L0-L3 Capability Matrix](../../governance/capability-matrix.md). This page
> predates that consolidated matrix and is retained only as legacy detail —
> not, as an earlier revision of this page claimed, because any
> `aa-devtool-saas` source comment references this directory (none do; that
> claim was wrong and has been removed). Where the two disagree, the rendered
> matrix wins.

**Governance level:** L2Enforce  
**Detection:** `~/.vscode/extensions/github.copilot-*` directory  
**MCP support:** Yes  
**Managed settings:** Yes (VS Code user `settings.json`)

| Capability | Status | Reason |
|---|---|---|
| network deny | Partial — proxy | VS Code routes LLM calls through the host network; proxy can intercept if configured as system proxy |
| network allowlist | Partial — proxy | Same as network deny — proxy-only |
| file read | No | Copilot extension runs inside the VS Code sandbox; eBPF kprobes require root and are unreliable on macOS |
| file write | No | Same as file read — no viable enforcement path without root on most developer machines |
| process spawn | No | VS Code extension lifecycle is opaque; no spawn hook available |
| MCP allowlist | Yes | The adapter mutates the `chat.mcp.servers` object (removing denied entries, keeping only allowed ones when a non-empty allowlist is set) and forces `chat.mcp.requireApproval: "always"` when anything is denied, written into the VS Code user-settings file (`aa-devtool-copilot/src/lib.rs`, `apply_mcp_governance`) |
| sub-agent lineage | No | No CLI wrapper available; VS Code extension lifecycle is not observable via the agent identity flow |
| prompt redaction | Partial — proxy | Proxy can intercept and redact if configured as system proxy |
| response redaction | Partial — proxy | Proxy can redact inbound responses |
| budget enforcement | Partial — proxy | Request-level token counting via proxy only; no semantic cost metadata |
| audit ingestion | Partial — proxy | HTTP-level events only; no action-level semantic audit |

## Notes

Copilot declares `L2Enforce` (`aa-devtool-copilot/src/lib.rs`), the same static
ceiling as every other in-tree adapter. `GovernanceLevel` is a self-declared
ceiling, not a measurement. Copilot operates entirely as a VS Code extension
with no CLI surface and no SDK integration path, but it **does** write a
managed-settings file: `generate_managed_settings` / `apply_settings` merge
`github.copilot.enable`, `chat.tools.autoApprove`, `chat.agent.maxRequests`,
`chat.mcp.requireApproval` and `chat.mcp.deny` into the VS Code user
`settings.json`, preserving unrelated keys. That surface covers the MCP
allowlist row above; it does not extend to terminal-exec or file-write, which
still require `aa-proxy` (Layer 2) running alongside. eBPF can observe file
and process activity only in privileged (root) environments on Linux — not
recommended for typical developer workstations.
