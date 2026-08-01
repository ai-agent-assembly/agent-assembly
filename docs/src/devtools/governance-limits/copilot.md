# GitHub Copilot — Governance Capability Matrix

> **Superseded.** The maintained, evidence-cited matrix is
> `docs/src/governance/capability-matrix.md`, which renders as part of the book.
> This page does not render and is kept only for the `aa-devtool-saas` source
> comments that reference this directory. Where the two disagree, the rendered
> matrix wins.

**Governance level:** L2Enforce  
**Detection:** `~/.vscode/extensions/github.copilot-*` directory  
**MCP support:** No  
**Managed settings:** No

| Capability | Status | Reason |
|---|---|---|
| network deny | Partial — proxy | VS Code routes LLM calls through the host network; proxy can intercept if configured as system proxy |
| network allowlist | Partial — proxy | Same as network deny — proxy-only |
| file read | No | Copilot extension runs inside the VS Code sandbox; eBPF kprobes require root and are unreliable on macOS |
| file write | No | Same as file read — no viable enforcement path without root on most developer machines |
| process spawn | No | VS Code extension lifecycle is opaque; no spawn hook available |
| MCP allowlist | No | Copilot does not expose MCP server configuration to external governance tools |
| sub-agent lineage | No | No CLI wrapper available; VS Code extension lifecycle is not observable via the agent identity flow |
| prompt redaction | Partial — proxy | Proxy can intercept and redact if configured as system proxy |
| response redaction | Partial — proxy | Proxy can redact inbound responses |
| budget enforcement | Partial — proxy | Request-level token counting via proxy only; no semantic cost metadata |
| audit ingestion | Partial — proxy | HTTP-level events only; no action-level semantic audit |

## Notes

Copilot declares `L2Enforce` (`aa-devtool-copilot/src/lib.rs`), the same static
ceiling as every other in-tree adapter. `GovernanceLevel` is a self-declared
ceiling, not a measurement: what Copilot's integration can actually reach is
narrow, because it operates entirely as a VS Code extension with no CLI surface,
no managed-settings file, and no SDK integration path. The proxy is the only
layer that can observe and partially enforce policy. eBPF can observe file and
process activity only in privileged (root) environments on Linux — not
recommended for typical developer workstations.
