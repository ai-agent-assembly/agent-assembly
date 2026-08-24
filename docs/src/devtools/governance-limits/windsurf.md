# Windsurf Cascade — Governance Capability Matrix

> **Superseded.** The maintained, evidence-cited matrix is
> [L0-L3 Capability Matrix](../../governance/capability-matrix.md). This page
> predates that consolidated matrix and is retained only as legacy detail —
> not, as an earlier revision of this page claimed, because any
> `aa-devtool-saas` source comment references this directory (none do; that
> claim was wrong and has been removed). Where the two disagree, the rendered
> matrix wins.

**Governance level:** L2Enforce  
**Detection:** `which windsurf` / `/Applications/Windsurf.app` (macOS) / `~/.local/share/windsurf` (Linux)  
**MCP support:** Yes  
**Managed settings:** Yes (`~/.codeium/windsurf/admin_settings.json`)

| Capability | Status | Reason |
|---|---|---|
| network deny | Partial — proxy | Proxy intercepts outbound Windsurf API traffic when configured as system proxy |
| network allowlist | Partial — proxy | Same as network deny — proxy-only |
| file read | Partial — eBPF | eBPF kprobes on `openat` detect file reads on Linux |
| file write | Partial — eBPF | eBPF kprobes on `write` / `unlink` detect file writes |
| process spawn | Partial — eBPF | eBPF `sched_process_exec` tracepoint detects spawned processes |
| MCP allowlist | Yes | `apply_mcp_governance` writes the disabled-server list (explicit denies, plus any configured server not on a non-empty allowlist) into `mcp.disabled_servers` in the admin settings file (`aa-devtool-windsurf/src/lib.rs`) |
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
Linux. Windsurf **does** have a managed-settings surface —
`generate_managed_settings` / `apply_settings` write terminal command
allowlists and the MCP disabled-server list to `admin_settings.json` — closing
the gap noted in an earlier revision of this page (AAASM-204 shipped this).
It governs MCP servers and terminal-exec allowlisting only; file-write and
network-egress enforcement still require `aa-proxy`.

**AAASM-5644:** `aa-proxy` interception additionally requires the Windsurf
process to trust the Agent Assembly CA, and no launch-time mechanism
establishes that for Windsurf. Windsurf is Electron (a VS Code fork): traffic
splits across Chromium's own net stack (majority) and Node (extension host).
`NODE_EXTRA_CA_CERTS` is documented-unreliable for Electron's Chromium stack
(open upstream Electron/Chromium issues), and Windsurf's own docs expose no
CA-trust env var or setting. The only trust path that does work is OS-level —
`aa-proxy` installs its CA into the system trust store independently of any
adapter — so proxy interception of Windsurf traffic depends on that, not on
anything `aa-devtool-windsurf` can inject per-launch.
