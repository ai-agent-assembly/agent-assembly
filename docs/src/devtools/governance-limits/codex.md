# Codex CLI — Governance Capability Matrix

> **Superseded.** The maintained, evidence-cited matrix is
> [L0-L3 Capability Matrix](../../governance/capability-matrix.md). This page
> predates that consolidated matrix and is retained only as legacy detail.
> Where the two disagree, the rendered matrix wins.

**Governance level:** L2Enforce  
**Detection:** `which codex` / `~/.npm/bin/codex`  
**MCP support:** No  
**Managed settings:** Yes (`~/.codex/config.json`)

| Capability | Status | Reason |
|---|---|---|
| network deny | Yes — sandbox | `generate_managed_settings`/`apply_settings` (`aa-devtool-codex/src/lib.rs:219-279`) writes `blocked_domains` (via `sandbox.rs::network_block_list`) into `~/.codex/config.json` alongside `sandbox_mode`/`approval_policy`. The proxy leg is separately broken (see Notes) but does not affect this row — the sandbox enforces on its own. |
| network allowlist | Yes — sandbox | Same mechanism as network deny — `allowed_domains` synced to the sandbox config |
| file read | Partial — eBPF | No SDK integration; eBPF kprobes on `openat` are the only path |
| file write | Partial — eBPF | Same as file read — eBPF only |
| process spawn | Partial — eBPF | eBPF `sched_process_exec` tracepoint detects spawned processes |
| MCP allowlist | No | Codex does not expose MCP server configuration; no governance surface |
| sub-agent lineage | Partial — proxy | No SDK; `AA_AGENT_ID` can be injected as an env var via the wrapper launch command |
| prompt redaction | No | Depends on the same unestablished proxy CA trust as network deny/allowlist above (AAASM-5644/AAASM-5856) |
| response redaction | No | Same CA-trust gap — the proxy never sees a decrypted response to redact |
| budget enforcement | No | Gateway spend tracking is proxy-observed; with the tunnel uninspected, nothing is observed to track |
| audit ingestion | Partial — proxy | HTTP-level action events only; no SDK-level semantic events |

## Notes

Codex reaches L2Enforce declaratively via the `~/.codex/config.json`
managed-settings surface (`aa-devtool-codex/src/lib.rs`, `apply_settings`),
which lets the adapter push `sandbox_mode` / `allowed_domains` /
`blocked_domains` / `approval_policy` without modifying the tool binary — an
earlier revision of this page named the file `.codex/config.toml`, which does
not match the adapter's actual write path. eBPF fills the file-system and
process-spawn gaps that the proxy cannot observe.

**AAASM-5644/AAASM-5856:** prompt redaction, response redaction, and budget
enforcement above previously read `Yes`, on the assumption that setting
`HTTPS_PROXY` was sufficient. It is not — the proxy can only enforce or
redact what it decrypts, and decrypting requires Codex to trust the Agent
Assembly CA, which nothing in `build_launch_command` establishes. Unlike
Windsurf, Codex is fixable (`CODEX_CA_CERTIFICATE`/`SSL_CERT_FILE`, a native
mechanism its own `reqwest`/rustls stack reads), tracked in AAASM-5856. Until
that lands, nothing currently substitutes for the proxy on redaction or
budget enforcement. Network deny/allowlist are unaffected by this gap — they
run on the sandbox-native path above, not the proxy.
