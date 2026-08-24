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
| network deny | Partial — sandbox only | `build_launch_command` sets proxy env vars but injects no CA-trust variable, so the proxy MitM handshake fails and traffic tunnels through uninspected (AAASM-5644/AAASM-5856); the Codex sandbox's own native `blocked_domains` is the enforcement actually in effect |
| network allowlist | Partial — sandbox only | Same gap as network deny — proxy allowlisting requires the same unestablished CA trust |
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

**AAASM-5644/AAASM-5856:** the proxy-dependent rows above (network deny/
allowlist, prompt/response redaction, budget enforcement) previously read
`Yes`, on the assumption that setting `HTTPS_PROXY`/`HTTP_PROXY` was
sufficient. It is not — the proxy can only enforce or redact what it
decrypts, and decrypting requires Codex to trust the Agent Assembly CA, which
nothing in `build_launch_command` establishes. Unlike Windsurf, Codex is
fixable (`CODEX_CA_CERTIFICATE`/`SSL_CERT_FILE`, a native mechanism its own
`reqwest`/rustls stack reads), tracked in AAASM-5856. Until that lands, the
sandbox's native `allowed_domains`/`blocked_domains` config is the real
enforcement for network deny/allowlist; nothing currently substitutes for the
proxy on redaction or budget enforcement.
