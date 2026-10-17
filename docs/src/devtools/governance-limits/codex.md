# Codex CLI — Governance Capability Matrix

> **Superseded.** The maintained, evidence-cited matrix is
> [L0-L3 Capability Matrix](../../governance/capability-matrix.md). This page
> predates that consolidated matrix and is retained only as legacy detail.
> Where the two disagree, the rendered matrix wins.

**Governance level:** L2Enforce  
**Detection:** `which codex` / `~/.npm/bin/codex`  
**MCP support:** No  
**Managed settings:** Yes (`~/.codex/config.toml`)

| Capability | Status | Reason |
|---|---|---|
| network deny | Partial — proxy | Codex 0.160.0 does not honor top-level `allowed_domains`/`blocked_domains` (AAASM-6330: `unknown configuration field` under `--strict-config`, ignored otherwise), so the adapter writes neither. Enforcement is `aa-proxy`-only, limited to `llm_only`-classified hosts. |
| network allowlist | Partial — proxy | Same correction and mechanism as network deny. |
| file read | Partial — eBPF | No SDK integration; eBPF kprobes on `openat` are the only path |
| file write | Partial — eBPF | Same as file read — eBPF only |
| process spawn | Partial — eBPF | eBPF `sched_process_exec` tracepoint detects spawned processes |
| MCP allowlist | No | Codex does not expose MCP server configuration; no governance surface |
| sub-agent lineage | Partial — proxy | No SDK; `AA_AGENT_ID` can be injected as an env var via the wrapper launch command |
| prompt redaction | Partial — proxy | Proxy CA trust established via `CODEX_CA_CERTIFICATE` (AAASM-5856); limited to `llm_only` hosts |
| response redaction | Partial — proxy | Proxy CA trust established via `CODEX_CA_CERTIFICATE` (AAASM-5856); limited to `llm_only` hosts |
| budget enforcement | Partial — proxy | Proxy CA trust established via `CODEX_CA_CERTIFICATE` (AAASM-5856); limited to `llm_only` hosts |
| audit ingestion | Partial — proxy | HTTP-level action events only; no SDK-level semantic events |

## Notes

Codex reaches L2Enforce declaratively via the `~/.codex/config.toml`
managed-settings surface (`aa-devtool-codex/src/lib.rs`, `apply_settings`),
which lets the adapter push `sandbox_mode` / `approval_policy` without
modifying the tool binary (it no longer writes `allowed_domains` /
`blocked_domains`: codex-cli 0.160.0 does not honor them and rejects them
under `--strict-config`, AAASM-6330; network egress rests on `aa-proxy`. A
`config.toml` written by an earlier version may still contain those two keys: the
adapter cannot tell its own legacy lines from yours, so it does not delete
them — remove them by hand if `codex --strict-config` rejects the file) —
this page named the file `.codex/config.toml` when first written, was
changed to `.codex/config.json` in a later correction to match the
adapter's actual (buggy) write path, and is back to `.toml` now that
AAASM-5336 fixed the adapter itself — the file the real `codex` CLI reads —
rather than editing the doc to match a wrong implementation a second time.
eBPF fills the file-system and process-spawn gaps that the proxy cannot
observe.

**AAASM-5644/AAASM-5856:** see the rendered matrix's Codex "honest boundaries"
section for the current, evidence-cited state of the proxy leg — the CA-trust
gap this section used to describe is closed. In short: prompt redaction,
response redaction, and budget enforcement above now read `Partial — proxy`,
not `Yes`, because coverage is limited to `llm_only`-classified hosts and the
evidence is a stand-in client, not the shipped `codex` binary; see the
rendered matrix for the full caveat and citation.
