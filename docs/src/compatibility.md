# Version Compatibility Matrix

This document tracks which versions of `aa-runtime` are compatible with each SDK version. Update this file whenever any component version changes — see [CI enforcement](#ci-enforcement) below.

> **CI enforcement for SDK version changes is pending cross-repo CI integration.** Until then, SDK version bumps must be accompanied by a manual update to this file.

---

## Compatibility Matrix

| `aa-runtime` | Python SDK (`aa-ffi-python`) | Node.js SDK (`aa-ffi-node`) | Go SDK (`aa-ffi-go`) | Protocol Version |
|---|---|---|---|---|
| v0.0.1 | v0.0.1 ✓ | v0.0.1 ✓ | v0.0.1 ✓ | protocol/v1 |

**Legend:**
- ✓ Compatible — fully supported
- ⚠️ Partial — works with known limitations (see notes)
- ✗ Incompatible — do not use together

---

## Minimum Supported Runtime Version per SDK

| SDK | Minimum `aa-runtime` Version |
|---|---|
| Python SDK (`aa-ffi-python`) v0.0.1 | aa-runtime v0.0.1 |
| Node.js SDK (`aa-ffi-node`) v0.0.1 | aa-runtime v0.0.1 |
| Go SDK (`aa-ffi-go`) v0.0.1 | aa-runtime v0.0.1 |

---

## Supported Protocol Versions per Runtime

A runtime version may support multiple protocol versions to allow SDK upgrades without simultaneous runtime upgrades.

| `aa-runtime` Version | Supported Protocol Versions |
|---|---|
| v0.0.1 | protocol/v1 |

---

## CI Enforcement

A CI check (`compat-matrix-check`) enforces that this file is updated whenever version-carrying files change in a pull request.

**Currently enforced (monorepo scope):**
- `Cargo.toml` (workspace root)
- `crates/*/Cargo.toml` (all crate manifests)

**Deferred — pending cross-repo CI integration:**
- `sdk/python/pyproject.toml` (Python SDK)
- `sdk/node/package.json` (Node.js SDK)
- `sdk/go/go.mod` (Go SDK)

Until cross-repo CI exists, SDK version bumps require a **manual update** to this file before merging.

---

## How to Update This File

When bumping a component version:

1. Add a new row to the [Compatibility Matrix](#compatibility-matrix) table for the new version combination.
2. Update the [Minimum Supported Runtime Version](#minimum-supported-runtime-version-per-sdk) table if the minimum changes.
3. Update the [Supported Protocol Versions](#supported-protocol-versions-per-runtime) table if the runtime adds or drops protocol version support.
4. Commit the change in the same PR as the version bump.

See [versioning.md](versioning.md) for the full versioning and deprecation policy.

---

## Workspace changes (non-version bumps)

| PR / Ticket | Change | Compatibility impact |
|---|---|---|
| AAASM-107 | Added `conformance` workspace crate (test infrastructure, not shipped) | None — internal tooling only |
| AAASM-39 | Added `aa-ebpf-common` workspace crate (shared eBPF types, not shipped standalone) | None — internal shared types only |
| AAASM-37  | Added `aa-ebpf-common` workspace crate (no_std shared eBPF event types, not shipped as a public API) | None — internal kernel/userspace bridge only |
| AAASM-39 (impl) | Added exec tracepoint BPF programs, ProcessLineageTracker, ShellDetector, ExecLoader in `aa-ebpf` | None — kernel-level monitoring, not a public API |
| AAASM-64 | Added `aa-ffi-go` workspace crate (Go C-ABI staticlib bindings) | None — new FFI crate, no existing API changes |
| AAASM-936 | Added `examples/aa-devtool-sample-myeditor` workspace crate (sample `DevToolAdapter` impl + plugin authoring reference; `publish = false`) | None — example only, not shipped, depends on existing `aa-core` API surface |
| AAASM-971 | Added `aa-devtool-codex` workspace crate (OpenAI Codex CLI `DevToolAdapter` implementation; `detect()` + `governance_level()` wired in this PR; `generate_managed_settings`, `apply_settings`, `build_launch_command` land in AAASM-978/983/988) | None — new adapter crate, no changes to existing public APIs |
| AAASM-204 | Added `aa-devtool-windsurf` workspace crate (`DevToolAdapter` for Windsurf Cascade; L2 governance via admin settings + MCP registry control; `publish = false`) | None — new adapter crate, no changes to existing public API surface |
| AAASM-997 | Added `aa-devtool-copilot` workspace crate (`DevToolAdapter` for GitHub Copilot — VS Code extension detection, `publish = false`); added `semver` v1 dependency for latest-version selection | None — new adapter crate, no changes to existing public API surface |
| AAASM-1006 | Implemented MCP governance in `aa-devtool-copilot`: `list_mcp_servers()` reads `chat.mcp.servers` from VS Code `settings.json`; `apply_mcp_governance()` filters the server set (keep allowed, remove denied) and sets `chat.mcp.requireApproval: "always"` when deny list is non-empty; `build_launch_command()` returns `LaunchFailed` (Copilot is IDE-resident, not CLI-launchable) | None — implementation only within existing `aa-devtool-copilot` crate; no new crates, no existing public API changes |
| AAASM-946 | Added `aa-devtool-claude-code` workspace crate (`ClaudeCodeAdapter` — detection layer for Claude Code CLI; `publish = false` pending AAASM-201 completion) | None — new crate, no existing API surface changed; depends on existing `aa-core::DevToolAdapter` trait |
| AAASM-918 | Added `aa-devtool-saas` workspace crate (SaaS coding-agent `DevToolAdapter` for Claude.ai, ChatGPT, Cursor cloud; L1Observe governance; HMAC-SHA256 webhook signature verification; MCP allowlist advisory overlay for Claude.ai; `publish = false`) | None — new adapter crate, no changes to existing public APIs |
| AAASM-205 | Added `aa-devtool` workspace crate (`DiscoveryService` + built-in adapters for Claude Code, Codex, GitHub Copilot, Windsurf) | None — new crate, no existing API changes; `aa-api` and `aa-cli` gain a new optional dependency on it |
