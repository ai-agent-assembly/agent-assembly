# L0–L3 Governance Capability Matrix

This document defines the four governance tiers used across all AI Agent Assembly dev-tool adapters
and declares the tier attained by each supported tool for each capability dimension. It is the
single source of truth for "what does L2 mean for this tool" — adapter implementation Stories
reference this document rather than defining tiers ad hoc.

> **Status:** Codex, GitHub Copilot, and Windsurf Cascade tiers are final (adapters merged).
> Claude Code (`AAASM-201`) and SaaS coding-agent (`AAASM-918`) rows are placeholders pending
> those adapters landing.

---

## Tier definitions

| Tier | Name | What AAASM can do |
|---|---|---|
| **L0** | **Discover** | Auto-inventory the tool: name, version, config file paths. No runtime hooks. AAASM knows the tool is present but cannot observe or affect its actions. |
| **L1** | **Observe** | Tool actions appear in the AAASM audit log. Policy rules are evaluated and results are visible to operators, but the tool is not blocked — it runs uninhibited. Provides real-time observability without enforcement. |
| **L2** | **Enforce** | Policy overlay is active. AAASM evaluates rules and blocks, redirects, or redacts violating actions while AAASM is running. The tool cannot bypass enforcement, but may operate without constraint if AAASM is offline. |
| **L3** | **Native Governed** | AAASM writes the tool's own native configuration (settings files, sandbox config, MCP registry). Governance is baked into the tool's startup state — even if AAASM goes offline, the last-written settings cap what the tool can do. Strongest enforcement tier. |

---

## Capability matrix

Rows are the seven governance capability dimensions. Columns are the four tiers.
A cell answers: *"At this tier, is this capability available?"*

| Capability | L0 Discover | L1 Observe | L2 Enforce | L3 Native Governed |
|---|---|---|---|---|
| **Audit log capture** | No | Yes — every action emits an audit event with agent attribution, timestamp, and tool context | Yes | Yes |
| **Policy decision visibility** | No | Yes — policy rules evaluated per action; results visible in dashboard and `aasm policy check` | Yes | Yes |
| **MCP server allowlist enforcement** | No | No — MCP server list is observed but not restricted | Yes — deny list enforced at proxy layer | Yes — allowed MCP server list written to tool's native config; tool cannot load unlisted servers at startup |
| **Terminal-exec block** | No | No | Yes — exec calls intercepted at proxy or SDK layer; blocked when policy says deny | Partial — depends on tool-native sandbox support; see per-tool declarations below |
| **File-write block** | No | No | Yes — file-write events evaluated by policy; violations blocked at proxy or SDK layer | Partial — depends on tool-native sandbox support; see per-tool declarations below |
| **Network-egress block** | No | No | Yes — outbound HTTPS intercepted by `aa-proxy`; hosts not in allowlist receive 403 | Partial — some tools support native network restrictions in their config; see per-tool declarations below |
| **Sub-agent governance** | No | Yes — spawned agents are registered and appear in the topology tree | Yes — child agents inherit parent's policy scope; budget shared | Yes — spawned agents are registered with governing tool's team ID at the native config level |

---

## Per-tool tier declarations

### Codex

> **Adapter:** `AAASM-202` (Done) · **Mechanism:** sandbox policy sync + approval alignment + wrapper integration

| Capability | Tier | Notes |
|---|---|---|
| Audit log capture | **L2** | Wrapper intercepts Codex API calls; audit events emitted for every tool invocation |
| Policy decision visibility | **L2** | Policy evaluated per call; decisions surfaced via `aasm topology` and dashboard |
| MCP server allowlist | **L3** | AAASM writes the Codex sandbox `allowed_mcp_servers` list at startup and on policy change |
| Terminal-exec block | **L3** | Codex sandbox natively restricts exec; AAASM syncs the allowed-commands list from policy |
| File-write block | **L3** | Codex sandbox file restrictions synced from AAASM policy (`allowed_paths`, `denied_paths`) |
| Network-egress block | **L2** | Proxy layer intercepts outbound HTTPS; Codex sandbox network restrictions also synced (belt-and-suspenders) |
| Sub-agent governance | **L2** | Sub-processes spawned by Codex register with AAASM via wrapper; inherit parent team policy |

**Honest boundaries for Codex:**
- If the user invokes Codex with `--no-sandbox`, all L3 enforcement is bypassed. AAASM detects this at L1 (audit event) but cannot enforce.
- Codex sandbox restrictions apply to the Codex subprocess only; they do not restrict processes Codex spawns via `subprocess.run()` unless the sandbox's exec allowlist is set correctly.
- Approval-queue flows require AAASM gateway to be reachable; offline mode defaults to the policy's `offline_action` (allow or deny).

---

### GitHub Copilot

> **Adapter:** `AAASM-203` (Done) · **Mechanism:** VS Code settings alignment + MCP governance

| Capability | Tier | Notes |
|---|---|---|
| Audit log capture | **L1** | VS Code extension telemetry hooks emit audit events for Copilot chat messages and inline suggestions |
| Policy decision visibility | **L1** | Policy decisions are visible in dashboard; enforcement is observability-only at this tier |
| MCP server allowlist | **L3** | AAASM writes `github.copilot.chat.mcp.enabled` and the allowed MCP server list to VS Code `settings.json` via the settings sync adapter |
| Terminal-exec block | **L0** | VS Code's extension API does not expose a hook to block terminal commands initiated by Copilot. Blocking requires proxy layer (Layer 2) running alongside. |
| File-write block | **L0** | VS Code extension API provides no file-write veto for inline edits. Observable via audit but not blockable at the extension level. |
| Network-egress block | **L1** | Proxy layer can intercept outbound HTTPS from the VS Code process; no native Copilot setting restricts outbound hosts. |
| Sub-agent governance | **L0** | Copilot does not expose a sub-agent spawning API that AAASM can intercept at the extension level. |

**Honest boundaries for GitHub Copilot:**
- Terminal-exec and file-write enforcement **require** `aa-proxy` (Layer 2) running as a system-level MitM. The VS Code extension adapter alone cannot provide L2+ enforcement for these capabilities.
- VS Code settings sync writes `settings.json` at the workspace level; a user can override at the user-settings level. Enterprise-grade enforcement requires VS Code managed device policies (outside AAASM scope).
- Network-egress block via proxy does not cover VS Code's built-in Copilot HTTPS calls unless the proxy CA is trusted by the VS Code process.

---

### Windsurf Cascade

> **Adapter:** `AAASM-204` (Done) · **Mechanism:** admin settings sync + MCP registry control

| Capability | Tier | Notes |
|---|---|---|
| Audit log capture | **L1** | Windsurf telemetry hooks emit audit events for Cascade tool calls and agent spawning |
| Policy decision visibility | **L1** | Policy evaluated and results visible; enforcement passive at this tier |
| MCP server allowlist | **L3** | AAASM writes the Windsurf MCP registry (`~/.codeium/windsurf/mcp_registry.json`) via admin settings sync; unlisted servers are not loaded at Windsurf startup |
| Terminal-exec block | **L1** | Cascade terminal actions are observable; no Windsurf-native exec block API exists. L2 blocking requires proxy layer. |
| File-write block | **L1** | File edits are observable in audit log; no Windsurf-native veto API. L2 blocking requires proxy layer. |
| Network-egress block | **L1** | Outbound HTTPS interceptable by proxy layer; no Windsurf-native network restriction config. |
| Sub-agent governance | **L1** | Windsurf Cascade multi-agent flows are observable; child agents appear in topology but do not inherit policy scope automatically without the SDK. |

**Honest boundaries for Windsurf Cascade:**
- Windsurf does not expose a sandbox mode. L2 enforcement for exec and file operations requires `aa-proxy` running at the system level.
- Admin settings sync requires Windsurf's config directory to be writable by the AAASM process. In multi-user environments, this requires elevated permissions or a per-user deployment.
- MCP registry control only governs MCP servers loaded by Windsurf at startup. A user can manually add servers to a workspace-level config that overrides the registry.

---

### Claude Code

> **Adapter:** `AAASM-201` — **Pending** (in backlog) · _Placeholder — do not rely on these declarations until AAASM-201 is merged_

| Capability | Tier | Notes |
|---|---|---|
| Audit log capture | TBD | — |
| Policy decision visibility | TBD | — |
| MCP server allowlist | TBD | — |
| Terminal-exec block | TBD | — |
| File-write block | TBD | — |
| Network-egress block | TBD | — |
| Sub-agent governance | TBD | — |

---

### SaaS Coding-Agent (Claude.ai / ChatGPT / Codex-web)

> **Adapter:** `AAASM-918` — **Pending** (in backlog) · _Placeholder — tier declarations incomplete_

| Capability | Tier | Notes |
|---|---|---|
| Audit log capture | **L1** | SaaS agents emit L0–L1 events via the observability adapter (browser extension or API-level hook); execution is remote and not fully inspectable |
| Policy decision visibility | **L1** | Policy decisions are visible but enforcement is not possible at the cloud execution layer |
| MCP server allowlist | **L0** | Cloud-hosted tools do not expose an MCP allowlist config that AAASM can control |
| Terminal-exec block | **L0** | Remote execution; no AAASM enforcement path |
| File-write block | **L0** | Remote execution; no AAASM enforcement path |
| Network-egress block | **L0** | Remote execution; egress is controlled by the SaaS provider, not AAASM |
| Sub-agent governance | **L0** | SaaS multi-agent orchestration is opaque; AAASM cannot intercept spawn events |

**Honest boundaries for SaaS coding-agents:**
- SaaS-hosted tools execute remotely. AAASM's enforcement capabilities (L2–L3) apply only to locally-running processes. This is a fundamental architectural limit, not a product gap.
- L1 observability is available only if the user installs the observability adapter (browser extension or API hook). Without it, even L1 is not available.
- These tools are out-of-scope for any enforcement stronger than L1 for v0.0.1.

---

## Summary table

| Tool | Audit | Policy Vis. | MCP Allowlist | Exec Block | File Block | Net Block | Sub-agent |
|---|---|---|---|---|---|---|---|
| **Codex** | L2 | L2 | L3 | L3 | L3 | L2 | L2 |
| **GitHub Copilot** | L1 | L1 | L3 | L0† | L0† | L1 | L0 |
| **Windsurf Cascade** | L1 | L1 | L3 | L1† | L1† | L1 | L1 |
| **Claude Code** | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| **SaaS Coding-Agent** | L1 | L1 | L0 | L0 | L0 | L0 | L0 |

† These capabilities require `aa-proxy` (Layer 2) running alongside the tool for enforcement.
Without the proxy, the declared tier drops to L0 (discovery/inventory only).

---

## Relationship to the three interception layers

The dev-tool adapter tier system is separate from but complementary to AAASM's three interception
layers (SDK / proxy / eBPF). The layers provide runtime enforcement regardless of which tool is
active; the adapter tiers describe what each specific tool's native API exposes:

| Layer | What it governs | Interaction with adapter tiers |
|---|---|---|
| **Layer 1 — SDK shim** (`aa-ffi-*`) | Agents that use the AAASM SDK explicitly | Provides L2 enforcement for SDK-aware tools independent of adapter tier |
| **Layer 2 — `aa-proxy`** | All outbound HTTPS from the machine | Provides L2 network/exec enforcement for any tool; fills gaps where adapter tier is L0 for exec/file/net |
| **Layer 3 — `aa-ebpf`** (Linux only) | SSL uprobes + exec/file syscalls at kernel level | Provides L1 detection + alerting for any tool; cannot modify traffic in flight (no redaction at this layer) |

In practice, for tools where the adapter tier is L0 or L1 for exec/file/network enforcement, deploying
`aa-proxy` alongside the tool upgrades effective enforcement to L2 for those dimensions without
requiring a new adapter.

---

## References

- `AAASM-199` — Agent Assembly SDK interception overview
- `AAASM-201` — Claude Code adapter (pending; will update Claude Code row above)
- `AAASM-202` — Codex adapter
- `AAASM-203` — GitHub Copilot adapter
- `AAASM-204` — Windsurf Cascade adapter
- `AAASM-918` — SaaS coding-agent adapter (pending; will finalize SaaS row above)
- `docs/src/architecture.md` — Three-layer interception model
- `docs/src/policy-rbac.md` — RBAC role matrix for policy mutations
