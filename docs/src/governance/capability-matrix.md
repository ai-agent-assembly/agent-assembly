# L0–L3 Governance Capability Matrix

This document defines the four governance tiers used across all AI Agent Assembly dev-tool adapters
and declares the tier attained by each supported tool for each capability dimension. It is the
single source of truth for "what does L2 mean for this tool" — adapter implementation Stories
reference this document rather than defining tiers ad hoc.

> **Status:** Codex, GitHub Copilot, and Windsurf Cascade tiers are final (adapters merged).
> The Claude Code row is now filled from measured evidence — the `AAASM-5276` mechanism matrix
> plus the adapter productized in `AAASM-5281` — and is the only row backed by a Spike rather
> than by an adapter's own declaration. The SaaS coding-agent (`AAASM-918`) row remains a
> placeholder.

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

> **Why the per-capability rows above were left unchanged when `AAASM-5274` normalised Copilot's
> overall level to `L2Enforce`.** `AAASM-5274` §3 resolved the *tool-wide* `governance_level()`
> declaration in favour of the dedicated `aa-devtool-copilot` crate (`L2Enforce`) over the deleted
> minimal stub (`L1Observe`). That same section states explicitly that `governance_level()` is the
> tool's **overall** declaration and that per-capability tiers belong in this matrix — the two are
> not the same number, which is why Codex declares `L2Enforce` overall while holding L3 on three
> dimensions. Raising the rows here would require per-capability evidence for Copilot, and no
> Copilot Spike exists: unlike Claude Code, its tiers come from the adapter's own declarations. The
> rows therefore stay as `AAASM-1064` set them, and the inconsistency is recorded here rather than
> resolved by a guess. A Copilot equivalent of `AAASM-5276` is what would settle it.

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

> **Adapter:** `aa-devtool-claude-code` (`AAASM-201` implementation, productized by `AAASM-5281`) ·
> **Mechanism:** managed settings + proxy CA trust injection + MitM interception + MCP governance ·
> **Overall declared `governance_level()`:** **`L2Enforce`** (`aa-devtool-claude-code/src/lib.rs`)

The overall declaration was resolved by `AAASM-5274` §3. Claude Code writes **native** managed
settings, which is an L3-shaped capability, but it cannot natively enforce exec, file or network
policy — those still require `aa-proxy` (Layer 2). A tool-wide `L3Native` would therefore
over-claim, while individual dimensions below genuinely reach L3. This is the same shape as Codex,
which declares `L2Enforce` overall while achieving L3 on individual capabilities.

| Capability | Tier | Notes |
|---|---|---|
| Audit log capture | **L2** | The managed launch injects `AA_AGENT_ID` / `AA_TEAM_ID` into the child process, so actions are attributable (`aa-devtool-claude-code/src/lib.rs`, `build_launch_command`). `AAASM-5276` measured one headless `claude -p` run producing **four** upstream requests — two `/v1/messages` POSTs, an MCP-registry `GET` and a 130 KB `POST /api/event_logging/v2/batch` telemetry payload — and **all four** traversed the proxy and passed through the scanner. Not L3: nothing written into Claude Code's own config keeps emitting audit events, and an **unmanaged launch emits nothing** (measured). |
| Policy decision visibility | **L2** | Policy is evaluated by the runtime on intercepted traffic; the decision and the evidence behind it are surfaced by `aasm integrations status`, split into *exercised* and *read-back*. Requires the core to be running and is **re-derived on read, never cached** — `AAASM-5276` measured ~0.07 ms from core stop to connections being refused. |
| MCP server allowlist | **L3** | `apply_mcp_governance_at` writes `enabledMcpjsonServers` / `disabledMcpjsonServers` into Claude Code's **own** `settings.json`, idempotently and preserving every unmanaged key (`aa-devtool-claude-code/src/apply.rs`; idempotence and preservation measured in `AAASM-5276` scenarios 11.1–11.2). Those keys cap what the tool loads at startup whether or not Agent Assembly is running. Bounded: at `user`/`project` scope the file is user-writable, so this **constrains, it does not prevent**. |
| Terminal-exec block | **L3‡** | Policy rules are mapped to `permissions.allow` / `permissions.deny` tool patterns (e.g. `Bash`) and to `permissionMode` (`plan` / `default` / `acceptEdits`) and written into the tool's own config (`aa-devtool-claude-code/src/settings.rs`, `apply.rs`). ‡ **The write path was measured; a block was never exercised** — `AAASM-5276` classified managed settings as tool-governance and measured only their idempotence and footprint. Fully overridden by `bypassPermissions` or `--dangerously-skip-permissions`, which are **detected, not prevented**. |
| File-write block | **L3‡** | Same mechanism and the same ‡ caveat: `Edit` / `Write` tool patterns land in the same two managed keys, and the same permission-mode bypass switches them off wholesale. |
| Network-egress block | **L2** | The strongest measured dimension. `aa-proxy` MitM with the CA injected via `NODE_EXTRA_CA_CERTS` intercepted 4/4 real-binary requests; the scanner matched the synthetic secret and the forwarded body carried `[REDACTED:AnthropicKey]` while remaining valid Messages JSON, at sub-millisecond added cost. Interception is scoped per-integration to `api.anthropic.com` / `*.anthropic.com` so the binary's side channels are covered without flipping `llm_only` globally. Not L3: Claude Code exposes no native network-restriction config, and enforcement ends when the core stops. |
| Sub-agent governance | **L0** | Nothing in the adapter handles sub-agents: the managed launch injects **one** `AA_AGENT_ID` per process, and there is no registration, topology entry or per-child policy scope. Sub-agent model traffic is covered *incidentally* because it shares the launched process's proxy environment — that is egress coverage, not sub-agent governance, and claiming L1 would require them to appear in the topology tree. |

‡ **Declared from the write path, not from an exercised block.** The mechanism is native and
survives Agent Assembly going offline, which is what L3 denotes; the *effect* was not measured by
`AAASM-5276`, and the endpoint managed-settings keys that would make it non-overridable are
unmeasured (see below).

**Honest boundaries for Claude Code:**
- **No non-overridable-enforcement claim is made.**
  `/Library/Application Support/ClaudeCode/managed-settings.json` is root-owned; the Spike
  deliberately made no privileged writes, so its managed-only keys
  (`allowManagedPermissionRulesOnly`, `disableBypassPermissionsMode`, …) — the strongest available
  bypass counters — remain **unmeasured** (`AAASM-5276` condition C6). `--scope managed` is
  refused, and the path is resolved only so a refusal can name it. Measuring it on a managed macOS
  device is tracked by `AAASM-5298`.
- **`Gateway Protected` is not reportable on a default build.** The shipped `UnadjudicatedProbe`
  reports `Inconclusive` because a client on the near side of the proxy cannot see the forwarded
  body, so `aasm integrations verify claude-code` exits `6` and the level stays at `Integrated` —
  even though the interception itself was proven end-to-end. An adjudicating probe is *planned*.
  See [Limitations](../devtools/limitations.md#verify-cannot-adjudicate-so-it-exits-6).
- **All L2 dimensions require the managed launch.** A `claude` started directly inherits neither
  the proxy nor `NODE_EXTRA_CA_CERTS` and is unprotected — measured, not theoretical. Worse, it
  fails *silently*: a proxy that cannot terminate TLS still lets the connection through, which is
  why CA injection is a first-class, receipted plan step.
- **`ANTHROPIC_BASE_URL` redirection is unsuitable for protection.** Measured delivering the raw
  synthetic secret to the provider with **no Agent Assembly component in the path**. It is routing,
  not protection, and it is deliberately not offered as a mechanism.
- **Hooks carry no sensitive-data claim.** They govern tool and action execution and cannot see or
  modify model-bound prompt content.
- **Three bypasses are demonstrated and eleven more are inferred but undemonstrated.** The split is
  published in full at [Limitations](../devtools/limitations.md#known-bypasses-demonstrated-versus-inferred);
  neither list is asserted to be exhaustive.

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
| **Claude Code** | L2† | L2† | L3 | L3‡ | L3‡ | L2† | L0 |
| **SaaS Coding-Agent** | L1 | L1 | L0 | L0 | L0 | L0 | L0 |

† These capabilities require `aa-proxy` (Layer 2) running alongside the tool for enforcement.
Without the proxy, the declared tier drops to L0 (discovery/inventory only). For Claude Code they
additionally require the **managed launch** (`aasm run claude`), which is what injects the proxy
environment and the CA trust the interception depends on.

‡ Declared from the native write path, not from an exercised block — see the Claude Code
declarations above.

Only the Claude Code row is backed by a measured Spike (`AAASM-5276`). Every other row states what
its adapter declares.

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

- `AAASM-199` — Agent Assembly SDK interception overview (`DevToolAdapter` trait + `GovernanceLevel` enum)
- `AAASM-201` — Claude Code adapter (`aa-devtool-claude-code`)
- `AAASM-5274` — DevTool reconciliation; resolved Claude Code's overall `governance_level()` to `L2Enforce`
- `AAASM-5276` — Claude Code lifecycle Spike; the measured evidence behind the Claude Code row
- `AAASM-5281` — Claude Code productization (CA trust injection, side-channel scoping, explicit scope)
- `AAASM-5298` — measure the endpoint managed-settings path on a managed macOS device (open)
- `docs/src/devtools/protection-levels.md` — `Integrated` / `Gateway Protected` / `Host Enforced`
- `docs/src/devtools/limitations.md` — demonstrated-versus-inferred bypasses and other honest limits
- `AAASM-202` — Codex adapter
- `AAASM-203` — GitHub Copilot adapter
- `AAASM-204` — Windsurf Cascade adapter
- `AAASM-206` — Governance level (L0–L3) classification in policy schema (`governance_level` field in `AgentRecord` and policy conditions)
- `AAASM-918` — SaaS coding-agent adapter (pending; will finalize SaaS row above)
- `docs/src/architecture/system-architecture.md` — Three-layer interception model
- `docs/src/policy-rbac.md` — RBAC role matrix for policy mutations
