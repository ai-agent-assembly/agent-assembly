# ADR 0030: Developer Integration Boundaries, Capability Model & Local Trust Model

**Status**: Proposed
**Date**: 2026-07
**Ticket**: [AAASM-5275](https://lightning-dust-mite.atlassian.net/browse/AAASM-5275)

This ADR fixes the architectural boundaries and the trust model for **Developer
Integrations** — the machinery by which AASM installs, verifies, repairs and removes
governance for a developer's AI coding tool (Claude Code, Codex, Copilot, Windsurf, a
SaaS coding agent) — *before* the shared lifecycle contract
([AAASM-5277](https://lightning-dust-mite.atlassian.net/browse/AAASM-5277)), the
plan/receipt model ([AAASM-5278](https://lightning-dust-mite.atlassian.net/browse/AAASM-5278))
and the local client API ([AAASM-5279](https://lightning-dust-mite.atlassian.net/browse/AAASM-5279))
are implemented against it. It is the contract those three tickets implement.

It **complements and does not supersede** [ADR 0002](0002-sdk-security-boundary.md)
(the SDK is not a security boundary; `aa-runtime` is the authoritative chokepoint),
[ADR 0004](0004-governance-enforcement-flow.md) (all client↔core *governance* traffic
goes through the single `aa-sdk-client` transport boundary; REST is the non-SDK
operator surface), [ADR 0015](0015-dlp-trust-boundary-and-redaction-semantics.md)
(fail-closed redaction, audit-visible resolution failures) and
[ADR 0029](0029-capability-over-permission-derivation.md) (capability is a structural,
declared-vs-effective property; fail-absent, never fabricate a grant).

---

## Context

### The four concepts that keep getting conflated

The product vision names several things that are easy to collapse into one another,
and every collapse produces a different security failure:

| Concept | What it actually is | The failure if conflated |
| --- | --- | --- |
| A **plugin / IDE extension / installer / CLI** | A user-facing shell distributed through a marketplace or a package manager. Untrusted code running as the developer. | If it carries policy or DLP logic, the guarantee is anchored in attacker-controllable code — the exact mistake ADR 0002 exists to prevent. |
| A **`DevToolAdapter` crate** | Per-tool knowledge: where the settings live, what the native config dialect is, how to wire a proxy. | If it is given the whole of `aa-core`, one under-reviewed adapter PR reaches identity, storage and gateway tokens (AAASM-3565). |
| An **integration mechanism** (managed settings, hooks, base URL, proxy, MCP) | One of several *optional* levers, each supported by a different subset of tools. | If MCP is treated as *the* plugin protocol, every non-MCP tool needs a misleading no-op, and the product is coupled to one vendor's extension model. |
| The **core runtime / gateway** | Policy evaluation, sensitive-data detection and redaction, approvals, audit. | If duplicated per plugin, N divergent policy engines with no single source of truth. |

### The constraint that forces the design: there is already a trust model in-tree

`aa-runtime` already runs a local IPC server, and its trust model is written down and
tested. Any new local surface must reuse it rather than invent a second one:

- **`aa-runtime/src/ipc/server.rs`** binds a `UnixListener` under a tightened
  `umask(0o077)` so the socket inode is `0600` *from the first instant* — the earlier
  bind→`chmod` sequence left a TOCTOU window (AAASM-3581). A test asserts
  `mode == 0o600`. Connections are semaphore-bounded and dispatched to a reader/writer
  task pair. The socket path is `/tmp/aa-runtime-{agent_id}.sock`
  (`IpcServerConfig::from_runtime_config`).
- **`aa-runtime/src/ipc/peercred.rs`** rejects any connection whose peer UID is not the
  runtime's own effective UID, portably (`SO_PEERCRED` on Linux,
  `getpeereid`/`LOCAL_PEERCRED` on macOS/BSD).
- **`aa-runtime/src/ipc/handshake.rs`** performs a per-session Ed25519 challenge over
  `nonce || sdk_version` (AAASM-3585 / AAASM-3666). Its module doc is explicit
  (AAASM-3922) that this is **not** an authentication secret:

  > The expected verifying key is derived deterministically from the configured
  > **agent id** … and the agent id is the UDS socket filename — a public, non-secret
  > identifier. Any local process that can reach the socket can recompute the same
  > keypair and produce a valid signature, so the signature proves *integrity and
  > version-binding*, not possession of a secret.
  >
  > The real trust boundary for the IPC channel is enforced elsewhere: the socket is
  > created with `0600` permissions, and the runtime checks the connecting peer's
  > credentials (peercred UID) against the expected owner.

  That distinction is load-bearing for this ADR. A per-client capability token that was
  derived from a public identifier would repeat exactly the mistake AAASM-3922 documented,
  and would be a regression rather than a new control.

### The compile-time boundary that already exists

`aa-devtool-contract` (AAASM-3565) is the **compile-time analogue of a restricted IPC
interface**. Adapters depend on it and never on `aa-core`; its module doc states that a
smuggled `aa_core::storage::…` call is *"a **compile error** in a plugin crate, not a
silent capability"*. The re-export list is deliberately flat and CODEOWNERS/security
reviewed: `DevToolAdapter`, `DevToolInfo`, `DevToolKind`, `GovernanceLevel`,
`McpServerInfo`, `AdapterError`, `EnforcementMode`, `PolicyDecision`, `PolicyDocument`,
`PolicyRule`, `Capability`, `CapabilitySet`, `AuditEntry`. Whatever this ADR adds must
stay inside that boundary and keep the widening reviewable.

### Why the current `DevToolAdapter` cannot carry the product

The only definition of the trait is `aa-core/src/dev_tool.rs:231-341`: `detect()`,
`generate_managed_settings()`, `apply_settings()`, `build_launch_command()`,
`list_mcp_servers()`, `apply_mcp_governance()`, `governance_level()`. Three structural
problems follow directly from that shape:

1. **Every mechanism is mandatory.** `aa-devtool-codex/src/lib.rs:312` implements
   `apply_mcp_governance` as `Ok(())` with the comment *"Codex does not expose MCP
   governance"*. A tool that cannot do a thing is forced to claim it can and then lie
   quietly.
2. **Unsupported capabilities fail at the wrong time.** `aa-devtool-copilot` returns
   `AdapterError::LaunchFailed("GitHub Copilot is a VS Code extension and cannot be
   launched by `aasm run`…")` — a *run-time* error for a fact that is knowable at
   *plan* time.
3. **There is no lifecycle at all.** No plan, no receipt, no verify, no drift, no repair,
   no remove. Nothing in the trait can answer "is this developer actually protected right
   now, and how do you know?".

### The registration model is build-time linking, and that is not an accident

`docs/devtools/plugins.md` is explicit:

> Right now Agent Assembly uses **build-time linking**… There is **no**
> `inventory::submit!`-style runtime registration in `aa-core` today, and there is no
> dynamic shared-library loading. Both were proposed in early designs but neither has
> been implemented; do not write code that assumes either exists.

This ADR turns that observation into a decision: build-time linking is the *chosen*
model, not a temporary gap (see Decision 6).

### Known current-state divergence (not fixed here)

Three disconnected Claude Code adapters exist today —
`aa-devtool/src/adapters/claude_code.rs` (detection-only, `L3Native`),
`aa-devtool-claude-code` (a full `L2Enforce` implementation, orphaned), and
`PlaceholderAdapter` in `aa-cli/src/commands/run.rs:124` (`L0Discover`, the one
`aasm run claude` actually uses) — and `GET /api/v1/tools` always returns `[]` because
`aa-api/src/state.rs:370` constructs `DiscoveryService::with_adapters(vec![])`.
Reconciling those is
[AAASM-5274](https://lightning-dust-mite.atlassian.net/browse/AAASM-5274), in flight on a
parallel branch. This ADR describes the target boundaries and assumes 5274 has produced
exactly one adapter per tool; it does not attempt the reconciliation.

### Threat model

The design must hold against three distinct adversaries, which want different answers:

| Adversary | Capability | What must still hold |
| --- | --- | --- |
| **A compromised or malicious thin client** (a trojaned marketplace extension, a supply-chained installer, a mis-scoped script) running as the developer's own UID | Can open the local socket, replay any request it has ever seen, and present any token it can read from the developer's home directory | It must not be able to obtain or shortcut a policy decision, forge agent events, read raw prompts/tool outputs or audit content, reach storage/identity, act on a tool it was not scoped to, or acquire a credential usable against the gateway |
| **An unrelated local user** on a shared host | Can enumerate `/tmp` and attempt to connect to any socket | It must not be able to connect at all — OS-enforced, not application-enforced |
| **A steered agent inside the trust boundary** (the ADR 0015 adversary) | Controls payload content, may attempt to make the product *report* protection it does not have | Protection state must never be reported higher than the evidence supports; missing evidence must lower the reported state, never raise it |

The developer's own UID is *not* an adversary: nothing here defends against a user who
edits their own settings file, and it is not supposed to. Host-level tamper prevention is
out of scope (it is an explicit non-goal of AAASM-5278).
