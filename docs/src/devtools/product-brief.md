# Developer Integrations — Product Capability Brief

This brief defines the **canonical Developer Integration experience**: how a developer installs
Agent Assembly protection into an AI development tool, what protection they get, what they
provably do *not* get, and how the experience fails. It is the product-level source of truth that
the lifecycle contract (`AAASM-5277`), the plan/receipt/rollback model (`AAASM-5278`), the local
integration API (`AAASM-5279`), the CLI surface (`AAASM-5280`) and the Claude Code
productization (`AAASM-5281`) all implement against.

> **Status:** product definition. Behaviour described here is either (a) grounded in code that
> exists today and cited as such, or (b) explicitly marked **_planned_** with the ticket that
> builds it. Nothing here should be read as a shipped capability unless it is cited to code.
>
> This document deliberately does **not** fill in the Claude Code row of the
> [L0–L3 Capability Matrix](../governance/capability-matrix.md) — that row stays `TBD` until
> `AAASM-5276` produces evidence and `AAASM-5284` publishes it.

---

## 1. Purpose and scope

### Why this document exists

The dev-tool governance work to date is organised around *technical* primitives: the
`DevToolAdapter` trait, per-tool adapter crates, the `aasm run` launcher, the gateway and the
proxy. Those primitives are necessary but they are not a product. A developer cannot currently
answer three questions without reading source code:

1. What do I run to become protected?
2. How do I know protection is actually *on*, as opposed to merely *configured*?
3. What is still able to leak?

Every one of those questions is a product question with a security consequence. Answering them
inconsistently per tool is how a governance product ends up over-claiming. This brief fixes the
answers once, at the product layer, so that every tool integration either implements them or
declares the gap explicitly.

### The thin-surface principle

> **Plugins, extensions and installers are thin integration and UX surfaces. The security core —
> policy evaluation, sensitive-data detection, redaction, approval, and audit — lives in Agent
> Assembly and is never reimplemented inside a plugin.**

This is a security boundary, not a code-organisation preference. A plugin runs inside a host
process that the user (and the agent under governance) can influence: it can be disabled,
downgraded, or fed a tampered configuration. If a plugin *decided* whether a secret may leave the
machine, the enforcement decision would sit inside the thing being governed. Instead:

| Concern | Owner | Why |
|---|---|---|
| Detecting the tool, planning changes, writing native config, rendering status | Integration surface (plugin / extension / CLI installer) | Host-specific, UX-shaped, non-authoritative |
| Policy evaluation and the resulting verdict | `aa-gateway` policy engine | Single decision point; auditable |
| Sensitive-data detection and redaction | `aa-security` scanner, driven authoritatively by `aa-runtime` | Must run where the tool cannot suppress it |
| Egress allow/deny on the wire | `aa-gateway` allowlist + `aa-proxy` | Enforced on decrypted traffic, no tool cooperation needed |
| Audit record of what happened | `aa-gateway` audit path | Written outside the governed process |

A corollary the whole document depends on: **an integration surface may never be the source of a
protection claim.** It reports what the core observed; it does not assert protection on the
core's behalf.

### In scope

- The persona set, entry points and end-to-end journey every tool integration must support.
- The user-visible protection profiles and protection levels, with testable definitions.
- Truthful guarantee and limitation copy, reusable verbatim by the CLI, a future UI and public docs.
- The MVP boundary and the non-goals that must not be quietly re-entered.
- The acceptance-test scenarios the `AAASM-5276` Spike is expected to satisfy.

### Out of scope

- Choosing the IPC transport between an integration client and the core (`AAASM-5279`).
- The concrete API/trait shape of the lifecycle contract (`AAASM-5275`, `AAASM-5277`).
- Implementing any CLI or plugin UI (`AAASM-5280`, `AAASM-5282`).
- Per-tool tier declarations — those belong in the
  [L0–L3 Capability Matrix](../governance/capability-matrix.md).

---

## 2. MCP is one optional tool capability, not the plugin architecture

**MCP is not the integration mechanism, and no integration is required to use it.** "Plugin" here
is a *product and distribution* concept — the thing a developer installs. MCP is one of several
*mechanisms* an integration may drive, and for several tools it is not the most useful one.

Conflating the two is a live risk because the word "plugin" is overloaded by the tools themselves.
The concrete failure mode it would cause: designing the lifecycle around an MCP server would make
protection depend on the agent choosing to call a tool — an agent-cooperative design, which is
exactly the property enforcement must not have.

The mechanisms an integration may use, and what each is good for:

| Mechanism | What it can do | Agent-cooperative? |
|---|---|---|
| **Managed settings** (tool-native config file) | Constrain what the tool will do at startup — permission lists, MCP server enable/disable. For Claude Code this is `settings.json`; the adapter owns exactly four keys (`permissions`, `permissionMode`, `enabledMcpjsonServers`, `disabledMcpjsonServers`) and preserves every other key (`aa-devtool-claude-code/src/apply.rs`). | No — applied before the agent runs |
| **Managed launch** (`aasm run`) | Start the tool as a child process with governance identity and proxy routing injected (`AA_AGENT_ID`, `AA_TEAM_ID`, `HTTPS_PROXY` — `aa-cli/src/commands/run.rs`). | No |
| **Model gateway / base URL** | Route model-bound traffic through a governed endpoint so requests are scanned before egress. | No |
| **HTTP/HTTPS proxy** | Intercept outbound HTTPS at the wire via `aa-proxy`'s per-host CA, independent of the tool's cooperation. | No |
| **Hooks / permission callbacks** | Let the tool ask AASM for a verdict before performing an action, enabling approval flows. | Partly — the tool must invoke the hook |
| **Environment injection** | Carry identity and endpoint configuration into the tool process. | No |
| **MCP configuration** | Govern *which* MCP servers the tool may load, and optionally expose AASM capabilities as MCP tools. | Loading control: no. Tool exposure: yes |
| **IDE extension API** | Surface status/UX inside an editor, and where the host allows it, veto actions. | Depends on host |
| **Host enforcement** (OS-level) | Constrain the process regardless of its configuration. **Not available in this MVP** — see §7. | No |

Read the table by the last column. The mechanisms that produce a real guarantee are the ones the
governed agent cannot decline. MCP appears twice, and only its *loading control* half is
non-cooperative — which is why MCP is classified as **optional, defence-in-depth**, never as a
required substrate.

---

## 3. Personas and entry points

<!-- populated in a later commit -->

## 4. The canonical journey

<!-- populated in a later commit -->

## 5. Journey diagrams

<!-- populated in a later commit -->

## 6. Protection profiles

<!-- populated in a later commit -->

## 7. Protection levels

<!-- populated in a later commit -->

## 8. Product guarantees and their limits

<!-- populated in a later commit -->

## 9. Failure journeys

<!-- populated in a later commit -->

## 10. MVP scope and non-goals

<!-- populated in a later commit -->

## 11. Acceptance-test scenarios for the `AAASM-5276` Spike

<!-- populated in a later commit -->

## 12. Assumptions register

<!-- populated in a later commit -->

---

## References

- [L0–L3 Governance Capability Matrix](../governance/capability-matrix.md) — canonical tier
  definitions and per-tool declarations. The Claude Code row is `TBD` by design.
- [Protection and enforcement](../security/protection-model.md) — the policy pipeline, redaction
  semantics and fail-closed behaviour this brief's guarantees rest on.
- [Three-layer defense in depth](../security/three-layer-defense.md) — SDK / proxy / eBPF.
- `aa-core/src/dev_tool.rs` — `GovernanceLevel` (`L0Discover` … `L3Native`).
- `aa-core/src/policy.rs` — `EnforcementMode` (`Enforce` / `Observe` / `Disabled`).
- `AAASM-5275` — plugin, adapter, lifecycle API and core-runtime boundaries.
- `AAASM-5276` — Claude Code lifecycle Spike (consumes §11 of this document).
- `AAASM-5277` … `AAASM-5281` — lifecycle contract, plan/receipt/rollback, local integration API,
  CLI commands, Claude Code productization.
- `AAASM-5284` — public onboarding, protection-level and limitation docs.
