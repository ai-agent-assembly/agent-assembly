# Security Model — Overview

Agent Assembly governs AI agents that you do not fully trust, running inside
processes you do not fully control. The Security Model describes **what the
system protects, against whom, and how** — and, just as importantly, **where it
refuses to place its trust**.

This section is the *why*. For the *how* — concrete crates, types, and data
paths — follow the cross-links into [Architecture](../architecture/README.md).

## What the Security Model protects

An AI agent is, from a security standpoint, an *attacker-shaped* component:
it executes language-model output, calls external tools, opens network
connections, reads files, and spends money — all driven by prompts that may be
adversarially crafted (prompt injection) or by a model that has been
compromised or simply behaves unpredictably. The Security Model exists to keep
that component inside a governed boundary. Concretely it protects:

- **Tool and capability use** — an agent may only invoke the tools its policy
  permits. Denied tool calls are refused *before* they execute.
- **Network egress** — outbound connections are constrained to an allowlist;
  exfiltration to an arbitrary host is blocked.
- **Credentials and sensitive data** — API keys, private keys, and connection
  strings are detected and redacted on every path before they are forwarded or
  persisted, so a leaked secret never lands in an upstream request or an audit
  record.
- **Spend** — per-team and per-org budgets cap how much an agent can cost; a
  runaway agent is denied or suspended when it exceeds its limit.
- **The audit trail itself** — every governed action produces a sanitized,
  tamper-evident record, so the system's own evidence cannot be quietly
  poisoned with raw secrets or per-event noise.

## Defense-in-depth philosophy

The Security Model rests on three principles, each developed in its own page.

### 1. Layered interception — see the action before you can govern it

To govern an action the system must first *observe* it. Agent Assembly
intercepts at [three independent layers](three-layer-defense.md) — the
in-process SDK shim (`aa-sdk-client`), the sidecar proxy (`aa-proxy`), and
kernel-level eBPF (`aa-ebpf`) — ordered lowest-latency-first and
highest-detection-authority-first. The layers are not alternatives; they
**stack**, so an action that slips past one is caught by the next. Coverage is
the union of the layers you deploy.

### 2. The SDK is not a trust boundary — the runtime is authoritative

The fastest layer runs *inside the agent's own process*, which is exactly the
component we do not trust. So the system treats SDK-side checks as
**best-effort advisory only** and re-does the authoritative work at a trusted
chokepoint: the runtime (`aa-runtime`) re-scans, re-redacts, and re-normalizes
**every** event unconditionally, and the gateway (`aa-gateway`) is the sole
source of truth for policy. This is recorded as a formal decision in
[ADR 0002](../adr/0002-sdk-security-boundary.md) and detailed in
[Trust boundaries](trust-boundaries.md).

> **Invariant:** nothing the SDK asserts can shorten the trusted side's work.
> *Position — not code — confers authority.* The same `aa-security` scanner is
> *advisory* inside the SDK and *authoritative* inside `aa-runtime`.

### 3. Fail-closed by default

When the system cannot make a safe decision, it denies. An empty policy cascade
returns a fail-closed `Deny` (`aa-gateway/src/engine/decision.rs`), and a
secret-bearing field too large to fully scan is redacted whole rather than
forwarded raw (`aa-runtime/src/pipeline/enforcement.rs`,
`OversizedPolicy::RedactWhole`). See
[Protection and enforcement](protection-model.md).

## How the pages fit together

| Page | Question it answers |
|---|---|
| [Threat model](threat-model.md) | What assets, adversaries, and threats are in scope? |
| [Release threat model](release-threat-model.md) | What does **this** release change about our exposure, and is each change covered? (versioned, refreshed every major) |
| [Three-layer defense in depth](three-layer-defense.md) | How do SDK, proxy, and eBPF compose so nothing slips through? |
| [Protection and enforcement](protection-model.md) | How are policy, fail-closed, egress, scanning, and budgets enforced? |
| [Trust boundaries](trust-boundaries.md) | Why is the SDK untrusted and the runtime/gateway authoritative? |
| [Audit and assurance](audit-assurance.md) | How is the audit trail kept tamper-evident and free of secrets? |
