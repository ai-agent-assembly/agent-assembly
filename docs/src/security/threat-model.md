# Threat model

This page enumerates what the Security Model defends: the **assets** worth
protecting, the **adversaries** who threaten them, and the concrete **threats**
each control answers. It is specific to Agent Assembly — the system that governs
AI agents at the [three interception layers](three-layer-defense.md) and a
central [gateway](../architecture/README.md).

## Assets

| Asset | Why it matters | Primary guard |
|---|---|---|
| **Credentials & secrets** — API keys, private keys, DB connection strings | Leaking one grants an attacker the agent's privileges across third-party systems | `aa-security` credential scanner + redaction, run authoritatively in `aa-runtime` |
| **Tool / capability surface** | An unauthorized tool call is arbitrary code or data access on the agent's behalf | Gateway policy engine (`aa-gateway/src/policy/`, `aa-gateway/src/engine/`) |
| **Network egress paths** | The channel through which data is exfiltrated | Network-egress policy (`aa-gateway/src/policy/network.rs`) + proxy MitM (`aa-proxy`) + eBPF SSL uprobes |
| **Spend / budget** | A looping or hijacked agent can burn unbounded cost | Budget control (`aa-gateway/src/budget/`) — deny or suspend on exceed |
| **The audit trail** | It is the evidence of what happened; if it can be poisoned, accountability is lost | Write-boundary sanitizer (`aa-gateway/src/sanitizer/`) + tamper-evident publish (`aa-runtime/src/audit_publisher/`) |
| **Policy as source of truth** | If the agent could author its own policy, governance is meaningless | Policy SoT is server-side in the gateway; the SDK cannot mutate it |

## Adversaries

The model assumes the agent's own process is **not trusted**. The relevant
adversaries are:

- **The prompt-injected agent.** A legitimate, SDK-adopting agent whose model
  has been steered by adversarial input into making tool calls, network
  requests, or data accesses its operator never intended. It is *cooperative
  at the binary level* but *hostile at the behavioral level*.
- **The compromised / modified agent.** An agent whose code has been altered —
  including one running a **patched, outdated, or stubbed SDK** — that
  deliberately tries to suppress, weaken, or skip the in-process checks.
- **The bypassing agent.** An agent that ignores the SDK entirely and makes raw
  syscalls, opens its own sockets, or links TLS directly to avoid the
  fastest interception layer.
- **The careless integrator.** Not malicious, but ships secrets in tool
  arguments or LLM payloads, or wires an agent to an over-broad capability set.

> **Trust posture.** Because the SDK runs inside an attacker-controllable
> process, *any guarantee anchored in the SDK is not a guarantee*. Security must
> hold even when the SDK does nothing — see
> [Trust boundaries](trust-boundaries.md) and
> [ADR 0002](../adr/0002-sdk-security-boundary.md).

## Threat scenarios

1. **Unauthorized tool call** — a prompt-injected agent invokes a tool outside
   its policy (e.g. `terminal_exec`, or `read_file` on `/etc/...`). Caught by the
   gateway tool allow/deny stage and, for MCP `tools/call`, by argument-level
   matching in the proxy (`aa-proxy/src/intercept/mcp.rs`).
2. **Credential / data exfiltration** — the agent embeds an API key in an LLM
   prompt or a tool argument and sends it upstream. The `aa-security` scanner
   detects the secret (via Aho-Corasick literal patterns) and redacts it
   *before* forward and *before* audit, on every path.
3. **Network egress to an arbitrary host** — the agent attempts to POST data to
   an attacker-controlled domain. The gateway's network allowlist denies the
   request; the proxy enforces it at the wire even with no agent code change;
   eBPF SSL uprobes observe the plaintext if the agent bypasses both.
4. **Policy evasion / SDK bypass** — the agent disables, stubs, or skips the
   SDK scanner, or asserts an "already clean" marker. Defeated structurally:
   there is **no trust marker on the wire**, and `aa-runtime` re-scans
   unconditionally. This is proven by the bypass-resistance suite
   (`aa-runtime/tests/aaasm_2568_gate_verification.rs`).
5. **Runaway spend** — a looping agent issues unbounded LLM calls. The budget
   tracker denies further requests once the daily/monthly limit is met, or
   suspends the agent, per `action_on_exceed`.
6. **Audit poisoning / secret leakage into logs** — a sender emits raw prompts,
   full payloads, or per-beat heartbeat noise into the audit stream. The
   write-boundary sanitizer strips banned keys recursively and collapses
   heartbeats before anything reaches `audit_logs`.

## STRIDE mapping

| STRIDE category | Threat in this system | Control |
|---|---|---|
| **S**poofing | Agent claims an identity / lineage it does not have to widen its policy scope | Gateway resolves agent lineage server-side from registered context; the policy cascade is keyed to it (`aa-gateway/src/engine/mod.rs`) |
| **T**ampering | Agent forges event fields or asserts "already scanned" to skip enforcement | No trust marker honored; `aa-runtime` re-scans every event; the sanitizer drops unknown top-level fields (`aa-gateway/src/sanitizer/`) |
| **R**epudiation | Action happens with no trustworthy record | Tamper-evident audit publish to NATS, subject `assembly.audit.<tenant>.<agent>` (`aa-runtime/src/audit_publisher/subject.rs`) |
| **I**nformation disclosure | Secrets leak via upstream requests or audit logs | `aa-security` scan + redact on every path; banned-key sanitizer as the final write-boundary backstop |
| **D**enial of service / spend exhaustion | Runaway agent burns budget or floods events | Budget deny/suspend (`aa-gateway/src/budget/`); fail-closed oversized-field cap bounds per-event scan cost |
| **E**levation of privilege | Agent invokes a tool or egress beyond its grant | Policy engine deny stages; fail-closed empty cascade → `Deny` (`aa-gateway/src/engine/decision.rs`) |

Each control is detailed in [Protection and enforcement](protection-model.md).
