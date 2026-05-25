# Agent-to-Agent Identity (Zero-trust A2A)

Agent Assembly enforces a zero-trust posture on every agent-to-agent
(A2A) tool dispatch: when agent A calls a tool exposed by agent B, the
gateway verifies that the caller's credentials match the claimed
identity before any policy rule is evaluated. An impersonator (a third
agent C presenting A's `agent_id` with C's own `credential_token`) is
rejected at the front door and the attempt is recorded in the audit log.

## How identity flows on an A2A call

```
agent A ── tool dispatch ──▶ agent B
                  │
                  ▼
         gateway PolicyService.CheckAction
                  │
                  ▼
   ┌───── validate_credential_token ─────┐
   │  registered token for agent_id      │
   │  matches the supplied token?        │
   └─────────────────┬───────────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
  Allow → evaluate policy   Reject → A2AImpersonationAttempted
                                    audit event + Deny response
```

* `agent_id` in the request = the **callee** (the agent performing
  the action B).
* `caller_agent_id` in the request = the **originator** (A).
* `credential_token` is validated against the **callee's** registered
  token — `caller_agent_id` is an attestation by the callee, not a
  credential.

## Audit events

Two `AuditEventType` variants make A2A traffic explicit in the chain:

| Variant | Emitted when | Payload fields |
|---|---|---|
| `A2ACallIntercepted` | Allow decision on a request whose `caller_agent_id` differs from `agent_id`. | `caller_agent_id`, `callee_agent_id`, plus the usual `action_type`, `decision`, `policy_rule`, `latency_us`. |
| `A2AImpersonationAttempted` | Pre-policy-eval rejection because `credential_token` is empty or does not match the registered token for the claimed `agent_id`. | `claimed_agent_id`, `credential_token_present` (bool), `reason`, `policy_rule = "a2a_identity_verification"`. |

Single-agent calls (no `caller_agent_id`, or caller equals callee) keep
emitting the existing `ToolCallIntercepted` / `PolicyViolation`
variants — nothing changes for non-A2A traffic.

## Rejection rules

The gateway rejects before policy evaluation when:

1. The claimed `agent_id` is registered AND the supplied
   `credential_token` is **empty** → Deny with reason
   `"missing credential token"`.
2. The claimed `agent_id` is registered AND the supplied
   `credential_token` is **non-empty but does not match** the
   registered token → Deny with reason `"credential token mismatch"`.

When the claimed agent is **not registered**, the gateway skips
identity validation and lets the policy engine decide (this preserves
the lightweight detection-slice fixtures that bypass the registry
entirely). To opt into strict validation for a specific agent,
register it via the `AgentRegistry` — that's the activation gesture.

## Operator visibility

Use the existing audit tooling to surface A2A activity:

```bash
# All A2A allows in the last hour
aasm audit list --since 1h --event-type A2ACallIntercepted

# Rejected impersonation attempts (security investigation)
aasm audit list --event-type A2AImpersonationAttempted

# Compliance export covering A2A traffic specifically
aasm audit compliance-export \
  --input      /var/lib/aa-gateway/audit/session-<hex>.jsonl \
  --event-type A2ACallIntercepted \
  --format     jsonl \
  --output-file ./a2a-traffic.jsonl
```

## SDK expectations

When you build an A2A dispatch helper in your SDK, populate the
`CheckActionRequest` like this:

| Field | Set to |
|---|---|
| `agent_id` | The **callee** (the agent that will execute the tool). |
| `credential_token` | The **callee's** registered token. |
| `caller_agent_id` | The **originator** of the dispatch, attested by the callee. |

The Python / Node / Go SDKs ship A2A helpers that wrap this for you.
For framework-level integrations that build `CheckActionRequest`
directly, the new field is optional and proto3-additive — single-agent
SDKs that don't populate it continue working unchanged.

## What does *not* change

* Single-agent tool calls — no behavioural change, no new audit
  events.
* The credential validation is **scoped to registered agents** —
  bypassing the registry continues to be the recommended path for
  in-process tests and CI fixtures that don't model identity.
* The policy engine — A2A enforcement is a pre-evaluation gate, not a
  new policy clause; existing rules still apply once the call passes
  identity validation.
