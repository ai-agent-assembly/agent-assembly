# DID

## Definition

A **DID** (Decentralized Identifier) is a self-describing identifier whose
trust is rooted in a public key rather than in a central registrar. Agent
Assembly uses the `did:key` method, where the identifier encodes an Ed25519
public key directly — for example
`did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T`. The DID *is* the key, so anyone
holding the DID can verify a signature without consulting an external directory.

## How it works

When an agent registers, it presents an Ed25519 `public_key` alongside its name,
framework, and declared tools, plus a `possession_proof` over a gateway-issued
challenge nonce — see [Agent](agent.md) for that two-round-trip exchange. The
gateway validates that the key is a well-formed Ed25519 verifying key (32 bytes,
hex-encoded) before storing the agent's `AgentRecord`, and rejects anything
malformed at the lifecycle boundary.

**The DID is derived, not supplied.** The `agent_id` you configure — for example
`"quickstart-agent"` — names a *durable local key*: the SDK establishes a keypair
for it and derives the `did:key` from that key's public half, so asking twice
returns the same DID. Handing a *provisioned* `did:key` in as the `agent_id` does
not work and is deliberately refused rather than quietly substituted: the client
holds no private key for a DID it did not generate, so no possession proof it could
build would verify. In that case the identity resolves to a visible
`<no-durable-identity-key>` placeholder — chosen precisely because it is not
shaped like a DID, so nobody mistakes an unresolved identity for a registered one.

In return the gateway issues a short-lived `credential_token`. That token — not
the public key — is what the agent presents on subsequent calls, and it is the
basis of the zero-trust agent-to-agent (A2A) check: when agent A calls a tool
exposed by agent B, the gateway validates the supplied `credential_token`
against the **callee's** registered token *before any policy rule runs*. An
impersonator presenting another agent's `agent_id` with its own token is
rejected at the front door and the attempt is recorded as
`A2AImpersonationAttempted` in the [audit](audit.md) log.

```mermaid
sequenceDiagram
    participant A as Agent
    participant G as Gateway
    A->>A: Derive did:key from the durable local keypair
    A->>G: Register (did:key + public_key + possession_proof)
    G->>G: Validate verifying key (32 bytes), verify proof
    G-->>A: credential_token (short-lived)
    A->>G: Action (agent_id + credential_token)
    G->>G: Match token to registered identity
    G-->>A: allow / reject (impersonation)
```

**Why a DID for agent identity.** Agents are ephemeral and may be spawned by
other agents across teams and orgs. A key-rooted identifier gives each agent a
verifiable identity that does not depend on a shared secret or a central
authority, and lets the gateway distinguish the *callee* (the agent performing
an action) from the *caller* (an attestation, not a credential) on every A2A
dispatch.

**Key rotation.** There is no rotate-key operation, and that is a consequence of
the model rather than a gap in the API surface: with `did:key` the identifier *is*
the key, so a new key is a new identity, not the same identity wearing a new
credential. Replacing a key therefore means registering under the new DID and
retiring the old registration through the normal lifecycle — deregistration, or the
registry's age sweep (see [Agent](agent.md)). The consequence worth planning for is
that the two DIDs are distinct principals in the [audit](audit.md) trail, so a
rotation is visible as a handover between identities rather than as a silent
in-place swap.

## Example

A registration carries the DID and its Ed25519 key; the conformance wire-format
vectors use exactly this shape:

```json
{
  "agent_id": "did:key:z6Mkm5rByiqq5UNbvPFPfXtGJwdg2kD1T",
  "public_key": "<64 hex chars — 32-byte Ed25519 verifying key>",
  "framework": "langgraph"
}
```

A delegated sub-agent references its parent the same way:

```json
{
  "agent_id": "did:key:child",
  "parent_agent_id": "did:key:parent"
}
```

## Related

- [Agent](agent.md) — the identity a DID names and the registration lifecycle.
- [Audit](audit.md) — `A2AImpersonationAttempted` and A2A audit events.
- [Approval](approval.md) — `spawn` approvals gate delegated identities.
- [Agent-to-agent identity](../operations/a2a-identity.md) — the full
  zero-trust A2A verification flow.
- [API reference](../api-reference.md) — `aa-gateway` lifecycle service and
  registry rustdoc entry points.
