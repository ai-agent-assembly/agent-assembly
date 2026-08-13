# Migration Guide — agent identity keys are generated, not derived

**Security fix introduced in:** AAASM-5332
**Affected components:** every agent registered by `aa-sdk-client` or `aasm run` before this change
**Estimated migration effort:** Low mechanically, but it requires a deliberate decision per agent

---

## What changed

An agent's Ed25519 identity keypair used to be **derived** from its
operator-facing identifier: the signing key was seeded with
`SHA-256(agent_id)`. The keypair is now **generated from the operating system's
CSPRNG** and stored, owner-only, at
`${AASM_STATE_DIR:-~/.aasm}/identity/<hash>.key`.

The derivation looked deliberate — it bought a stable identity across restarts
with nothing to persist — but the seed was a hash of a **public** value. Agent
identifiers appear in audit records, in topology views, and on the dashboard.
`AgentLifecycleService.Register` is reachable unauthenticated by design (it is a
bootstrap endpoint, mounted behind `enrich_interceptor`, which authenticates
nothing), so the possession proof is the only control deciding who may register
as a given agent. With a derived key, that proof established only that the caller
could compute SHA-256 of a string anyone could read.

The controls around it were all correctly implemented and none of them helped,
because each rested on the same non-secret:

| Control | Why it did not close the gap |
|---|---|
| `enforce_did_key_binding` | Binds the DID to the presented public key — but an attacker who derives the keypair derives a *self-consistent* pair. |
| `verify_possession_proof` | Verifies a real Ed25519 signature — made with a key the attacker holds just as legitimately. |
| Single-use registration nonce | Correct, and orthogonal: it prevents replay, not impersonation. |

---

## What this means for identities you already have

> **Treat every `did:key` registered before this change as compromised.**

Its private key is `SHA-256(<agent_id>)`, and the `agent_id` is published. Anyone
who has read one of your audit records, topology views, or dashboard pages can
reconstruct the corresponding private key and register as that agent, sign its
possession proof, and obtain a `credential_token` for it. This is true
retroactively and cannot be fixed by upgrading alone — an attacker who recorded
the identifiers already has the keys.

Two things make the cleanup tractable:

- **No key material has to be migrated.** The gateway never stored a private
  key. `AgentRecord` holds the public key hex and a composite hash of the
  identity; nothing on the server side needs rewriting.
- **Upgrading does not silently reuse the compromised key.** An upgraded agent
  finds no key file, enrols a fresh random one, and registers under a **new**
  `did:key`. The old identity simply stops being presented.

---

## What upgrading does on its own

1. The first registration after upgrading enrols a new key at
   `${AASM_STATE_DIR:-~/.aasm}/identity/<hash>.key`, mode `0600`, in a directory
   at mode `0700`.
2. The agent registers under a new `did:key` derived from that key.
3. Every later run reads the same key back, so the identity is stable — the
   identity that registered is the one the launch runs under and the one the
   gateway attributes audit records to.

Nothing about the old registration is cleaned up automatically. That is
deliberate: deregistering an agent is an operational act with a blast radius, and
this change does not perform one on your behalf.

---

## Migration steps

1. **Enumerate the compromised identities.** For each identifier still in use,
   `aa_sdk_client::legacy_derived_did(agent_id)` returns the `did:key` that
   identifier mapped to under the old scheme. It exists only for this purpose.

2. **Upgrade and let each agent re-enrol.** Run each agent (or `aasm run`) once.
   It will enrol a durable key and register under its new DID. Verify the new
   identity is the one you expect:

   ```bash
   aasm run <tool> --agent-id <identifier> --dry-run
   ```

   The printed `registration_did` is read from the stored key. If it shows
   `<no-durable-identity-key>`, the key could not be established — check that
   `AASM_STATE_DIR` (or `$HOME`) is writable and that no existing key file is
   group- or world-accessible.

3. **Deregister the old identities.** Once the new registration is confirmed,
   remove the pre-migration record so the compromised DID cannot be used to
   impersonate a live agent. Deregistration is authenticated by the
   `credential_token` the original registration minted; where that token is no
   longer held, remove the record through the operator-authenticated
   `DELETE /api/v1/agents/{id}`.

4. **Protect the new key files.** They are the agent's identity. They are created
   `0600` and are *refused* on read — not used — if they become group- or
   world-accessible, are owned by another user, or are replaced by a symlink. A
   backup or configuration-management system that copies them to a shared
   location, or that widens their permissions, will make the agent fail to
   register rather than register insecurely.

5. **Do not carry an agent id that is already a `did:key`.** That configuration
   is now refused locally. It could never have registered successfully anyway —
   the `public_key` came from a key the SDK holds, so a caller-supplied DID was
   guaranteed to fail the binding check — and it now fails with a message saying
   so instead of an opaque `Unauthenticated` from the gateway.

---

## Audit continuity

Gateway-written audit entries attribute actions to `SHA-256(did)[..16]`, so
**pre- and post-migration entries for the same operator-facing agent will not
join**. Entries written by `aa-runtime` on the SDK path hash the plaintext
`AA_AGENT_ID` instead and are unaffected, so that half of the trail stays
continuous across the migration.

If you need the two eras joined, record the mapping from
`legacy_derived_did(agent_id)` to the new DID at migration time — after
re-enrolment the old DID is no longer derivable from anything the system stores.

---

## Rotation and revocation

Once an identity is a stored key rather than a function of a name, replacing it
becomes a real operation:

- **Rotation** retires the current key (retained on disk, never deleted) and
  enrols a fresh one. It produces a **new `did:key`**, because a `did:key` *is*
  an encoding of a public key; the previous DID should be deregistered.
- **Revocation** writes a marker beside the key. The key file itself is left
  intact for forensic comparison, and the store refuses to load — or to quietly
  re-enrol — a revoked identity, so revocation cannot be undone by running the
  agent again.

Both are **local** operations. Propagating a revocation to the gateway is
currently limited to deregistering the revoked DID: `AgentLifecycleService`
exposes no revoke RPC, so there is no revocation list a gateway consults before
honouring a credential. That gap is tracked separately.

---

## What this change deliberately does not add

**No key expiry and no automatic renewal.** Renewal introduces a clock, a grace
window, and a set of failure modes that belong in their own change rather than in
the repair of a key-generation defect. Keys created by this change do not expire.

---

## See also

- [Trust boundaries](../security/trust-boundaries.md)
- [Threat model](../security/threat-model.md)
