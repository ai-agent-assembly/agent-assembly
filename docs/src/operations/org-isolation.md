# Org-Tier Isolation (Multi-Tenancy)

Agent Assembly enforces a three-tier isolation hierarchy — **Org / Team /
Agent** — so a single gateway can safely host workloads from multiple
tenants. AAASM-1524 covers the Agent and Team tiers; this guide describes
the **Org tier** added in AAASM-2008.

## What the Org tier guarantees

When agents are registered with a non-empty `proto.AgentId.org_id`, the
gateway enforces the following invariants:

| Surface | Org-tier behaviour |
|---|---|
| Audit log | Every audit entry carries the originating agent's `org_id` on `Lineage`. `GET /api/v1/logs?org_id=X` filters to a single tenant. |
| Topology | `GET /api/v1/topology/overview?org_id=X` returns only X's agents. The registry maintains an `org_index` secondary index for O(members) lookup. |
| Credential validation | An agent registered in Org A presenting its valid token but claiming `agent_id.org_id = "B"` is rejected with `A2AImpersonationAttempted`. The registry's credential reverse-index catches cross-org reuse before any policy evaluation. |
| Policy scope | A policy with `scope: org:<id>` cascades only for agents in that org. (Requires the multi-document loader from [AAASM-2023](https://lightning-dust-mite.atlassian.net/browse/AAASM-2023) — partial today.) |
| Budget | Per-team budget isolation provides implicit Org-tier isolation when each Org uses distinct team_ids. Explicit Org-tier budget tracking is tracked under [AAASM-2022](https://lightning-dust-mite.atlassian.net/browse/AAASM-2022). |

## How to set up multi-tenancy

Register each agent with a non-empty `org_id`:

```python
init_assembly(
    gateway="grpc://gateway:50051",
    agent_id={
        "org_id":   "acme",
        "team_id":  "platform",
        "agent_id": "research-bot-001",
    },
    credential_token=os.environ["AA_CREDENTIAL"],
)
```

The same convention applies via the Node and Go SDKs and via direct
`PolicyService.CheckAction` calls — the proto `AgentId` triple is the
canonical identity.

## Querying by Org

### Audit log

```bash
# Browser / curl
curl 'http://gateway/api/v1/logs?org_id=acme&per_page=50'

# Compliance export covering one org's audit trail
aasm audit compliance-export \
  --input      /var/lib/aa-gateway/audit/session-<hex>.jsonl \
  --org-id     acme \
  --format     jsonl \
  --output-file ./acme-audit.jsonl
```

Audit entries written before the agent was registered with an `org_id`
(or by lightweight test fixtures that bypass the registry) carry
`org_id = None` on Lineage and **never match** an explicit `org_id`
filter. This is intentional — multi-tenancy isolation requires explicit
Org tagging on the entry at write time.

### Topology

```bash
curl 'http://gateway/api/v1/topology/overview?org_id=acme'
```

The overview endpoint scopes via `AgentRegistry::org_members(oid)`. The
other topology endpoints (tree, team, lineage, stats) accept the
`org_id` query parameter but currently ignore it — the next ticket in
the Org-tier rollout will wire each handler.

## Cross-org credential reuse detection

When an agent in Org A presents its credential but claims `agent_id.org_id =
"B"`, the gateway:

1. Computes the registry key from the claimed `{org_id, team_id, agent_id}`
   triple. Because `org_id` is part of the hash, the claimed key
   differs from the agent's actual registration key.
2. Looks up the claimed key — fails (no agent registered there).
3. Looks up the supplied credential_token in the reverse index — finds
   the actual owner.
4. Detects the mismatch, returns `Deny` with reason
   `"credential token registered to a different agent"`, and emits an
   `A2AImpersonationAttempted` audit event with `claimed_org_id` in
   the payload.

A reviewer searching `aasm audit list --event-type A2AImpersonationAttempted`
sees these attempts grouped by the org the attacker tried to claim.

## Known gaps

* **Org-tier budget**: explicit Org-tier limits not yet wired —
  [AAASM-2022](https://lightning-dust-mite.atlassian.net/browse/AAASM-2022).
* **Org-scoped policy E2E**: `PolicyEngine::load_from_file` doesn't
  populate the scope_index, so `scope: org:<id>` policies need a
  multi-document loader — [AAASM-2023](https://lightning-dust-mite.atlassian.net/browse/AAASM-2023).
* **Topology endpoints beyond `overview`**: tree / team / lineage /
  stats accept the `org_id` query param but currently ignore it.

These are all carry-overs from the F116 Org-tier isolation acceptance
work (AAASM-2008). The headline scenarios — audit isolation, topology
overview scoping, cross-org credential rejection — ship complete in
AAASM-2008.
