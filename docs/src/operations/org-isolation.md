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
| Budget | Every Org owns an independent spend envelope on the `BudgetTracker.org_budgets` map. `record_cost` rolls each charge into the agent's `org_id` and enforces `org_daily_limit_usd` / `org_monthly_limit_usd` set via policy YAML or the `with_org_*_limit` builders. Exhausting one Org's envelope never affects another. |

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
    credential_token=os.environ["AA_API_KEY"],
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

## Configuring Org-tier budget limits

Operator-facing knobs live in the `budget:` section of any Global-scoped
policy document:

```yaml
budget:
  daily_limit_usd:        10000.0   # global cap across all orgs
  monthly_limit_usd:      250000.0
  org_daily_limit_usd:    1000.0    # AAASM-2022 — per-org daily cap
  org_monthly_limit_usd:  25000.0   # AAASM-2022 — per-org monthly cap
  timezone: "UTC"
  action_on_exceed: deny
```

Semantics:

* `org_daily_limit_usd` / `org_monthly_limit_usd` are **uniform per-Org**
  caps — the same envelope applies to every Org that records spend.
  Cross-Org isolation comes from the tracker maintaining an independent
  `BudgetState` per `org_id`, not from per-Org-customised limits.
* Enforcement order in `record_cost` is **global → org → team → agent**,
  monthly checked before daily within each tier. The first tier that
  exceeds returns `BudgetStatus::LimitExceeded` and the deny is recorded.
* Limits enter the tracker via `with_org_daily_limit` /
  `with_org_monthly_limit` builders during policy load. Restoring from
  persisted snapshot preserves limits via the same path — the
  `org_budgets` map is empty on first restore until the migration in
  AAASM-2022 follow-up lands.

### Observing per-Org spend

```rust
// In-process accessor:
let alpha = budget.org_state("acme").map(|s| s.spent_usd);
```

The dashboard / CLI surfaces for `aasm budget status --org <id>` are
queued under [AAASM-1232](https://lightning-dust-mite.atlassian.net/browse/AAASM-1232)
follow-up subtasks.

## Known gaps

* **Org-scoped policy E2E**: `PolicyEngine::load_from_file` doesn't
  populate the scope_index, so `scope: org:<id>` policies need a
  multi-document loader — [AAASM-2023](https://lightning-dust-mite.atlassian.net/browse/AAASM-2023).
* **Topology endpoints beyond `overview`**: tree / team / lineage /
  stats accept the `org_id` query param but currently ignore it.
* **Persistence schema for Org-tier spend**: the on-disk snapshot does
  not yet carry the `org_budgets` map; a restored tracker starts with
  empty Org state.

The headline scenarios — audit isolation, topology overview scoping,
cross-org credential rejection (AAASM-2008), and cross-org budget
envelope isolation (AAASM-2022) — ship complete.
