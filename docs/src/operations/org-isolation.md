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

## How an agent gets an organization

An organization is **bound to an operator credential, never taken from the
client**. `agent_id.org_id` on a registration is only a *claim*; the gateway
decides the agent's org from the operator API key presented with the
registration (the same `aa-auth` key store, `AA_API_KEYS_PATH`, that binds REST
callers to a tenant) and refuses a claim the key does not back.

1. The operator issues an org-bound key (an `ApiKeyEntry` with `org_id: acme`)
   and gives it to the agent's deployment.
2. The SDK presents it on `Register` in the `x-aa-registration-key` gRPC
   metadata (never in the signed body):

```python
init_assembly(
    gateway_url="http://gateway:7391",
    agent_id="research-bot-001",
    team_id="platform",
    org_id="acme",                      # optional claim; omit to take the key's org
    registration_key=os.environ["AA_REGISTRATION_KEY"],  # org-bound operator key
)
```

`AA_REGISTRATION_KEY` is also read by the native client when the argument is
omitted.

`aasm run` does not pass `AA_REGISTRATION_KEY` on to the tool it launches
(AAASM-6463), so a key exported in the operator's shell is not inherited by the
governed tool by accident. `aasm run` registers the agent itself, from its own
environment. This removes inheritance only. It is not a confidentiality boundary:
`aasm run`'s own process still holds the key, and on the default non-isolated path
a hostile tool running as the same user can read a parent process's environment
(`/proc/<ppid>/environ` on Linux, `ps eww` or `KERN_PROCARGS2` on macOS) and use the
key. Whether an `--isolation` backend hides the parent's environment from the tool
is not something this change verifies or claims. Give an SDK-side process the key
explicitly rather than through an inherited variable.

The key is a bearer credential: use an `https://` gateway for anything that is not
on loopback. The client marks the header sensitive, but it does not encrypt the
connection.

The runtime sidecar of an org-bound agent must be started with
`AA_AGENT_ORG_ID=<org>` so its op-control subscription finds the agent (the
registry keys an agent by `org/team/agent`).

### Registration outcomes

| Registration key | Claimed `org_id` | Result |
|---|---|---|
| none | empty | Registered **org-less** (the single-tenant default; unchanged) |
| none | `X` | Rejected `PermissionDenied` |
| invalid, revoked or expired | any | Rejected `Unauthenticated` |
| bound to `O`, `write` or `admin` scope | empty | Registered in `O` (derived; echoed in `RegisterResponse.org_id`) |
| bound to `O`, `write` or `admin` scope | `O` | Registered in `O` |
| bound to `O`, `write` or `admin` scope | other | Rejected `PermissionDenied` (spoof) |
| bound to `O`, `read` scope only | any | Rejected `PermissionDenied` (needs write scope) |
| admin key, no org binding | `X` | Registered in `X` (operator-authorised) |
| non-admin key, no org binding | `X` | Rejected `PermissionDenied` |
| non-admin key, no org binding | empty | Registered org-less |

Only the org the registration binding validated is ever used as the agent's org
(audit stamp, policy cascade, sensitive-data scope). A free-form
`RegisterRequest.metadata` entry named `org_id` is client text and is ignored.

An unusable header (blank, non-ASCII, or sent twice) is `Unauthenticated`, never
"no key".

### A later process of an already-registered agent

A second process of an agent that is already registered (same did:key, team and
organization) re-binds to the existing record, and receives its credential and
`team_id`, in exactly two cases. While the gateway that registered the agent keeps
running the credential is the existing one; after a gateway restart it is a new one
(see below). Proving possession of an agent key shows who the
agent is, and that is enough to take over its credential only when no one else can
compute that key:

1. **An organization-bound agent**, when the process presents a registration key bound
   to the record's organization. The operator's key is what authorizes it.
2. **A keyless (org-less) agent**, by possession of its own key, when its first
   registration declared that key to be random and held by the agent. The SDK and the
   CLI generate a random identity key per agent identity and keep it owner-only in the
   state directory (`AASM_STATE_DIR`), and say so on every registration
   (`RegisterRequest.durable_identity_key`). The gateway records that when it creates
   the record and reads it back from the stored record, never from a later request,
   and the later process must declare a held key too. A process restarted from the
   same state directory proves possession of the same key and keeps the agent's id
   and credential; no operator key is involved.

An identifier alone never authorizes either: the identifier is public, the key is not.

A key confined to one team (`team_id` on the key) re-binds only agents of that
team; it is compared with the team stored on the record, not the `team_id` the
caller sends. An org-wide key re-binds any team's agent in its organization.

Every other case that reaches the existing record is the same `AlreadyExists` a plain
duplicate gets, with no credential in the response:

* the record has no organization and did not declare a durable key, so its key may be
  computable from a public identifier (registered by a client that predates the
  declaration);
* the record is a row written by a gateway older than the restart re-bind
  (AAASM-6451), which did not store the agent's key: nothing shows the caller holds
  the key the record was created with;
* the caller is an unbound admin key merely asserting the organization;
* the key is confined to a different team than the record's;
* the registration is still in flight, or its durable write failed (retry).

A process with no key, or with a key bound to a different organization, does not
reach the record at all: the registry identity includes the organization, so it
simply registers a separate agent. A different key bound to the same organization
does reach the record and re-binds only if the team rule above allows it.

A registration abandoned mid-write (the client went away) is removed again, so a
later re-bind is never handed its credential. If the durable write had already
completed when the request was dropped, the stored row survives until the next
registration of that agent replaces it.

**Limitations.**

* Registration does not check the key's scope (read, write or admin): a read-scope
  org-bound key can re-bind, as it can register.
* A key revoked through REST/IAM after the agent registered still authorizes a
  re-bind until the gateway restarts.
* **After a gateway restart** an agent re-registers with the same agent id, from the
  same state directory (keyless) or with its organization's operator key, and
  receives a **new** credential. The gateway stores the agent's organization and public
  key, never its credential, so a leaked database is not a leaked token. The
  pre-restart credential stops working, and an empty token never authenticates.
  Processes that re-register at the same moment normally share the one new
  credential, but one of them can be refused with `AlreadyExists` if it races the
  install; retrying succeeds. Every rehydrated agent comes back `Active`, so a
  suspension does not survive a restart. A running process holds the old credential and does not re-register by itself: it
  has to be restarted after the gateway restarts (the SDK does not yet re-register on
  `Unauthenticated`).
* Rows written before AAASM-6451, and records created by clients built before the
  declaration, cannot be re-bound and occupy the agent's registry slot: a later
  process of that agent gets `AlreadyExists` until the record is removed
  (`DELETE /api/v1/agents/:id`; a record with no team needs an admin-scope key). After upgrading, every agent registered by the older
  gateway is in this state once.
* The durable-key declaration is a claim by the client that creates the record. A
  hand-built client can declare it while using a computable key, so a record is only
  as trustworthy as its creator: whoever registers an identity first holds its
  credential (as before), and a later process that also declares a held key and
  proves possession of the same key shares that credential.
* The credential is shared: every re-bound process holds the same token, so one
  process's Deregister ends the agent for all of them. Anyone who copies the agent's
  key file from the state directory holds the agent's identity and its credential.
* Another holder of the same label (another machine, a fresh state directory) has a
  different key and so is a different agent; the two do not merge.

### Issuing and revoking keys

`cargo run -p aa-auth --example aa-keygen -- --keys-file <AA_API_KEYS_PATH file>
--key-out <raw key file> --org <org> [--team <team>] [--scope read|write|admin]`
appends the key's argon2 hash to the key file and writes the raw key to a separate
owner-only file; it never prints the key and rejects an empty `--org`.

* **A registration key needs `--scope write`.** `aa-keygen` defaults to `read`,
  and the gateway refuses a read-scope org-bound key at `Register` (reason
  `insufficient_scope`): registering an agent, and re-adopting its credential on a
  re-bind, change tenant state. Keys issued before this check with the default
  scope stop registering; re-issue them with `--scope write`. Read-scope org-bound
  keys remain valid as REST read credentials.

* The gateway reads the key file **once at boot**. A new key, or a key you remove
  from the file, takes effect when the gateway restarts. A key revoked through the
  REST/IAM path stays valid for `Register` until that restart.
* A key file that is missing or unreadable at boot leaves the gateway with an
  empty key store (it logs `registration key file unreadable`): org-less
  registration keeps working and every org claim and every key is refused.
* The key's `team_id` is not enforced at `Register`; only its org is.

Every refusal increments `aa_register_org_rejected_total{reason}`. An org-less
agent's audit entries carry `org_id = null` and never match an `?org_id=`
filter. `team_id` is never read as an organization, and entries recorded before
an agent had an org are never relabelled.

An SDK built before this field existed sends no key and no org, which is the
org-less row above, so older SDKs keep registering unchanged.

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

`GET /api/v1/logs` is also bound to the caller's own org: a key or token bound
to one org is pinned to it, admin scope included (an explicit `?org_id=` for
another org returns the caller's own org's entries, never the other's), and only
an admin with **no** org binding may choose the org.

**Admin scope is cross-org on the other API routes.** Only `/api/v1/logs` pins an
org-bound key. Other routes (violations and sandbox summaries under `/api/v1/audit`,
topology, agents, approvals, edges, alerts) still treat the `admin` scope as a global
administrator, so an `admin` key issued with `--org` can read other orgs' data there.
Do not issue `--scope admin` keys with `--org` expecting a tenant-limited administrator;
use `read` or `write` for org-bound keys.

Audit entries written before
the agent was registered with an `org_id`
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
