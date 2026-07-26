# ADR 0017: Dashboard Design-Parity — Ratified Evolutions

**Status**: Accepted
**Date**: 2026-07
**Ticket**: [AAASM-5077](https://lightning-dust-mite.atlassian.net/browse/AAASM-5077)

The shipped operator dashboard (`dashboard/src/`) diverges from its hi-fi reference
mocks (`design/v1/hi-fi/`) on a number of structural points. A per-surface parity
audit ([AAASM-5071](https://lightning-dust-mite.atlassian.net/browse/AAASM-5071)…[5080](https://lightning-dust-mite.atlassian.net/browse/AAASM-5080),
under the reconciliation program [AAASM-5077](https://lightning-dust-mite.atlassian.net/browse/AAASM-5077))
classified every discrete drift item as one of: **RATIFY** (keep the shipped behavior,
record the decision, no rebuild), **FE-buildable-now** (rebuild the FE toward the mock),
or **backend-blocked** (needs API/data work first). This ADR records the **20 RATIFY
decisions** — the cases where the *shipped implementation is authoritative over the
mock* and the prior mock behavior is no longer the required implementation target. The
FE-buildable and backend-blocked items are tracked separately on their stories and on
the backend-decomposition Epic; they are **not** in scope here.

This ADR does not mandate any product rebuild. It ratifies decisions already realized
in code and supersedes the corresponding mock behavior so that future FE work does not
"correct" the shipped dashboard back toward a mock that is no longer the target.

---

## Context

`design/v1/hi-fi/*.jsx` is a high-fidelity React/CSS prototype used as the visual spec
for the dashboard. During implementation, several surfaces deliberately evolved past
their mock — either because the mock's structure was depth-informed but not final, or
because the shipped version is a strict superset (exposes more states / more data /
more affordances), or because a mock feature depended on backend capability that does
not yet exist and a narrower v0 shipped instead.

The reconciliation program normalized the 9 per-surface audit comments into a single
authoritative item inventory (recorded on AAASM-5077). Of that inventory, **20 items**
were classified RATIFY. The remaining items (27 FE-buildable, ~32 backend-dependent)
are execution work owned by the individual stories and the backend Epic and are out of
scope for this decision record.

The audit is **not adversarial** — the concern is design-drift governance: keeping the
mock and the shipped product from silently disagreeing about what "correct" is, so that
neither a future contributor nor an LLM agent rebuilds a shipped surface back to a stale
mock.

---

## Decision

For each item below, the **shipped implementation in `dashboard/src/` is authoritative**;
the referenced `design/v1/hi-fi/<surface>.jsx` mock behavior is **superseded** and is no
longer the required implementation target. Each mock file carries a top-of-file
supersession note pointing back to this ADR.

### Topology — [AAASM-5071](https://lightning-dust-mite.atlassian.net/browse/AAASM-5071) (`design/v1/hi-fi/topology.jsx`)

1. **Force-directed layout.** Shipped uses a D3 force-directed graph; the mock's
   hierarchical team-grid layout is superseded. The layout choice is deliberate and
   depth-informed (grounded in AAASM-1335 / AAASM-5033). *Why shipped is authoritative:*
   force-directed scales to real inter-team edge density where the fixed 3-column grid
   does not, and it is the layout the depth work already tuned.
2. **Team budget bars on clusters.** Shipped renders per-team budget bars on the graph
   clusters (beyond the mock). *Why:* surfaces budget pressure where the operator is
   already looking at the fleet, at zero extra navigation.
3. **5s polling as the "live" stand-in.** Shipped treats a 5-second poll as the "live"
   feed. *Why:* the mock implies a WebSocket push feed that has no backend yet; 5s
   polling is the honest v0 and is authoritative until the live event-stream lands.

### Policy — [AAASM-5072](https://lightning-dust-mite.atlassian.net/browse/AAASM-5072) (`design/v1/hi-fi/policy.jsx`, `design/v1/hi-fi/policy-editor.jsx`)

4. **List + overlay layout.** Shipped uses a policy list with an editor overlay; the
   mock's `split-pane` layout is superseded. *Why:* the overlay preserves list context
   and reads better at the dashboard's working widths; the split-pane is optional and
   only revisited if visual fidelity is later mandated.
5. **Visual rule-builder as ported.** Shipped ports the mock's visual rule-builder
   faithfully; this is ratified as-is (no drift to reconcile — recorded so it is not
   re-litigated). *Why authoritative:* the port is the intended target.
6. **Single-request dry-run Simulate as the v0 feature.** Shipped ships a single-request
   dry-run ("Simulate 4a") as the v0 Simulate; the mock's replay-impact `SimulateModal`
   (draft-replayed against recent traffic) is **deferred to backend**
   ([AAASM-5094](https://lightning-dust-mite.atlassian.net/browse/AAASM-5094) / SaaS).
   *Why:* true draft-replay needs a backend replay endpoint that does not exist; the
   single-request dry-run is the honest v0.

### Agent-Detail — [AAASM-5073](https://lightning-dust-mite.atlassian.net/browse/AAASM-5073) (`design/v1/hi-fi/agent-detail.jsx`)

7. **Master-detail drawer paradigm.** Shipped opens agent detail as a right-side drawer
   over the Fleet view; the mock's full-page paradigm is superseded. *Why:* the drawer
   preserves Fleet context and supports deep-linking into a specific agent without
   losing the list — the master-detail pattern the fleet workflow needs.
8. **Keep burn-chart + recent-events on Overview** *(ratify-flavored sub-note of the
   drawer HYBRID; counted as the +1 that makes 21).* Shipped keeps the burn-chart and
   recent-events blocks on the agent Overview as an additive evolution. *Why:* they are
   the highest-signal at-a-glance panels for an operator inspecting one agent.

### Live-Ops — [AAASM-5074](https://lightning-dust-mite.atlassian.net/browse/AAASM-5074) (`design/v1/hi-fi/live-ops.jsx`)

9. **5-state LIVE pill.** Shipped's LIVE status pill exposes 5 states; the mock's
   2-state pill is superseded. *Why:* strictly more informative — the extra states
   (connecting / degraded / etc.) are real conditions the operator needs to distinguish.
10. **Pipeline-as-client-side-simulation.** Shipped renders the pipeline animation as a
    client-side simulation. *Why:* the visual is a stand-in until the live op-stream
    backend lands; the simulation is the honest, authoritative v0 for that panel.

### Trace — [AAASM-5075](https://lightning-dust-mite.atlassian.net/browse/AAASM-5075) (`design/v1/hi-fi/trace.jsx`)

11. **TraceDrawer container.** Shipped uses a single generic right-side `TraceDrawer`
    shell; the mock's per-variant `ApprovalDetailDrawer` is superseded. *Why:* one
    container that renders any trace type is simpler and consistent across trace kinds.
12. **Generic RedactionPreview.** Shipped renders a generic redaction-preview block; the
    mock's semantic per-type redaction templates are superseded. *Why:* per-type
    semantic templates would **fabricate data** the backend does not actually emit — the
    generic block is more truthful about what is known.
13. **LayerSteps renderer.** Shipped uses a `LayerSteps` renderer that handles all 7
    layer states. *Why authoritative:* it is complete-by-design and correct once the
    per-state data lands; no mock-side rebuild is warranted.

### Costs — [AAASM-5076](https://lightning-dust-mite.atlassian.net/browse/AAASM-5076) (`design/v1/hi-fi/costs.jsx`)

14. **Budget-utilisation + Blocked-by-budget KPIs.** Shipped adds Utilisation and
    Blocked-by-budget KPIs alongside the spec KPIs. *Why:* additive, high-value budget
    signals; kept.
15. **7-day HistoryChart + Budget-inheritance tree.** Shipped ports these faithfully;
    ratified as-is. *Why authoritative:* the port is the intended target.
16. **CostBreakdownPanel superset.** Shipped's `CostBreakdownPanel` is a superset of the
    mock's per-agent cost table and is kept alongside the spec KPIs. *Why:* superset —
    it does everything the mock table did and more.

### Fleet — [AAASM-5078](https://lightning-dust-mite.atlassian.net/browse/AAASM-5078) (`design/v1/hi-fi/fleet.jsx`)

17. **FE columns built ahead-of-data.** Shipped's Fleet table lays out columns whose
    data is not fully wired yet; the layout is correct and authoritative. *Why:* the
    column layout is the right target; the data is backend-gated (Fleet has zero
    FE-buildable-now work), so the ahead-of-data layout stays.
18. **Bulk suspend/resume bar + filters.** Shipped adds a bulk-actions bar and filters
    beyond the mock. *Why:* additive operator affordances; kept.

### Identity — [AAASM-5079](https://lightning-dust-mite.atlassian.net/browse/AAASM-5079) (`design/v1/hi-fi/identity.jsx`)

19. **4-tab Service-Identities model.** Shipped uses a 4-tab Service-Identities model; it
    is a real superset of the mock's 3-tab Members / API-Tokens / Roles model. The
    **human-user directory is Cloud-only** (SaaS-tier, out of the OSS scope), so OSS
    Identity is pure design-artifact ratification. *Why authoritative:* the OSS product
    governs service identities (agents), not human users; the 4-tab model reflects that
    reality and supersets the mock.

### Teams — [AAASM-5080](https://lightning-dust-mite.atlassian.net/browse/AAASM-5080) (`design/v1/hi-fi/teams.jsx`)

20. **Members-as-agents (OSS model).** Shipped models team membership as agents, not
    human users. *Why:* matches the OSS product's identity model (human directory is
    Cloud-only, as in Identity above).
21. **Approval-routing from the live approvals queue** *(20th primary RATIFY decision;
    listed 21st because item 8 is a sub-note).* Shipped shows approval-routing as a live
    queue driven by the real approvals data. *Why authoritative:* it renders actual
    queue state rather than a static mock of routing rules.

> **Count.** 20 primary RATIFY decisions. Item 8 ("keep burn-chart + events") is a
> ratify-flavored part of the Agent-Detail drawer HYBRID; counting it standalone gives
> 21 enumerated items, which is why the list runs to 21. The authoritative program
> inventory (AAASM-5077) records both figures.

---

## Consequences

- **Positive.** The shipped dashboard and its reference mocks no longer silently
  disagree about what "correct" is. Future FE work will not rebuild a ratified surface
  back toward a stale mock. Each mock carries an inline pointer to this ADR, so the
  supersession is discoverable at the point of use.
- **Positive.** The RATIFY set is design-record-only — no product code changes, no
  rebuild cost. The genuine build work (FE-buildable, backend-blocked) stays tracked on
  its own stories where it can be prioritized independently.
- **Neutral / accepted.** Several ratified items (5s polling, pipeline simulation,
  Fleet ahead-of-data columns, single-request dry-run) are explicitly *honest v0*
  stand-ins for backend capability that does not exist yet. When that backend lands, the
  relevant surface may evolve again — that is expected and does **not** retroactively
  invalidate this ratification; it would be recorded as a new decision.
- **Supersedes mock behavior.** For the 20 items above, the corresponding
  `design/v1/hi-fi/*.jsx` behavior is superseded. The mock files are **not deleted** —
  their FE-parity spec sections are still referenced by the in-flight FE-buildable and
  backend-blocked work — but the ratified parts now carry a supersession note stating
  the shipped implementation is authoritative.

---

## Relationship to the mocks and to other work

- **Mocks (`design/v1/hi-fi/`)** — annotated, not rewritten. Only the ratified behavior
  is marked superseded; the FE-parity spec content other work still depends on is left
  intact.
- **FE-buildable-now items** (27, ≈ 1L + 11M + 15S) — tracked on stories 5071–5080; not
  in this ADR.
- **Backend-blocked items** (~32) — tracked on the backend-decomposition Epic and its
  children (5082-family, incl. the deferred Policy replay `SimulateModal` at
  [AAASM-5094](https://lightning-dust-mite.atlassian.net/browse/AAASM-5094)); not in this
  ADR.
- **Cloud/SaaS-tier items** (human-user directory on Identity and Teams; policy
  rollout/canary) — out of the OSS scope entirely.

---

## Addendum — Topology deviations introduced after ratification

**Ticket**: [AAASM-5099](https://lightning-dust-mite.atlassian.net/browse/AAASM-5099)

The 21 items above are the closed output of the AAASM-5077 reconciliation program.
This addendum records deviations from `design/v1/hi-fi/topology.jsx` introduced by
*later* work, under the same rule the Decision section states: the shipped
implementation is authoritative and the mock behavior is superseded. It is appended
rather than folded into the list above so that the program's item numbering, its
count note, and the three already-ratified Topology entries all stay untouched.

### Topology — [AAASM-5099](https://lightning-dust-mite.atlassian.net/browse/AAASM-5099) (`design/v1/hi-fi/topology.jsx`)

A1. **No `③ parent` inheritance row.** The mock's node-detail Policy-Inheritance
    panel draws a `parent` tier between org and team. Shipped emits no parent row.
    *Why shipped is authoritative:* there is no parent tier in the product's scope
    vocabulary — `aa_gateway::policy::scope::PolicyScope` is
    `Global | Org | Team | Agent | Tool`, and a parent agent's own `agent:`-scoped
    policies are **not** inherited by the agents it spawns. Rendering a parent row
    would assert an inheritance relationship the policy engine does not implement,
    which is worse than omitting it: an operator would read a permission as
    inherited when nothing grants it.
A2. **`① org baseline` renders as a `global` tier.** The mock's broadest row is
    labelled "org baseline" and it has no global row at all. Shipped emits
    `global` as the broadest tier and `org` only when the agent actually carries an
    `org_id`. *Why:* the cascade the gateway walks is `Global → Org → Team → Agent`;
    `Global` is a real, separately-authorable scope whose documents apply to every
    agent, and an agent with no `org_id` has no org tier to show. Collapsing the two
    would mislabel a fleet-wide policy as one org's baseline.
A3. **`→ effective` verdict wording is derived from the payload.** The mock hardcodes
    the verdict row to `narrowed (pending)` / `baseline`. Shipped derives the wording
    client-side from the node's actual `allow` / `deny` / `allowRestricted` values.
    *Why:* those two mock strings are placeholder copy for a static screenshot, not a
    vocabulary the API produces; a real cascade can be restricted, deny-listed, both,
    or neither, and the panel must say which. `narrowed (pending)` in particular
    describes credential-narrowing, which is a different policy stage
    ([AAASM-5094](https://lightning-dust-mite.atlassian.net/browse/AAASM-5094)) and
    is not readable from this payload at all.

These three follow the same *honest v0* principle as the ratified items: where the
mock implies a capability the backend does not model, ship what the data supports and
record the gap rather than rendering a plausible-looking fiction.

---

## Correction — two recorded claims disproven on re-audit (AAASM-5082)

**Ticket**: [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082)
**Date**: 2026-07

A dashboard-truthfulness re-audit under Epic
[AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082) checked the
ratified items above against the source. **Two of the claims recorded in the Decision
section are false.** They are corrected here rather than edited away: the point of an
ADR is that the record shows what was believed, and shows it being corrected. The
original item text above is **left untouched**, as are the item numbering, the count
note, and every other ratified entry — only the two claims below are affected, and only
in the respects stated.

Both errors are of the same kind, and it is worth naming it: **a plausible-looking
fact about the shipped code was recorded without being verified against the shipped
code.** That is precisely the failure mode the truthfulness programme exists to catch,
so it is fitting that the programme's first finding is in its own governance record.

### C1 — Item 17: "Fleet has zero FE-buildable-now work" is false

- **What was claimed.** Item 17 (Fleet, AAASM-5078) ratifies the ahead-of-data column
  layout, and in doing so asserts parenthetically that *"the data is backend-gated
  (Fleet has zero FE-buildable-now work)"*. That parenthetical was the basis for Fleet
  contributing no items to the 27-item FE-buildable set.
- **What is actually true.** Fleet has at least one item that is buildable with the
  data already on hand today: **there is no filtered-empty state.**
  `dashboard/src/pages/FleetPage.tsx:472-479` handles only the *unfiltered* empty case
  (`agents?.length === 0` → "No agents registered yet."). The table is driven by
  `filteredFleet` (`FleetPage.tsx:230`, passed as `data` at `FleetPage.tsx:292`), and
  nothing renders a message when `filteredFleet` is empty but `agents` is not — the
  operator gets a header row above nothing, with no explanation of whether their
  filters excluded everything or the fleet is empty.
- **Evidence that this is a real parity gap, not an invention.** Both mocks specify the
  state explicitly: `design/v1/hi-fi/fleet.jsx:291` and
  `design/v2/hi-fi/fleet.jsx:275` render
  `<div className="empty">no agents match these filters</div>`. It requires no backend
  data whatsoever — `filteredFleet.length` and `filteredCount`
  (`FleetPage.tsx:301`) are already computed in the component.
- **Effect on the ratification.** **Item 17's ratification itself stands.** The
  ahead-of-data column layout is still authoritative and still needs no rebuild. Only
  the parenthetical claim about Fleet's FE-buildable inventory is withdrawn: Fleet is
  **not** empty of FE-buildable-now work, and the AAASM-5077 inventory's Fleet line
  should be re-opened rather than treated as closed.
- **Not re-derived here.** This correction records *one* verified counter-example. It
  does not claim to be a complete re-audit of Fleet, and the count note above is
  therefore left as-is: no *ratified* item count changed.

### C2 — Item 3: the ratified 5s Topology polling was never implemented

- **What was claimed.** Item 3 (Topology, AAASM-5071) records *"5s polling as the
  'live' stand-in. **Shipped** treats a 5-second poll as the 'live' feed"*, and ratifies
  it as authoritative over the mock's implied WebSocket push feed. The claim is stated
  in the past tense, as shipped behaviour.
- **What is actually true.** **No dashboard query polls.**
  `grep -rn "refetchInterval" dashboard/src` returns **zero matches**. React Query does
  not poll unless `refetchInterval` is set — its default is `false` — and the app's
  client is constructed with no default options at all
  (`dashboard/src/main.tsx:9`: `const queryClient = new QueryClient()`). The topology
  view issues a single `useQuery` (`dashboard/src/features/topology/api.ts:40-42`, used
  at `dashboard/src/pages/TopologyPage.tsx:29`) which fetches on mount and then only on
  remount or window refocus.

  Stated precisely, because an imprecise correction is worse than the error it
  corrects: the claim is about **polling**, not about updates in general. One
  `setInterval` does exist in `dashboard/src` — `AppShell.tsx:103`, a 1-second clock
  tick that re-renders the "last sync" relative timestamp and **fetches nothing**. It is
  not a poll.
- **The likely origin of the error.** `dashboard/src/features/topology/api.ts:43`
  carries `staleTime: 5_000`, and its doc-comment (`api.ts:37-38`) says the shorter
  `staleTime` is chosen because "topology reflects live agent state and benefits from
  periodic refresh". `staleTime` is a **cache-freshness window, not a timer** — it
  governs whether an already-mounted query *may* refetch when something else triggers
  it, and it never schedules a fetch on its own. The 5-second number in the ADR and the
  5-second number in the code are the same number meaning two different things.
- **Effect on the ratification.** The ratification's *intent* — a poll is the honest v0
  stand-in for a live push feed that has no backend — is unaffected and is not
  withdrawn. What is withdrawn is the factual claim that it is **shipped**. Item 3
  should be read as **ratified but unimplemented**: a decision on record, awaiting
  build, not a description of current behaviour. Any subsequent audit, screenshot, or
  status report that treated Topology as having a live/5s feed was reading this record,
  not the product.
- **Consequence beyond Topology.** Because no query polls, **no dashboard surface
  refreshes on a timer.** Surfaces that update without operator action do so by
  **push**, not by poll, and there are three of them, not one: Live-Ops
  (`useOpsStream`), Approvals (`useApprovalsStream()`, `ApprovalsPage.tsx:141`) and
  Alerts (`useAlertsStream({…})`, `AlertsPage.tsx:123`). Every other surface — Topology
  included — is static between mounts and window refocus. Any ratified item that assumed
  *periodic* refresh should be re-checked against that fact before it is relied on.

### What this correction does *not* change

- No other ratified item is disturbed; the 20/21 counts and the item numbering are
  unchanged.
- The AAASM-5099 addendum above is unaffected.
- No product code changes as a result of this correction. It is a record correction;
  the two follow-ups it implies (the Fleet filtered-empty state, and building or
  re-scoping the Topology refresh) are execution work for the owning stories.
