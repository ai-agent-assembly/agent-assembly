# ADR 0020: Rolling vs Calendar Monthly Budget Windows — and the Missing Team Tier

**Status**: Accepted (2026-07-30, Option C) — the **team-tier limit on the existing calendar-month budget** is ratified for implementation (AAASM-5087). The rolling N-day window + persisted daily-usage ledger (timezone/boundary semantics, refunds/reversals, late events, retention/aggregation) remain **decision-gated** and are tracked separately in AAASM-5286; they are NOT authorised by this ratification.
**Date**: 2026-07 (ratified 2026-07-30)
**Ticket**: [AAASM-5087](https://lightning-dust-mite.atlassian.net/browse/AAASM-5087) (Epic [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082))

This ADR proposes options for the monthly budget capability the Costs monthly KPI
and the Teams monthly-budget card are blocked on. **It changes nothing.** No code,
schema, or configuration is modified by merging it.

**Budgets are an enforcement surface, not a display surface.** A budget limit
causes a hard `Deny` on the gRPC `CheckAction` path, and — when
`action_on_exceed: suspend` is configured — suspends the agent outright. Every
option below therefore alters *when agents get blocked*. That is why this is
sign-off-gated rather than a normal implementation ticket, and why it follows the
ADR 0018 precedent of freezing the decision before touching the hot path.

It complements ADR 0004 (governance enforcement flow) and ADR 0017 (dashboard
design-parity, which ratified the Costs and Teams surfaces this data backs).

---

## Context

### The ticket's premise is partly wrong — a calendar-month budget already exists and is enforced

AAASM-5087 asks for a "monthly rolling budget limit + spend alongside existing
daily". Verified against the source, a **calendar**-month budget is already
implemented end-to-end and already blocks:

- `BudgetKind::Monthly` is a first-class window —
  `aa-gateway/src/budget/types.rs:18-19`, documented as "Per-calendar-month spend
  window, reset on the first of each month".
- `BudgetState` carries `month: u32` (a `YYYYMM` tag) and
  `monthly_spent_usd: Option<Decimal>` — `aa-gateway/src/budget/types.rs:100-105`;
  the tag is computed by `BudgetState::month_tag` at
  `aa-gateway/src/budget/types.rs:118-120`.
- Rollover zeroes monthly spend when the tag changes —
  `aa-gateway/src/budget/types.rs:147-151`.
- It is **enforced on the atomic reservation path**: `reserve_spend` preflights the
  agent's own monthly limit and returns
  `BudgetError::SelfBudgetExhausted { kind: Monthly }` at
  `aa-gateway/src/budget/tracker.rs:906-912`, before the daily check at
  `aa-gateway/src/budget/tracker.rs:913-919`.
- The engine maps that to a deny reason `"monthly budget exceeded"` at
  `aa-gateway/src/engine/mod.rs:1695-1699`, reached via
  `aa-gateway/src/engine/mod.rs:1685`.
- It is configurable from policy YAML as `budget.monthly_limit_usd`
  (`aa-gateway/src/policy/document.rs:46`, lifted into the tracker at
  `aa-gateway/src/engine/mod.rs:342-347`), and validated with the constraint
  `monthly >= daily` (`aa-gateway/src/policy/validator.rs:273-345`).
- It is already on the wire and already populated: `CostSummary.monthly_limit_usd`
  / `monthly_spend_usd` at `openapi/v1.yaml:4973-4982`, filled by
  `aa-api/src/routes/costs.rs:131` and `aa-api/src/routes/costs.rs:134`.

**Precedence is already decided and implemented: monthly is checked before daily,
at every tier.** `aa-gateway/src/budget/tracker.rs:527-534` (tier),
`aa-gateway/src/budget/tracker.rs:647-653` (agent, in `record_cost`),
`aa-gateway/src/budget/tracker.rs:906-919` (agent, in `reserve_spend`). The first
limit that trips wins and nothing is committed. So "what happens when one is
exceeded and not the other" already has an answer: **whichever trips first denies;
monthly is evaluated first, so a monthly breach is reported as
`"monthly budget exceeded"` even if the daily limit also has headroom.**

### So what is actually missing

Three distinct gaps, only one of which is what the ticket literally asks for:

1. **Rolling-window semantics do not exist.** Grepping `rolling`, `trailing`,
   `last_30`, `30[ _-]?day` across the Rust, YAML and Markdown sources finds no
   rolling monthly budget. The one adjacent construct — `budget.window`, a
   humantime duration (`aa-gateway/src/policy/raw.rs:60-64`, validated at
   `aa-gateway/src/policy/validator.rs:325-344`) — is a true wall-clock rolling
   window, but it zeroes **only the daily accumulator**
   (`aa-gateway/src/budget/types.rs:193`); the monthly branch in the same function
   still uses the calendar `month_tag`
   (`aa-gateway/src/budget/types.rs:174-178`). `window:` therefore cannot express a
   rolling month.

2. **The data model cannot support a rolling window today.** A trailing-30-day sum
   requires a per-day ledger. The only date-keyed series is
   `spend_history: DashMap<AgentId, BTreeMap<NaiveDate, Decimal>>`
   (`aa-gateway/src/budget/tracker.rs:138`), and it is **in-memory only and wiped
   on every restart** (`aa-gateway/src/budget/tracker.rs:281`; documented at
   `aa-gateway/src/budget/tracker.rs:1029-1031`). The persisted snapshot
   `PersistedBudget` (`aa-gateway/src/budget/persistence.rs:11-19`) stores only
   *current-window totals* — `spent_usd`, `date`, `month`, `monthly_spent_usd`,
   `last_reset_at`. There is no persisted history from which a trailing-30-day sum
   could be reconstructed after a restart.

3. **The team tier has no configurable limit at all — of any window.** The
   enforcement code exists (`team_daily_limit_usd` /`team_monthly_limit_usd` at
   `aa-gateway/src/budget/tracker.rs:111` and `:113`, enforced at
   `aa-gateway/src/budget/tracker.rs:598-607`), but the builders that set them
   (`with_team_daily_limit` / `with_team_monthly_limit`,
   `aa-gateway/src/budget/tracker.rs:192` and `:198`) have **zero production
   callers** — only `aa-gateway/tests/team_budget_test.rs` and
   `aa-integration-tests/tests/common/mod.rs:1271`. `BudgetPolicy`
   (`aa-gateway/src/policy/document.rs:42-62`) has no team-tier field. The ticket
   says "team + agent"; today *neither* is settable per-entity outside the policy
   cascade, and the cascade route has its own limitation (below).

### Restart and persistence behaviour, verified

- Agent, team and global accumulators **do** survive restart: written to
  `~/.aa/budget.json` (`aa-gateway/src/budget/persistence.rs:44-47`) every 60s
  (`aa-gateway/src/budget/persistence.rs:81`), flushed on shutdown
  (`aa-gateway/src/server.rs:530-536`), restored at
  `aa-gateway/src/budget/tracker.rs:252-261`. `monthly_spent_usd` is included.
  Pinned by `aa-gateway/tests/budget_persistence_test.rs:20-59`.
- **Org accumulators do not** — restored empty with an explicit comment at
  `aa-gateway/src/budget/tracker.rs:265-269`; `PersistedBudget` has no
  `org_budgets` field.
- A **corrupt** `budget.json` starts the gateway at zero spend
  (`aa-gateway/src/server.rs:155-163`), pinned by
  `aa-gateway/tests/budget_persistence_test.rs:113-134`. For a monthly window this
  is a materially larger fail-open than for a daily one: it grants a full month of
  headroom back, not a day's.

### Two enforcement paths, and they do not agree

- **Path A (atomic reservation)** — `check_action`/`batch_check` →
  `aa-gateway/src/service/policy_service.rs:1333` →
  `aa-gateway/src/engine/mod.rs:1685` → `reserve_spend`
  (`aa-gateway/src/budget/tracker.rs:848`). Uses **tracker-level** limits only.
- **Path B (Stage-7 read-check)** — `aa-gateway/src/engine/mod.rs:1326-1332`,
  cascade variant `check_cascade_budget` at `aa-gateway/src/engine/mod.rs:1448-1469`.
  This one applies **each cascade document's own `budget:` block**, which is the
  only way to express a per-agent or per-team limit today.

Consequence: **cascade-scoped budgets do not participate in the TOCTOU-safe
reservation.** Any option that leans on the cascade to deliver "team + agent"
monthly limits inherits that concurrency gap. This is a pre-existing condition, not
something the options below introduce, but it bounds what "enforced" honestly means.

### Not verified

- Whether `org_daily_limit_usd` / `org_monthly_limit_usd` from policy YAML actually
  take effect in the **shipped `serve` path**. The lifting code
  (`aa-gateway/src/engine/mod.rs:368-373`) runs in `load_from_file` /
  `load_cascade_from_dir`, but the binary builds its tracker via
  `with_state_and_alert_sender`, which hardcodes all four tenant limits to `None`
  (`aa-gateway/src/budget/tracker.rs:274-277`) and is then handed to the
  `*_with_budget` loaders. This is strongly indicated by reading the code but **is
  not covered by any test I found**, so it is reported as a suspected inert path,
  not an asserted defect. It should be confirmed before any option here is costed,
  because it changes whether the org tier is a working precedent or a second broken
  one.
- Schema drift: `schemas/policy/v1/policy-document.schema.json:75-86` declares
  `budget` with `"additionalProperties": false` and **only** `daily_limit_usd`. A
  policy using `monthly_limit_usd` appears to be invalid against the published JSON
  Schema while being accepted by the Rust validator. I have not verified which
  consumers enforce that schema, so the practical impact is unknown.

---

## Options

### Option A — Ship the team tier; keep the calendar month; do not build rolling

Add `team_daily_limit_usd` / `team_monthly_limit_usd` to `BudgetPolicy` and wire
them to the existing builders. Extend `BudgetTreeNode`
(`openapi/v1.yaml:4539-4593`, today daily-only per `:4556`) with the monthly
figures. Fix the JSON-Schema drift. Declare the calendar month the product's
monthly semantic and say so in the docs.

- **Enforcement change:** limits become *reachable* at the team tier for the first
  time. The comparison logic is untouched — `tier_limit_exceeded`
  (`aa-gateway/src/budget/tracker.rs:516-542`) already runs; it just always sees
  `None` today. Blast radius is bounded by the fact that a limit only binds where an
  operator explicitly sets one.
- **Pro:** smallest diff; no new persistence; reuses a path already covered by
  `aa-gateway/tests/team_budget_test.rs`; unblocks the Teams monthly-budget card and
  the Costs monthly KPI immediately.
- **Con:** does not deliver what the ticket's title says. Calendar months have a
  real operational flaw — the reset is a cliff. An agent that exhausts its cap on
  the 3rd is blocked for 28 days; one that exhausts it on the 30th is unblocked
  hours later. Spend is not billed uniformly across the month, so a calendar cap
  is a poor proxy for a burn-rate control.
- **Con:** leaves the per-*agent* limit still unreachable except via the cascade,
  which is Path B only.

### Option B — Add a persisted daily ledger, then build a true rolling window on top

Introduce a persisted per-scope, per-day spend ledger (promoting today's
in-memory `spend_history` to durable state in `PersistedBudget`), and add a
`BudgetKind::Rolling { days }` window computed as the sum of the trailing N daily
buckets. Keep `Monthly` (calendar) as-is; `rolling` becomes a third, opt-in window.

- **Enforcement change:** a genuinely new deny condition, on a counter that did not
  previously exist. Precedence has to be decided (proposed: rolling → monthly →
  daily, most-restrictive-first, matching the existing convention).
- **Pro:** it is what the ticket asks for, and it is the right control for burn
  rate — no cliff, no gaming the reset date.
- **Pro:** the ledger is independently valuable: it also fixes the per-agent 7-day
  cost sparkline in the same Epic (which today reads the volatile in-memory
  `spend_history`, `aa-api/src/routes/analytics.rs:1325`) and survives restarts.
- **Con: this is the highest-blast-radius option in the Epic.** If the window is
  computed wrongly the failure is silent and asymmetric. Off-by-one on the trailing
  bound over-counts by a day and blocks agents that are legitimately under budget —
  a fleet-wide false denial that looks exactly like a policy problem. Off-by-one the
  other way, or a ledger that silently drops buckets on restart, under-counts and
  fails **open** on a spend cap. Both are hard to notice from the dashboard, which
  shows the same number the (wrong) enforcement is using.
- **Con:** ledger growth and retention become a new concern (unbounded per-agent
  per-day rows), as does the corrupt-file fallback: today a corrupt snapshot resets
  one day/one month of spend; with a ledger it would reset the whole rolling window.
- **Con:** largest change to a hot path guarded by proptests and concurrency tests
  (`aa-gateway/src/budget/tracker.rs:1806`, `:2029`).

### Option C — Split: ship Option A now, file the rolling window as a separate decision

Take Option A as the AAASM-5087 deliverable (rename the ticket to match: "team +
agent monthly budget limits, calendar month"). Open a separate Story for the
persisted ledger + rolling window, sequenced after it, with its own sign-off.

- **Pro:** unblocks both blocked dashboard surfaces this Epic cares about without
  putting a new arithmetic-sensitive deny condition on the enforcement path in the
  same change. Keeps the risky part separable and separately reviewable.
- **Pro:** the ledger work (Option B's prerequisite) is then scoped honestly as its
  own piece of infrastructure rather than smuggled in under a "limits" ticket.
- **Con:** the ticket's stated goal is deferred; if product genuinely needs rolling
  semantics for a customer commitment, this is a delay.
- **Con:** two rounds of enforcement-path review instead of one.

---

## Recommendation

**Option C.**

The reasoning is that AAASM-5087 currently bundles two things of very different
risk. The part the dashboard is actually blocked on — a monthly figure for the
Costs KPI and a team monthly budget card — is satisfied by making the *existing,
already-enforced, already-tested* calendar-month machinery reachable at the team
tier. That is a small, reviewable change to configuration plumbing.

The rolling window is a different animal: it requires new persisted state, and it
introduces a deny condition whose miscomputation fails silently in **both**
directions. It deserves its own decision, its own tests, and its own sign-off — not
to ride along with a plumbing fix.

Recommended precedence if and when rolling lands: **most-restrictive-first
(rolling → monthly → daily)**, extending the existing monthly-before-daily
convention rather than inventing a new ordering.

Two things should be settled regardless of which option is chosen, because they
affect the correctness of the monthly number the dashboard already renders:

- Confirm or refute the suspected inert org-limit path
  (`aa-gateway/src/budget/tracker.rs:274-277`).
- Decide whether the corrupt-`budget.json` fallback
  (`aa-gateway/src/server.rs:155-163`) should stay fail-open for a *monthly*
  window. Resetting a day of spend is a modest gift; resetting a month is not.

---

## Consequences

**If Option C (recommended) is accepted:**

- *Positive:* Costs monthly KPI and the Teams monthly budget card unblock against
  real, enforced data. Team limits stop being test-only dead code. No new counter
  arithmetic enters the deny path.
- *Negative / accepted:* the calendar-month reset cliff remains. Operators who want
  burn-rate control do not get it in this Epic.
- *Neutral:* `BudgetTreeNode` and the policy JSON Schema both need extending;
  neither is behaviour-bearing.

**If Option B is accepted instead:** budget denial semantics change for every
deployment that opts into a rolling limit, and a new persisted artefact enters the
gateway's state directory. Validation would have to include, at minimum: a test
that the trailing window boundary is inclusive-exclusive exactly as specified; a
restart test proving the ledger reconstructs the same window sum; and a test that a
corrupt/absent ledger fails **closed** rather than granting a month of headroom.

**If Option A is accepted:** identical to Option C's first phase, but the rolling
window is dropped rather than deferred, and AAASM-5087 should be closed as
"delivered, scope corrected" with the rolling ask explicitly declined.

---

## What this unblocks

- The Costs page monthly KPI and the Teams monthly budget card
  ([AAASM-5076](https://lightning-dust-mite.atlassian.net/browse/AAASM-5076),
  [AAASM-5080](https://lightning-dust-mite.atlassian.net/browse/AAASM-5080) surfaces
  ratified in ADR 0017).
- Under Option B/C's second phase, the per-agent cost-history sparkline in the same
  Epic, which today reads a counter that does not survive restart.

---

## Decision required from: product + architecture

1. **Rolling or calendar?** Is a trailing-N-day window a product requirement, or is
   the calendar month the intended monthly semantic? (Option A/C vs B.)
2. **If rolling:** what is N — 30 days, or a configurable `rolling_days`? And what
   is the precedence against daily and calendar-monthly limits?
3. **Team tier:** confirm team-scoped budget limits should be settable from policy
   YAML (`budget.team_daily_limit_usd` / `team_monthly_limit_usd`), given team caps
   are shared across a tenant's agents and one agent can therefore exhaust another's
   headroom.
4. **Fail-open posture:** should a corrupt or missing budget snapshot continue to
   reset spend to zero when a *monthly* (or rolling) limit is configured?

Until items 1–2 are answered, **no implementation ticket should be opened against
the enforcement path**. Merging this ADR does not authorise any of the options.

---

## Reconsideration triggers

- A customer commitment that requires burn-rate (rather than calendar) control.
- Confirmation that the org-tier limits are inert in the shipped path — which would
  make the tenant-tier story materially worse than described here and may reorder
  the options.
- Any move of budget state out of the JSON snapshot into a database, which would
  make the persisted ledger of Option B substantially cheaper.

## Traceability

- Proposes the decision for
  [AAASM-5087](https://lightning-dust-mite.atlassian.net/browse/AAASM-5087) under
  Epic [AAASM-5082](https://lightning-dust-mite.atlassian.net/browse/AAASM-5082),
  contract group 4 (budgets / costs).
- Enforcement-flow context is ADR 0004; the Costs and Teams surfaces were ratified
  in ADR 0017. Follows the sign-off-gating precedent set by ADR 0018.
