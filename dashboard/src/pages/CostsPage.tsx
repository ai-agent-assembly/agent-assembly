import { useMemo, useState, type ReactNode } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import { CostBreakdownPanel } from '../features/analytics/CostBreakdownPanel'
import { TruthfulValue } from '../components/truthfulness'
import {
  certain,
  certainFromQuery,
  isKnown,
  known,
  mapCertain,
  propagateAbsence,
  type Certain,
  type TruthState,
} from '../lib/truthfulness'
import {
  joinTeamRows,
  useCostSummaryQuery,
  useTopologyOverviewQuery,
  type CostSummary,
  type TeamListRow,
  type TopologyOverview,
} from '../features/teams/api'
import { useTopologyQuery } from '../features/topology/api'
import { deriveCostKpis, type MeasuredCount, type PeriodSpend } from '../features/costs/costKpis'
import { buildPerAgentRows } from '../features/costs/perAgentRows'
import { useCostHistoryQuery, useBudgetTreeQuery } from '../features/costs/api'
import { HistoryChart } from '../components/costs/HistoryChart'
import { BudgetTree } from '../components/costs/BudgetTree'
import { BudgetBar } from '../components/costs/BudgetBar'
import { BurnCallouts } from '../components/costs/BurnCallouts'
import { CostTabs, type CostTab } from '../components/costs/CostTabs'
import { PerAgentTable } from '../components/costs/PerAgentTable'
import { PerTeamTable } from '../components/costs/PerTeamTable'
import '../features/analytics/CostBreakdownPanel.css'
import './CostsPage.css'

/** Map a utilisation percentage to its KPI-value severity modifier. */
function utilisationClass(pct: number | null): string {
  if (pct == null) return ''
  if (pct >= 95) return ' costs-kpi__value--danger'
  if (pct >= 80) return ' costs-kpi__value--warn'
  return ' costs-kpi__value--ok'
}

/**
 * Burn-value severity for the Daily / Monthly cards — like `utilisationClass`
 * but with no green "ok" band: below 80% the figure stays neutral ink, matching
 * the mock's `kpiColor` (danger ≥95, warn ≥80, else ink).
 */
function burnValueClass(pct: number | null): string {
  if (pct == null) return ''
  if (pct >= 95) return ' costs-kpi__value--danger'
  if (pct >= 80) return ' costs-kpi__value--warn'
  return ''
}

function usd(value: number): string {
  return `$${value.toFixed(2)}`
}

/** `$x.xx`, or the reason there is no figure. Never a fabricated `$0.00`. */
function certainUsd(value: number | null, whenMissing: TruthState): Certain<ReactNode> {
  return mapCertain(certain(value, whenMissing), usd)
}

interface KpiCardProps {
  readonly label: string
  /**
   * The headline figure, or the reason there is none.
   *
   * `Certain` rather than `string` so an absence has somewhere to live. While
   * these were typed `string` the only way to render "we measured nothing" was
   * to pick a stand-in — and the stand-in picked was `0`, which on a compliance
   * KPI reads as a clean bill of health for teams nobody checked (AAASM-5185).
   */
  readonly value: Certain<ReactNode>
  /** The caption beneath the figure, subject to the same rule. */
  readonly sub: Certain<ReactNode>
  readonly valueClass?: string
  readonly footer?: ReactNode
  readonly testId: string
}

function KpiCard({ label, value, sub, valueClass = '', footer, testId }: KpiCardProps) {
  return (
    <div className="costs-kpi" data-testid={testId}>
      <div className="costs-kpi__label">{label}</div>
      {/* A severity colour is a claim about a measured figure, so it is only
          applied to one. An absence carries its own truth tone instead. */}
      <div className={`costs-kpi__value${isKnown(value) ? valueClass : ''}`}>
        <TruthfulValue value={value} format={node => node} testId={`${testId}-value`} />
      </div>
      <div className="costs-kpi__sub">
        <TruthfulValue value={sub} format={node => node} testId={`${testId}-sub`} />
      </div>
      {footer}
    </div>
  )
}

/**
 * Caption for a card whose figure comes from the cost summary.
 *
 * A caption may only describe the budget configuration when the summary that
 * would carry it actually resolved. `limit == null` means "nothing is
 * configured" *only* on a resolved payload; on a failed or in-flight request it
 * means nothing was read at all, and captioning that "no daily limit set" tells
 * the operator to go configure a budget that may well already exist. That left
 * the value saying `Unavailable` while its own caption asserted a configuration
 * fact — the same self-contradiction on one card that AAASM-5185 found between
 * two (`— · no daily budget limit set` beside `Failed to load cost data`).
 *
 * The absent branch stays a `known` sentence rather than a second `—`: the
 * operator is better served by being told why the figure is missing than by a
 * row of dashes. What it may never do is describe a configuration it did not
 * read.
 */
function summarySub(
  summary: Certain<CostSummary>,
  subject: string,
  describe: () => string,
): Certain<ReactNode> {
  if (isKnown(summary)) return known(describe())
  if (summary.state === 'unavailable') return known(`${subject} could not be loaded`)
  if (summary.state === 'unknown') return known(`waiting for the ${subject}`)
  return known(`no ${subject} was reported`)
}

interface SpendKpiCardProps {
  readonly label: string
  readonly period: string
  readonly spend: PeriodSpend
  /**
   * The cost summary this card's figures came from.
   *
   * Passed whole rather than as a pre-resolved `TruthState` because the card
   * needs it twice: to say which absence an unfilled figure is, and to know
   * whether it is entitled to describe the budget at all.
   */
  readonly summary: Certain<CostSummary>
  readonly testId: string
}

/** Daily / Monthly spend card: value, "of $limit" sub, mini budget bar + % used. */
function SpendKpiCard({ label, period, spend, summary, testId }: SpendKpiCardProps) {
  return (
    <KpiCard
      testId={testId}
      label={label}
      value={certainUsd(spend.spend, isKnown(summary) ? 'unconfigured' : summary.state)}
      valueClass={burnValueClass(spend.pct)}
      sub={summarySub(summary, `${period} budget`, () =>
        spend.limit == null
          ? `no ${period} limit set`
          : `of ${usd(spend.limit)} ${period} limit`,
      )}
      footer={
        <div className="costs-kpi__bar">
          {/* Spend is passed through, not defaulted: `monthly_spend_usd` is
              absent from the wire until a monthly limit is configured, and the
              `?? 0` this replaces drew a full-width empty track reading "0%" —
              a month of measured zero spend that was never measured
              (AAASM-5127). */}
          <BudgetBar used={spend.spend} limit={spend.limit} label={`${period} budget burn`} />
          {spend.pct != null && <div className="costs-kpi__used">{spend.pct.toFixed(1)}% used</div>}
        </div>
      }
    />
  )
}

interface TeamBudgetContentProps {
  readonly isError: boolean
  readonly isLoading: boolean
  readonly teamRows: readonly TeamListRow[]
  readonly onRetry: () => void
}

/**
 * Resolve the per-team budget section body for the current query state.
 *
 * Extracted from the JSX as an explicit if/else chain (rather than a nested
 * ternary) so each error / loading / empty / list branch reads on its own.
 */
function TeamBudgetContent({ isError, isLoading, teamRows, onRetry }: TeamBudgetContentProps): ReactNode {
  if (isError) {
    return (
      <p className="costs-state costs-state--error" data-testid="costs-error">
        Failed to load cost data.{' '}
        <button type="button" className="costs-state__retry" onClick={onRetry}>
          Retry
        </button>
      </p>
    )
  }
  if (isLoading) {
    return (
      <p className="costs-state" data-testid="costs-loading">
        Loading cost data…
      </p>
    )
  }
  if (teamRows.length === 0) {
    return (
      <p className="costs-team-bars__empty" data-testid="costs-team-empty">
        No teams registered yet.
      </p>
    )
  }
  return <PerTeamTable rows={teamRows} />
}

/**
 * Caption for the Blocked-by-budget KPI, stating coverage whenever the count
 * does not span the whole roster.
 *
 * The sub-text stays a `known` statement even when the count is absent: "no
 * team has a daily ceiling configured" is itself a fact worth telling the
 * operator, and dashing it too would leave the card silent about why. What it
 * may never do is assert compliance — the unconditional "no teams over the
 * daily limit" it replaces did exactly that for teams the page never measured
 * (AAASM-5185).
 */
function blockedSub(count: MeasuredCount): Certain<ReactNode> {
  if (!isKnown(count.value)) {
    // `total` is the structural difference between "the roster never arrived,
    // so nothing was examined" and "rows were examined and none proved
    // measurable". Only the second may be reported as a failed measurement: an
    // in-flight request has not failed to measure anything, it has not
    // finished, and `certainFromQuery` gives it the same `unknown` state as a
    // genuinely unmeasurable roster. Keying off `total` rather than the
    // absence `detail` keeps that distinction structural instead of a string
    // match (AAASM-5185).
    if (count.total === 0) {
      if (count.value.state === 'unavailable') return known('daily burn could not be loaded')
      if (count.value.state === 'unknown') return known('waiting for the daily burn figures')
      return known('no daily burn figures were reported')
    }
    if (count.value.state === 'unconfigured') return known('no team has a daily ceiling configured')
    return known('no team’s daily burn could be measured')
  }
  if (count.total === 0) return known('no teams registered')
  if (count.measured < count.total) {
    const unmeasured = count.total - count.measured
    return known(
      `${count.measured} of ${count.total} teams measured · ${unmeasured} unmeasured`,
    )
  }
  return known(
    count.value.value === 0
      ? 'no teams over the daily limit'
      : 'teams at ≥95% of the org daily limit',
  )
}

/**
 * Cost & Budget page (AAASM-3509, restructured for FE parity in AAASM-5076) —
 * replaces the `<ComingSoon>` stub at `/costs`.
 *
 * Composed from existing OSS blocks per design/v1/hi-fi/costs.jsx:
 *   - KPI strip   — Daily / Monthly spend (each with a mini budget bar), Agents
 *                   tracked, plus the live Budget-utilisation and Blocked-by-budget
 *                   KPIs (a superset of the mock's four cards).
 *   - Callouts    — daily-burn warning (≥80%) / critical (≥95%) banners.
 *   - History     — 7-day spend `HistoryChart`.
 *   - Tabs        — Per-agent (table + analytics breakdown) / Per-team (table) /
 *                   Budget tree (inheritance), replacing the previous stacked
 *                   sections.
 *
 * The OSS `/api/v1/costs` summary only carries an *org* budget limit, so per-team
 * utilisation is each team's spend against the org limit (its share of the org
 * budget) rather than a per-team configured limit, which the OSS API does not
 * expose. The mock's per-agent 7-day sparkline and per-team monthly *limit* are
 * omitted — neither has a backing endpoint yet (AAASM-5076 / ADR-0020 /
 * AAASM-5087). Per-team agent count and monthly *spend* are restored, both being
 * on the wire already (AAASM-5160).
 *
 * Every figure on the KPI strip is a `Certain`, so an absence renders as `—`
 * with its own state and tone rather than as a numeral. A compliance count that
 * measured nothing must not be indistinguishable from one that measured
 * everything and found nothing wrong (AAASM-5185).
 *
 * There is no Daily/Monthly period control (AAASM-5126). Both mocks
 * (`design/v1/hi-fi/costs.jsx` and `design/v2/hi-fi/costs.jsx` — ADR-0025 would
 * make the latter binding but is still `Proposed`, so both are read as
 * evidence) show the two windows side by side and neither has a toggle, and the
 * shipped control could not
 * honour the switch: the per-team bars, the blocked-by-budget count and the
 * burn callouts are all daily and stayed daily under "Monthly" — the wire has
 * no per-team ceiling of any window (`TeamCostEntry` carries spend only, and
 * adding a team-tier monthly limit is sign-off-gated on ADR-0020 /
 * AAASM-5087), and the org-monthly figure it *could* move was already printed
 * verbatim on the Monthly-spend card beside it. An affordance with no
 * successful path is removed, not relabelled.
 */
export function CostsPage() {
  const [tab, setTab] = useState<CostTab>('agents')
  const overviewQuery = useTopologyOverviewQuery()
  const costsQuery = useCostSummaryQuery()
  const topologyQuery = useTopologyQuery()

  const teamRows = useMemo(
    () => joinTeamRows(overviewQuery.data, costsQuery.data),
    [overviewQuery.data, costsQuery.data],
  )

  // The KPI strip is fed through the truthfulness vocabulary rather than the
  // raw query data, so an outage, an in-flight request and an unset budget stay
  // distinguishable all the way to the rendered card instead of collapsing into
  // a numeral (AAASM-5185). An empty `/costs` body is `unconfigured`: the
  // endpoint answers, there is simply no budget set up behind it.
  const costsCertain = certainFromQuery<CostSummary>(costsQuery, { whenEmpty: 'unconfigured' })
  const overviewCertain = certainFromQuery<TopologyOverview>(overviewQuery, {
    whenEmpty: 'unconfigured',
  })
  // Every per-team figure needs both halves — the roster from the overview and
  // the spend/ceiling from the summary — so either absence disqualifies the
  // rows. Joining them first would hand the derivation a full roster of null
  // pairs, which is indistinguishable from a configured-but-unspent org.
  let teamRowsCertain: Certain<readonly TeamListRow[]>
  if (!isKnown(overviewCertain)) teamRowsCertain = propagateAbsence(overviewCertain)
  else if (!isKnown(costsCertain)) teamRowsCertain = propagateAbsence(costsCertain)
  else teamRowsCertain = known(teamRows)

  const kpis = deriveCostKpis(costsCertain, teamRowsCertain)
  // Which absence an unfilled spend figure is. A resolved summary that simply
  // carries no monthly figure is `unconfigured` (the gateway only accumulates
  // `monthly_spent_usd` behind a `has_monthly` gate); anything else inherits
  // the query's own state, so a 503 reads `unavailable`, not "unset".
  const spendState: TruthState = isKnown(costsCertain) ? 'unconfigured' : costsCertain.state

  // Agent → team map for the per-agent table, resolved from the topology graph
  // (the cost summary's per-agent rows carry no team). Best-effort: agents with
  // no known team render a dash rather than blocking the table.
  const agentTeams = useMemo(() => {
    const map = new Map<string, string>()
    for (const node of topologyQuery.data?.nodes ?? []) {
      if (node.team) map.set(node.id, node.team)
    }
    return map
  }, [topologyQuery.data])
  const perAgentRows = useMemo(
    () => buildPerAgentRows(costsQuery.data, agentTeams),
    [costsQuery.data, agentTeams],
  )

  const historyQuery = useCostHistoryQuery(7)
  const budgetTreeQuery = useBudgetTreeQuery()

  const isLoading = costsQuery.isLoading || overviewQuery.isLoading
  const isError = costsQuery.isError

  return (
    <div className="costs-page" data-testid="costs-page">
      <header className="costs-head">
        <div>
          <h1 className="costs-title">Cost &amp; Budget</h1>
          <p className="costs-sub">
            LLM inference spend across all agents — daily / monthly breakdown with configured
            budget limits.
          </p>
        </div>
      </header>

      <div className="costs-kpis" data-testid="costs-kpis">
        <SpendKpiCard
          testId="costs-kpi-daily"
          label="Daily spend"
          period="daily"
          spend={kpis.daily}
          summary={costsCertain}
        />
        <SpendKpiCard
          testId="costs-kpi-monthly"
          label="Monthly spend"
          period="monthly"
          spend={kpis.monthly}
          summary={costsCertain}
        />
        {/* `0 across 0 teams` was the same false negative as the Blocked count:
            an absent breakdown is not a measured emptiness. A resolved summary
            that genuinely lists nothing still reads `0` (AAASM-5185). */}
        <KpiCard
          testId="costs-kpi-agents"
          label="Agents tracked"
          value={kpis.agentsTracked}
          sub={mapCertain(
            kpis.teamsTracked,
            teams => `across ${teams} ${teams === 1 ? 'team' : 'teams'}`,
          )}
        />
        {/* The fourth spec KPI (design/v1/hi-fi/costs.jsx:299-305) — restored
            per ADR-0017 item 14, which ratifies Utilisation and Blocked as
            *additive* to the spec strip, not a replacement for one of its
            cards (AAASM-5159). `avgPerAgent` folds to `not-evaluated` on a
            genuine zero-agent roster rather than `NaN` or a fabricated
            `$0.00`; the sub-caption is the cost date the mock pairs it with,
            which propagates its own absence when the summary has not
            resolved. */}
        <KpiCard
          testId="costs-kpi-avg-per-agent"
          label="Avg / agent today"
          value={mapCertain(kpis.avgPerAgent, usd)}
          sub={mapCertain(costsCertain, summary => summary.date)}
        />
        {/* Both of these describe the *daily* window, and both now say so.
            Utilisation used to follow the period toggle while its neighbour
            stayed hard-wired to daily, so the two silently disagreed about
            which window they were reporting (AAASM-5126). The monthly window
            is not hidden by this — it has its own card, above, permanently. */}
        <KpiCard
          testId="costs-kpi-utilisation"
          label="Budget utilisation"
          // `N/A` was a locally-invented placeholder; the vocabulary names `—`
          // as the one affordance for "no production value" and forbids the
          // ad-hoc variants precisely so an operator learns to read it once.
          value={mapCertain(certain(kpis.daily.pct, spendState), pct => `${pct.toFixed(1)}%`)}
          sub={summarySub(costsCertain, 'daily budget', () =>
            kpis.daily.limit == null
              ? 'no daily budget limit set'
              : `daily · of ${usd(kpis.daily.limit)} limit`,
          )}
          valueClass={utilisationClass(kpis.daily.pct)}
        />
        <KpiCard
          testId="costs-kpi-blocked"
          label="Blocked by budget"
          value={kpis.blockedByBudget.value}
          sub={blockedSub(kpis.blockedByBudget)}
          valueClass={
            isKnown(kpis.blockedByBudget.value) && kpis.blockedByBudget.value.value > 0
              ? ' costs-kpi__value--danger'
              : ''
          }
        />
      </div>

      <BurnCallouts dailyPct={kpis.daily.pct} dailyLimit={kpis.daily.limit} />

      <HistoryChart
        data={historyQuery.data}
        isLoading={historyQuery.isLoading}
        isError={historyQuery.isError}
      />

      <CostTabs
        value={tab}
        onChange={setTab}
        agentCount={perAgentRows.length}
        teamCount={teamRows.length}
      />

      {tab === 'agents' && (
        <>
          <section className="costs-section" data-testid="costs-agents">
            <PerAgentTable rows={perAgentRows} />
          </section>
          <section className="costs-section" data-testid="costs-breakdown">
            <CostBreakdownPanel />
          </section>
        </>
      )}

      {tab === 'teams' && (
        <section className="costs-section" data-testid="costs-team-budgets">
          <div className="costs-section__head">
            <h2 className="costs-section__title">Per-team budget</h2>
            {/* States the window the bars are actually drawn from. The hint
                used to interpolate the toggled period while `TeamBudgetContent`
                passed `daily_spend_usd` / `daily_limit_usd` regardless, so
                "monthly" was a label over daily bars (AAASM-5126). */}
            <span className="costs-section__hint" data-testid="costs-team-hint">
              daily spend vs org daily limit · green &lt;80% · amber 80–95% · red ≥95%
            </span>
          </div>
          <TeamBudgetContent
            isError={isError}
            isLoading={isLoading}
            teamRows={teamRows}
            onRetry={() => ignorePromise(costsQuery.refetch())}
          />
        </section>
      )}

      {tab === 'tree' && (
        <section className="costs-section" data-testid="costs-budget-tree">
          <div className="costs-section__head">
            <h2 className="costs-section__title">Budget inheritance</h2>
            <span className="costs-section__hint">
              org → team → agent · subtree spend vs each level's limit
            </span>
          </div>
          <BudgetTree
            data={budgetTreeQuery.data}
            isLoading={budgetTreeQuery.isLoading}
            isError={budgetTreeQuery.isError}
          />
        </section>
      )}
    </div>
  )
}
