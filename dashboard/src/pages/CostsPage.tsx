import { useMemo, useState, type ReactNode } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import { CostBreakdownPanel } from '../features/analytics/CostBreakdownPanel'
import { TeamBudgetBar } from '../components/topology/TeamBudgetBar'
import {
  joinTeamRows,
  useCostSummaryQuery,
  useTopologyOverviewQuery,
  type TeamListRow,
} from '../features/teams/api'
import { useTopologyQuery } from '../features/topology/api'
import { deriveCostKpis, type PeriodSpend } from '../features/costs/costKpis'
import { buildPerAgentRows } from '../features/costs/perAgentRows'
import { useCostHistoryQuery, useBudgetTreeQuery } from '../features/costs/api'
import { HistoryChart } from '../components/costs/HistoryChart'
import { BudgetTree } from '../components/costs/BudgetTree'
import { BudgetBar } from '../components/costs/BudgetBar'
import { BurnCallouts } from '../components/costs/BurnCallouts'
import { CostTabs, type CostTab } from '../components/costs/CostTabs'
import { PerAgentTable } from '../components/costs/PerAgentTable'
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

function usd(value: number | null): string {
  return value == null ? '—' : `$${value.toFixed(2)}`
}

interface KpiCardProps {
  readonly label: string
  readonly value: string
  readonly sub: string
  readonly valueClass?: string
  readonly footer?: ReactNode
  readonly testId: string
}

function KpiCard({ label, value, sub, valueClass = '', footer, testId }: KpiCardProps) {
  return (
    <div className="costs-kpi" data-testid={testId}>
      <div className="costs-kpi__label">{label}</div>
      <div className={`costs-kpi__value${valueClass}`}>{value}</div>
      <div className="costs-kpi__sub">{sub}</div>
      {footer}
    </div>
  )
}

interface SpendKpiCardProps {
  readonly label: string
  readonly period: string
  readonly spend: PeriodSpend
  readonly testId: string
}

/** Daily / Monthly spend card: value, "of $limit" sub, mini budget bar + % used. */
function SpendKpiCard({ label, period, spend, testId }: SpendKpiCardProps) {
  return (
    <KpiCard
      testId={testId}
      label={label}
      value={usd(spend.spend)}
      valueClass={burnValueClass(spend.pct)}
      sub={spend.limit == null ? `no ${period} limit set` : `of ${usd(spend.limit)} ${period} limit`}
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
  return (
    <div className="costs-team-bars">
      {/* Both fields are passed through rather than defaulted: they are
          genuinely nullable (`joinTeamRows` yields `null` for a team missing
          from the cost breakdown, and for every team while `/costs` is
          unresolved). The `?? 0` these replace rendered `$0 / $0 · 0%` at
          `aria-valuenow=0` — an unmeasured budget shown as a wholly unburnt
          one (AAASM-5135). */}
      {teamRows.map(row => (
        <TeamBudgetBar
          key={row.team_id}
          team={row.team_id}
          spent={row.daily_spend_usd}
          limit={row.daily_limit_usd}
        />
      ))}
    </div>
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
 *   - Tabs        — Per-agent (table + analytics breakdown) / Per-team (budget
 *                   bars) / Budget tree (inheritance), replacing the previous
 *                   stacked sections.
 *
 * The OSS `/api/v1/costs` summary only carries an *org* budget limit, so per-team
 * utilisation is each team's spend against the org limit (its share of the org
 * budget) rather than a per-team configured limit, which the OSS API does not
 * expose. The mock's per-agent 7-day sparkline and per-team monthly limit are
 * omitted — neither has a backing endpoint yet (AAASM-5076).
 *
 * There is no Daily/Monthly period control (AAASM-5126). Both mocks
 * (`design/v1/hi-fi/costs.jsx`, and `design/v2` per ADR-0025) show the two
 * windows side by side and neither has a toggle, and the shipped one could not
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
  const kpis = useMemo(() => deriveCostKpis(costsQuery.data, teamRows), [costsQuery.data, teamRows])

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
        <SpendKpiCard testId="costs-kpi-daily" label="Daily spend" period="daily" spend={kpis.daily} />
        <SpendKpiCard
          testId="costs-kpi-monthly"
          label="Monthly spend"
          period="monthly"
          spend={kpis.monthly}
        />
        <KpiCard
          testId="costs-kpi-agents"
          label="Agents tracked"
          value={String(kpis.agentsTracked)}
          sub={`across ${kpis.teamsTracked} ${kpis.teamsTracked === 1 ? 'team' : 'teams'}`}
        />
        {/* Both of these describe the *daily* window, and both now say so.
            Utilisation used to follow the period toggle while its neighbour
            stayed hard-wired to daily, so the two silently disagreed about
            which window they were reporting (AAASM-5126). The monthly window
            is not hidden by this — it has its own card, above, permanently. */}
        <KpiCard
          testId="costs-kpi-utilisation"
          label="Budget utilisation"
          value={kpis.daily.pct == null ? 'N/A' : `${kpis.daily.pct.toFixed(1)}%`}
          sub={
            kpis.daily.limit == null
              ? 'no daily budget limit set'
              : `daily · of ${usd(kpis.daily.limit)} limit`
          }
          valueClass={utilisationClass(kpis.daily.pct)}
        />
        <KpiCard
          testId="costs-kpi-blocked"
          label="Blocked by budget"
          value={String(kpis.blockedByBudget)}
          sub={
            kpis.blockedByBudget === 0
              ? 'no teams over the daily limit'
              : 'teams at ≥95% of the org daily limit'
          }
          valueClass={kpis.blockedByBudget > 0 ? ' costs-kpi__value--danger' : ''}
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
        agentCount={kpis.agentsTracked}
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
