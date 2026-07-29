import {
  bucketForConfiguredBudget,
  utilisationPercentForConfiguredBudget,
} from '../../components/topology/budgetThreshold'
import {
  absent,
  certain,
  isKnown,
  known,
  mapCertain,
  propagateAbsence,
  type Certain,
} from '../../lib/truthfulness'
import type { CostSummary, TeamListRow } from '../teams/api'

/**
 * Org spend against its configured limit for one budget period, plus the
 * derived burn percentage. Backs a Daily / Monthly KPI card and its mini
 * budget bar.
 *
 * Every field is nullable and none of them defaults to `0`. `limit` is absent
 * when none is configured; `spend` is absent for the monthly window until a
 * monthly limit exists at all, because the gateway only starts accumulating
 * `monthly_spent_usd` once one is configured; `pct` needs both.
 */
export interface PeriodSpend {
  readonly spend: number | null
  readonly limit: number | null
  readonly pct: number | null
}

/**
 * A count over a population only part of which may be measurable, carrying its
 * own coverage.
 *
 * A bare number cannot express the difference between "measured every row and
 * none of them qualified" and "could not measure a single row" — both render
 * `0`, and on a compliance KPI the second reads as a clean bill of health for
 * teams nobody checked (AAASM-5185). `value` is therefore absent when nothing
 * was measurable, and `measured` / `total` let the caller state its coverage
 * when only some rows could be counted.
 */
export interface MeasuredCount {
  /** The count, or the reason no count could be produced. */
  readonly value: Certain<number>
  /** Rows that carried both a spend figure and a ceiling. */
  readonly measured: number
  /** Rows considered, measurable or not. */
  readonly total: number
}

export interface CostKpis {
  /**
   * Number of teams whose burn against the org daily limit is in the `danger`
   * bucket (≥ 95%) — the teams a budget enforcer would be blocking right now —
   * together with how much of the roster that count actually covers.
   *
   * Daily, and only daily: there is no per-team monthly ceiling anywhere on
   * the wire (`TeamCostEntry` carries spend and no limit), and adding one is
   * sign-off-gated on ADR-0020 / AAASM-5087. Any monthly variant of this count
   * would have no denominator.
   */
  readonly blockedByBudget: MeasuredCount
  /** Org spend vs the configured daily limit. */
  readonly daily: PeriodSpend
  /** Org spend vs the configured monthly limit. */
  readonly monthly: PeriodSpend
  /** Number of agents with a per-agent cost row today. */
  readonly agentsTracked: Certain<number>
  /** Number of teams in the joined roster (the "across N teams" figure). */
  readonly teamsTracked: Certain<number>
  /**
   * `daily.spend / agentsTracked` — the mock's "Avg / agent today" KPI
   * (design/v1/hi-fi/costs.jsx:299-305).
   *
   * `not-evaluated` when `agentsTracked` is a genuine, measured `0`: the
   * ratio is mathematically undefined at that point, and dividing anyway
   * would render either `NaN` or a fabricated `$0.00` — the same false
   * negative the rest of this module exists to prevent. Any other absence
   * (an outage, an in-flight request, no breakdown configured) propagates
   * from `agentsTracked` unchanged.
   */
  readonly avgPerAgent: Certain<number>
}

function parseUsd(value: string | null | undefined): number | null {
  if (value == null) return null
  const n = Number.parseFloat(value)
  return Number.isFinite(n) ? n : null
}

/** Spend/limit/burn-% for one period, from its raw string-encoded USD figures. */
function periodSpend(
  spendRaw: string | null | undefined,
  limitRaw: string | null | undefined,
): PeriodSpend {
  const spend = parseUsd(spendRaw)
  const limit = parseUsd(limitRaw)
  // `limit > 0` was the same false negative the burn bars carried: it collapsed
  // a *configured* `$0` ceiling into "no percentage exists", so Utilisation
  // rendered `—` "nothing is configured to produce this value" while its own
  // caption quoted `of $0.00 limit`, and `BurnCallouts` — which returns null on
  // a null pct — suppressed the critical banner for the one ceiling that denies
  // everything (AAASM-5185).
  const pct =
    spend != null && limit != null ? utilisationPercentForConfiguredBudget(spend, limit) : null
  return { spend, limit, pct }
}

/** What the operator is told when not one team could be measured. */
const NO_CEILING_DETAIL = 'No team has a daily budget ceiling configured'
const NO_BURN_DETAIL = 'No team’s daily burn could be measured'

/**
 * Count the teams at or over their daily ceiling, reporting coverage.
 *
 * A row needs *both* a spend and a ceiling to be classified at all. Rows
 * missing either are excluded from `measured` rather than absorbed as
 * compliant, and when that leaves nothing measured the count itself is absent:
 * `unconfigured` when the ceiling is what is missing everywhere (the
 * `daily_limit_usd`-less summary the OSS gateway serves until a budget is set),
 * `unknown` otherwise. An absent roster or cost summary propagates its own
 * state — notably `unavailable`, so a failed `/costs` can never surface as a
 * compliance result.
 */
function countBlockedByBudget(teamRows: Certain<readonly TeamListRow[]>): MeasuredCount {
  if (!isKnown(teamRows)) {
    return { value: propagateAbsence(teamRows), measured: 0, total: 0 }
  }

  const rows = teamRows.value
  let measured = 0
  let blocked = 0
  let missingCeiling = 0
  for (const row of rows) {
    if (row.daily_limit_usd == null) missingCeiling += 1
    if (row.daily_spend_usd == null || row.daily_limit_usd == null) continue
    measured += 1
    // `bucketForConfiguredBudget`, not the plain threshold helper: the latter
    // maps a configured `$0` ceiling to `ok`, which would report a roster
    // spending against a budget that permits nothing as fully compliant — a
    // fabricated clean bill of health on the one KPI that exists to deny it.
    if (bucketForConfiguredBudget(row.daily_spend_usd, row.daily_limit_usd) === 'danger') {
      blocked += 1
    }
  }

  // An empty roster is a measured fact — the overview resolved and reported no
  // teams — so it counts zero rather than reporting an absence.
  if (rows.length > 0 && measured === 0) {
    const state = missingCeiling === rows.length ? 'unconfigured' : 'unknown'
    return {
      value: absent<number>(state, state === 'unconfigured' ? NO_CEILING_DETAIL : NO_BURN_DETAIL),
      measured,
      total: rows.length,
    }
  }
  return { value: known(blocked), measured, total: rows.length }
}

/**
 * Size of one of the summary's breakdown arrays.
 *
 * `[]` is a real measurement — the summary resolved and listed nothing — so it
 * counts `0`. An *absent* array is not: the key is optional on the wire, and
 * reporting the missing breakdown as "0 agents tracked" is the same false
 * negative as reporting a failed request as zero spend.
 */
function trackedCount(
  costs: Certain<CostSummary>,
  breakdown: readonly unknown[] | undefined,
): Certain<number> {
  if (!isKnown(costs)) return propagateAbsence(costs)
  return mapCertain(
    certain(breakdown, 'unconfigured', 'The cost summary carried no breakdown for this dimension'),
    rows => rows.length,
  )
}

/**
 * `dailySpend / agentsTracked`, guarding the zero-agent case.
 *
 * `agentsTracked` being absent (outage, in-flight, no breakdown configured)
 * propagates unchanged. A *known* `0` is different: the division is
 * undefined, not merely unmeasured, so it folds to `not-evaluated` rather
 * than to `NaN` or a fabricated `$0.00`.
 */
function averagePerAgent(dailySpend: number | null, agentsTracked: Certain<number>): Certain<number> {
  if (!isKnown(agentsTracked)) return propagateAbsence(agentsTracked)
  if (agentsTracked.value === 0) {
    return absent('not-evaluated', 'No agents were tracked today to average spend across')
  }
  if (dailySpend == null) return absent('unconfigured', 'No daily spend was reported')
  return known(dailySpend / agentsTracked.value)
}

/**
 * Derive the KPI-strip figures for the Cost & Budget page from the cost summary
 * and the already-joined per-team rows. Pure so it can be unit-tested without a
 * query client.
 *
 * Both inputs arrive as `Certain` rather than `| undefined` because the counts
 * this returns are compliance claims: only the caller knows whether an absent
 * payload means the request failed, is in flight, or came back empty, and that
 * distinction has to survive into the rendered KPI instead of collapsing to a
 * numeral (AAASM-5185).
 *
 * Deliberately takes no period argument. Every figure it returns is labelled
 * with the window it came from, so no caller can present one window's number
 * under another's heading.
 */
export function deriveCostKpis(
  costs: Certain<CostSummary>,
  teamRows: Certain<readonly TeamListRow[]>,
): CostKpis {
  const summary = isKnown(costs) ? costs.value : undefined
  const daily = periodSpend(summary?.daily_spend_usd, summary?.daily_limit_usd)
  const agentsTracked = trackedCount(costs, summary?.per_agent)

  return {
    blockedByBudget: countBlockedByBudget(teamRows),
    daily,
    monthly: periodSpend(summary?.monthly_spend_usd, summary?.monthly_limit_usd),
    agentsTracked,
    // The "across N teams" caption counts the same joined roster the Per-team
    // tab counts (`teamRows`), not the summary's `per_team` breakdown array.
    // The two are different populations — a team with agents but no cost row
    // appears in the roster and not in the breakdown — so sourcing them
    // separately let the KPI strip and the tab report two different team
    // counts on one page (AAASM-5172).
    teamsTracked: mapCertain(teamRows, rows => rows.length),
    avgPerAgent: averagePerAgent(daily.spend, agentsTracked),
  }
}
