import { describe, expect, it } from 'vitest'
import { deriveCostKpis } from './costKpis'
import { absent, isAbsent, isKnown, known } from '../../lib/truthfulness'
import type { CostSummary, TeamListRow } from '../teams/api'

const COSTS: CostSummary = {
  date: '2026-05-13',
  daily_spend_usd: '150.00',
  daily_limit_usd: '200.00',
  monthly_spend_usd: '3200.00',
  monthly_limit_usd: '5000.00',
  per_agent: [
    { agent_id: 'agent-spendy', daily_spend_usd: '120.00', date: '2026-05-13', monthly_spend_usd: '2400.00' },
    { agent_id: 'agent-thrifty', daily_spend_usd: '30.00', date: '2026-05-13', monthly_spend_usd: '800.00' },
  ],
  per_team: [
    { team_id: 'team-hot', daily_spend_usd: '150.00', date: '2026-05-13', monthly_spend_usd: '3200.00' },
  ],
}

function row(over: Partial<TeamListRow> & { team_id: string }): TeamListRow {
  return {
    agent_count: 2,
    root_agent_count: 1,
    daily_spend_usd: null,
    daily_limit_usd: null,
    monthly_spend_usd: null,
    burn_pct: null,
    ...over,
  }
}

const TEAM_ROWS: readonly TeamListRow[] = [
  row({ team_id: 'team-hot', daily_spend_usd: 150, daily_limit_usd: 200, burn_pct: 75 }),
]

describe('deriveCostKpis — daily / monthly / tracked figures', () => {
  it('derives daily and monthly spend, limit and burn %', () => {
    const kpis = deriveCostKpis(known(COSTS), known(TEAM_ROWS))

    expect(kpis.daily).toEqual({ spend: 150, limit: 200, pct: 75 })
    expect(kpis.monthly).toEqual({ spend: 3200, limit: 5000, pct: 64 })
  })

  it('counts agents and teams tracked from the summary rows', () => {
    const kpis = deriveCostKpis(known(COSTS), known(TEAM_ROWS))

    expect(kpis.agentsTracked).toEqual(known(2))
    expect(kpis.teamsTracked).toEqual(known(1))
  })

  it('leaves limit/pct null when a period has no configured limit', () => {
    const noLimit: CostSummary = { date: '2026-05-13', daily_spend_usd: '42.00' }
    const kpis = deriveCostKpis(known(noLimit), known([]))

    expect(kpis.daily).toEqual({ spend: 42, limit: null, pct: null })
    expect(kpis.monthly).toEqual({ spend: null, limit: null, pct: null })
  })

  describe('AAASM-5126 — no figure can be presented under another window’s heading', () => {
    it('exposes each window only under its own key, with no period-selected alias', () => {
      // The removed `period` argument used to re-key one of these two as
      // `totalSpend` / `limit` / `utilisationPct`, which is how "Monthly" came
      // to head a strip whose other figures were still daily. The shape now
      // makes that unexpressible: a caller must name the window it wants.
      const kpis = deriveCostKpis(known(COSTS), known(TEAM_ROWS))

      expect(Object.keys(kpis).sort()).toEqual([
        'agentsTracked',
        'blockedByBudget',
        'daily',
        'monthly',
        'teamsTracked',
      ])
      expect(kpis.daily).not.toEqual(kpis.monthly)
    })

    it('counts blocked teams against the daily ceiling only — the sole one on the wire', () => {
      // `TeamCostEntry` carries monthly spend but no limit of any window, and a
      // team-tier monthly ceiling is sign-off-gated on ADR-0020 / AAASM-5087.
      // A monthly variant of this count would have no denominator, so the
      // figure is daily and is labelled daily rather than following a toggle.
      const rows: readonly TeamListRow[] = [
        // 195/200 = 97.5% — danger.
        row({ team_id: 'team-hot', daily_spend_usd: 195, daily_limit_usd: 200, burn_pct: 97.5 }),
        // 20/200 = 10% — ok.
        row({ team_id: 'team-cool', daily_spend_usd: 20, daily_limit_usd: 200, burn_pct: 10 }),
      ]

      const blocked = deriveCostKpis(known(COSTS), known(rows)).blockedByBudget
      expect(blocked.value).toEqual(known(1))
      expect(blocked).toMatchObject({ measured: 2, total: 2 })
    })
  })
})

describe('deriveCostKpis — AAASM-5185: a count states its own coverage', () => {
  it('reports its coverage when only some rows are measurable, rather than absorbing the rest', () => {
    // The derivation always excluded unmeasurable rows, but the bare `1` it
    // returned was indistinguishable from a `1` over a fully-measured roster —
    // so the page captioned it "no teams over the daily limit" for the two it
    // never looked at. The coverage now travels with the count.
    const rows: readonly TeamListRow[] = [
      row({ team_id: 'team-unknown' }),
      row({ team_id: 'team-nolimit', daily_spend_usd: 900 }),
      row({ team_id: 'team-hot', daily_spend_usd: 195, daily_limit_usd: 200, burn_pct: 97.5 }),
    ]

    const blocked = deriveCostKpis(known(COSTS), known(rows)).blockedByBudget

    expect(blocked.value).toEqual(known(1))
    expect(blocked.measured).toBe(1)
    expect(blocked.total).toBe(3)
  })

  it('counts a team spending against a configured $0 ceiling as blocked', () => {
    // `bucketForBudget` maps `limit <= 0` to `ok`, so this roster — spending
    // real money against a ceiling that permits nothing — reported `0 · no
    // teams over the daily limit`: a clean bill of health on the compliance
    // KPI, for the one configuration that blocks everything.
    const rows: readonly TeamListRow[] = [
      row({ team_id: 'team-hot', daily_spend_usd: 400, daily_limit_usd: 0 }),
      row({ team_id: 'team-cool', daily_spend_usd: 100, daily_limit_usd: 0 }),
    ]

    const blocked = deriveCostKpis(known(COSTS), known(rows)).blockedByBudget

    expect(blocked.value).toEqual(known(2))
    expect(blocked).toMatchObject({ measured: 2, total: 2 })
  })

  it('is absent, not 0, when no row carries a ceiling to measure against', () => {
    // The successful-response case: `/costs` answered, spend is real, and not
    // one team has a `daily_limit_usd`. A `0` here asserts compliance for a
    // ceiling that does not exist.
    const rows: readonly TeamListRow[] = [
      row({ team_id: 'team-hot', daily_spend_usd: 130 }),
      row({ team_id: 'team-cool', daily_spend_usd: 20 }),
    ]

    const blocked = deriveCostKpis(known(COSTS), known(rows)).blockedByBudget

    expect(isKnown(blocked.value)).toBe(false)
    expect(isAbsent(blocked.value) && blocked.value.state).toBe('unconfigured')
    expect(blocked.measured).toBe(0)
    expect(blocked.total).toBe(2)
  })

  it('is `unknown` when ceilings exist but no spend was measured', () => {
    const rows: readonly TeamListRow[] = [row({ team_id: 'team-hot', daily_limit_usd: 200 })]

    const blocked = deriveCostKpis(known(COSTS), known(rows)).blockedByBudget
    expect(isAbsent(blocked.value) && blocked.value.state).toBe('unknown')
  })

  it('propagates a failed roster as `unavailable`, never as a compliance result', () => {
    const blocked = deriveCostKpis(
      absent<CostSummary>('unavailable', 'HTTP 503'),
      absent<readonly TeamListRow[]>('unavailable', 'HTTP 503'),
    ).blockedByBudget

    expect(isAbsent(blocked.value) && blocked.value.state).toBe('unavailable')
  })

  it('still reads 0 for a genuinely measured, fully-compliant roster', () => {
    // The whole point of the absence: a real zero must survive it intact.
    const rows: readonly TeamListRow[] = [
      row({ team_id: 'team-cool', daily_spend_usd: 20, daily_limit_usd: 200, burn_pct: 10 }),
    ]

    const blocked = deriveCostKpis(known(COSTS), known(rows)).blockedByBudget

    expect(blocked.value).toEqual(known(0))
    expect(blocked.measured).toBe(1)
    expect(blocked.total).toBe(1)
  })

  it('counts an empty roster as a measured zero — the overview answered', () => {
    const blocked = deriveCostKpis(known(COSTS), known([])).blockedByBudget
    expect(blocked.value).toEqual(known(0))
    expect(blocked.total).toBe(0)
  })

  it('reports tracked counts as absent when the summary never arrived', () => {
    // `agentsTracked: 0` / `across 0 teams` was the same false negative: an
    // absent breakdown is not an observation of emptiness.
    const kpis = deriveCostKpis(
      absent<CostSummary>('unavailable', 'HTTP 503'),
      absent<readonly TeamListRow[]>('unavailable', 'HTTP 503'),
    )

    expect(isAbsent(kpis.agentsTracked) && kpis.agentsTracked.state).toBe('unavailable')
    expect(isAbsent(kpis.teamsTracked) && kpis.teamsTracked.state).toBe('unavailable')
    expect(kpis.daily).toEqual({ spend: null, limit: null, pct: null })
  })

  it('reports tracked counts as absent when the summary carries no breakdown', () => {
    const bare: CostSummary = { date: '2026-05-13', daily_spend_usd: '42.00' }
    const kpis = deriveCostKpis(known(bare), known([]))

    expect(isAbsent(kpis.agentsTracked) && kpis.agentsTracked.state).toBe('unconfigured')
    expect(isAbsent(kpis.teamsTracked) && kpis.teamsTracked.state).toBe('unconfigured')
  })

  it('keeps an empty breakdown a measured zero', () => {
    const empty: CostSummary = {
      date: '2026-05-13',
      daily_spend_usd: '0.00',
      per_agent: [],
      per_team: [],
    }
    const kpis = deriveCostKpis(known(empty), known([]))

    expect(kpis.agentsTracked).toEqual(known(0))
    expect(kpis.teamsTracked).toEqual(known(0))
  })
})
