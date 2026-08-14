import { describe, expect, it } from 'vitest'
import { decodeCostSummary, decodeTopologyOverview } from './schema'

/**
 * Unit coverage for the two cost/topology fold decoders' own branches
 * (AAASM-5380 S7).
 *
 * The page tests prove each surface degrades to absence; this proves the
 * decoders themselves — the conforming path and every rejection path — so a
 * malformed body can never reach `countBlockedByBudget` as a fabricated
 * `known(0)` or `reconcileAgentCensus` as a `NaN`.
 */
describe('decodeCostSummary', () => {
  const SUMMARY = {
    date: '2026-05-13',
    daily_spend_usd: '210.00',
    daily_limit_usd: '200.00',
    monthly_spend_usd: '3200.00',
    monthly_limit_usd: '5000.00',
    per_agent: [{ agent_id: 'a-1', daily_spend_usd: '150.00', date: '2026-05-13' }],
    per_team: [{ team_id: 'team-hot', daily_spend_usd: '190.00', date: '2026-05-13' }],
  }

  it('conforms a well-formed summary and passes the body through', () => {
    const result = decodeCostSummary(SUMMARY)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.daily_spend_usd).toBe('210.00')
      expect(result.value.per_team).toHaveLength(1)
    }
  })

  it('conforms a summary with no ceiling and no breakdown arrays — the unconfigured shape', () => {
    // The `daily_limit_usd`-less body the OSS gateway serves until a budget is
    // set: readable, and its absence is the signal the page reads, not a fault.
    const result = decodeCostSummary({ date: '2026-05-13', daily_spend_usd: '0.00' })
    expect(result.ok).toBe(true)
  })

  it('conforms a null ceiling and null monthly figures', () => {
    const result = decodeCostSummary({
      date: '2026-05-13',
      daily_spend_usd: '10.00',
      daily_limit_usd: null,
      monthly_spend_usd: null,
      monthly_limit_usd: null,
    })
    expect(result.ok).toBe(true)
  })

  it('conforms an empty per_team — an empty breakdown is a readable measurement', () => {
    const result = decodeCostSummary({ date: '2026-05-13', daily_spend_usd: '0.00', per_team: [] })
    expect(result.ok).toBe(true)
  })

  it('rejects an empty object (the shape that silently produced known(0) blocked)', () => {
    const result = decodeCostSummary({})
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('daily_spend_usd')
  })

  it('rejects a missing daily_spend_usd, naming the offending field', () => {
    const result = decodeCostSummary({ date: '2026-05-13' })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('daily_spend_usd')
  })

  it('rejects a daily_spend_usd that is a number, not a USD string', () => {
    const result = decodeCostSummary({ date: '2026-05-13', daily_spend_usd: 210 })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('daily_spend_usd')
  })

  it('rejects a per_team row missing team_id — the field joinTeamRows keys by', () => {
    const result = decodeCostSummary({
      date: '2026-05-13',
      daily_spend_usd: '10.00',
      per_team: [{ daily_spend_usd: '5.00' }],
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('team_id')
  })

  it('rejects a per_team row whose daily_spend_usd is not a string', () => {
    const result = decodeCostSummary({
      date: '2026-05-13',
      daily_spend_usd: '10.00',
      per_team: [{ team_id: 'team-hot', daily_spend_usd: 5 }],
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('daily_spend_usd')
  })

  it('rejects a non-array per_team', () => {
    const result = decodeCostSummary({
      date: '2026-05-13',
      daily_spend_usd: '10.00',
      per_team: 'nope',
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('per_team')
  })

  it('rejects a scalar body via the root-path message branch', () => {
    const result = decodeCostSummary(42)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })
})

describe('decodeTopologyOverview', () => {
  const OVERVIEW = {
    root_agent_count: 2,
    standalone_root_agents: [],
    team_count: 2,
    total_agent_count: 5,
    teams: [
      { team_id: 'team-hot', agent_count: 3, root_agent_count: 1 },
      { team_id: 'team-cool', agent_count: 2, root_agent_count: 1 },
    ],
  }

  it('conforms a well-formed overview and passes the body through', () => {
    const result = decodeTopologyOverview(OVERVIEW)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value.total_agent_count).toBe(5)
      expect(result.value.teams).toHaveLength(2)
    }
  })

  it('conforms an empty teams array with a zero total', () => {
    const result = decodeTopologyOverview({ ...OVERVIEW, teams: [], team_count: 0, total_agent_count: 0 })
    expect(result.ok).toBe(true)
  })

  it('rejects an empty object (the shape that made the census go NaN)', () => {
    const result = decodeTopologyOverview({})
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('total_agent_count')
  })

  it('rejects a body missing total_agent_count — the whole TeamsPage defect', () => {
    const { total_agent_count: _t, ...noTotal } = OVERVIEW
    void _t
    const result = decodeTopologyOverview(noTotal)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('total_agent_count')
  })

  it('rejects a total_agent_count that is a string, not a number', () => {
    const result = decodeTopologyOverview({ ...OVERVIEW, total_agent_count: '5' })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('total_agent_count')
  })

  it('rejects a non-array teams', () => {
    const result = decodeTopologyOverview({ ...OVERVIEW, teams: {} })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('teams')
  })

  it('rejects a team row missing team_id', () => {
    const result = decodeTopologyOverview({ ...OVERVIEW, teams: [{ agent_count: 3 }] })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('team_id')
  })

  it('rejects a team row whose agent_count is not a number', () => {
    const result = decodeTopologyOverview({
      ...OVERVIEW,
      teams: [{ team_id: 'team-hot', agent_count: 'three' }],
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('agent_count')
  })

  it('rejects a scalar body via the root-path message branch', () => {
    const result = decodeTopologyOverview('nope')
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBeTruthy()
  })
})
