import { describe, expect, it } from 'vitest'
import { applyClientFilters, resolveTimeWindow, toggleFilterValue } from './alertFilters'
import { DEFAULT_ALERT_FILTERS, type Alert, type AlertFilters } from './types'

const NOW = Date.parse('2026-05-13T12:00:00Z')

function alert(patch: Partial<Alert>): Alert {
  return {
    id: 'a',
    ruleId: 'r',
    ruleName: 'budget burn',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: 'aa-1',
    firstFiredAt: '2026-05-13T09:00:00Z',
    resolvedAt: null,
    destinationIds: [],
    ...patch,
  }
}

const RECENT = alert({ id: 'a' })
const OTHER = alert({
  id: 'b',
  ruleName: 'low signal',
  severity: 'INFO',
  status: 'RESOLVED',
  agentId: 'aa-2',
  firstFiredAt: '2026-05-13T08:00:00Z',
  resolvedAt: '2026-05-13T08:15:00Z',
})
const ROWS: readonly Alert[] = [RECENT, OTHER]

describe('applyClientFilters', () => {
  it('returns every row inside the default window when no chip is selected', () => {
    expect(applyClientFilters(ROWS, DEFAULT_ALERT_FILTERS, NOW)).toHaveLength(2)
  })

  it('narrows rows when severity is selected', () => {
    const filters: AlertFilters = { ...DEFAULT_ALERT_FILTERS, severities: ['CRITICAL'] }
    expect(applyClientFilters(ROWS, filters, NOW)).toEqual([RECENT])
  })

  it('narrows rows when status is selected', () => {
    const filters: AlertFilters = { ...DEFAULT_ALERT_FILTERS, statuses: ['RESOLVED'] }
    expect(applyClientFilters(ROWS, filters, NOW)).toEqual([OTHER])
  })

  it('matches agent query case-insensitively', () => {
    const filters: AlertFilters = { ...DEFAULT_ALERT_FILTERS, agentQuery: 'AA-1' }
    expect(applyClientFilters(ROWS, filters, NOW)).toEqual([RECENT])
  })

  it.each([
    ['rule name', 'BUDGET BURN'],
    ['agent id', 'AA-1'],
    ['alert id', 'ALERT-RECENT-ID'],
  ])('matches q against %s case-insensitively', (_label, query) => {
    const target = { ...RECENT, id: 'alert-recent-id' }
    const filters: AlertFilters = { ...DEFAULT_ALERT_FILTERS, q: query }
    expect(applyClientFilters([target, OTHER], filters, NOW)).toEqual([target])
  })

  it('drops rows that fired before the selected preset window', () => {
    const stale = alert({ id: 'old', firstFiredAt: '2026-04-01T09:00:00Z' })
    expect(applyClientFilters([RECENT, stale], DEFAULT_ALERT_FILTERS, NOW)).toEqual([RECENT])
  })

  it('honours a wider preset', () => {
    const stale = alert({ id: 'old', firstFiredAt: '2026-05-09T09:00:00Z' })
    const filters: AlertFilters = { ...DEFAULT_ALERT_FILTERS, timeRange: '7d' }
    expect(applyClientFilters([RECENT, stale], filters, NOW)).toHaveLength(2)
  })

  it('applies both custom bounds', () => {
    const filters: AlertFilters = {
      ...DEFAULT_ALERT_FILTERS,
      timeRange: 'custom',
      customFrom: '2026-05-13T08:30:00Z',
      customTo: '2026-05-13T10:00:00Z',
    }
    expect(applyClientFilters(ROWS, filters, NOW)).toEqual([RECENT])
  })

  it('keeps a row whose timestamp cannot be parsed rather than hiding it', () => {
    const broken = alert({ id: 'broken', firstFiredAt: 'not-a-date' })
    expect(applyClientFilters([broken], DEFAULT_ALERT_FILTERS, NOW)).toEqual([broken])
  })

  it('combines severity, agent and window predicates', () => {
    const filters: AlertFilters = {
      ...DEFAULT_ALERT_FILTERS,
      severities: ['CRITICAL'],
      agentQuery: 'aa-9',
    }
    expect(applyClientFilters(ROWS, filters, NOW)).toEqual([])
  })
})

describe('resolveTimeWindow', () => {
  it('resolves a preset to a lower bound with no upper bound', () => {
    const w = resolveTimeWindow(DEFAULT_ALERT_FILTERS, NOW)
    expect(w.fromMs).toBe(NOW - 24 * 60 * 60 * 1000)
    expect(w.toMs).toBeNull()
  })

  it('resolves an unparseable custom bound to unbounded, never to an empty window', () => {
    const filters: AlertFilters = {
      ...DEFAULT_ALERT_FILTERS,
      timeRange: 'custom',
      customFrom: 'half-typed',
      customTo: null,
    }
    expect(resolveTimeWindow(filters, NOW)).toEqual({ fromMs: null, toMs: null })
  })
})

describe('toggleFilterValue', () => {
  it('adds a value that is absent', () => {
    expect(toggleFilterValue(['CRITICAL'], 'HIGH')).toEqual(['CRITICAL', 'HIGH'])
  })

  it('removes a value that is present', () => {
    expect(toggleFilterValue(['CRITICAL', 'HIGH'], 'CRITICAL')).toEqual(['HIGH'])
  })

  it('does not mutate the input list', () => {
    const list = ['CRITICAL']
    toggleFilterValue(list, 'HIGH')
    expect(list).toEqual(['CRITICAL'])
  })
})
