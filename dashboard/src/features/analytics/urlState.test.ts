import { encodeFilters, decodeFilters, isPresetRange, isCustomRange, PRESET_RANGES } from './urlState'
import type { FilterParams } from './urlState'

const BASE: FilterParams = { range: '7d', agents: [], teams: [] }

describe('PRESET_RANGES', () => {
  it('includes 24h, 7d, 30d, 90d', () => {
    expect(PRESET_RANGES).toEqual(['24h', '7d', '30d', '90d'])
  })
})

describe('isPresetRange', () => {
  it.each(['24h', '7d', '30d', '90d'])('returns true for %s', r => {
    expect(isPresetRange(r)).toBe(true)
  })

  it('returns false for custom date range', () => {
    expect(isPresetRange('2024-01-01..2024-01-07')).toBe(false)
  })
})

describe('isCustomRange', () => {
  it('returns true for valid YYYY-MM-DD..YYYY-MM-DD format', () => {
    expect(isCustomRange('2024-01-01..2024-01-07')).toBe(true)
  })

  it('returns false for preset ranges', () => {
    expect(isCustomRange('7d')).toBe(false)
  })

  it('returns false for partial date ranges', () => {
    expect(isCustomRange('2024-01-01')).toBe(false)
  })
})

describe('encodeFilters', () => {
  it('sets range param', () => {
    expect(encodeFilters({ ...BASE, range: '30d' }).get('range')).toBe('30d')
  })

  it('encodes 24h range', () => {
    expect(encodeFilters({ ...BASE, range: '24h' }).get('range')).toBe('24h')
  })

  it('encodes custom date range', () => {
    const params = encodeFilters({ ...BASE, range: '2024-01-01..2024-01-07' })
    expect(params.get('range')).toBe('2024-01-01..2024-01-07')
  })

  it('omits agents param when empty', () => {
    expect(encodeFilters(BASE).has('agents')).toBe(false)
  })

  it('omits teams param when empty', () => {
    expect(encodeFilters(BASE).has('teams')).toBe(false)
  })

  it('encodes multiple agents as comma-separated', () => {
    const params = encodeFilters({ ...BASE, agents: ['a1', 'a2'] })
    expect(params.get('agents')).toBe('a1,a2')
  })

  it('encodes multiple teams as comma-separated', () => {
    const params = encodeFilters({ ...BASE, teams: ['t1', 't2'] })
    expect(params.get('teams')).toBe('t1,t2')
  })
})

describe('decodeFilters', () => {
  it('decodes 24h range from params', () => {
    expect(decodeFilters(new URLSearchParams('range=24h')).range).toBe('24h')
  })

  it('decodes 90d range from params', () => {
    expect(decodeFilters(new URLSearchParams('range=90d')).range).toBe('90d')
  })

  it('decodes custom date range', () => {
    const p = new URLSearchParams('range=2024-01-01..2024-01-07')
    expect(decodeFilters(p).range).toBe('2024-01-01..2024-01-07')
  })

  it('defaults to 7d for missing range', () => {
    expect(decodeFilters(new URLSearchParams()).range).toBe('7d')
  })

  it('defaults to 7d for invalid range', () => {
    const p = new URLSearchParams('range=999d')
    expect(decodeFilters(p).range).toBe('7d')
  })

  it('decodes comma-separated agents', () => {
    const p = new URLSearchParams('agents=a1,a2,a3')
    expect(decodeFilters(p).agents).toEqual(['a1', 'a2', 'a3'])
  })

  it('returns empty agents array when param absent', () => {
    expect(decodeFilters(new URLSearchParams()).agents).toEqual([])
  })

  it('decodes comma-separated teams', () => {
    const p = new URLSearchParams('teams=t1,t2')
    expect(decodeFilters(p).teams).toEqual(['t1', 't2'])
  })

  it('round-trips preset filter state', () => {
    const original: FilterParams = { range: '30d', agents: ['a1'], teams: ['t1'] }
    expect(decodeFilters(encodeFilters(original))).toEqual(original)
  })

  it('round-trips custom date range', () => {
    const original: FilterParams = { range: '2024-01-01..2024-01-07', agents: [], teams: [] }
    expect(decodeFilters(encodeFilters(original))).toEqual(original)
  })
})
