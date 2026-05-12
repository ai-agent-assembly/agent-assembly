import { encodeFilters, decodeFilters } from './urlState'
import type { FilterParams } from './urlState'

const BASE: FilterParams = { range: '7d', agents: [], teams: [] }

describe('encodeFilters', () => {
  it('sets range param', () => {
    expect(encodeFilters({ ...BASE, range: '30d' }).get('range')).toBe('30d')
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
  it('decodes range from params', () => {
    const p = new URLSearchParams('range=90d')
    expect(decodeFilters(p).range).toBe('90d')
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

  it('round-trips non-empty filter state', () => {
    const original: FilterParams = { range: '30d', agents: ['a1'], teams: ['t1'] }
    expect(decodeFilters(encodeFilters(original))).toEqual(original)
  })
})
