import { describe, it, expect } from 'vitest'
import type { Agent } from './api'
import { toFleetAgent, type FleetAgent } from './fleetTypes'
import {
  DEFAULT_FLEET_FILTERS,
  applyFleetFilters,
  fleetFiltersFromParams,
  fleetFiltersToParamsRecord,
  frameworkOptions,
} from './fleetFilters'

function makeAgent(overrides: Partial<Agent> = {}): Agent {
  return {
    id: 'a',
    name: 'agent',
    framework: 'langgraph',
    status: 'active',
    version: '0.1.0',
    layer: null,
    last_event: null,
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    session_count: 0,
    policy_violations_count: 0,
    tool_names: [],
    metadata: {},
    pid: null,
    ...overrides,
  }
}

function makeFleet(...overrides: Partial<Agent>[]): FleetAgent[] {
  return overrides.map((o, i) => toFleetAgent(makeAgent({ id: `id-${i}`, ...o })))
}

describe('applyFleetFilters', () => {
  it('returns the full list when filters are at defaults', () => {
    const list = makeFleet({ name: 'alpha' }, { name: 'beta' })
    expect(applyFleetFilters(list, DEFAULT_FLEET_FILTERS)).toHaveLength(2)
  })

  it('filters by search query against name', () => {
    const list = makeFleet({ name: 'alpha-agent' }, { name: 'beta-agent' })
    expect(applyFleetFilters(list, { ...DEFAULT_FLEET_FILTERS, q: 'alpha' })).toHaveLength(1)
  })

  it('filters by search query against owner (metadata.owner)', () => {
    const list = makeFleet({ metadata: { owner: 'alice' } }, { metadata: { owner: 'bob' } })
    expect(applyFleetFilters(list, { ...DEFAULT_FLEET_FILTERS, q: 'bob' })).toHaveLength(1)
  })

  it('filters by framework when not "all"', () => {
    const list = makeFleet({ framework: 'langgraph' }, { framework: 'crewai' })
    expect(applyFleetFilters(list, { ...DEFAULT_FLEET_FILTERS, framework: 'crewai' })).toHaveLength(1)
  })

  it('filters by status when not "all"', () => {
    const list = makeFleet({ status: 'active' }, { status: 'suspended' })
    expect(applyFleetFilters(list, { ...DEFAULT_FLEET_FILTERS, status: 'suspended' })).toHaveLength(1)
  })

  it('filters out non-flagged agents when flaggedOnly is true', () => {
    const list = makeFleet(
      { policy_violations_count: 0 },
      { policy_violations_count: 100 },
    )
    expect(applyFleetFilters(list, { ...DEFAULT_FLEET_FILTERS, flaggedOnly: true })).toHaveLength(1)
  })

  it('combines filters with AND semantics', () => {
    const list = makeFleet(
      { name: 'alpha', framework: 'langgraph', status: 'active' },
      { name: 'alpha', framework: 'crewai',    status: 'active' },
      { name: 'beta',  framework: 'langgraph', status: 'active' },
    )
    const out = applyFleetFilters(list, { ...DEFAULT_FLEET_FILTERS, q: 'alpha', framework: 'crewai' })
    expect(out).toHaveLength(1)
    expect(out[0]?.framework).toBe('crewai')
  })
})

describe('frameworkOptions', () => {
  it('returns sorted distinct framework values', () => {
    const list = makeFleet({ framework: 'langgraph' }, { framework: 'crewai' }, { framework: 'langgraph' })
    expect(frameworkOptions(list)).toEqual(['crewai', 'langgraph'])
  })

  it('returns an empty list when there are no agents', () => {
    expect(frameworkOptions([])).toEqual([])
  })
})

describe('fleetFiltersFromParams', () => {
  it('reads all four params from the URL', () => {
    const p = new URLSearchParams('q=foo&framework=crewai&status=suspended&flagged=1')
    expect(fleetFiltersFromParams(p)).toEqual({
      q: 'foo',
      framework: 'crewai',
      status: 'suspended',
      flaggedOnly: true,
    })
  })

  it('defaults missing params to filter defaults', () => {
    expect(fleetFiltersFromParams(new URLSearchParams(''))).toEqual(DEFAULT_FLEET_FILTERS)
  })

  it('treats flagged values other than "1" as false', () => {
    expect(fleetFiltersFromParams(new URLSearchParams('flagged=true')).flaggedOnly).toBe(false)
    expect(fleetFiltersFromParams(new URLSearchParams('flagged=0')).flaggedOnly).toBe(false)
  })
})

describe('fleetFiltersToParamsRecord', () => {
  it('omits keys whose values are at the default', () => {
    expect(fleetFiltersToParamsRecord(DEFAULT_FLEET_FILTERS)).toEqual({})
  })

  it('includes non-default values', () => {
    expect(
      fleetFiltersToParamsRecord({ q: 'foo', framework: 'crewai', status: 'suspended', flaggedOnly: true }),
    ).toEqual({ q: 'foo', framework: 'crewai', status: 'suspended', flagged: '1' })
  })

  it('round-trips with fleetFiltersFromParams', () => {
    const original = { q: 'hello world', framework: 'crewai', status: 'active', flaggedOnly: true }
    const round = fleetFiltersFromParams(new URLSearchParams(fleetFiltersToParamsRecord(original)))
    expect(round).toEqual(original)
  })
})
