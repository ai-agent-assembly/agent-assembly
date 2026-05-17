import { describe, it, expect } from 'vitest'
import { applyFilter, deriveOptions, EMPTY_FILTER } from './filter'
import type { Approval } from './api'

const APPROVALS: Approval[] = [
  // age 15 min → high
  { id: '1', agent_id: 'a1', team_id: 't1', action: 'send_email', reason: 'r', status: 'pending', created_at: '2026-05-13T12:45:00Z', expires_at: '2026-05-13T13:45:00Z', routing_status: null },
  // age 3 h → medium
  { id: '2', agent_id: 'a2', team_id: 't1', action: 'exec_shell',  reason: 'r', status: 'pending', created_at: '2026-05-13T10:00:00Z', expires_at: '2026-05-13T11:00:00Z', routing_status: null },
  // age 25 h → low
  { id: '3', agent_id: 'a1', team_id: 't2', action: 'write_file',  reason: 'r', status: 'pending', created_at: '2026-05-12T12:00:00Z', expires_at: '2026-05-12T13:00:00Z', routing_status: null },
]

const NOW = new Date('2026-05-13T13:00:00Z').getTime()

describe('deriveOptions', () => {
  it('returns sorted unique agents/teams/actions', () => {
    const opts = deriveOptions(APPROVALS)
    expect(opts.agents).toEqual(['a1', 'a2'])
    expect(opts.teams).toEqual(['t1', 't2'])
    expect(opts.actions).toEqual(['exec_shell', 'send_email', 'write_file'])
  })

  it('returns empty arrays for empty input', () => {
    expect(deriveOptions([])).toEqual({ agents: [], teams: [], actions: [] })
  })
})

describe('applyFilter', () => {
  it('returns all approvals with empty filter', () => {
    expect(applyFilter(APPROVALS, EMPTY_FILTER, NOW)).toHaveLength(3)
  })

  it('filters by agent', () => {
    const r = applyFilter(APPROVALS, { ...EMPTY_FILTER, agent: 'a1' }, NOW)
    expect(r.map((a) => a.id)).toEqual(['1', '3'])
  })

  it('filters by team', () => {
    const r = applyFilter(APPROVALS, { ...EMPTY_FILTER, team: 't1' }, NOW)
    expect(r.map((a) => a.id)).toEqual(['1', '2'])
  })

  it('filters by action', () => {
    const r = applyFilter(APPROVALS, { ...EMPTY_FILTER, action: 'exec_shell' }, NOW)
    expect(r.map((a) => a.id)).toEqual(['2'])
  })

  it('filters by urgency (high < 1h)', () => {
    const r = applyFilter(APPROVALS, { ...EMPTY_FILTER, urgency: 'high' }, NOW)
    expect(r.map((a) => a.id)).toEqual(['1'])
  })

  it('filters by urgency (medium < 6h)', () => {
    const r = applyFilter(APPROVALS, { ...EMPTY_FILTER, urgency: 'medium' }, NOW)
    expect(r.map((a) => a.id)).toEqual(['2'])
  })

  it('filters by urgency (low >= 6h)', () => {
    const r = applyFilter(APPROVALS, { ...EMPTY_FILTER, urgency: 'low' }, NOW)
    expect(r.map((a) => a.id)).toEqual(['3'])
  })

  it('combines multiple filters with AND', () => {
    const r = applyFilter(APPROVALS, { agent: 'a1', team: 't1', action: '', urgency: '' }, NOW)
    expect(r.map((a) => a.id)).toEqual(['1'])
  })

  it('returns empty when no rows match', () => {
    expect(applyFilter(APPROVALS, { ...EMPTY_FILTER, agent: 'nonexistent' }, NOW)).toEqual([])
  })
})
