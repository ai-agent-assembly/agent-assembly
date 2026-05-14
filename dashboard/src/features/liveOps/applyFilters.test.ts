import { describe, expect, it } from 'vitest'
import { applyFilters } from './applyFilters'
import { EMPTY_FILTERS, type LiveOperation } from './types'

const OPS: LiveOperation[] = [
  {
    id: 'op-1',
    agent: 'support-agent',
    team: 'support',
    opType: 'read',
    resource: 'gmail.send',
    status: 'running',
    startedAt: '2026-05-13T14:23:01Z',
    latencyMs: 834,
  },
  {
    id: 'op-2',
    agent: 'deploy-agent',
    team: 'devops',
    opType: 'exec',
    resource: 'shell.exec',
    status: 'blocked',
    startedAt: '2026-05-13T14:23:02Z',
    latencyMs: 4523,
  },
  {
    id: 'op-3',
    agent: 'support-agent',
    team: 'support',
    opType: 'write',
    resource: 'pg.users',
    status: 'pending',
    startedAt: '2026-05-13T14:23:03Z',
    latencyMs: 220,
  },
  {
    id: 'op-4',
    agent: 'support-agent',
    team: 'support',
    opType: 'read',
    resource: 'gmail.send',
    status: 'completing',
    startedAt: '2026-05-13T14:23:04Z',
    latencyMs: 2.3,
  },
]

describe('applyFilters', () => {
  it('returns every op when no filters are set', () => {
    expect(applyFilters(OPS, EMPTY_FILTERS).map((o) => o.id)).toEqual([
      'op-1',
      'op-2',
      'op-3',
      'op-4',
    ])
  })

  it('treats null and undefined axes as unset', () => {
    expect(applyFilters(OPS, { agent: null, team: undefined }).map((o) => o.id))
      .toEqual(['op-1', 'op-2', 'op-3', 'op-4'])
  })

  it('filters by agent', () => {
    expect(applyFilters(OPS, { agent: 'support-agent' }).map((o) => o.id)).toEqual([
      'op-1',
      'op-3',
      'op-4',
    ])
  })

  it('filters by team', () => {
    expect(applyFilters(OPS, { team: 'devops' }).map((o) => o.id)).toEqual(['op-2'])
  })

  it('filters by opType', () => {
    expect(applyFilters(OPS, { opType: 'read' }).map((o) => o.id)).toEqual([
      'op-1',
      'op-4',
    ])
  })

  it('filters by status', () => {
    expect(applyFilters(OPS, { status: 'blocked' }).map((o) => o.id)).toEqual(['op-2'])
  })

  it('AND-combines multiple axes', () => {
    expect(
      applyFilters(OPS, {
        agent: 'support-agent',
        opType: 'read',
      }).map((o) => o.id),
    ).toEqual(['op-1', 'op-4'])
  })

  it('returns empty when no op matches every set axis', () => {
    expect(
      applyFilters(OPS, { agent: 'support-agent', status: 'blocked' }),
    ).toEqual([])
  })

  it('skips a filter when its value is the empty string', () => {
    expect(applyFilters(OPS, { agent: '' as unknown as string }).map((o) => o.id))
      .toEqual(['op-1', 'op-2', 'op-3', 'op-4'])
  })

  it('excludes ops without a team field when the team axis is set', () => {
    const opNoTeam: LiveOperation = {
      id: 'op-no-team',
      agent: 'support-agent',
      opType: 'read',
      resource: 'gmail.send',
      status: 'running',
      startedAt: '2026-05-13T14:23:05Z',
      latencyMs: 10,
    }
    const result = applyFilters([...OPS, opNoTeam], { team: 'support' })
    expect(result.map((o) => o.id)).toEqual(['op-1', 'op-3', 'op-4'])
    expect(result.find((o) => o.id === 'op-no-team')).toBeUndefined()
  })

  it('returns an empty array when given an empty op list', () => {
    expect(applyFilters([], EMPTY_FILTERS)).toEqual([])
    expect(applyFilters([], { agent: 'support-agent' })).toEqual([])
  })
})
