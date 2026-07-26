import { describe, expect, it } from 'vitest'
import { absent, known } from '../../lib/truthfulness'
import { applyFilters } from './applyFilters'
import { EMPTY_FILTERS, type LiveOperation } from './types'

const OPS: LiveOperation[] = [
  {
    id: 'op-1',
    agent: 'support-agent',
    team: 'support',
    opType: known('read'),
    resource: known('gmail.send'),
    status: 'running',
    startedAt: '2026-05-13T14:23:01Z',
    latencyMs: known(834),
  },
  {
    id: 'op-2',
    agent: 'deploy-agent',
    team: 'devops',
    opType: known('exec'),
    resource: known('shell.exec'),
    status: 'blocked',
    startedAt: '2026-05-13T14:23:02Z',
    latencyMs: known(4523),
  },
  {
    id: 'op-3',
    agent: 'support-agent',
    team: 'support',
    opType: known('write'),
    resource: known('pg.users'),
    status: 'pending',
    startedAt: '2026-05-13T14:23:03Z',
    latencyMs: known(220),
  },
  {
    id: 'op-4',
    agent: 'support-agent',
    team: 'support',
    opType: known('read'),
    resource: known('gmail.send'),
    status: 'completing',
    startedAt: '2026-05-13T14:23:04Z',
    latencyMs: known(2.3),
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
    expect(applyFilters(OPS, { agent: '' }).map((o) => o.id))
      .toEqual(['op-1', 'op-2', 'op-3', 'op-4'])
  })

  it('excludes ops without a team field when the team axis is set', () => {
    const opNoTeam: LiveOperation = {
      id: 'op-no-team',
      agent: 'support-agent',
      opType: known('read'),
      resource: known('gmail.send'),
      status: 'running',
      startedAt: '2026-05-13T14:23:05Z',
      latencyMs: known(10),
    }
    const result = applyFilters([...OPS, opNoTeam], { team: 'support' })
    expect(result.map((o) => o.id)).toEqual(['op-1', 'op-3', 'op-4'])
    expect(result.find((o) => o.id === 'op-no-team')).toBeUndefined()
  })

  // AAASM-5129: an ops_change row carries no verb. Narrowing by verb must drop
  // it, not silently count it as a match for whichever verb was picked.
  it('excludes an op whose verb the event never carried', () => {
    const opNoVerb: LiveOperation = {
      id: 'op-no-verb',
      agent: 'support-agent',
      team: 'support',
      opType: absent<string>('not-supported', 'not carried on ops_change events'),
      resource: absent<string>('not-supported', 'not carried on ops_change events'),
      status: 'running',
      startedAt: '2026-05-13T14:23:06Z',
      latencyMs: absent<number>('not-supported', 'not carried on ops_change events'),
    }
    expect(applyFilters([...OPS, opNoVerb], { opType: 'read' }).map((o) => o.id)).toEqual([
      'op-1',
      'op-4',
    ])
    // With no verb filter it is still a row like any other.
    expect(applyFilters([opNoVerb], EMPTY_FILTERS).map((o) => o.id)).toEqual(['op-no-verb'])
  })

  it('returns an empty array when given an empty op list', () => {
    expect(applyFilters([], EMPTY_FILTERS)).toEqual([])
    expect(applyFilters([], { agent: 'support-agent' })).toEqual([])
  })
})
