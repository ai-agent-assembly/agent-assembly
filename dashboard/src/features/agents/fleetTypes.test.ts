import { describe, it, expect } from 'vitest'
import type { Agent } from './api'
import { FLEET_FLAGGED_THRESHOLD, formatLastSeen, toFleetAgent } from './fleetTypes'

function makeAgent(overrides: Partial<Agent> = {}): Agent {
  return {
    id: 'abc',
    name: 'agent-name',
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

describe('toFleetAgent', () => {
  it('copies through identity fields', () => {
    const fa = toFleetAgent(makeAgent({ id: 'id-1', name: 'alpha', framework: 'crewai', status: 'idle' }))
    expect(fa.id).toBe('id-1')
    expect(fa.name).toBe('alpha')
    expect(fa.framework).toBe('crewai')
    expect(fa.status).toBe('idle')
    expect(fa.source.id).toBe('id-1')
  })

  it('derives owner / note from metadata; missing keys become null', () => {
    const withMeta = toFleetAgent(makeAgent({ metadata: { owner: 'alice', note: 'flaky' } }))
    expect(withMeta.owner).toBe('alice')
    expect(withMeta.note).toBe('flaky')

    const withoutMeta = toFleetAgent(makeAgent({ metadata: {} }))
    expect(withoutMeta.owner).toBeNull()
    expect(withoutMeta.note).toBeNull()
  })

  it('parses mode from metadata; invalid or missing values default to enforce', () => {
    expect(toFleetAgent(makeAgent({ metadata: { mode: 'shadow' } })).mode).toBe('shadow')
    expect(toFleetAgent(makeAgent({ metadata: { mode: 'off' } })).mode).toBe('off')
    expect(toFleetAgent(makeAgent({ metadata: { mode: 'enforce' } })).mode).toBe('enforce')
    expect(toFleetAgent(makeAgent({ metadata: { mode: 'gibberish' } })).mode).toBe('enforce')
    expect(toFleetAgent(makeAgent({ metadata: {} })).mode).toBe('enforce')
  })

  it('marks the agent flagged at or above the violations threshold', () => {
    expect(toFleetAgent(makeAgent({ policy_violations_count: FLEET_FLAGGED_THRESHOLD - 1 })).flagged).toBe(false)
    expect(toFleetAgent(makeAgent({ policy_violations_count: FLEET_FLAGGED_THRESHOLD })).flagged).toBe(true)
    expect(toFleetAgent(makeAgent({ policy_violations_count: FLEET_FLAGGED_THRESHOLD + 100 })).flagged).toBe(true)
  })

  it('surfaces last_event as lastSeen; null when absent', () => {
    expect(toFleetAgent(makeAgent({ last_event: '2026-05-13T00:00:00Z' })).lastSeen).toBe('2026-05-13T00:00:00Z')
    expect(toFleetAgent(makeAgent({ last_event: null })).lastSeen).toBeNull()
  })

  it('leaves unwired analytics metrics as null so tables render an em-dash', () => {
    const fa = toFleetAgent(makeAgent())
    expect(fa.trust).toBeNull()
    expect(fa.blocked24h).toBeNull()
    expect(fa.scrubbed24h).toBeNull()
  })
})

describe('formatLastSeen', () => {
  const now = Date.parse('2026-05-13T12:00:00Z')

  it('renders an em-dash for null and the raw string for unparseable input', () => {
    expect(formatLastSeen(null, now)).toBe('—')
    expect(formatLastSeen('not-a-date', now)).toBe('not-a-date')
  })

  it('humanizes into the largest whole unit (s / m / h / d)', () => {
    expect(formatLastSeen('2026-05-13T11:59:48Z', now)).toBe('12s ago')
    expect(formatLastSeen('2026-05-13T11:55:00Z', now)).toBe('5m ago')
    expect(formatLastSeen('2026-05-13T10:00:00Z', now)).toBe('2h ago')
    expect(formatLastSeen('2026-05-10T12:00:00Z', now)).toBe('3d ago')
  })

  it('clamps future timestamps to "0s ago"', () => {
    expect(formatLastSeen('2026-05-13T12:01:00Z', now)).toBe('0s ago')
  })
})
