import { describe, expect, it } from 'vitest'
import { NO_DATA, orNoData, relativeTime } from '../display'

describe('orNoData', () => {
  it('passes real values through, including a genuine zero', () => {
    expect(orNoData('team-alpha')).toBe('team-alpha')
    expect(orNoData(42)).toBe('42')
    // A real measured 0 must survive — only absence folds.
    expect(orNoData(0)).toBe('0')
  })

  it('folds absent values to the shared placeholder', () => {
    expect(orNoData(undefined)).toBe(NO_DATA)
    expect(orNoData(null)).toBe(NO_DATA)
    expect(orNoData('')).toBe(NO_DATA)
  })
})

describe('relativeTime', () => {
  const now = Date.parse('2026-07-25T12:00:00Z')

  it('renders each magnitude band from an ISO timestamp', () => {
    expect(relativeTime('2026-07-25T11:59:30Z', now)).toBe('30s ago')
    expect(relativeTime('2026-07-25T11:45:00Z', now)).toBe('15m ago')
    expect(relativeTime('2026-07-25T09:00:00Z', now)).toBe('3h ago')
    expect(relativeTime('2026-07-22T12:00:00Z', now)).toBe('3d ago')
  })

  it('clamps a future timestamp rather than rendering a negative age', () => {
    expect(relativeTime('2026-07-25T12:00:30Z', now)).toBe('0s ago')
  })

  it('folds an absent or unparseable timestamp', () => {
    expect(relativeTime(undefined, now)).toBe(NO_DATA)
    expect(relativeTime('not-a-date', now)).toBe(NO_DATA)
  })
})
