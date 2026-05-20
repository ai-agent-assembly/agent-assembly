import { describe, it, expect } from 'vitest'
import {
  formatCountdown,
  getCountdownTier,
  getRemainingMs,
  getUrgency,
} from './urgency'

const NOW = new Date('2026-05-20T12:00:00Z').getTime()

describe('getUrgency', () => {
  it('returns high for <1h old', () => {
    expect(getUrgency('2026-05-20T11:30:00Z', NOW)).toBe('high')
  })

  it('returns medium for 1–6h old', () => {
    expect(getUrgency('2026-05-20T09:00:00Z', NOW)).toBe('medium')
  })

  it('returns low for >=6h old', () => {
    expect(getUrgency('2026-05-20T05:00:00Z', NOW)).toBe('low')
  })
})

describe('getRemainingMs', () => {
  it('returns positive ms when expiry is in the future', () => {
    expect(getRemainingMs('2026-05-20T12:00:30Z', NOW)).toBe(30_000)
  })

  it('clamps to 0 when expiry is in the past', () => {
    expect(getRemainingMs('2026-05-20T11:59:00Z', NOW)).toBe(0)
  })

  it('returns 0 for an unparseable timestamp', () => {
    expect(getRemainingMs('not-a-date', NOW)).toBe(0)
  })
})

describe('getCountdownTier', () => {
  it('returns high for <60s remaining', () => {
    expect(getCountdownTier(59_999)).toBe('high')
    expect(getCountdownTier(0)).toBe('high')
  })

  it('returns medium for 1–5min remaining', () => {
    expect(getCountdownTier(60_000)).toBe('medium')
    expect(getCountdownTier(4 * 60 * 1000)).toBe('medium')
  })

  it('returns low for >=5min remaining', () => {
    expect(getCountdownTier(5 * 60 * 1000)).toBe('low')
    expect(getCountdownTier(60 * 60 * 1000)).toBe('low')
  })
})

describe('formatCountdown', () => {
  it('formats mm:ss under 1h', () => {
    expect(formatCountdown(0)).toBe('00:00')
    expect(formatCountdown(9 * 1000)).toBe('00:09')
    expect(formatCountdown(65 * 1000)).toBe('01:05')
    expect(formatCountdown(59 * 60 * 1000 + 59 * 1000)).toBe('59:59')
  })

  it('formats Xh Ym at or above 1h', () => {
    expect(formatCountdown(60 * 60 * 1000)).toBe('1h 0m')
    expect(formatCountdown(2 * 60 * 60 * 1000 + 15 * 60 * 1000)).toBe('2h 15m')
  })

  it('clamps negative input to 00:00', () => {
    expect(formatCountdown(-5_000)).toBe('00:00')
  })
})
