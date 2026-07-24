import { describe, it, expect } from 'vitest'
import { elapsedLabel } from './sessionTime'

describe('elapsedLabel', () => {
  const now = 10_000_000_000

  it('formats seconds, minutes, and hours', () => {
    expect(elapsedLabel(new Date(now - 30_000).toISOString(), now)).toBe('30s')
    expect(elapsedLabel(new Date(now - 5 * 60_000).toISOString(), now)).toBe('5m')
    expect(elapsedLabel(new Date(now - 3 * 3600_000).toISOString(), now)).toBe('3h')
  })

  it('returns an em dash for an unparseable or future timestamp', () => {
    expect(elapsedLabel('not-a-date', now)).toBe('—')
    expect(elapsedLabel(new Date(now + 60_000).toISOString(), now)).toBe('—')
  })

  it('defaults now to the wall clock when omitted', () => {
    expect(elapsedLabel(new Date().toISOString())).toMatch(/^\d+s$/)
  })
})
