import { formatDelta, isDeltaPositive } from './kpi-delta'

describe('formatDelta', () => {
  // Normal values
  it('formats positive delta with + sign', () => {
    expect(formatDelta(0.12)).toBe('+12.0%')
  })

  it('formats negative delta without + sign', () => {
    expect(formatDelta(-0.08)).toBe('-8.0%')
  })

  it('formats zero delta without sign', () => {
    expect(formatDelta(0)).toBe('0.0%')
  })

  it('formats small positive delta', () => {
    expect(formatDelta(0.001)).toBe('+0.1%')
  })

  it('formats small negative delta', () => {
    expect(formatDelta(-0.001)).toBe('-0.1%')
  })

  // Non-finite values (AAASM-4195)
  it('returns dash for Infinity', () => {
    expect(formatDelta(Infinity)).toBe('—')
  })

  it('returns dash for -Infinity', () => {
    expect(formatDelta(-Infinity)).toBe('—')
  })

  it('returns dash for NaN', () => {
    expect(formatDelta(NaN)).toBe('—')
  })

  // Large values with compact notation (AAASM-4195)
  it('uses compact notation for very large positive delta (>=10000%)', () => {
    const result = formatDelta(100) // 100 = 10,000%
    expect(result).toMatch(/^\+\d+(\.\d)?K%$/) // e.g. +10K%
  })

  it('uses compact notation for very large negative delta', () => {
    const result = formatDelta(-150) // -150 = -15,000%
    expect(result).toMatch(/^-?\d+(\.\d)?K%$/) // e.g. -15K%
  })

  it('does not use compact notation below threshold', () => {
    expect(formatDelta(99.9)).toBe('+9990.0%') // Just below 100x threshold
  })
})

describe('isDeltaPositive', () => {
  // Standard metrics (higher is better)
  it('returns true for positive delta on agents', () => {
    expect(isDeltaPositive('agents', 0.1)).toBe(true)
  })

  it('returns false for negative delta on agents', () => {
    expect(isDeltaPositive('agents', -0.1)).toBe(false)
  })

  it('returns true for positive delta on invocations', () => {
    expect(isDeltaPositive('invocations', 0.5)).toBe(true)
  })

  // Inverse metrics (lower is better)
  it('returns true for negative delta on p99 (lower latency is good)', () => {
    expect(isDeltaPositive('p99', -0.1)).toBe(true)
  })

  it('returns false for positive delta on p99 (higher latency is bad)', () => {
    expect(isDeltaPositive('p99', 0.1)).toBe(false)
  })

  it('returns true for negative delta on cost (lower cost is good)', () => {
    expect(isDeltaPositive('cost', -0.2)).toBe(true)
  })

  it('returns true for negative delta on anomalies (fewer is good)', () => {
    expect(isDeltaPositive('anomalies', -0.5)).toBe(true)
  })

  // Edge cases
  it('returns true for zero delta on standard metrics', () => {
    expect(isDeltaPositive('agents', 0)).toBe(true)
  })

  it('returns true for zero delta on inverse metrics', () => {
    expect(isDeltaPositive('p99', 0)).toBe(true)
  })
})
