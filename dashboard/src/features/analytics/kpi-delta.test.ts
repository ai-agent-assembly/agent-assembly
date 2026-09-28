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
    // AAASM-6200: the sign is required, not optional. The previous `-?` let the
    // unsigned `15K%` satisfy an assertion whose own comment said `-15K%`, which
    // is how the dropped minus sign survived. An optional group here makes the
    // site unobserved: the pattern passes under both behaviours.
    expect(result).toMatch(/^-\d+(\.\d)?K%$/) // e.g. -15K%
  })

  // AAASM-6199: this formatter's compact path had no exact-literal assertion —
  // both tests above bind the result to a variable and match a regex whose
  // groups are optional, so neither would notice a change in fraction digits.
  // Asserted exactly now. Unlike the three currency formatters this one is NOT
  // engine-dependent: it has no `style: 'currency'`, so `minimumFractionDigits`
  // resolves to 0 on every V8 from 11.3 to 14.6 and these literals hold on all
  // of them. That is why it needs coverage rather than a code change.
  // AAASM-6200 completed this: the negative compact path is now pinned too. It
  // was left out above because the formatter dropped the minus sign, so the only
  // literal that would have passed was the wrong one.
  it('formats the compact path to an exact string on any engine', () => {
    expect(formatDelta(100)).toBe('+10K%')
    expect(formatDelta(123.45)).toBe('+12.3K%')
    expect(formatDelta(1234.5)).toBe('+123.5K%')
  })

  // AAASM-6200: the sign, not the magnitude, is what these assert. The boundary
  // is the interesting part — it is sharp, and only the compact side was wrong:
  // -99.9 renders `-9990.0%` and has always been correct, while -100, one step
  // over the threshold, rendered `10K%`.
  it('keeps the minus sign on the compact path', () => {
    expect(formatDelta(-100)).toBe('-10K%')
    expect(formatDelta(-150)).toBe('-15K%')
    expect(formatDelta(-1234.5)).toBe('-123.5K%')
  })

  it('renders the same sign either side of the compact threshold', () => {
    expect(formatDelta(-99.9)).toBe('-9990.0%')
    expect(formatDelta(-100)).toBe('-10K%')
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
