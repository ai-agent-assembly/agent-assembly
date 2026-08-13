import { describe, it, expect } from 'vitest'
import { clampChartValue, CHART_VALUE_LIMIT } from './chartDomain'

describe('clampChartValue', () => {
  it('passes finite in-range values through unchanged', () => {
    expect(clampChartValue(0)).toBe(0)
    expect(clampChartValue(42)).toBe(42)
    expect(clampChartValue(-17.5)).toBe(-17.5)
    expect(clampChartValue(CHART_VALUE_LIMIT)).toBe(CHART_VALUE_LIMIT)
    expect(clampChartValue(-CHART_VALUE_LIMIT)).toBe(-CHART_VALUE_LIMIT)
  })

  it('clamps the schema-boundary -Number.MAX_VALUE to a finite bound', () => {
    // -1.797e308: the exact value that collapsed the axis / spawned duplicate
    // tick keys before this fix (AAASM-4334).
    const clamped = clampChartValue(-Number.MAX_VALUE)
    expect(clamped).toBe(-CHART_VALUE_LIMIT)
    expect(Number.isFinite(clamped)).toBe(true)
  })

  it('clamps finite-but-extreme magnitudes while preserving sign', () => {
    expect(clampChartValue(Number.MAX_VALUE)).toBe(CHART_VALUE_LIMIT)
    expect(clampChartValue(1e300)).toBe(CHART_VALUE_LIMIT)
    expect(clampChartValue(-1e300)).toBe(-CHART_VALUE_LIMIT)
  })

  it('collapses non-finite values (NaN / ±Infinity) to 0', () => {
    expect(clampChartValue(Number.NaN)).toBe(0)
    expect(clampChartValue(Number.POSITIVE_INFINITY)).toBe(0)
    expect(clampChartValue(Number.NEGATIVE_INFINITY)).toBe(0)
  })
})
