import { describe, expect, it } from 'vitest'
import {
  bucketForBudget,
  bucketForConfiguredBudget,
  burnPercentForConfiguredBudget,
  utilisationPercentForConfiguredBudget,
} from './budgetThreshold'

describe('bucketForConfiguredBudget — AAASM-5185: one rule for a configured ceiling', () => {
  it.each([
    [0, 10, 'ok'],
    [7.99, 10, 'ok'],
    [8, 10, 'warn'],
    [9.49, 10, 'warn'],
    [9.5, 10, 'danger'],
    [11, 10, 'danger'],
  ] as const)('matches the shared bands above zero: spent=%s limit=%s → %s', (spent, limit, expected) => {
    expect(bucketForConfiguredBudget(spent, limit)).toBe(expected)
    // Above zero the two helpers must not diverge, or the Costs surfaces would
    // disagree with topology for ordinary budgets rather than only at $0.
    expect(bucketForConfiguredBudget(spent, limit)).toBe(bucketForBudget(spent, limit))
  })

  it.each([
    [400, 0],
    [0.01, 0],
    // Zero spend against a zero ceiling is still fully consumed: the gateway
    // denies on `spent >= limit`, so `0 >= 0` already blocks.
    [0, 0],
    [5, -1],
  ] as const)('reports a configured $%s / $%s ceiling as danger, never ok', (spent, limit) => {
    expect(bucketForConfiguredBudget(spent, limit)).toBe('danger')
    // The divergence from the shared helper is the whole point of this module:
    // `bucketForBudget` paints the same case green for topology's benefit.
    expect(bucketForBudget(spent, limit)).toBe('ok')
  })
})

describe('utilisationPercentForConfiguredBudget', () => {
  it('reports a real overrun rather than flattening it to exhausted', () => {
    // The clamped burn percentage exists for bar widths; the utilisation KPI
    // prints the number, and 105% is a different fact from 100%.
    expect(utilisationPercentForConfiguredBudget(210, 200)).toBe(105)
    expect(burnPercentForConfiguredBudget(210, 200)).toBe(100)
  })

  it.each([
    [500, 0],
    [0, 0],
  ] as const)('reads a configured $%s / $%s ceiling as 100, not as no percentage', (spent, limit) => {
    // The `limit > 0` guard this replaces yielded `null` here, which the
    // Utilisation card rendered as "nothing is configured" beside a caption
    // quoting `of $0.00 limit`, and which silenced the critical burn banner.
    expect(utilisationPercentForConfiguredBudget(spent, limit)).toBe(100)
  })
})

describe('burnPercentForConfiguredBudget', () => {
  it.each([
    [0, 10, 0],
    [5, 10, 50],
    [10, 10, 100],
  ] as const)('is the plain ratio above zero: spent=%s limit=%s → %s%%', (spent, limit, expected) => {
    expect(burnPercentForConfiguredBudget(spent, limit)).toBe(expected)
  })

  it('clamps an over-budget period to 100 rather than overflowing the track', () => {
    expect(burnPercentForConfiguredBudget(30, 10)).toBe(100)
  })

  it.each([
    [400, 0],
    [0, 0],
  ] as const)('reads a configured $%s / $%s ceiling as fully burnt, not as 0%%', (spent, limit) => {
    expect(burnPercentForConfiguredBudget(spent, limit)).toBe(100)
  })
})
