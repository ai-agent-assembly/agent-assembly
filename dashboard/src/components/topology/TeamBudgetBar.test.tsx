import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TeamBudgetBar } from './TeamBudgetBar'
import { bucketForBudget } from './budgetThreshold'

describe('bucketForBudget', () => {
  it.each([
    [0, 10, 'ok'],
    [4, 10, 'ok'],
    [7.99, 10, 'ok'],
    [8, 10, 'warn'],
    [9.4, 10, 'warn'],
    [9.49, 10, 'warn'],
    [9.5, 10, 'danger'],
    [10, 10, 'danger'],
    [11, 10, 'danger'],
    [0, 0, 'ok'], // div-by-zero guard
  ] as const)('spent=%s limit=%s → %s', (spent, limit, expected) => {
    expect(bucketForBudget(spent, limit)).toBe(expected)
  })
})

describe('TeamBudgetBar', () => {
  it('renders team name, amount, percent, and data attributes', () => {
    render(<TeamBudgetBar team="support" spent={4} limit={10} />)
    const bar = screen.getByTestId('team-budget-bar')
    expect(bar).toHaveAttribute('data-team', 'support')
    expect(bar).toHaveAttribute('data-threshold-bucket', 'ok')
    expect(bar).toHaveAttribute('aria-valuenow', '40')
    expect(bar).toHaveTextContent('support')
    expect(bar).toHaveTextContent('$4 / $10 · 40%')
  })

  it('flips to warn at 80% (inclusive lower)', () => {
    render(<TeamBudgetBar team="t" spent={8} limit={10} />)
    expect(screen.getByTestId('team-budget-bar')).toHaveAttribute('data-threshold-bucket', 'warn')
  })

  it('flips to danger at 95% (inclusive lower)', () => {
    render(<TeamBudgetBar team="t" spent={9.5} limit={10} />)
    expect(screen.getByTestId('team-budget-bar')).toHaveAttribute('data-threshold-bucket', 'danger')
  })

  it('caps the rendered ratio at 100% even when spent exceeds limit', () => {
    render(<TeamBudgetBar team="t" spent={20} limit={10} />)
    expect(screen.getByTestId('team-budget-bar')).toHaveAttribute('aria-valuenow', '100')
  })
})
