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

  // AAASM-5135. The old bar printed `$4 / $0 · 0%` with `aria-valuenow=0` for a
  // team whose limit is simply not configured — an unknown ceiling presented as
  // a measured, wholly-unburnt one.
  describe('with no configured limit', () => {
    it('never renders a 0 limit or a 0 percentage', () => {
      render(<TeamBudgetBar team="support" spent={4} limit={null} />)
      const bar = screen.getByTestId('team-budget-bar')
      expect(bar).not.toHaveTextContent('$0')
      expect(bar).not.toHaveTextContent('0%')
      expect(screen.getByTestId('team-budget-bar-amount')).toHaveTextContent('$4 /')
    })

    it('omits aria-valuenow so the progressbar reads as indeterminate', () => {
      render(<TeamBudgetBar team="support" spent={4} limit={null} />)
      const bar = screen.getByTestId('team-budget-bar')
      expect(bar).not.toHaveAttribute('aria-valuenow')
      expect(bar.getAttribute('aria-label')).not.toMatch(/\d+%/)
    })

    it('marks the absence as unconfigured and draws no fill', () => {
      render(<TeamBudgetBar team="support" spent={4} limit={null} />)
      expect(screen.getByTestId('team-budget-bar')).toHaveAttribute('data-truth-state', 'unconfigured')
      expect(screen.getByTestId('team-budget-bar-no-limit')).toBeInTheDocument()
      // A zero-width fill is still a rendered measurement of zero, so there is
      // no fill element at all.
      expect(document.querySelector('.team-budget-bar__fill')).toBeNull()
    })

    it('still claims no threshold bucket, so nothing reads as a healthy budget', () => {
      render(<TeamBudgetBar team="support" spent={4} limit={null} />)
      expect(screen.getByTestId('team-budget-bar')).not.toHaveAttribute('data-threshold-bucket')
    })
  })

  // A configured ceiling of exactly $0 is a real fact and must keep behaving as
  // one — it is the case a naive falsy check would merge with the absent one.
  it('treats a configured $0 limit as a measurement, not an absence', () => {
    render(<TeamBudgetBar team="t" spent={0} limit={0} />)
    const bar = screen.getByTestId('team-budget-bar')
    expect(bar).not.toHaveAttribute('data-truth-state')
    expect(bar).toHaveAttribute('aria-valuenow', '0')
    expect(bar).toHaveTextContent('$0 / $0 · 0%')
  })
})
