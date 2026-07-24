import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TeamBudgetCard } from './TeamBudgetCard'

describe('TeamBudgetCard', () => {
  it('shows a loading state', () => {
    render(<TeamBudgetCard budget={null} isLoading />)
    expect(screen.getByTestId('team-budget-loading')).toBeInTheDocument()
  })

  it('renders a null-safe empty state when there is no budget node', () => {
    render(<TeamBudgetCard budget={null} isLoading={false} />)
    expect(screen.getByTestId('team-budget-empty')).toHaveTextContent('No budget data')
  })

  it('renders spend-only when the team has no configured limit', () => {
    render(<TeamBudgetCard budget={{ limitUsd: null, spentUsd: 12.5, burnPct: null, bucket: null }} isLoading={false} />)
    expect(screen.getByTestId('team-budget-empty')).toHaveTextContent('$12.50')
    expect(screen.getByTestId('team-budget-empty')).toHaveTextContent('no daily limit')
  })

  it('renders daily spend, limit and burn % when a limit is configured', () => {
    render(<TeamBudgetCard budget={{ limitUsd: 40, spentUsd: 38, burnPct: 95, bucket: 'danger' }} isLoading={false} />)
    expect(screen.getByTestId('team-budget-daily')).toHaveTextContent('$38.00')
    expect(screen.getByTestId('team-budget-daily')).toHaveTextContent('/ $40 daily')
    expect(screen.getByTestId('team-budget-pct')).toHaveTextContent('95.0% used')
  })

  it('clamps the bar fill to 100% when over budget', () => {
    render(<TeamBudgetCard budget={{ limitUsd: 10, spentUsd: 25, burnPct: 250, bucket: 'danger' }} isLoading={false} />)
    expect(screen.getByTestId('team-budget-bar-fill')).toHaveStyle({ width: '100%' })
  })
})
